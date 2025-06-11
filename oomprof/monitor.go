package oomprof

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -tags linux bpf ../oomprof.c

const (
	lowMemEvent = iota
	profileEvent
)

func SetupOomProf(ctx context.Context) error {
	// Check context before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	
	log.Println("Starting BPF object loading...")
	
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
		Programs: ebpf.ProgramOptions{
			// Set the log level to 1 to get more information about the loading process.
			LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelInstruction | ebpf.LogLevelStats,
			LogSizeStart: 1024 * 1024,
		},
	}
	
	// Load BPF objects - this is the slow part that might get stuck
	loadStart := time.Now()
	if err := loadBpfObjects(&objs, &opts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}
		return fmt.Errorf("loading objects: %v", err)
	}
	log.Printf("BPF objects loaded in %v", time.Since(loadStart))
	defer objs.Close()

	kp1, err := link.Kprobe("oom_badness", objs.OomBadnessEntry, nil)
	if err != nil {
		return err
	}
	defer kp1.Close()

	kp2, err := link.Kretprobe("oom_badness", objs.OomBadnessReturn, nil)
	if err != nil {
		return err
	}
	defer kp2.Close()

	kp3, err := link.Kprobe("oom_kill_process", objs.OomKillProcessHandler, nil)
	if err != nil {
		return err
	}
	defer kp3.Close()

	// sigKprobe, err := link.Kretprobe("complete_signal", objs.SignalProbe, nil)
	// if err != nil {
	// 	log.Fatalf("linking kprobe: %v", err)
	// }
	// defer sigKprobe.Close()
	schedSwitch, err := link.Tracepoint("signal", "signal_deliver", objs.SignalProbe, nil)
	if err != nil {
		return fmt.Errorf("linking tracepoint: %v", err)
	}
	defer schedSwitch.Close()

	// All BPF objects are now loaded successfully
	log.Println("All BPF probes attached successfully")

	// add verbose flag
	go readTracePipe(ctx)

	// Fixme: remove entries when process goes away
	seenMap := make(map[uint32]int64)

	go monitorEventMap(ctx, &objs.bpfMaps)

	log.Println("Starting main monitoring loop...")
	
	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, shutting down SetupOomProf")
			return ctx.Err()
		default:
			newProcs, err := scanGoProcesses(ctx, seenMap)
			if err != nil {
				return err
			}
			// Display the results
			for _, p := range newProcs {
				// update go_procs map
				goProc := bpfGoProc{
					Mbuckets: p.MBucketsAddr,
				}
				if err := objs.GoProcs.Put(p.PID, &goProc); err != nil {
					log.Printf("error putting PID %d into go_procs map: %v", p.PID, err)
					return err
				}
			}
			// sleep for a second with context check
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(1 * time.Second):
			}
		}
	}
}

func readProfile(maps *bpfMaps, numBuckets uint32) error {
	const maxBatchSize = uint32(32) // Adjust based on your needs and kernel limits

	var allBuckets []bpfGobucket
	var cursor ebpf.MapBatchCursor

	// Process buckets in batches
	for start := uint32(0); start < numBuckets; start += maxBatchSize {
		// Calculate batch size
		batchSize := maxBatchSize
		if start+batchSize > numBuckets {
			batchSize = numBuckets - start
		}

		// Prepare keys and values for batch lookup
		keys := make([]uint32, batchSize)
		values := make([]bpfGobucket, batchSize)

		for i := uint32(0); i < batchSize; i++ {
			keys[i] = start + i
		}

		// Batch lookup
		count, err := maps.MemBuckets.BatchLookup(&cursor, keys, values, nil)
		if err != nil {
			return fmt.Errorf("batch lookup failed at offset %d: %v", start, err)
		}

		// Add retrieved buckets to our collection
		allBuckets = append(allBuckets, values[:count]...)

		// If we got fewer buckets than requested, we've reached the end
		if count < int(batchSize) {
			break
		}
	}

	// Process the retrieved buckets
	log.Printf("Retrieved %d buckets out of %d", len(allBuckets), numBuckets)

	// TODO: Process the buckets as needed (e.g., format as pprof, analyze, etc.)
	for i, bucket := range allBuckets {
		if bucket.Size > 0 {
			log.Printf("Bucket %d: size=%d, nstk=%d, hash=%x", i, bucket.Size, bucket.Nstk, bucket.Hash)
		}
	}

	return nil
}

func monitorEventMap(ctx context.Context, maps *bpfMaps) {
	eventReader, err := perf.NewReader(maps.SignalEvents, 1)
	if err != nil {
		log.Printf("error creating perf reader: %v", err)
		return
	}
	defer eventReader.Close()
	
	// Close reader when context is cancelled
	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()
	
	for {
		var pid uint32
		select {
		case <-ctx.Done():
			return
		default:
			rec, err := eventReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %s", err)
				continue
			}
			if rec.LostSamples != 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", rec.LostSamples)
				continue
			}
			// Extract the PID from the raw sample data
			ev := bpfEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}
			switch ev.EventType {
			case profileEvent:
				pid = ev.Payload
				log.Println("Received profile event for PID:", pid)
				// Read pprof data

				var gop bpfGoProc
				if err := maps.GoProcs.Lookup(pid, &gop); err != nil {
					log.Printf("error getting PID %d from go_procs map: %v", pid, err)
					continue
				}
				log.Printf("Found Go process with PID %d with %d buckets", pid, gop.NumBuckets)
				if err := readProfile(maps, gop.NumBuckets); err != nil {
					log.Printf("error reading profile for PID %d: %v", pid, err)
				} else {
					log.Printf("Successfully read profile for PID %d", pid)
				}
			case lowMemEvent:
				pid = ev.Payload
				// Send SIGUSR1 signal to the target process
				if err := syscall.Kill(int(pid), syscall.SIGUSR1); err != nil {
					log.Printf("Failed to send SIGUSR1 to PID %d: %v", pid, err)
				} else {
					log.Printf("Successfully sent SIGUSR1 to PID %d", pid)
				}
			}
		}

	}
}

// scanGoProcesses scans the /proc filesystem for running Go processes
// and returns a slice of GoProcessInfo structs with PID and mbuckets address
func scanGoProcesses(ctx context.Context, goProcs map[uint32]int64) ([]GoProcessInfo, error) {
	var results []GoProcessInfo

	// Open /proc directory
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, fmt.Errorf("error opening /proc: %v", err)
	}
	defer procDir.Close()

	// Read all directory entries
	entries, err := procDir.Readdir(-1)
	if err != nil {
		return nil, fmt.Errorf("error reading /proc directory: %v", err)
	}

	// Iterate through all entries in /proc
	for _, entry := range entries {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
		// We're only interested in directories with numeric names (PIDs)
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			// Not a PID directory
			continue
		}

		if goProcs[uint32(pid)] != 0 {
			// Already in the map, skip
			continue
		}

		// Get the executable path for this PID
		exePath := fmt.Sprintf("/proc/%d/exe", pid)

		// Try to read the command line to get more info
		cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
		cmdline, err := os.ReadFile(cmdlinePath)
		if err != nil {
			// Skip if we can't read the command line (usually permission issues)
			goProcs[uint32(pid)] = -1
			continue
		}

		cmdlineStr := strings.Replace(string(cmdline), "\x00", " ", -1)

		// Try to open the executable using pfelf.Open
		elfFile, err := pfelf.Open(exePath)
		if err != nil {
			// Skip if we can't open the executable (usually permission issues)
			goProcs[uint32(pid)] = -1
			continue
		}

		// Get Go version for this executable
		goVersion, err := elfFile.GoVersion()
		if err != nil || goVersion == "" {
			elfFile.Close()
			goProcs[uint32(pid)] = -1
			continue
		}

		symtab, err := elfFile.ReadSymbols()
		if err != nil {
			log.Printf("error looking up symbol table: %s %s %v %v", cmdlineStr, goVersion, pid, err)
			goProcs[uint32(pid)] = -1
			continue
		}

		// This is a Go program - look up the mbuckets symbol
		mbucketsAddr, err := symtab.LookupSymbol("runtime.mbuckets")
		if err != nil {
			log.Printf("error looking up mbuckets symbol: %v", err)
			goProcs[uint32(pid)] = -1
			continue
		}

		goProcs[uint32(pid)] = int64(mbucketsAddr.Address)
		log.Printf("Found Go program with PID %d mbuckets: %x %s\n", pid, mbucketsAddr.Address, cmdlineStr)
		// Create a GoProcessInfo struct and add it to our results
		procInfo := GoProcessInfo{
			PID:          uint32(pid),
			GoVersion:    goVersion,
			MBucketsAddr: uint64(mbucketsAddr.Address),
			CmdLine:      cmdlineStr,
			ExePath:      exePath,
		}

		results = append(results, procInfo)
		elfFile.Close()
	}

	return results, nil
}

// GoProcessInfo holds information about a running Go process
type GoProcessInfo struct {
	PID          uint32 // Process ID
	GoVersion    string // Go version
	MBucketsAddr uint64 // Address of mbuckets
	CmdLine      string // Command line
	ExePath      string // Path to executable
}

func getTracePipe() (*os.File, error) {
	for _, mnt := range []string{
		"/sys/kernel/debug/tracing",
		"/sys/kernel/tracing",
		"/tracing",
		"/trace"} {
		t, err := os.Open(mnt + "/trace_pipe")
		if err == nil {
			return t, nil
		}
		log.Printf("Could not open trace_pipe at %s: %s", mnt, err)
	}
	return nil, os.ErrNotExist
}

func readTracePipe(ctx context.Context) {
	tp, err := getTracePipe()
	if err != nil {
		log.Printf("Could not open trace_pipe, check that debugfs is mounted")
		return
	}

	// When we're done kick ReadString out of blocked I/O.
	go func() {
		<-ctx.Done()
		tp.Close()
	}()

	r := bufio.NewReader(tp)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				continue
			}
			if errors.Is(err, os.ErrClosed) {
				return
			}
			log.Print(err)
			return
		}
		line = strings.TrimSpace(line)
		if line != "" {
			log.Printf("%s", line)
		}
	}
}
