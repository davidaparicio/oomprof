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

func SetupOomProf() error {
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
	if err := loadBpfObjects(&objs, &opts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}
		log.Fatalf("loading objects: %v", err)
		return err
	}
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

	sigKprobe, err := link.Kretprobe("complete_signal", objs.SignalProbe, nil)
	if err != nil {
		log.Fatalf("linking kprobe: %v", err)
	}
	defer sigKprobe.Close()

	// add verbose flag
	go readTracePipe(context.Background())

	// Fixme: remove entries when process goes away
	seenMap := make(map[uint32]int64)

	go monitorEventMap(context.Background(), objs.bpfMaps.SignalEvents, objs.bpfMaps.GoProcs)

	for {
		newProcs, err := scanGoProcesses(seenMap)
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
		// sleep for a second
		time.Sleep(1 * time.Second)
	}
}

func monitorEventMap(ctx context.Context, m *ebpf.Map, goProcs *ebpf.Map) {
	eventReader, err := perf.NewReader(m, 1)
	if err != nil {
		log.Fatalf("error creating perf reader: %v", err)
	}
	var data perf.Record
	for {
		pid := 0
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
				pid = int(ev.Payload)
				log.Println("Received profile event for PID:", pid)
				// Read pprof data

			case lowMemEvent:
				pid = int(ev.Payload)
				// Send SIGUSR1 signal to the target process
				if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
					log.Printf("Failed to send SIGUSR1 to PID %d: %v", pid, err)
				} else {
					log.Printf("Successfully sent SIGUSR1 to PID %d", pid)
				}
			}
		}

		if err := goProcs.Lookup(pid, &data); err != nil {
			log.Printf("error getting PID %d from go_procs map: %v", pid, err)
			continue
		}
	}
}

// scanGoProcesses scans the /proc filesystem for running Go processes
// and returns a slice of GoProcessInfo structs with PID and mbuckets address
func scanGoProcesses(goProcs map[uint32]int64) ([]GoProcessInfo, error) {
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
		fmt.Printf("Found Go program with PID %d mbuckets: %x %s\n", pid, mbucketsAddr.Address, cmdlineStr)
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
