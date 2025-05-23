//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -tags linux bpf gooomer.c -- -I../headers

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--canary" {
		for {
			// Spin forever
			time.Sleep(1 * time.Second)
		}
	}
	runtime.MemProfile(nil, false)
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
		Programs: ebpf.ProgramOptions{
			// Set the log level to 1 to get more information about the loading process.
			LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelInstruction | ebpf.LogLevelStats,
		},
	}
	if err := loadBpfObjects(&objs, &opts); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp1, err := link.Kprobe("oom_badness", objs.OomBadnessEntry, nil)
	if err != nil {
		log.Fatalf("linking kprobe: %v", err)
	}
	defer kp1.Close()

	kp2, err := link.Kretprobe("oom_badness", objs.OomBadnessReturn, nil)
	if err != nil {
		log.Fatalf("linking kprobe: %v", err)
	}
	defer kp2.Close()

	kp3, err := link.Kprobe("oom_kill_process", objs.OomKillProcessHandler, nil)
	if err != nil {
		log.Fatalf("linking kprobe: %v", err)
	}
	defer kp3.Close()

	go readTracePipe(context.Background())

	// Fixme: remove entries when process goes away
	seenMap := make(map[uint32]int64)

	go spinOOMCanary(seenMap, objs.GoProcs)

	for {
		newProcs, err := scanGoProcesses(seenMap)
		if err != nil {
			log.Fatalf("error scanning /proc: %v", err)
		}
		// Display the results
		for _, p := range newProcs {
			// update go_procs map
			if err := objs.GoProcs.Put(p.PID, p.MBucketsAddr); err != nil {
				log.Fatalf("error putting PID %d into go_procs map: %v", p.PID, err)
			}
		}
		// sleep for a second
		time.Sleep(1 * time.Second)
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

func spinOOMCanary(seenMap map[uint32]int64, goProcs *ebpf.Map) {
	for {
		// launch myself with --canary arg
		c := exec.Command(os.Args[0], "--canary")
		if err := c.Start(); err != nil {
			log.Fatalf("error starting canary process: %v", err)
		}
		// get pid of the canary process
		pid := c.Process.Pid
		// write 1000 to /proc/<pid>/oom_score_adj
		oomAdjPath := fmt.Sprintf("/proc/%d/oom_score_adj", pid)
		if err := os.WriteFile(oomAdjPath, []byte("1000"), 0644); err != nil {
			log.Fatalf("error writing to %s: %v", oomAdjPath, err)
		}
		// wait for it to finish
		if err := c.Wait(); err != nil {
			log.Printf("error waiting for canary process: %v", err)
		}
		// Sleep for a second to let the kernel OOM killer do its thing
		time.Sleep(1 * time.Second)
	}
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
