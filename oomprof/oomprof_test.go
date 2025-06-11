//go:build linux

package oomprof

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPass(t *testing.T) {
}

func TestOOM(t *testing.T) {
	//t.Skip()

	// Create a context with cancel for clean shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// WaitGroup to track goroutines
	var wg sync.WaitGroup

	// Start canary
	can := exec.Command("./oompa.taux", "--canary")
	err := can.Start()
	require.NoError(t, err)
	err = Rescore(can.Process.Pid)
	require.NoError(t, err)

	// Track if canary was killed
	canaryKilled := make(chan struct{})

	// Start OOM profiler
	wg.Add(1)
	oomProfDone := make(chan struct{})
	oomProfReady := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(oomProfDone)
		// Signal that we're starting
		close(oomProfReady)
		err := SetupOomProf(ctx)
		if err != nil && err != context.Canceled {
			t.Log("SetupOomProf error:", err)
		}
	}()

	// Wait for OOM profiler to start loading
	<-oomProfReady
	t.Log("Waiting for BPF objects to load...")
	time.Sleep(2 * time.Second)

	// Start target process which will consume all memory
	wg.Add(1)
	oomerDone := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(oomerDone)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				cmd := exec.CommandContext(ctx, "./oomer.taux")
				out, err := cmd.CombinedOutput()
				if err != nil {
					// Check if context was cancelled
					if ctx.Err() != nil {
						return
					}
					// we were killed
					t.Log("oomer killed:", err)
					break
				}
				if len(out) > 0 {
					t.Log(string(out))
				}
				// go around again, sometimes we don't oom
				t.Log("oomer didn't get killed")
			}
		}
	}()

	// Wait for canary to be killed
	wg.Add(1)
	canaryDone := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(canaryDone)
		err = can.Wait()
		// err should be kill'd
		t.Log("canary killed:", err)
		close(canaryKilled)
	}()

	// Wait for canary to be killed or timeout
	select {
	case <-canaryKilled:
		t.Log("Test completed: canary was killed")
	case <-time.After(30 * time.Second):
		t.Log("Test timeout: canary was not killed within 30 seconds")
	}

	// Cancel context to stop all goroutines
	cancel()

	// Give goroutines time to exit cleanly
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("All goroutines exited cleanly")
	case <-time.After(15 * time.Second):
		// Check which goroutines are still running
		var stillRunning []string
		select {
		case <-oomProfDone:
		default:
			stillRunning = append(stillRunning, "SetupOomProf")
		}
		select {
		case <-oomerDone:
		default:
			stillRunning = append(stillRunning, "oomer launcher")
		}
		select {
		case <-canaryDone:
		default:
			stillRunning = append(stillRunning, "canary waiter")
		}
		
		// Get goroutine dump
		buf := make([]byte, 1<<16)
		stackSize := runtime.Stack(buf, true)
		stackDump := string(buf[:stackSize])
		
		panic(fmt.Sprintf("Timeout waiting for goroutines to exit. Still running: %v\n\nGoroutine dump:\n%s", 
			stillRunning, stackDump))
	}
}
