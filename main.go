//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"parca.dev/oomprof/oomprof"
)

func main() {
	// Enable memory profiling for this process
	runtime.MemProfile(nil, false)
	if len(os.Args) > 1 && os.Args[1] == "--canary" {
		fmt.Println("starting canary subprocess")
		// Allocate 1% of system memory as ballast
		oomprof.Canary(1.0)
		// never returns...
	}
	oomprof.LaunchOOMCanary(os.Args[0])
	if err := oomprof.SetupOomProf(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup OOM profiler: %v\n", err)
		os.Exit(1)
	}
}
