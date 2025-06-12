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
		// Allocate some memory as ballast in a subprocess
		fmt.Println("starting canary subprocess")
		// Things get flaky at 1%
		oomprof.Canary(2.5)
		// never returns...
	}
	oomprof.LaunchOOMCanary(os.Args[0])
	if err := oomprof.SetupOomProf(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup OOM profiler: %v\n", err)
		os.Exit(1)
	}
}
