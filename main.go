//go:build linux

package main

import (
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
		oomprof.Canary(10)
		// never returns...
	}
	oomprof.LaunchOOMCanary()
	oomprof.SetupOomProf()
}
