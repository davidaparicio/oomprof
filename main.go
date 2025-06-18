//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"

	"parca.dev/oomprof/oomprof"
)

func main() {
	// Enable memory profiling for this process
	runtime.MemProfile(nil, false)
	ctx := context.Background()
	
	// Create channel for profile data
	profileChan := make(chan oomprof.ProfileData)
	
	if err := oomprof.SetupOomProf(ctx, profileChan); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup OOM profiler: %v\n", err)
		os.Exit(1)
	}
	
	// Scan profileChan and write profiles until channel is closed
	for profile := range profileChan {
		// Create filename from command and PID
		filename := fmt.Sprintf("%s-%d.pb.gz", profile.Command, profile.PID)
		f, err := os.Create(filename)
		if err != nil {
			log.Printf("Failed to create profile file %s: %v", filename, err)
			continue
		}
		
		if err := profile.Profile.Write(f); err != nil {
			log.Printf("Failed to write profile to %s: %v", filename, err)
		}
		f.Close()
		log.Printf("Profile written to %s", filename)
	}
}
