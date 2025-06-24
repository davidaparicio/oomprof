// Copyright 2022-2025 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"parca.dev/oomprof/oomprof"
)

func main() {
	// Enable memory profiling for this process
	runtime.MemProfile(nil, false)

	var pidsFlag string
	var debug bool
	flag.StringVar(&pidsFlag, "p", "", "Comma-delimited list of PIDs to profile")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	// Configure logging
	if debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	ctx := context.Background()

	// Create channel for profile data with buffer to avoid blocking
	profileChan := make(chan oomprof.ProfileData, 10)

	cfg := oomprof.Config{
		MemLimit:     32,
		Verbose:      true,
		Symbolize:    true,
		LogTracePipe: debug,
	}
	state, clos, err := oomprof.Setup(ctx, &cfg, profileChan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup OOM profiler: %v\n", err)
		os.Exit(1)
	}
	defer clos()

	// Start goroutine to write profiles to disk
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Debug("Profile writer goroutine started")
		for profile := range profileChan {
			log.WithFields(log.Fields{"pid": profile.PID, "command": profile.Command}).Debug("Received profile")
			
			// Skip empty profiles
			if profile.Profile == nil || len(profile.Profile.Sample) == 0 {
				log.WithField("pid", profile.PID).Debug("Skipping empty profile")
				continue
			}
			
			// Create filename with timestamp: command-pid-YYYYMMDDHHmmss.pb.gz
			timestamp := time.Now().Format("20060102150405")
			filename := fmt.Sprintf("%s-%d-%s.pb.gz", profile.Command, profile.PID, timestamp)
			f, err := os.Create(filename)
			if err != nil {
				log.WithError(err).WithField("filename", filename).Error("Failed to create profile file")
				continue
			}

			if err := profile.Profile.Write(f); err != nil {
				log.WithError(err).WithField("filename", filename).Error("Failed to write profile")
			}
			f.Close()
			log.WithField("filename", filename).Info("Profile written")
		}
		log.Debug("Profile writer goroutine exiting")
	}()

	// If -p flag is provided, profile specific PIDs
	if pidsFlag != "" {
		pids := strings.Split(pidsFlag, ",")
		for _, pidStr := range pids {
			pidStr = strings.TrimSpace(pidStr)
			var pid int

			if pidStr == "self" {
				// Profile the current process (oompa itself)
				pid = os.Getpid()
				log.WithField("pid", pid).Debug("Profiling self")
			} else {
				var err error
				pid, err = strconv.Atoi(pidStr)
				if err != nil {
					log.WithField("pid", pidStr).Error("Invalid PID")
					continue
				}
				log.WithField("pid", pid).Debug("Profiling PID")
			}

			if err := state.ProfilePid(ctx, uint32(pid)); err != nil {
				log.WithError(err).WithField("pid", pid).Error("Failed to profile PID")
			}
		}
		// Close the channel after all PIDs are profiled
		close(profileChan)
		// Wait for all profiles to be written
		wg.Wait()
	} else {
		// For OOM monitoring mode, keep running until interrupted
		wg.Wait()
	}
}
