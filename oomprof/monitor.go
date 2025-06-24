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

package oomprof

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/pprof/profile"
	log "github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -tags linux bpf ../oomprof.c

// ProfileData holds the profile information to be sent through the channel
type ProfileData struct {
	PID            uint32
	Command        string
	Profile        *profile.Profile
	MaxStackErrors uint32 // Number of buckets with stack depth > MAX_STACK_DEPTH
	ReadError      bool
}

const (
	lowMemEvent = iota
	profileEvent
)

type State struct {
	// Add fields as needed
	maps *bpfMaps
}

type Config struct {
	ScanInterval time.Duration
	Symbolize    bool
	MemLimit     int
	Verbose      bool
	LogTracePipe bool
}

// The test scanner runs every 10ms so have tests sleep this long to make sure they
// are scanned before they OOM (the tests oom pretty fast by design.
var TestSleep = 20 * time.Millisecond

// Setup initializes the eBPF programs and maps, and starts the monitoring loop.
// If Config.ScanForProcs is true, it will also scan for Go processes and populate the go_procs map.
func Setup(ctx context.Context, cfg *Config, profileChan chan<- ProfileData) (*State, func(), error) {
	//TODO: check if kernel is older than 5.4 and exit if so

	log.Debug("Starting BPF object loading...")

	objs, closer, err := loadBPF()

	if err != nil {
		return nil, nil, fmt.Errorf("loading BPF objects: %v", err)
	}

	s := &State{
		maps: &objs.bpfMaps,
	}

	// All BPF objects are now loaded successfully
	log.Debug("All BPF probes attached successfully")

	if cfg.LogTracePipe {
		go readTracePipe(ctx)
	}
	// Fixme: remove entries when process goes away
	seenMap := make(map[uint32]int64)

	// Create a sync.Map to store pid -> exe path mapping

	var pidToExePath *sync.Map
	if cfg.Symbolize {
		pidToExePath = &sync.Map{}
	}

	go monitorEventMap(ctx, &objs.bpfMaps, pidToExePath, profileChan)

	log.Debug("Starting main monitoring loop...")

	// Channel to signal when first scan is complete
	firstScanDone := make(chan struct{})

	// Run the process monitoring loop in a goroutine and return after one scan.
	go func() {
		firstScan := true
		for {
			select {
			case <-ctx.Done():
				log.Debug("Context cancelled, shutting down monitoring loop")
				return
			default:
				newProcs, err := scanGoProcesses(ctx, seenMap, pidToExePath)
				if err != nil {
					log.WithError(err).Error("error scanning Go processes")
					if firstScan {
						close(firstScanDone)
						firstScan = false
					}
					continue
				}
				for _, p := range newProcs {
					s.addGoProcess(p.PID, p.MBucketsAddr)
				}

				// Signal that first scan is complete
				if firstScan {
					close(firstScanDone)
					firstScan = false
				}

				// sleep for a second with context check
				select {
				case <-ctx.Done():
					return
				case <-time.After(cfg.ScanInterval):
				}
			}
		}
	}()

	// Wait for first scan to complete before returning
	select {
	case <-firstScanDone:
		log.Debug("First Go process scan completed")
	case <-ctx.Done():
		closer()
		return nil, nil, ctx.Err()
	}

	return s, closer, nil
}

func loadBPF() (*bpfObjects, func(), error) {
	// Allow the current process to lok memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, err
	}
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}

	// Set program options - disable CO-RE for compatibility
	var progOpts ebpf.ProgramOptions
	// Only enable verbose logging if we're in debug mode
	if log.GetLevel() == log.DebugLevel {
		progOpts.LogLevel = ebpf.LogLevelBranch | ebpf.LogLevelInstruction | ebpf.LogLevelStats
		progOpts.LogSizeStart = 50 * 1024 * 1024 // Increased to 50MB
	}

	opts := ebpf.CollectionOptions{
		Maps:     ebpf.MapOptions{},
		Programs: progOpts,
	}

	// Load BPF objects - this is the slow part that might get stuck
	loadStart := time.Now()
	if err := loadBpfObjects(&objs, &opts); err != nil {
		// Try to find VerifierError in the error chain
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("Verifier error details:\n%+v\n", verr)
		} else {
			// Try unwrapping the error
			fmt.Printf("BPF load error: %+v\n", err)
			// Check each level of the error chain
			currentErr := err
			for i := 0; i < 10; i++ {
				currentErr = errors.Unwrap(currentErr)
				if currentErr == nil {
					break
				}
				if errors.As(currentErr, &verr) {
					fmt.Printf("Found VerifierError at level %d:\n%+v\n", i+1, verr)
					break
				}
			}
		}
		return nil, nil, fmt.Errorf("loading objects: %v", err)
	}
	log.WithField("duration", time.Since(loadStart)).Debug("BPF objects loaded")

	// Initialize profile_pid map with key 0 and value 0
	var key uint32 = 0
	var pidValue int32 = 0
	if err := objs.ProfilePid.Put(key, pidValue); err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("initializing profile_pid map: %w", err)
	}


	oomMarkVictimTracepoint, err := link.Tracepoint("oom", "mark_victim", objs.OomMarkVictimHandler, nil)
	if err != nil {
		objs.Close()
		return nil, nil, err
	}

	schedSwitch, err := link.Tracepoint("signal", "signal_deliver", objs.SignalProbe, nil)
	if err != nil {
		oomMarkVictimTracepoint.Close()
		objs.Close()
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}
		return nil, nil, fmt.Errorf("linking tracepoint: %v", err)
	}

	// Register tail call program for bucket processing
	tailCallIndex := uint32(0)  // RECORD_PROFILE_BUCKETS_PROG = 0
	if err := objs.TailCallMap.Put(tailCallIndex, objs.RecordProfileBucketsProg); err != nil {
		schedSwitch.Close()
		oomMarkVictimTracepoint.Close()
		objs.Close()
		return nil, nil, fmt.Errorf("registering tail call program: %v", err)
	}

	return &objs, func() {
		schedSwitch.Close()
		oomMarkVictimTracepoint.Close()
		objs.Close()
	}, nil
}

// Consider making this a public API and letting clients manage which processes to monitor.
func (s *State) addGoProcess(pid uint32, mbucketsAddr uint64) error {
	// update go_procs map
	goProc := bpfGoProc{
		Mbuckets: mbucketsAddr,
	}
	if err := s.maps.GoProcs.Put(pid, &goProc); err != nil {
		log.WithError(err).WithField("pid", pid).Error("error putting PID into go_procs map")
		return err
	}
	return nil
}

// ProfilePid profiles a specific PID by setting it in the profile_pid map and sending a signal
func (s *State) ProfilePid(ctx context.Context, pid uint32) error {
	// Check if the PID exists in go_procs map
	var gop bpfGoProc
	if err := s.maps.GoProcs.Lookup(pid, &gop); err != nil {
		return fmt.Errorf("PID %d not found in go_procs map: %w", pid, err)
	}

	// Reset num_buckets to 0 to allow re-profiling
	gop.NumBuckets = 0
	if err := s.maps.GoProcs.Put(pid, &gop); err != nil {
		return fmt.Errorf("failed to reset num_buckets for PID %d: %w", pid, err)
	}

	// Set the PID in profile_pid map
	var key uint32 = 0
	pidValue := int32(pid)
	if err := s.maps.ProfilePid.Put(key, pidValue); err != nil {
		return fmt.Errorf("failed to set profile_pid: %w", err)
	}

	// Send SIGUSR1 to trigger profile collection
	if err := syscall.Kill(int(pid), syscall.SIGUSR1); err != nil {
		// Reset profile_pid on error
		s.maps.ProfilePid.Put(key, int32(0))
		return fmt.Errorf("failed to send SIGUSR1 to PID %d: %w", pid, err)
	}

	log.WithField("pid", pid).Debug("Sent SIGUSR1 to PID, waiting for profile...")

	// Wait for profile_pid to be reset to 0 by monitorEventMap
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			var currentPid int32
			if err := s.maps.ProfilePid.Lookup(key, &currentPid); err != nil {
				return fmt.Errorf("failed to check profile_pid: %w", err)
			}
			if currentPid == 0 {
				log.WithField("pid", pid).Debug("Profile for PID completed")
				return nil
			}
		}
	}
}

func readProfile(maps *bpfMaps, numBuckets uint32, binaryPath string) (*profile.Profile, error) {
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
			return nil, fmt.Errorf("batch lookup failed at offset %d: %v", start, err)
		}

		// Add retrieved buckets to our collection
		allBuckets = append(allBuckets, values[:count]...)

		// If we got fewer buckets than requested, we've reached the end
		if count < int(batchSize) {
			break
		}
	}

	// Process the retrieved buckets
	log.WithFields(log.Fields{"retrieved": len(allBuckets), "total": numBuckets}).Info("Retrieved buckets")

	// Convert to pprof format
	convertStart := time.Now()
	prof, err := bucketsToPprof(allBuckets, binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to convert buckets to pprof: %v", err)
	}
	log.WithField("duration", time.Since(convertStart)).Info("Converted buckets to pprof")

	return prof, nil
}

func monitorEventMap(ctx context.Context, maps *bpfMaps, pidToExePath *sync.Map, profileChan chan<- ProfileData) {
	eventReader, err := perf.NewReader(maps.SignalEvents, 1)
	if err != nil {
		log.WithError(err).Error("error creating perf reader")
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
				log.WithError(err).Error("reading from perf event reader")
				continue
			}
			if rec.LostSamples != 0 {
				log.WithField("lost_samples", rec.LostSamples).Warn("perf event ring buffer full")
				continue
			}
			// Extract the PID from the raw sample data
			ev := bpfEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				log.WithError(err).Error("parsing perf event")
				continue
			}
			switch ev.EventType {
			case profileEvent:
				pid = ev.Payload
				log.WithField("pid", pid).Debug("Received profile event for PID")
				// Read pprof data

				var gop bpfGoProc
				if err := maps.GoProcs.Lookup(pid, &gop); err != nil {
					log.WithError(err).WithField("pid", pid).Error("error getting PID from go_procs map")
					continue
				}
				log.WithFields(log.Fields{"pid": pid, "buckets": gop.NumBuckets}).Debug("Found Go process")

				// Retrieve the binary path from the sync.Map
				binaryPath := ""
				if pidToExePath != nil {
					if pathValue, ok := pidToExePath.Load(pid); ok {
						binaryPath = pathValue.(string)
					} else {
						log.WithField("pid", pid).Debug("binary path not found for PID")
					}
				}

				prof, err := readProfile(maps, gop.NumBuckets, binaryPath)
				if err != nil {
					log.WithError(err).WithField("pid", pid).Error("error reading profile for PID")
				} else {
					log.WithField("pid", pid).Debug("Successfully read profile for PID")
					// Extract command name from exe path
					command := "unknown"
					if binaryPath != "" {
						// Get just the basename of the binary path
						if idx := strings.LastIndex(binaryPath, "/"); idx != -1 {
							command = binaryPath[idx+1:]
						} else {
							command = binaryPath
						}
					}
					// Send profile data through channel
					sendStart := time.Now()
					log.WithField("pid", pid).Debug("Attempting to send profile to channel")
					select {
					case profileChan <- ProfileData{
						PID:            pid,
						Command:        command,
						Profile:        prof,
						ReadError:      gop.ReadError,
						MaxStackErrors: gop.MaxStackErrors,
					}:
						log.WithFields(log.Fields{
							"pid": pid,
							"send_duration": time.Since(sendStart),
						}).Info("Successfully sent profile to channel")
						// Clear the profile_pid map after successfully sending the profile
						var key uint32 = 0
						var pidValue int32 = 0
						if err := maps.ProfilePid.Put(key, pidValue); err != nil {
							log.WithError(err).Error("Failed to clear profile_pid map")
						}
					case <-ctx.Done():
						log.WithField("pid", pid).Debug("Context cancelled while sending profile")
						return
					}
				}
			case lowMemEvent:
				pid = ev.Payload
				log.WithField("pid", pid).Debug("Received lowMemEvent for PID")

				// Send SIGUSR1 signal to the target process
				if err := syscall.Kill(int(pid), syscall.SIGUSR1); err != nil {
					log.WithError(err).WithField("pid", pid).Error("Failed to send SIGUSR1 to PID")
				} else {
					log.WithField("pid", pid).Debug("Successfully sent SIGUSR1 to PID")
				}
			}
		}
	}
}
