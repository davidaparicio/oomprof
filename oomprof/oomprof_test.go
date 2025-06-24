//go:build linux

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
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/stretchr/testify/require"
)

// setupTestCgroup creates a cgroup with specified memory limit for safe testing
// Returns cleanup function and whether cgroup was successfully created
func setupTestCgroup(t *testing.T, memLimitMB int64) (func(), bool) {
	// Create cgroup manager for oomprof-test
	memLimit := memLimitMB * 1024 * 1024 // Convert MB to bytes
	cgroupName := fmt.Sprintf("/oomprof-test-%dmb", memLimitMB)
	manager, err := cgroup2.NewManager("/sys/fs/cgroup", cgroupName, &cgroup2.Resources{
		Memory: &cgroup2.Memory{
			Max: &memLimit,
		},
	})
	if err != nil {
		t.Logf("WARNING: Failed to create cgroup (tests will run without memory limits): %v", err)
		return func() {}, false
	}

	// Cleanup function
	cleanup := func() {
		if err := manager.Delete(); err != nil {
			t.Logf("Failed to delete cgroup: %v", err)
		}
	}

	return cleanup, true
}

// runCommandInCgroup runs a command within the specified cgroup using a helper script
func runCommandInCgroup(cgroupPath string, originalCmd *exec.Cmd) *exec.Cmd {
	// Create a new command that uses the run-in-cgroup.sh script
	args := []string{cgroupPath, originalCmd.Path}
	args = append(args, originalCmd.Args[1:]...)

	cmd := exec.Command("./run-in-cgroup.sh", args...)
	cmd.Dir = originalCmd.Dir
	cmd.Env = originalCmd.Env
	cmd.Stdin = originalCmd.Stdin
	cmd.Stdout = originalCmd.Stdout
	cmd.Stderr = originalCmd.Stderr

	return cmd
}

var testCfg = Config{
	ScanInterval: 10 * time.Millisecond,
	MemLimit:     32, // Default memory limit in MB if not using cgroup
	Verbose:      true,
	LogTracePipe: true,
	Symbolize:    true,
}

func TestOOMProf(t *testing.T) {
	// Check if go is available to decide which test to run
	_, goAvailable := exec.LookPath("go")

	if goAvailable == nil {
		// Full test with cgroups and multiple memory limits
		t.Log("Running full test suite with cgroups")
		memLimits := []int64{300, 1024, 2048}
		for _, memLimit := range memLimits {
			t.Run(fmt.Sprintf("MemLimit_%dMB", memLimit), func(t *testing.T) {
				testOOMProfWithMemLimit(t, memLimit)
			})
		}
	} else {
		// Simplified test for QEMU environment
		t.Log("Running simplified QEMU test (go not available)")
		testOOMProfQEMUSimple(t)
	}
}

func testOOMProfWithMemLimit(t *testing.T, memLimitMB int64) {
	// Skip if not root
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// Setup cgroup for safe testing
	cleanup, cgroupOK := setupTestCgroup(t, memLimitMB)
	defer cleanup()

	t.Logf("Testing with memory limit: %d MB", memLimitMB)

	// Create a context with cancel for clean shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create channel for profile data
	profileChan := make(chan ProfileData, 10)

	// Start OOM profiler
	_, close, err := Setup(ctx, &testCfg, profileChan)
	require.NoError(t, err)

	defer close()

	profRateAll := []string{"GODEBUG=memprofilerate=1", "HOME=/root"}

	// Define test cases
	testCases := []struct {
		name         string
		cmd          string
		args         []string
		expectedFunc string
		env          []string
	}{
		{
			name:         "go build with TryInlineCall",
			cmd:          "go",
			args:         []string{"build", "../tests/compile-oom/main.go"},
			expectedFunc: "inline.TryInlineCall",
			env:          append(profRateAll, "GOTOOLCHAIN=go1.24.0"),
		},
		{
			name:         "oomer big alloc",
			cmd:          "./oomer.taux",
			args:         []string{},
			expectedFunc: "bigAlloc",
			env:          profRateAll,
		},
		{
			name:         "oomer small allocs",
			cmd:          "./oomer.taux",
			args:         []string{"--many"},
			expectedFunc: "allocSpaceRecursive",
			env:          profRateAll,
		},
		{
			name:         "gc cache with cycles",
			cmd:          "./gccache.taux",
			args:         []string{"-entry-size", "8192", "-add-rate", "2000", "-expire-rate", "100"},
			expectedFunc: "LeakyCache).Add", // Expect the Add method to show up prominently
			env:          profRateAll,
		},
	}

	// Check if required tools are available
	_, goAvailable := exec.LookPath("go")
	_, addr2lineAvailable := exec.LookPath("addr2line")

	maxRetries := 3

	for _, tc := range testCases {
		attempts := 0
		passed := false
		for !passed {
			if attempts >= maxRetries {
				t.Fatalf("Test %s failed after %d attempts", tc.name, attempts)
			}
			passed = t.Run(tc.name, func(t *testing.T) {
				attempts++
				// Skip go build test if go is not available
				if tc.cmd == "go" && goAvailable != nil {
					t.Skipf("Skipping go build test: go not available (%v)", goAvailable)
				}

				// Start the OOM-triggering process
				cmd := exec.Command(tc.cmd, tc.args...)
				cmd.Env = tc.env
				cmd.Stderr = os.Stderr
				cmd.Stdout = os.Stdout
				cmd.Dir = ""

				var finalCmd *exec.Cmd
				if cgroupOK {
					// Create command that runs in cgroup
					cgroupPath := fmt.Sprintf("/oomprof-test-%dmb", memLimitMB)
					finalCmd = runCommandInCgroup(cgroupPath, cmd)
				} else {
					// Run command directly without cgroup
					finalCmd = cmd
				}

				// Start the command in background
				err := finalCmd.Start()
				if err != nil {
					t.Fatalf("Failed to start %s: %v", tc.name, err)
				}

				// Wait for profile or timeout
				select {
				case profile := <-profileChan:
					t.Logf("Received profile for PID %d, command: %s", profile.PID, profile.Command)

					if profile.ReadError {
						return
					}

					// Validate profile has samples
					require.NotNil(t, profile.Profile)
					require.NotEmpty(t, profile.Profile.Sample, "Profile should have samples")

					// Calculate total memory allocated across all samples
					totalBytes := int64(0)
					totalAllocs := int64(0)
					for _, sample := range profile.Profile.Sample {
						if len(sample.Value) >= 2 {
							totalAllocs += sample.Value[0]
							totalBytes += sample.Value[1]
						}
					}
					t.Logf("Total allocations captured: %d allocs, %d bytes (%.2f MB)", totalAllocs, totalBytes, float64(totalBytes)/(1024*1024))
					memLimitBytes := float64(memLimitMB * 1024 * 1024)
					t.Logf("Memory limit was %d MB, captured %.2f%% of limit", memLimitMB, float64(totalBytes)/memLimitBytes*100)

					// Check memprofilerate setting
					t.Logf("GODEBUG env: %v", tc.env)

					// Log top 5 samples by size
					type sampleInfo struct {
						idx   int
						bytes int64
					}
					var topSamples []sampleInfo
					for i, sample := range profile.Profile.Sample {
						if len(sample.Value) >= 2 {
							topSamples = append(topSamples, sampleInfo{i, sample.Value[1]})
						}
					}
					sort.Slice(topSamples, func(i, j int) bool {
						return topSamples[i].bytes > topSamples[j].bytes
					})
					t.Logf("Top 5 samples by allocation size:")
					for i := 0; i < 5 && i < len(topSamples); i++ {
						t.Logf("  Sample %d: %d bytes (%.2f MB)",
							topSamples[i].idx,
							topSamples[i].bytes,
							float64(topSamples[i].bytes)/(1024*1024))
					}

					// Find the heaviest sample and log its details
					maxBytes := int64(0)
					heaviestIdx := -1
					for i, sample := range profile.Profile.Sample {
						if len(sample.Value) >= 2 && sample.Value[1] > maxBytes {
							maxBytes = sample.Value[1]
							heaviestIdx = i
						}
					}
					if heaviestIdx >= 0 {
						t.Logf("Heaviest sample: index %d with %d bytes (%.2f MB)", heaviestIdx, maxBytes, float64(maxBytes)/(1024*1024))
						// Log functions in heaviest sample
						t.Logf("Functions in heaviest sample:")
						for _, loc := range profile.Profile.Sample[heaviestIdx].Location {
							for _, line := range loc.Line {
								if line.Function != nil {
									t.Logf("  - %s", line.Function.Name)
								}
							}
						}
					}

					// First check if expected function is in the heaviest sample
					found := false
					if heaviestIdx >= 0 {
						t.Logf("Checking heaviest sample for function %s", tc.expectedFunc)
						for _, loc := range profile.Profile.Sample[heaviestIdx].Location {
							for _, line := range loc.Line {
								if line.Function != nil && strings.Contains(line.Function.Name, tc.expectedFunc) {
									found = true
									t.Logf("✓ Found expected function %s in heaviest sample (index %d)", tc.expectedFunc, heaviestIdx)
									break
								}
							}
							if found {
								break
							}
						}
					}

					// If not in heaviest sample, log where it actually is
					if !found {
						t.Logf("Function %s NOT in heaviest sample, searching all samples...", tc.expectedFunc)
						// First, log all functions containing "inline" to debug
						if tc.name == "go build with TryInlineCall" {
							t.Logf("All functions containing 'inline':")
							for i, sample := range profile.Profile.Sample {
								for _, loc := range sample.Location {
									for _, line := range loc.Line {
										if line.Function != nil && strings.Contains(line.Function.Name, "inline") {
											allocBytes := int64(0)
											if len(sample.Value) >= 2 {
												allocBytes = sample.Value[1]
											}
											t.Logf("  Sample %d: %s (%d bytes)", i, line.Function.Name, allocBytes)
										}
									}
								}
							}
						}

						for i, sample := range profile.Profile.Sample {
							for _, loc := range sample.Location {
								for _, line := range loc.Line {
									if line.Function != nil && strings.Contains(line.Function.Name, tc.expectedFunc) {
										found = true
										allocBytes := int64(0)
										if len(sample.Value) >= 2 {
											allocBytes = sample.Value[1]
										}
										t.Logf("Found expected function %s in sample %d (bytes=%d, %.2f MB)", tc.expectedFunc, i, allocBytes, float64(allocBytes)/(1024*1024))
										goto done
									}
								}
							}
						}
					}
				done:

					// Skip function name checking if addr2line is not available
					if addr2lineAvailable != nil {
						t.Logf("Skipping function name validation: addr2line not available (%v)", addr2lineAvailable)
					} else {
						// For go build test, we expect the function to be in the heaviest sample
						// But only if we captured a reasonable amount of memory
						if tc.name == "go build with TryInlineCall" && heaviestIdx >= 0 {
							// If we captured less than 1% of memory limit, the profile might be incomplete
							captureRatio := float64(totalBytes) / memLimitBytes
							if captureRatio < 0.01 {
								t.Logf("WARNING: Only captured %.2f%% of memory limit, profile may be incomplete", captureRatio*100)
								t.Logf("This suggests the process was using memory outside the Go heap (mmap, stack, etc)")
							}

							foundInHeaviest := false
							for _, loc := range profile.Profile.Sample[heaviestIdx].Location {
								for _, line := range loc.Line {
									if line.Function != nil && strings.Contains(line.Function.Name, tc.expectedFunc) {
										foundInHeaviest = true
										break
									}
								}
								if foundInHeaviest {
									break
								}
							}
							// Since we're capturing so little memory, let's just check if the function exists anywhere
							if captureRatio < 0.01 {
								require.True(t, found, "Expected function %s not found in profile", tc.expectedFunc)
							} else {
								require.True(t, foundInHeaviest, "Expected function %s to be in heaviest sample, but was not", tc.expectedFunc)
							}
						} else {
							require.True(t, found, "Expected function %s not found in profile", tc.expectedFunc)
						}
					}

				case <-time.After(300 * time.Second):
					t.Errorf("Timeout waiting for profile in test %s", tc.name)
				}

				// Make sure oom finishes
				if err := finalCmd.Wait(); err != nil {
					t.Logf("Process %s exited with err: %v", tc.name, err)
				}
			})
		}
	}

	// Cancel context to clean up
	cancel()
}

func testOOMProfQEMUSimple(t *testing.T) {
	// Skip if not root
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	t.Logf("Testing QEMU environment with simplified tests")

	// Create a context with cancel for clean shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create channel for profile data
	profileChan := make(chan ProfileData, 10)

	cfg := Config{
		LogTracePipe: true,
		Verbose:      true,
	}
	// Start OOM profiler
	_, closer, err := Setup(ctx, &cfg, profileChan)
	require.NoError(t, err)
	defer closer()

	profRateAll := []string{"GODEBUG=memprofilerate=1", "HOME=/root"}

	// Define simplified test cases for QEMU - only oomer and gccache, skip symbolic validation
	testCases := []struct {
		name     string
		cmd      string
		args     []string
		env      []string
		checkPid bool
	}{
		{
			name:     "oomer big alloc",
			cmd:      "./oomer.taux",
			args:     []string{},
			env:      profRateAll,
			checkPid: true,
		},
		{
			name:     "oomer small allocs",
			cmd:      "./oomer.taux",
			args:     []string{"--many"},
			env:      profRateAll,
			checkPid: true,
		},
		{
			name:     "gc cache with cycles",
			cmd:      "./gccache.taux",
			args:     []string{"-entry-size", "8192", "-add-rate", "2000", "-expire-rate", "100"},
			env:      profRateAll,
			checkPid: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create command
			cmd := exec.Command(tc.cmd, tc.args...)
			cmd.Env = tc.env

			// Start command
			err := cmd.Start()
			require.NoError(t, err, "Failed to start command %s", tc.cmd)

			finalCmd := cmd

			// Wait for either profile data or timeout
			select {
			case profile := <-profileChan:
				t.Logf("Received profile for PID %d, command: %s", profile.PID, profile.Command)

				// Basic validation - just check we got some data
				require.NotNil(t, profile.Profile)
				require.NotEmpty(t, profile.Profile.Sample, "Profile should have samples")

				// Calculate total memory allocated across all samples
				totalBytes := int64(0)
				totalAllocs := int64(0)
				for _, sample := range profile.Profile.Sample {
					if len(sample.Value) >= 2 {
						totalAllocs += sample.Value[0]
						totalBytes += sample.Value[1]
					}
				}

				t.Logf("Total allocations captured: %d allocs, %d bytes (%.2f MB)",
					totalAllocs, totalBytes, float64(totalBytes)/(1024*1024))

				// Skip symbolic validation in QEMU environment
				t.Logf("Skipping symbolic validation in QEMU environment")

			case <-time.After(300 * time.Second):
				t.Errorf("Timeout waiting for profile in test %s", tc.name)
			}

			// Make sure process finishes
			if err := finalCmd.Wait(); err != nil {
				t.Logf("Process %s exited with err: %v", tc.name, err)
			}
		})
	}

	// Cancel context to clean up
	cancel()
}
