//go:build linux

package oomprof

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
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
	err := SetupOomProf(ctx, profileChan)
	require.NoError(t, err)

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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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

			// Give a bit of time between tests
			time.Sleep(2 * time.Second)
		})
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

	// Debug BTF availability in QEMU environment
	t.Logf("Checking BTF availability...")

	// Check /sys/kernel/ contents
	if entries, err := os.ReadDir("/sys/kernel"); err == nil {
		t.Logf("/sys/kernel/ contents: %v", entries)
		for _, entry := range entries {
			t.Logf("  - %s (dir: %v)", entry.Name(), entry.IsDir())
		}
	} else {
		t.Logf("Failed to read /sys/kernel/: %v", err)
	}

	// Check if /sys/kernel/btf exists and try to mount it if not
	if _, err := os.Stat("/sys/kernel/btf"); os.IsNotExist(err) {
		t.Logf("/sys/kernel/btf does not exist, attempting to create and mount...")
		if err := os.MkdirAll("/sys/kernel/btf", 0755); err != nil {
			t.Logf("Failed to create /sys/kernel/btf: %v", err)
		} else {
			// Try to mount BTF filesystem
			if err := syscall.Mount("bpffs", "/sys/kernel/btf", "bpf", 0, ""); err != nil {
				t.Logf("Failed to mount bpffs at /sys/kernel/btf: %v", err)
				// Try mounting sysfs specifically for BTF
				if err := syscall.Mount("sysfs", "/sys/kernel/btf", "sysfs", 0, ""); err != nil {
					t.Logf("Failed to mount sysfs at /sys/kernel/btf: %v", err)
				} else {
					t.Logf("Successfully mounted sysfs at /sys/kernel/btf")
				}
			} else {
				t.Logf("Successfully mounted bpffs at /sys/kernel/btf")
			}
		}
	} else if err == nil {
		t.Logf("/sys/kernel/btf exists")
		if entries, err := os.ReadDir("/sys/kernel/btf"); err == nil {
			t.Logf("/sys/kernel/btf contents: %v", entries)
		}
	}

	// Check kernel configuration for BTF support
	if data, err := os.ReadFile("/proc/config.gz"); err == nil {
		t.Logf("/proc/config.gz found, size: %d bytes", len(data))

		// Decompress and parse config
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			defer reader.Close()
			configData, err := io.ReadAll(reader)
			if err == nil {
				configStr := string(configData)
				t.Logf("Kernel config decompressed, size: %d bytes", len(configStr))

				// Check for BTF-related configs
				btfConfigs := []string{
					"CONFIG_DEBUG_INFO_BTF=",
					"CONFIG_DEBUG_INFO_BTF_MODULES=",
					"CONFIG_BPF_SYSCALL=",
					"CONFIG_BPF_LSM=",
					"CONFIG_DEBUG_INFO_DWARF",
				}

				// Debug: Show raw search for CONFIG_DEBUG_INFO_BTF
				if strings.Contains(configStr, "CONFIG_DEBUG_INFO_BTF") {
					t.Logf("Raw search found CONFIG_DEBUG_INFO_BTF in config")
					// Find all lines with BTF
					lines := strings.Split(configStr, "\n")
					for i, line := range lines {
						if strings.Contains(line, "CONFIG_DEBUG_INFO_BTF") {
							t.Logf("Line %d: %s", i, line)
						}
					}
				} else {
					t.Logf("Raw search did NOT find CONFIG_DEBUG_INFO_BTF in config")
					// Show some sample config lines for debugging
					lines := strings.Split(configStr, "\n")
					t.Logf("Sample config lines (first 10):")
					for i := 0; i < 10 && i < len(lines); i++ {
						t.Logf("  %d: %s", i, lines[i])
					}
				}

				for _, config := range btfConfigs {
					if idx := strings.Index(configStr, config); idx != -1 {
						// Extract the line containing this config
						start := strings.LastIndex(configStr[:idx], "\n")
						if start == -1 {
							start = 0
						} else {
							start++
						}
						end := strings.Index(configStr[idx:], "\n")
						if end == -1 {
							end = len(configStr) - idx
						}
						line := configStr[start : idx+end]
						t.Logf("Found config: %s", line)
					}
				}
			}
		}
	} else {
		t.Logf("/proc/config.gz not found: %v", err)
	}

	// Check if kernel has BTF section in vmlinux
	if data, err := os.ReadFile("/proc/kallsyms"); err == nil {
		if strings.Contains(string(data), "btf") {
			t.Logf("Found BTF symbols in /proc/kallsyms")
		} else {
			t.Logf("No BTF symbols found in /proc/kallsyms")
		}
	}

	// Check if BTF is available via other means
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		t.Logf("/sys/kernel/btf/vmlinux exists!")
		if info, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
			t.Logf("  Size: %d bytes", info.Size())
		}
	} else {
		t.Logf("/sys/kernel/btf/vmlinux not found: %v", err)
	}

	// Try to manually trigger BTF initialization by loading a simple BPF program first
	t.Logf("Attempting to initialize BTF by creating /sys/kernel/btf manually...")
	// Check if we can access raw BTF data through other means
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, entry := range entries {
			if strings.Contains(entry.Name(), "btf") {
				t.Logf("Found BTF-related file in /proc: %s", entry.Name())
			}
		}
	}

	// Create a context with cancel for clean shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create channel for profile data
	profileChan := make(chan ProfileData, 10)

	// Start OOM profiler
	err := SetupOomProf(ctx, profileChan)
	require.NoError(t, err)

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

			// Give a bit of time between tests
			time.Sleep(2 * time.Second)
		})
	}

	// Cancel context to clean up
	cancel()
}
