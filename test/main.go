// go:build linux

package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func main() {
	// Enable memory profiling for this process
	runtime.MemProfile(nil, false)
	fmt.Println("oomer")
	checkSwap()
	_, i := getSystemMemory()
	fmt.Println("memory: ", i)
	bigAlloc(i)
}

func checkSwap() {
	content, err := os.ReadFile("/proc/swaps")
	if err != nil {
		panic("Could not read /proc/swaps")
	}

	lines := strings.Split(string(content), "\n")
	// If there's more than just the header line, swap is configured
	if len(lines) > 1 && len(lines[1]) > 0 {
		panic("swap enabled, disable it")
	}

}

// getSystemMemory returns the amount of total and available memory in bytes
func getSystemMemory() (int64, int64) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	totalSystem := int64(0)
	availableSystem := int64(0)

	// Linux-specific approach using /proc/meminfo
	content, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					val, err := strconv.ParseInt(fields[1], 10, 64)
					if err == nil {
						totalSystem = val * 1024 // Convert from KB to bytes
					}
				}
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					val, err := strconv.ParseInt(fields[1], 10, 64)
					if err == nil {
						availableSystem = val * 1024 // Convert from KB to bytes
					}
				}
			}
		}
	}

	// If we couldn't get system memory through OS-specific means, use Go runtime info
	if totalSystem == 0 {
		// This is not accurate for system RAM, just Go memory usage limits
		totalSystem = int64(memStats.Sys)
		availableSystem = totalSystem - int64(memStats.Alloc)
		fmt.Println("Warning: Could not determine system memory accurately, using estimates")
	}

	return totalSystem, availableSystem
}

func bigAlloc(i int64) {
	var space []byte

	// Try to allocate memory, reducing size if allocation fails
	for space == nil && i > 0 {
		// Use defer and recover to handle potential OOM errors
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("Failed to allocate %d bytes, trying a smaller size\n", i)
					i = i - 4096
				}
			}()

			// Try to allocate memory
			space = make([]byte, i)
		}()
	}

	if space == nil {
		fmt.Println("Could not allocate memory")
		return
	}

	fmt.Printf("Successfully allocated %d bytes\n", i)

	// Actually use the memory by writing to it
	for k := int64(0); k < i; k += 4096 {
		space[k] = byte(k & 255)
	}

	fmt.Println("Memory filled. Should have oomed, going for more ...")
	bigAlloc(i / 2)
}
