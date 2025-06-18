//go:build linux

package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	_ "github.com/KimMachineGun/automemlimit"
)

func main() {
	// Enable memory profiling for this process
	runtime.MemProfile(nil, false)

	// Sleep to ensure the process gets scanned by scanGoProcesses
	// The scan interval is 100ms, so we sleep for 200ms to be safe
	time.Sleep(50 * time.Millisecond)

	fmt.Printf("oomer %d\n", os.Getpid())
	checkSwap()
	if len(os.Args) > 1 && os.Args[1] == "--many" {
		allocSpace()
	}
	i := debug.SetMemoryLimit(-1)
	bigAlloc(i * 2)
}

type mem struct {
	space    []byte
	children []*mem
}

func allocSpace() {
	allocSpaceRecursive(10, 10)
}

func allocSpaceRecursive(depth, children int) *mem {
	// recursive function to allocate memory
	if depth <= 0 {
		return nil
	}
	// Allocate a slice of bytes
	var node mem

	node.space = make([]byte, os.Getpagesize())
	node.space[0] = 0xFF // touch the page to ensure it's allocated
	for i := 0; i < children; i++ {
		node.children = append(node.children, allocSpaceRecursive(depth-1, children))
	}
	return &node
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
	fmt.Printf("Successfully allocated %d bytes\n", i)
}
