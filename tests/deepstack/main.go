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

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"time"
)

const allocSize = 4096

// Global variable to prevent compiler optimization
var keepAlive [][]byte

// Track which functions have been called in the current call path to avoid recursion
type callStack struct {
	called [8]bool
}

func (cs *callStack) canCall(funcNum int) bool {
	return !cs.called[funcNum]
}

func (cs *callStack) markCalled(funcNum int) callStack {
	newCS := *cs
	newCS.called[funcNum] = true
	return newCS
}

func func0(cs callStack) {
	data := make([]byte, allocSize)
	keepAlive = append(keepAlive, data)

	newCS := cs.markCalled(0)

	// Call all other functions that haven't been called yet
	if newCS.canCall(1) {
		func1(newCS)
	}
	if newCS.canCall(2) {
		func2(newCS)
	}
	if newCS.canCall(3) {
		func3(newCS)
	}
	if newCS.canCall(4) {
		func4(newCS)
	}
	if newCS.canCall(5) {
		func5(newCS)
	}
	if newCS.canCall(6) {
		func6(newCS)
	}
	if newCS.canCall(7) {
		func7(newCS)
	}
}

func func1(cs callStack) {
	data := make([]byte, allocSize)
	keepAlive = append(keepAlive, data)

	newCS := cs.markCalled(1)

	// Call all other functions that haven't been called yet
	if newCS.canCall(0) {
		func0(newCS)
	}
	if newCS.canCall(2) {
		func2(newCS)
	}
	if newCS.canCall(3) {
		func3(newCS)
	}
	if newCS.canCall(4) {
		func4(newCS)
	}
	if newCS.canCall(5) {
		func5(newCS)
	}
	if newCS.canCall(6) {
		func6(newCS)
	}
	if newCS.canCall(7) {
		func7(newCS)
	}
}

func func2(cs callStack) {
	data := make([]byte, allocSize)
	keepAlive = append(keepAlive, data)

	newCS := cs.markCalled(2)

	// Call all other functions that haven't been called yet
	if newCS.canCall(0) {
		func0(newCS)
	}
	if newCS.canCall(1) {
		func1(newCS)
	}
	if newCS.canCall(3) {
		func3(newCS)
	}
	if newCS.canCall(4) {
		func4(newCS)
	}
	if newCS.canCall(5) {
		func5(newCS)
	}
	if newCS.canCall(6) {
		func6(newCS)
	}
	if newCS.canCall(7) {
		func7(newCS)
	}
}

func func3(cs callStack) {
	data := make([]byte, allocSize)
	keepAlive = append(keepAlive, data)

	newCS := cs.markCalled(3)

	// Call all other functions that haven't been called yet
	if newCS.canCall(0) {
		func0(newCS)
	}
	if newCS.canCall(1) {
		func1(newCS)
	}
	if newCS.canCall(2) {
		func2(newCS)
	}
	if newCS.canCall(4) {
		func4(newCS)
	}
	if newCS.canCall(5) {
		func5(newCS)
	}
	if newCS.canCall(6) {
		func6(newCS)
	}
	if newCS.canCall(7) {
		func7(newCS)
	}
}

func func4(cs callStack) {
	data := make([]byte, allocSize)
	keepAlive = append(keepAlive, data)

	newCS := cs.markCalled(4)

	// Call all other functions that haven't been called yet
	if newCS.canCall(0) {
		func0(newCS)
	}
	if newCS.canCall(1) {
		func1(newCS)
	}
	if newCS.canCall(2) {
		func2(newCS)
	}
	if newCS.canCall(3) {
		func3(newCS)
	}
	if newCS.canCall(5) {
		func5(newCS)
	}
	if newCS.canCall(6) {
		func6(newCS)
	}
	if newCS.canCall(7) {
		func7(newCS)
	}
}

func func5(cs callStack) {
	// Allocate 1KB of memory
	data := make([]byte, allocSize)
	keepAlive = append(keepAlive, data)

	newCS := cs.markCalled(5)

	// Call all other functions that haven't been called yet
	if newCS.canCall(0) {
		func0(newCS)
	}
	if newCS.canCall(1) {
		func1(newCS)
	}
	if newCS.canCall(2) {
		func2(newCS)
	}
	if newCS.canCall(3) {
		func3(newCS)
	}
	if newCS.canCall(4) {
		func4(newCS)
	}
	if newCS.canCall(6) {
		func6(newCS)
	}
	if newCS.canCall(7) {
		func7(newCS)
	}
}

func func6(cs callStack) {
	// Allocate 1KB of memory
	data := make([]byte, allocSize)
	keepAlive = append(keepAlive, data)

	newCS := cs.markCalled(6)

	// Call all other functions that haven't been called yet
	if newCS.canCall(0) {
		func0(newCS)
	}
	if newCS.canCall(1) {
		func1(newCS)
	}
	if newCS.canCall(2) {
		func2(newCS)
	}
	if newCS.canCall(3) {
		func3(newCS)
	}
	if newCS.canCall(4) {
		func4(newCS)
	}
	if newCS.canCall(5) {
		func5(newCS)
	}
	if newCS.canCall(7) {
		func7(newCS)
	}
}

func func7(cs callStack) {
	// Allocate 1KB of memory
	data := make([]byte, allocSize)
	keepAlive = append(keepAlive, data)

	newCS := cs.markCalled(6)

	// Call all other functions that haven't been called yet
	if newCS.canCall(0) {
		func0(newCS)
	}
	if newCS.canCall(1) {
		func1(newCS)
	}
	if newCS.canCall(2) {
		func2(newCS)
	}
	if newCS.canCall(3) {
		func3(newCS)
	}
	if newCS.canCall(4) {
		func4(newCS)
	}
	if newCS.canCall(5) {
		func5(newCS)
	}
	if newCS.canCall(6) {
		func6(newCS)
	}
}

func main() {
	// Enable memory profiling and set profile rate to 1 to capture all allocations
	runtime.MemProfileRate = 1
	runtime.MemProfile(nil, false)

	fmt.Printf("Starting deep stack allocation test...\n")
	fmt.Printf("PID: %d\n", os.Getpid())

	var cs callStack

	// Start from each function to create different initial call paths
	func0(cs)
	func1(cs)
	func2(cs)
	func3(cs)
	func4(cs)
	func5(cs)
	func6(cs)

	bind := ":8888"
	log.Println("Starting HTTP server on", bind)
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	go func() { log.Fatal(http.ListenAndServe(bind, mux)) }()

	fmt.Printf("Allocated %d chunks\n", len(keepAlive))
	fmt.Printf("Total memory allocated: %d bytes\n", len(keepAlive)*allocSize)

	// Keep the program running so we can profile it
	fmt.Printf("Program running, use 'sudo ./oompa -p %d' to profile\n", os.Getpid())
	fmt.Println("Press Ctrl+C to exit...")

	// Sleep indefinitely
	for {
		time.Sleep(time.Hour)
	}
}
