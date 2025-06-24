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
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// scanGoProcesses scans the /proc filesystem for running Go processes
// and returns a slice of GoProcessInfo structs with PID and mbuckets address
func scanGoProcesses(ctx context.Context, goProcs map[uint32]int64, pidToExePath *sync.Map) ([]GoProcessInfo, error) {
	var results []GoProcessInfo

	// Open /proc directory
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, fmt.Errorf("error opening /proc: %v", err)
	}
	defer procDir.Close()

	// Read all directory entries
	entries, err := procDir.Readdir(-1)
	if err != nil {
		return nil, fmt.Errorf("error reading /proc directory: %v", err)
	}

	// Iterate through all entries in /proc
	for _, entry := range entries {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
		// We're only interested in directories with numeric names (PIDs)
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			// Not a PID directory
			continue
		}

		if goProcs[uint32(pid)] != 0 {
			// Already in the map, skip
			continue
		}

		// Get the executable path for this PID
		exePath := fmt.Sprintf("/proc/%d/exe", pid)

		// Resolve the actual executable path by following the symlink
		realExePath, err := os.Readlink(exePath)
		if err != nil {
			// Skip if we can't read the exe link (usually permission issues)
			goProcs[uint32(pid)] = -1
			//log.Printf("error reading exe link for PID %d: %v", pid, err)
			continue
		}

		// Try to read the command line to get more info
		cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
		cmdline, err := os.ReadFile(cmdlinePath)
		if err != nil {
			// Skip if we can't read the command line (usually permission issues)
			goProcs[uint32(pid)] = -1
			log.WithError(err).WithField("pid", pid).Debug("error reading cmdline for PID")
			continue
		}
		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		comm, err := os.ReadFile(commPath)
		if err != nil {
			// Skip if we can't read the command line (usually permission issues)
			goProcs[uint32(pid)] = -1
			log.WithError(err).WithField("pid", pid).Debug("error reading comm for PID")
			continue
		}

		cmdlineStr := strings.Replace(string(cmdline), "\x00", " ", -1)

		// Try to open the executable using pfelf.Open
		elfFile, err := pfelf.Open(exePath)
		if err != nil {
			// Skip if we can't open the executable (usually permission issues)
			goProcs[uint32(pid)] = -1
			log.WithError(err).WithField("pid", pid).Debug("error opening ELF file for PID")
			continue
		}

		// Get Go version for this executable
		goVersion, err := elfFile.GoVersion()
		if err != nil || goVersion == "" {
			elfFile.Close()
			goProcs[uint32(pid)] = -1
			//log.Printf("error getting Go version for PID %d: %v", pid, err)
			continue
		}

		symtab, err := elfFile.ReadSymbols()
		if err != nil {
			log.WithError(err).WithFields(log.Fields{"cmdline": cmdlineStr, "go_version": goVersion, "pid": pid}).Debug("error looking up symbol table")
			goProcs[uint32(pid)] = -1
			continue
		}

		// This is a Go program - look up the mbuckets symbol
		mbucketsAddr, err := symtab.LookupSymbol("runtime.mbuckets")
		if err != nil {
			log.WithError(err).Error("error looking up mbuckets symbol")
			goProcs[uint32(pid)] = -1
			continue
		}

		goProcs[uint32(pid)] = int64(mbucketsAddr.Address)
		log.WithFields(log.Fields{"pid": pid, "mbuckets": fmt.Sprintf("%x", mbucketsAddr.Address), "comm": strings.TrimSpace(string(comm)), "cmdline": cmdlineStr}).Debug("Found Go program")

		// Store the PID to exe path mapping in the sync.Map
		if pidToExePath != nil {
			pidToExePath.Store(uint32(pid), realExePath)
		}
		// Create a GoProcessInfo struct and add it to our results
		procInfo := GoProcessInfo{
			PID:          uint32(pid),
			GoVersion:    goVersion,
			MBucketsAddr: uint64(mbucketsAddr.Address),
			CmdLine:      cmdlineStr,
			ExePath:      realExePath,
		}

		results = append(results, procInfo)
		elfFile.Close()
	}

	return results, nil
}

// GoProcessInfo holds information about a running Go process
type GoProcessInfo struct {
	PID          uint32 // Process ID
	GoVersion    string // Go version
	MBucketsAddr uint64 // Address of mbuckets
	CmdLine      string // Command line
	ExePath      string // Path to executable
}
