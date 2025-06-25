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
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/google/pprof/profile"
	log "github.com/sirupsen/logrus"
)

func (b *bpfGobucket) memRecord() *bpfMemRecord {
	//get a pointer to end of the stk elements
	return (*bpfMemRecord)(unsafe.Pointer(uintptr(unsafe.Pointer(&b.Stk[0])) + uintptr(b.Header.Nstk*8)))
}

func bucketsToPprof(buckets []bpfGobucket, binaryPath string) (*profile.Profile, error) {
	// Create a new pprof profile
	prof := &profile.Profile{
		DefaultSampleType: "inuse_space",
		SampleType: []*profile.ValueType{
			{Type: "alloc_objects", Unit: "count"},
			{Type: "alloc_space", Unit: "bytes"},
			{Type: "inuse_objects", Unit: "count"},
			{Type: "inuse_space", Unit: "bytes"},
		},
		PeriodType: &profile.ValueType{Type: "space", Unit: "bytes"},
		Period:     512 * 1024, // TODO: read this from process
	}

	// Track unique locations and functions
	locationMap := make(map[uint64]*profile.Location)
	functionMap := make(map[uint64]*profile.Function)
	nextLocationID := uint64(1)
	nextFunctionID := uint64(1)

	// Collect all unique addresses first
	uniqueAddrs := make(map[uint64]bool)
	for _, bucket := range buckets {
		mr := bucket.memRecord()
		allocs := mr.Active.Allocs - mr.Active.Frees
		for i := 0; i < 3; i++ {
			allocs += mr.Future[i].Allocs - mr.Future[i].Frees
		}
		if allocs == 0 {
			continue
		}

		stackLen := int(bucket.Header.Nstk)
		for i := 0; i < stackLen; i++ {
			addr := bucket.Stk[i]
			if addr != 0 {
				uniqueAddrs[addr] = true
			}
		}
	}

	// Batch symbolize all addresses at once
	symbolMap := make(map[uint64]symbolInfo)
	if binaryPath != "" && len(uniqueAddrs) > 0 {
		symbolMap = batchResolveSymbols(binaryPath, uniqueAddrs)
	}

	// Process each bucket
	for b, _ := range buckets {
		mr := buckets[b].memRecord()
		allocs, allocBytes := mr.Active.Allocs, mr.Active.AllocBytes
		inuse, inuseBytes := mr.Active.Allocs-mr.Active.Frees, mr.Active.AllocBytes-mr.Active.FreeBytes
		for i := 0; i < 3; i++ {
			allocs += mr.Future[i].Allocs
			allocBytes += mr.Future[i].AllocBytes
			inuse += mr.Future[i].Allocs - mr.Future[i].Frees
			inuseBytes += mr.Future[i].AllocBytes - mr.Future[i].FreeBytes
		}
		if allocs == 0 {
			continue
		}

		// Create locations for the stack trace
		var locations []*profile.Location

		// Process stack frames (up to nstk)
		stackLen := int(buckets[b].Header.Nstk)

		for i := 0; i < stackLen; i++ {
			addr := buckets[b].Stk[i]
			if addr == 0 {
				break
			}

			// Check if we already have this location
			loc, exists := locationMap[addr]
			if !exists {
				// Create a new location
				loc = &profile.Location{
					ID:      nextLocationID,
					Address: addr,
				}
				nextLocationID++

				// Create a function for this location using symbol resolution
				fn, fnExists := functionMap[addr]
				if !fnExists {
					var funcName, location string
					var lineNum int64 = 1

					if symInfo, ok := symbolMap[addr]; ok {
						funcName = symInfo.name
						location = symInfo.file
						lineNum = symInfo.line
					} else {
						funcName = fmt.Sprintf("func_%x", addr)
						location = ""
					}

					fn = &profile.Function{
						ID:         nextFunctionID,
						Name:       funcName,
						SystemName: funcName,
						Filename:   location,
						StartLine:  lineNum,
					}
					nextFunctionID++
					functionMap[addr] = fn
					prof.Function = append(prof.Function, fn)
				}

				// Add function to location
				loc.Line = []profile.Line{
					{
						Function: fn,
						Line:     1,
					},
				}

				locationMap[addr] = loc
				prof.Location = append(prof.Location, loc)
			}

			locations = append(locations, loc)
		}

		// Create a sample
		//log.Println("Adding sample with allocs:", allocs, "bytes:", allocBytes, "locations:", len(locations))
		sample := &profile.Sample{
			Location: locations,
			Value:    []int64{int64(allocs), int64(allocBytes), int64(inuse), int64(inuseBytes)}, // count, bytes
		}
		prof.Sample = append(prof.Sample, sample)
	}

	// Sort locations by ID
	for i := range prof.Location {
		for j := i + 1; j < len(prof.Location); j++ {
			if prof.Location[i].ID > prof.Location[j].ID {
				prof.Location[i], prof.Location[j] = prof.Location[j], prof.Location[i]
			}
		}
	}

	return prof, nil
}

type symbolInfo struct {
	name string
	file string
	line int64
}

// batchResolveSymbols uses a single addr2line call to resolve all addresses at once
func batchResolveSymbols(binaryPath string, addrs map[uint64]bool) map[uint64]symbolInfo {
	result := make(map[uint64]symbolInfo)

	if len(addrs) == 0 {
		return result
	}

	// Build address list
	var addrList []string
	var addrOrder []uint64
	for addr := range addrs {
		addrList = append(addrList, fmt.Sprintf("0x%x", addr))
		addrOrder = append(addrOrder, addr)
	}

	log.WithField("count", len(addrList)).Debug("Batch symbolizing addresses")
	startTime := time.Now()

	// Call addr2line with all addresses at once
	cmd := exec.Command("addr2line", append([]string{"-e", binaryPath, "-f", "-C"}, addrList...)...)
	output, err := cmd.Output()
	if err != nil {
		log.WithError(err).Debug("addr2line batch call failed")
		// Return empty symbols
		for _, addr := range addrOrder {
			result[addr] = symbolInfo{
				name: fmt.Sprintf("func_%x", addr),
				file: "",
				line: 0,
			}
		}
		return result
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	// addr2line outputs 2 lines per address: function name, then file:line
	for i := 0; i < len(addrOrder) && i*2+1 < len(lines); i++ {
		addr := addrOrder[i]
		funcName := strings.TrimSpace(lines[i*2])
		location := strings.TrimSpace(lines[i*2+1])

		var lineNum int64 = 1
		var fileName string = location

		// Extract line number if available
		if parts := strings.Split(location, ":"); len(parts) >= 2 {
			fileName = parts[0]
			if num, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				lineNum = num
			}
		}

		// Use address as function name if symbolization failed
		if funcName == "??" || location == "??:0" {
			funcName = fmt.Sprintf("func_%x", addr)
			fileName = ""
			lineNum = 0
		}

		result[addr] = symbolInfo{
			name: funcName,
			file: fileName,
			line: lineNum,
		}
	}

	log.WithField("duration", time.Since(startTime)).Debug("Batch symbolization completed")
	return result
}
