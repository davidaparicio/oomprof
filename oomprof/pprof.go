package oomprof

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/google/pprof/profile"
)

func (b *bpfGobucket) memRecord() *bpfMemRecord {
	//get a pointer to end of the stk elements
	return (*bpfMemRecord)(unsafe.Pointer(uintptr(unsafe.Pointer(&b.Stk[0])) + uintptr(b.Header.Nstk*8)))
}

func bucketsToPprof(buckets []bpfGobucket, binaryPath string) (*profile.Profile, error) {
	// Create a new pprof profile
	prof := &profile.Profile{
		SampleType: []*profile.ValueType{
			{Type: "alloc_objects", Unit: "count"},
			{Type: "alloc_space", Unit: "bytes"},
		},
		PeriodType: &profile.ValueType{Type: "space", Unit: "bytes"},
		Period:     1,
		TimeNanos:  time.Now().UnixNano(),
	}

	// Track unique locations and functions
	locationMap := make(map[uint64]*profile.Location)
	functionMap := make(map[uint64]*profile.Function)
	nextLocationID := uint64(1)
	nextFunctionID := uint64(1)

	// Process each bucket
	for b, _ := range buckets {
		mr := buckets[b].memRecord()
		allocs, allocBytes := mr.Active.Allocs-mr.Active.Frees, mr.Active.AllocBytes-mr.Active.FreeBytes
		for i := 0; i < 3; i++ {
			allocs += mr.Future[i].Allocs - mr.Future[i].Frees
			allocBytes += mr.Future[i].AllocBytes - mr.Future[i].FreeBytes
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
					funcName, location, lineNum := resolveSymbol(binaryPath, addr)
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
			Value:    []int64{int64(allocs), int64(allocBytes)}, // count, bytes
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

// resolveSymbol uses addr2line to resolve an address to function name and location
func resolveSymbol(binaryPath string, addr uint64) (string, string, int64) {
	if binaryPath == "" {
		return fmt.Sprintf("func_%x", addr), "", 0
	}

	cmd := exec.Command("addr2line", "-e", binaryPath, "-f", "-C", fmt.Sprintf("0x%x", addr))
	output, err := cmd.Output()
	if err != nil {
		return fmt.Sprintf("func_%x", addr), "", 0
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) >= 2 {
		funcName := strings.TrimSpace(lines[0])
		location := strings.TrimSpace(lines[1])

		// Extract line number if available
		var lineNum int64 = 1
		if parts := strings.Split(location, ":"); len(parts) >= 2 {
			if num, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				lineNum = num
			}
		}

		if funcName != "??" && location != "??:0" {
			return funcName, location, lineNum
		}
	}

	return fmt.Sprintf("func_%x", addr), "", 0
}
