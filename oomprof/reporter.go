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

// Reporter is the interface that oomprof clients must implement to receive oom memory profile events.
type Reporter interface {
	// SampleEvents reports a batch of samples with their metadata.
	// This is called once for every 1000 buckets to reduce overhead.
	SampleEvents(samples []Sample, meta SampleMeta) error
}

// Address represents a memory address.
type Address uint64

// Sample represents a profiling sample with stack trace and metrics.
type Sample struct {
	// Addresses contains the stack frame addresses.
	Addresses []Address
	// Allocs is the number of allocations.
	Allocs uint64
	// Frees is the number of frees.
	Frees uint64
	// AllocBytes is the number of bytes allocated.
	AllocBytes uint64
	// FreeBytes is the number of bytes freed.
	FreeBytes uint64
}

// SampleMeta contains metadata for a trace event.
type SampleMeta struct {
	// Timestamp is the time the event occurred.
	Timestamp uint64
	// Comm is the command name of the process.
	Comm string
	// ProcessName is the name of the process.
	ProcessName string
	// ExecutablePath is the full path to the executable.
	ExecutablePath string
	// PID is the process ID.
	PID uint32
	// buildid for exe
	BuildID string
	// CustomLabels contains custom labels associated with the memory profile.
	CustomLabels map[string]string
}
