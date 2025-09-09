# OOMProf - eBPF-based OOM Kill Profiler

OOMProf is an eBPF-based process monitor that automatically captures heap profiles from Go programs just before they are killed by the Linux Out-of-Memory (OOM) killer, or on-demand for specific processes. This enables post-mortem analysis of memory usage patterns that led to OOM conditions.

## Features

- **Real-time Go process detection**: Automatically discovers and monitors running Go programs
- **Pre-OOM profiling**: Captures memory profiles at the moment of OOM kill signals
- **On-demand profiling**: Profile specific processes by PID using the `-p` flag
- **eBPF-powered monitoring**: Uses kernel tracepoints for low-overhead and stable process monitoring
- **Standard pprof output**: Generates profiles compatible with Go's pprof toolchain
- **Memory limit testing**: Includes cgroup-based testing framework for reproducible OOM scenarios

## How It Works

OOMProf uses eBPF tracepoints to monitor kernel OOM killer events and automatically:

1. **Scans** the system for running Go processes and tracks their memory bucket addresses
2. **Detects** when the OOM killer is about to terminate a Go process via `oom/mark_victim` tracepoint
3. **Captures** the process's heap profile data from kernel space using `signal/signal_deliver` tracepoint
4. **Generates** a standard pprof-compatible profile file

The captured profiles show memory allocation patterns, call stacks, and heap usage that can help identify memory leaks, excessive allocations, or other issues that led to the OOM condition.

## Requirements

- Linux kernel with eBPF support (4.9+)
- Root privileges (required for eBPF program loading)
- Go 1.21+ for building

## Installation

```bash
# Clone the repository
git clone https://github.com/parca-dev/oomprof.git
cd oomprof

# Build the binaries
make
```

This creates:
- `oompa` - Main OOMProf monitor (OOM Profiler Agent)
- `tests/oomer.taux` - Test binary for generating OOM conditions
- `tests/gccache.taux` - Test binary for GC cache stress testing
- `oomprof.test` - Test suite

## Usage

### Basic Monitoring

Run OOMProf as root to monitor all Go processes:

```bash
sudo ./oompa
```

When a Go process is OOM killed, `oompa` will automatically generate a profile file named `{command}-{pid}.pb.gz`.

### On-Demand Profiling

Profile specific processes by PID using the `-p` flag with comma-delimited PIDs:

```bash
# Profile a single process
sudo ./oompa -p 1234

# Profile multiple processes
sudo ./oompa -p 1234,5678,9012
```

This will generate profile files for each specified PID and exit once profiling is complete.

### Analyzing Profiles

View the captured profile using Go's pprof tool:

```bash
# Interactive analysis
go tool pprof {command}-{pid}.pb.gz

# Generate a web interface
go tool pprof -http=:8080 {command}-{pid}.pb.gz

# View top memory consumers
go tool pprof -top {command}-{pid}.pb.gz
```

### Programmatic Usage

OOMProf can be used as a library in your own applications:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/parca-dev/oomprof/oomprof"
)

func main() {
    profileChan := make(chan oomprof.ProfileData)
    state, err := oomprof.Setup(context.Background(), &oomprof.Config{}, profileChan)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to setup OOM profiler: %v\n", err)
        os.Exit(1)
    }
    defer state.Close()

    for profile := range profileChan {
        // Create filename with timestamp: command-pid-YYYYMMDDHHmmss.pb.gz
        timestamp := time.Now().Format("20060102150405")
        filename := fmt.Sprintf("%s-%d-%s.pb.gz", profile.Command, profile.PID, timestamp)

        f, err := os.Create(filename)
        if err != nil {
            log.Printf("Failed to create profile file %s: %v\n", filename, err)
            continue
        }
        if err := profile.Profile.Write(f); err != nil {
            log.Printf("Failed to write profile %s: %v\n", filename, err)
        }
        f.Close()
        log.Printf("Saved profile for %s (PID %d) to %s\n", profile.Command, profile.PID, filename)
    }
}
```

### Testing with Controlled OOM

Test OOMProf with the included test binaries:

```bash
# Run tests with different memory limits
sudo go test -v ./oomprof -run TestOOMProf

# Test with specific memory constraints
sudo go test -v ./oomprof -run TestOOMProfLowMemoryLimits
```

## Configuration

### Environment Variables

- `GODEBUG=memprofilerate=1` - Enable detailed memory profiling (set automatically by test programs)


## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Go Process    │    │       eBPF       │    │   OOMProf       │
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ Memory      │ │    │ │ oom/mark_    │ │    │ │ Process     │ │
│ │ Allocations │ │────┼▶│ victim       │ │────┼▶│ Scanner     │ │
│ │             │ │    │ │ signal/      │ │    │ │             │ │
│ └─────────────┘ │    │ │ signal_      │ │    │ └─────────────┘ │
│                 │    │ │ deliver      │ │    │                 │
│ ┌─────────────┐ │    │ └──────────────┘ │    │ ┌─────────────┐ │
│ │ runtime.    │ │    │ ┌──────────────┐ │    │ │ Profile     │ │
│ │ mbuckets    │ │◀───┼─┤ record_      │ ├────┼▶│ Generator   │ │
│ └─────────────┘ │    │ │ profile_     │ │    │ └─────────────┘ │
│                 │    │ │ buckets      │ │    │                 │
└─────────────────┘    │ └──────────────┘ │    └─────────────────┘
                       └──────────────────┘
```

## Development

### Building

```bash
# Generate eBPF objects and build binaries
make

# Run tests (requires root)
sudo go test -v ./oomprof

# Run specific test with memory limits
sudo go test -v ./oomprof -run TestOOMProfLowMemoryLimits
```

### Project Structure

```
oomprof/
├── main.go              # CLI interface
├── oomprof.c            # eBPF programs (kernel space)
├── oomprof/
│   ├── monitor.go       # Main monitoring logic
│   ├── pprof.go         # Profile generation
│   └── oomprof_test.go  # Test suite
├── tests/
│   ├── oomer/           # Memory allocation test scenarios
│   ├── gccache/         # GC cache stress test program
│   └── compile-oom/     # Go compiler stress test program
└── include/             # eBPF headers
```

## Roadmap

### Current Features (MVP)
- [x] eBPF-based OOM monitoring
- [x] Go process heap profiling
- [x] Standard pprof output format
- [x] Cgroup-based testing framework

### Planned Features
- [ ] Goroutine dump collection
- [ ] Kubernetes/cgroup deployment support
- [ ] Remote profile upload (pprof.me integration)
- [ ] Integration with standard observability reporters
- [ ] jemalloc/tcmalloc/mimalloc support
- [ ] Python memory profiling

## Contributing

Contributions are welcome! Please see the [development](#development) section for build instructions and testing guidelines.

## License

This project is licensed under the Apache License 2.0. See LICENSE for details.
