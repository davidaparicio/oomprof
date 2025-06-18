# OOMProf - eBPF-based OOM Kill Profiler

OOMProf is an eBPF-based process monitor that automatically captures heap profiles from Go programs just before they are killed by the Linux Out-of-Memory (OOM) killer. This enables post-mortem analysis of memory usage patterns that led to OOM conditions.

## Features

- **Real-time Go process detection**: Automatically discovers and monitors running Go programs
- **Pre-OOM profiling**: Captures memory profiles at the moment of OOM kill signals
- **eBPF-powered monitoring**: Uses kernel probes for low-overhead process monitoring
- **Standard pprof output**: Generates profiles compatible with Go's pprof toolchain
- **Memory limit testing**: Includes cgroup-based testing framework for reproducible OOM scenarios

## How It Works

OOMProf uses eBPF probes to monitor kernel OOM killer events and automatically:

1. **Scans** the system for running Go processes and tracks their memory bucket addresses
2. **Detects** when the OOM killer is about to terminate a Go process
3. **Captures** the process's heap profile data from kernel space
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
- `oompa` - Main OOMProf monitor
- `tests/oomer.taux` - Test binary for generating OOM conditions  
- `tests/gccache.taux` - Test binary for GC cache stress testing
- `oomprof.test` - Test suite

## Usage

### Basic Monitoring

Run OOMProf as root to monitor all Go processes:

```bash
sudo ./oompa
```

When a Go process is OOM killed, OOMProf will automatically generate a profile file named `{command}-{pid}.pb.gz`.

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
│   Go Process    │    │   eBPF Probes    │    │   OOMProf       │
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ Memory      │ │    │ │ oom_badness  │ │    │ │ Process     │ │
│ │ Allocations │ │────┼▶│ oom_kill_    │ │────┼▶│ Scanner     │ │
│ │             │ │    │ │ process      │ │    │ │             │ │
│ └─────────────┘ │    │ │ signal_      │ │    │ └─────────────┘ │
│                 │    │ │ deliver      │ │    │                 │
│ ┌─────────────┐ │    │ └──────────────┘ │    │ ┌─────────────┐ │
│ │ runtime.    │ │    │                  │    │ │ Profile     │ │
│ │ mbuckets    │ │◀───┼──────────────────┼────│ │ Generator   │ │
│ └─────────────┘ │    │                  │    │ └─────────────┘ │
└─────────────────┘    └──────────────────┘    └─────────────────┘
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
- [ ] Rust jemalloc support
- [ ] Python memory profiling
- [ ] Native oomkill tracepoint support (replacing kprobes)

## Contributing

Contributions are welcome! Please see the [development](#development) section for build instructions and testing guidelines.

## License

This project is licensed under the Apache License 2.0. See LICENSE for details.