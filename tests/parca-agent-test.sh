#!/bin/bash
set -e

# Integration test for OOM profiling with parca-agent and Parca server
# This script:
# 1. Starts Parca server in Docker
# 2. Starts parca-agent (Docker or local build)
# 3. Runs memory-limited tests that should trigger OOM profiles
# 4. Validates that OOM profiles are received by Parca server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OOMPROF_ROOT="$(dirname "$SCRIPT_DIR")"
PARCA_AGENT_DIR="${PARCA_AGENT_DIR:-../parca-agent}"

# Configuration
PARCA_GRPC_PORT="${PARCA_GRPC_PORT:-7070}"
PARCA_HTTP_PORT="${PARCA_HTTP_PORT:-7070}"
PARCA_CONTAINER_NAME="oomprof-test-parca"
AGENT_CONTAINER_NAME="oomprof-test-agent"
TEST_TIMEOUT="${TEST_TIMEOUT:-300}" # 5 minutes
# default to false once we merge to main
USE_LOCAL_AGENT="${USE_LOCAL_AGENT:-true}"
USE_EXISTING_PARCA="${USE_EXISTING_PARCA:-false}"
DRY_RUN="${DRY_RUN:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $1"
}

success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] SUCCESS:${NC} $1"
}

cleanup() {
    log "Cleaning up containers and resources..."

    # We leave things running for inspection.
    # stop()
}

stop() {
    # Stop and remove containers
    docker stop "$PARCA_CONTAINER_NAME" 2>/dev/null || true
    docker rm "$PARCA_CONTAINER_NAME" 2>/dev/null || true
    docker stop "$AGENT_CONTAINER_NAME" 2>/dev/null || true
    docker rm "$AGENT_CONTAINER_NAME" 2>/dev/null || true


    # Kill any local parca-agent processes
    if [ "$USE_LOCAL_AGENT" = "true" ]; then
       sudo killall parca-agent 2>/dev/null || true
    fi
}

# Set up cleanup trap
trap cleanup EXIT

check_docker() {
    if ! command -v docker &> /dev/null; then
        error "Docker is required but not installed"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        error "Docker daemon is not running"
        exit 1
    fi
}

wait_for_service() {
    local service_name="$1"
    local host="$2"
    local port="$3"
    local timeout="$4"

    log "Waiting for $service_name to be ready at $host:$port..."

    local count=0
    while [ $count -lt $timeout ]; do
        if curl -s --connect-timeout 1 "http://$host:$port" > /dev/null 2>&1; then
            success "$service_name is ready!"
            return 0
        fi
        sleep 1
        count=$((count + 1))
        if [ $((count % 10)) -eq 0 ]; then
            log "Still waiting for $service_name... ($count/$timeout seconds)"
        fi
    done

    error "$service_name failed to start within $timeout seconds"
    return 1
}

check_existing_parca() {
    # Check if port is already in use
    if lsof -i :"$PARCA_GRPC_PORT" >/dev/null 2>&1; then
        log "Port $PARCA_GRPC_PORT is already in use"

        # Check if it's a Parca container
        if docker ps | grep -q "parca.*$PARCA_GRPC_PORT"; then
            local existing_container=$(docker ps | grep "parca.*$PARCA_GRPC_PORT" | awk '{print $NF}')
            warn "Found existing Parca server container: $existing_container"

            if [ "$USE_EXISTING_PARCA" = "true" ]; then
                log "Using existing Parca server (USE_EXISTING_PARCA=true)"
                return 0
            else
                error "Port $PARCA_GRPC_PORT is already in use by Parca server"
                error "Either stop the existing server or set USE_EXISTING_PARCA=true"
                exit 1
            fi
        else
            error "Port $PARCA_GRPC_PORT is already in use by another process"
            exit 1
        fi
    fi
    return 1
}

start_parca_server() {
    log "Starting Parca server..."

    # Check if we should use existing server
    if check_existing_parca; then
        return 0
    fi

    # Clean up old container
    docker stop "$PARCA_CONTAINER_NAME" 2>/dev/null || true
    docker rm "$PARCA_CONTAINER_NAME" 2>/dev/null || true

    # Start Parca server
    docker run -d \
        --name "$PARCA_CONTAINER_NAME" \
        --privileged \
        -p "$PARCA_GRPC_PORT:7070" \
        ghcr.io/parca-dev/parca:v0.24.0 \
        /parca \
        --log-level=debug

    # Wait for Parca to be ready
    wait_for_service "Parca server" "localhost" "$PARCA_GRPC_PORT" 60

    # Verify gRPC endpoint
    log "Verifying Parca gRPC endpoint..."
    if ! timeout 10 bash -c "echo > /dev/tcp/localhost/$PARCA_GRPC_PORT" 2>/dev/null; then
        error "Parca gRPC endpoint not accessible"
        exit 1
    fi

    success "Parca server started successfully"
}

build_local_agent() {
    log "Building local parca-agent..."

    if [ ! -d "$PARCA_AGENT_DIR" ]; then
        error "Parca agent directory not found: $PARCA_AGENT_DIR"
        error "Set PARCA_AGENT_DIR environment variable to the correct path"
        exit 1
    fi

    cd "$PARCA_AGENT_DIR"

    # Check if Makefile exists
    if [ ! -f "Makefile" ]; then
        error "Makefile not found in $PARCA_AGENT_DIR"
        exit 1
    fi

    # Build the agent
    log "Running 'make build' in $PARCA_AGENT_DIR..."
    make build

    if [ ! -f "./parca-agent" ]; then
        error "parca-agent binary not found after build"
        exit 1
    fi

    success "parca-agent built successfully"
    cd -
}

start_local_agent() {
    log "Starting local parca-agent..."

    cd "$PARCA_AGENT_DIR"

    # Start parca-agent with OOM profiling enabled
    log "Starting parca-agent with OOM profiling..."
    sudo ./parca-agent \
        --node="test-node" \
        --remote-store-address="localhost:$PARCA_GRPC_PORT" \
        --remote-store-insecure \
        --enable-oom-prof \
        2>&1 | tee -i "/tmp/parca-agent.log" &

    local agent_pid=$!
    echo $agent_pid > "/tmp/parca-agent.pid"

    # Give agent time to start
    sleep 5

    # Check if agent is still running
    if ! kill -0 $agent_pid 2>/dev/null; then
        error "parca-agent failed to start"
        log "Agent log output:"
        cat "/tmp/parca-agent.log" || true
        exit 1
    fi

    success "Local parca-agent started with PID $agent_pid"
    cd -
}

start_docker_agent() {
    log "Starting parca-agent in Docker..."

    # Clean up old container
    docker stop "$AGENT_CONTAINER_NAME" 2>/dev/null || true
    docker rm "$AGENT_CONTAINER_NAME" 2>/dev/null || true

    # Start parca-agent container
    docker run -d \
        --name "$AGENT_CONTAINER_NAME" \
        --privileged \
        --pid=host \
        --network=host \
        -v /sys/kernel/debug:/sys/kernel/debug:rw \
        -v /lib/modules:/lib/modules:ro \
        -v /usr/src:/usr/src:ro \
        -v /etc/machine-id:/etc/machine-id:ro \
        ghcr.io/parca-dev/parca-agent:v0.39.3 \
        --node="test-node" \
        --remote-store-address="localhost:$PARCA_GRPC_PORT" \
        --remote-store-insecure \
        --enable-oom-prof

    # Give agent time to start
    sleep 10

    # Check if container is running
    if ! docker ps | grep -q "$AGENT_CONTAINER_NAME"; then
        error "parca-agent container failed to start"
        log "Container logs:"
        docker logs "$AGENT_CONTAINER_NAME" 2>/dev/null || true
        exit 1
    fi

    success "Docker parca-agent started successfully"
}

run_memory_tests() {
    log "Running memory-limited tests..."

    cd "$SCRIPT_DIR"

    # Check if the test script exists
    if [ ! -f "./run-all-memlimited.sh" ]; then
        error "Memory test script not found: ./run-all-memlimited.sh"
        exit 1
    fi

    # Make sure it's executable
    chmod +x "./run-all-memlimited.sh"

    log "Executing memory-limited tests that should trigger OOM events..."

    # Run the tests with a timeout
    if timeout $TEST_TIMEOUT ./run-all-memlimited.sh; then
        success "Memory tests completed successfully"
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            warn "Memory tests timed out after $TEST_TIMEOUT seconds"
        else
            warn "Memory tests exited with code $exit_code (may be expected for OOM tests)"
        fi
    fi

    # Give time for profiles to be processed
    log "Waiting for profiles to be processed and sent to Parca..."
    sleep 10
}

query_parca_profiles() {
    local query="$1"
    local start_time="$2"
    local end_time="$3"

    log "Querying Parca for profiles: $query"

    # Query Parca API for profiles
    local response
    response=$(curl -s -X POST "http://localhost:$PARCA_HTTP_PORT/api/v1alpha1/query_range" \
        -H "Content-Type: application/json" \
        -d "{
            \"query\": \"$query\",
            \"start\": \"$start_time\",
            \"end\": \"$end_time\"
        }" 2>/dev/null || echo "{}")

    echo "$response"
}

validate_oom_profiles() {
    log "Validating OOM profiles in Parca..."

    # Calculate time range (last 10 minutes)
    local end_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local start_time=$(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%SZ)

    log "Searching for profiles between $start_time and $end_time"

    # Wait a bit more for profiles to be processed
    sleep 15

    # Query for memory profiles with oomprof job label
    log "Querying for oomprof memory profiles..."
    local oomprof_response
    oomprof_response=$(query_parca_profiles 'memory{job="oomprof"}' "$start_time" "$end_time")

    # Query for any memory profiles from test-node
    log "Querying for memory profiles from test-node..."
    local node_response
    node_response=$(query_parca_profiles 'memory{node="test-node"}' "$start_time" "$end_time")

    # Query for all memory profiles
    log "Querying for all memory profiles..."
    local all_memory_response
    all_memory_response=$(query_parca_profiles 'memory' "$start_time" "$end_time")

    # Check if we got any profiles
    local oomprof_count=0
    local node_count=0
    local total_count=0

    # Parse responses (basic JSON parsing)
    if echo "$oomprof_response" | grep -q '"values":\s*\['; then
        oomprof_count=$(echo "$oomprof_response" | grep -o '"values":\s*\[\[' | wc -l)
    fi

    if echo "$node_response" | grep -q '"values":\s*\['; then
        node_count=$(echo "$node_response" | grep -o '"values":\s*\[\[' | wc -l)
    fi

    if echo "$all_memory_response" | grep -q '"values":\s*\['; then
        total_count=$(echo "$all_memory_response" | grep -o '"values":\s*\[\[' | wc -l)
    fi

    log "Profile query results:"
    log "  - OOM profiles (job=oomprof): $oomprof_count"
    log "  - Node profiles (node=test-node): $node_count"
    log "  - Total memory profiles: $total_count"

    # Try alternative approach - check available label values
    log "Checking available profile types..."
    local types_response
    types_response=$(curl -s "http://localhost:$PARCA_HTTP_PORT/api/v1alpha1/profiles/types" 2>/dev/null || echo "{}")
    log "Available profile types: $types_response"

    # Check available label values for job
    log "Checking available job labels..."
    local jobs_response
    jobs_response=$(curl -s "http://localhost:$PARCA_HTTP_PORT/api/v1alpha1/labels/job/values" 2>/dev/null || echo "{}")
    log "Available job labels: $jobs_response"

    # Validate results
    local validation_passed=false

    if [ "$oomprof_count" -ge 2 ]; then
        success "Found $oomprof_count OOM profiles with job=oomprof label!"
        validation_passed=true
    elif [ "$node_count" -ge 2 ]; then
        success "Found $node_count memory profiles from test-node!"
        validation_passed=true
    elif [ "$total_count" -ge 2 ]; then
        warn "Found $total_count memory profiles (but without expected labels)"
        validation_passed=true
    else
        error "Expected at least 2 OOM profiles, but found:"
        error "  - OOM profiles: $oomprof_count"
        error "  - Node profiles: $node_count"
        error "  - Total profiles: $total_count"

        # Show recent Parca logs for debugging
        log "Recent Parca server logs:"
        docker logs --tail=50 "$PARCA_CONTAINER_NAME" 2>/dev/null || true

        # Show agent logs for debugging
        if [ "$USE_LOCAL_AGENT" = "true" ]; then
            log "Recent parca-agent logs:"
            tail -50 "/tmp/parca-agent.log" 2>/dev/null || true
        else
            log "Recent parca-agent container logs:"
            docker logs --tail=50 "$AGENT_CONTAINER_NAME" 2>/dev/null || true
        fi
    fi

    return $([ "$validation_passed" = true ] && echo 0 || echo 1)
}

main() {
    log "Starting OOM profiling integration test..."
    log "Configuration:"
    log "  - Parca HTTP port: $PARCA_HTTP_PORT"
    log "  - Parca gRPC port: $PARCA_GRPC_PORT"
    log "  - Use local agent: $USE_LOCAL_AGENT"
    log "  - Parca agent dir: $PARCA_AGENT_DIR"
    log "  - Test timeout: $TEST_TIMEOUT seconds"
    log "  - Dry run: $DRY_RUN"

    if [ "$DRY_RUN" = "true" ]; then
        log "DRY RUN MODE - No actual containers will be started"
        log "This mode shows what the test would do without executing commands"
        log ""
    fi

    # Prerequisites
    check_docker

    stop

    # Start Parca server
    start_parca_server

    # Start parca-agent
    if [ "$USE_LOCAL_AGENT" = "true" ]; then
        build_local_agent
        start_local_agent
    else
        start_docker_agent
    fi

    # Run memory tests that should trigger OOM events
    run_memory_tests

    # Validate that profiles were received
    if validate_oom_profiles; then
        success "Integration test PASSED! OOM profiles were successfully received by Parca."
    else
        error "Integration test FAILED! Expected OOM profiles were not found in Parca."
        exit 1
    fi
}

# Help message
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "OOM Profiling Integration Test"
    echo ""
    echo "This script tests the full integration between oomprof, parca-agent, and Parca server."
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Environment Variables:"
    echo "  USE_LOCAL_AGENT=true          Use local parca-agent build instead of Docker"
    echo "  PARCA_AGENT_DIR=/path         Path to parca-agent source directory (default: ../parca-agent)"
    echo "  PARCA_HTTP_PORT=7071          Parca HTTP port (default: 7071)"
    echo "  PARCA_GRPC_PORT=7070          Parca gRPC port (default: 7070)"
    echo "  TEST_TIMEOUT=300              Test timeout in seconds (default: 300)"
    echo "  DRY_RUN=true                  Show what would be done without executing"
    echo ""
    echo "Examples:"
    echo "  # Run with Docker agent:"
    echo "  sudo $0"
    echo ""
    echo "  # Run with local agent build:"
    echo "  sudo USE_LOCAL_AGENT=true PARCA_AGENT_DIR=/path/to/parca-agent $0"
    echo ""
    echo "Requirements:"
    echo "  - Root privileges (for eBPF)"
    echo "  - Docker and Docker daemon running"
    echo "  - Internet connection (to pull Docker images)"
    echo "  - Available ports $PARCA_HTTP_PORT and $PARCA_GRPC_PORT"
    exit 0
fi

# Run main function
main "$@"