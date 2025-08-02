#!/bin/bash

# Script to run all Go programs under tests/ in a 0.5GB memory limited cgroup
# Requires root or appropriate cgroup permissions

set -e

# Memory limit in bytes (0.5GB = 512MB)
MEMORY_LIMIT=$((100 * 1024 * 1024))
# Use environment variable if set (for parallel execution), otherwise use default
CGROUP_NAME="${CGROUP_NAME:-oomprof-test-$$}"
CGROUP_PATH="/sys/fs/cgroup/${CGROUP_NAME}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Setting up cgroup with 512MB memory limit...${NC}"

# Create cgroup v2 directory
if [ ! -d "$CGROUP_PATH" ]; then
    sudo mkdir -p "$CGROUP_PATH"
fi

# Set memory limit
echo "$MEMORY_LIMIT" | sudo tee "${CGROUP_PATH}/memory.max" > /dev/null
echo -e "${GREEN}Created cgroup: ${CGROUP_PATH}${NC}"
echo -e "${GREEN}Memory limit: 512MB${NC}\n"

# Function to run a Go program in the cgroup
run_in_cgroup() {
    local name="$1"

    echo -e "${YELLOW}Running ${name}...${NC}"

    # Check if the .taux binary exists
    if [ -f "${name}.taux" ]; then
        echo "Executing ${name}.taux in memory-limited cgroup..."
        sudo bash ./run-in-cgroup.sh "/${CGROUP_NAME}" "./${name}.taux" 2>&1 | tee "${name}.log" || {
            echo -e "${RED}${name} failed (likely OOM)${NC}"
        }
    else
        echo -e "${RED}No ${name}.taux binary found. Run 'make tests' first.${NC}"
    fi

    echo -e "${GREEN}Completed ${name}${NC}\n"
}

# Build test binaries using Makefile
echo -e "${YELLOW}Building test binaries with Makefile...${NC}"
cd ..
make tests
cd tests
echo -e "${GREEN}Test binaries built successfully${NC}\n"

# Run all Go programs
echo -e "${YELLOW}Running all Go programs with 512MB memory limit...${NC}\n"

# Run each Go program
#run_in_cgroup "compile-oom"
#run_in_cgroup "deepstack"
run_in_cgroup "gccache"
run_in_cgroup "oomer"

# Cleanup
echo -e "${YELLOW}Cleaning up cgroup...${NC}"
# First, ensure no processes are in the cgroup
sudo sh -c "echo 0 > '${CGROUP_PATH}/cgroup.procs' 2>/dev/null || true"
# Remove the cgroup
sudo rmdir "$CGROUP_PATH" 2>/dev/null || {
    echo -e "${RED}Warning: Could not remove cgroup. It may still have processes.${NC}"
    echo "You can manually remove it with: sudo rmdir $CGROUP_PATH"
}

echo -e "${GREEN}All tests completed!${NC}"
echo -e "${YELLOW}Check individual .log files in each directory for output.${NC}"