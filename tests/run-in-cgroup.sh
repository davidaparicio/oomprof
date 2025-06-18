#!/bin/bash

# Script to run a command within a specific cgroup
# Usage: run-in-cgroup.sh <cgroup-path> <command> [args...]

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <cgroup-path> <command> [args...]" >&2
    exit 1
fi

CGROUP_PATH="$1"
shift
COMMAND="$1"
shift

# Move current process to the cgroup
echo $$ > "/sys/fs/cgroup${CGROUP_PATH}/cgroup.procs"

export GOTOOLCHAIN=$GOTOOLCHAIN
export GODEBUG=$GODEBUG
export GOMODCACHE=$GOMODECACHE

# Exec the command (replace this process)
"$COMMAND" "$@"