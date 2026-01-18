#!/bin/bash
# WolfProxy Run Script
# (C) 2025 Wolf Software Systems Ltd

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if release binary exists, if not build it
if [ ! -f "target/release/wolfproxy" ]; then
    echo "Release binary not found, building..."
    cargo build --release
fi

# Export environment for logging
export RUST_LOG=${RUST_LOG:-info}

echo "Starting WolfProxy..."
./target/release/wolfproxy
