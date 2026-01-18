#!/bin/bash
# WolfProxy Build Script
# (C) 2025 Wolf Software Systems Ltd

set -e

echo "Building WolfProxy..."

# Check for cargo
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found. Please install Rust: https://rustup.rs"
    exit 1
fi

# Build in release mode
cargo build --release

echo ""
echo "Build complete!"
echo "Binary location: target/release/wolfproxy"
echo ""
echo "To run: ./target/release/wolfproxy"
echo "To install as service: sudo ./install_service.sh"
