#!/bin/bash
# WolfProxy Installation Script
# (C) 2026 Wolf Software Systems Ltd
# 
# This script builds and installs WolfProxy on the local machine

set -e

echo ""
echo " __          ______  _      ______ _____  _____   ______   ____     __"
echo " \ \        / / __ \| |    |  ____|  __ \|  __ \ / __ \ \ / /\ \   / /"
echo "  \ \  /\  / / |  | | |    | |__  | |__) | |__) | |  | \ V /  \ \_/ / "
echo "   \ \/  \/ /| |  | | |    |  __| |  ___/|  _  /| |  | |> <    \   /  "
echo "    \  /\  / | |__| | |____| |    | |    | | \ \| |__| / . \    | |   "
echo "     \/  \/   \____/|______|_|    |_|    |_|  \_\\\\____/_/ \_\   |_|   "
echo ""
echo " (C) 2026 Wolf Software Systems Ltd - http://wolf.uk.com"
echo " Installation Script"
echo ""

# Source cargo environment if it exists
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi

# Check for Rust - try common locations
if ! command -v cargo &> /dev/null; then
    if [ -x "$HOME/.cargo/bin/cargo" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        echo "Error: Rust/Cargo is not installed."
        echo "Please install Rust from https://rustup.rs/"
        exit 1
    fi
fi

echo "Step 1: Building WolfProxy (release mode)..."
cargo build --release

if [ ! -f "target/release/wolfproxy" ]; then
    echo "Error: Build failed - binary not found"
    exit 1
fi

echo ""
echo "Step 2: Build complete!"
echo "  Binary: $(pwd)/target/release/wolfproxy"
echo "  Size: $(du -h target/release/wolfproxy | cut -f1)"
echo ""

# Check if running as root for service installation
if [ "$EUID" -eq 0 ]; then
    echo "Step 3: Installing systemd service..."
    ./install_service.sh
else
    echo "Step 3: Skipping service installation (not running as root)"
    echo ""
    echo "To install as a systemd service, run:"
    echo "  sudo ./install_service.sh"
    echo ""
    echo "Or to run manually:"
    echo "  sudo ./target/release/wolfproxy"
fi

echo ""
echo "Installation complete!"
