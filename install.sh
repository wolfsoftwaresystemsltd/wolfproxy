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

# Function to detect OS and install build dependencies
install_build_deps() {
    echo "Checking build dependencies..."
    
    # Check if cc/gcc is available
    if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; then
        echo "  Build tools already installed."
        return 0
    fi
    
    echo "  Build tools (cc/gcc) not found. Installing..."
    
    # Detect package manager and install
    if command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu
        echo "  Detected Debian/Ubuntu - using apt"
        apt-get update -qq
        apt-get install -y build-essential pkg-config libssl-dev
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora/RHEL 8+/CentOS Stream
        echo "  Detected Fedora/RHEL - using dnf"
        dnf install -y gcc gcc-c++ make pkg-config openssl-devel
    elif command -v yum >/dev/null 2>&1; then
        # RHEL 7/CentOS 7
        echo "  Detected RHEL/CentOS - using yum"
        yum install -y gcc gcc-c++ make pkg-config openssl-devel
    elif command -v pacman >/dev/null 2>&1; then
        # Arch Linux
        echo "  Detected Arch Linux - using pacman"
        pacman -Sy --noconfirm base-devel openssl
    elif command -v zypper >/dev/null 2>&1; then
        # openSUSE
        echo "  Detected openSUSE - using zypper"
        zypper install -y gcc gcc-c++ make pkg-config libopenssl-devel
    else
        echo "  ERROR: Could not detect package manager."
        echo "  Please install build-essential/gcc manually:"
        echo "    Debian/Ubuntu: apt install build-essential pkg-config libssl-dev"
        echo "    Fedora/RHEL:   dnf install gcc gcc-c++ make pkg-config openssl-devel"
        exit 1
    fi
    
    echo "  Build tools installed successfully."
}

# Source cargo environment if it exists (use . for POSIX compatibility)
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi

# Check for Rust - try common locations
if ! command -v cargo >/dev/null 2>&1; then
    if [ -x "$HOME/.cargo/bin/cargo" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        echo "Error: Rust/Cargo is not installed."
        echo "Please install Rust from https://rustup.rs/"
        exit 1
    fi
fi

# Install build dependencies if needed (requires root)
if [ "$EUID" -eq 0 ]; then
    install_build_deps
else
    # Check if cc exists, warn if not
    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
        echo "WARNING: Build tools (cc/gcc) not found."
        echo "Run this script as root to auto-install, or manually install:"
        echo "  Debian/Ubuntu: sudo apt install build-essential pkg-config libssl-dev"
        echo "  Fedora/RHEL:   sudo dnf install gcc gcc-c++ make pkg-config openssl-devel"
        echo ""
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
