#!/bin/bash
#
# WolfProxy One-Line Installer
# (C) 2026 Wolf Software Systems Ltd - http://wolf.uk.com
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfproxy/main/setup.sh | sudo bash
#   wget -qO- https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfproxy/main/setup.sh | sudo bash
#

set -e

# Colors
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
RESET='\033[0m'
BOLD='\033[1m'

banner() {
    echo ""
    echo -e "${CYAN} __          ______  _      ______ _____  _____   ______   ____     __${RESET}"
    echo -e "${CYAN} \\ \\        / / __ \\| |    |  ____|  __ \\|  __ \\ / __ \\ \\ / /\\ \\   / /${RESET}"
    echo -e "${CYAN}  \\ \\  /\\  / / |  | | |    | |__  | |__) | |__) | |  | \\ V /  \\ \\_/ / ${RESET}"
    echo -e "${CYAN}   \\ \\/  \\/ /| |  | | |    |  __| |  ___/|  _  /| |  | |> <    \\   /  ${RESET}"
    echo -e "${CYAN}    \\  /\\  / | |__| | |____| |    | |    | | \\ \\| |__| / . \\    | |   ${RESET}"
    echo -e "${CYAN}     \\/  \\/   \\____/|______|_|    |_|    |_|  \\_\\\\____/_/ \\_\\   |_|   ${RESET}"
    echo ""
    echo -e "${BOLD} (C) 2026 Wolf Software Systems Ltd - http://wolf.uk.com${RESET}"
    echo -e "${BOLD} One-Line Installer${RESET}"
    echo ""
}

info() {
    echo -e "${BLUE}[INFO]${RESET} $1"
}

success() {
    echo -e "${GREEN}[OK]${RESET} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${RESET} $1"
}

error() {
    echo -e "${RED}[ERROR]${RESET} $1"
    exit 1
}

command_exists() {
    command -v "$1" &> /dev/null
}

detect_package_manager() {
    if command_exists apt-get; then
        echo "apt"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists yum; then
        echo "yum"
    elif command_exists pacman; then
        echo "pacman"
    elif command_exists zypper; then
        echo "zypper"
    else
        echo ""
    fi
}

install_dependencies() {
    local pm=$1
    info "Installing build dependencies using $pm..."

    case $pm in
        apt)
            apt-get update -qq
            apt-get install -y build-essential pkg-config libssl-dev git curl
            ;;
        dnf)
            dnf install -y gcc gcc-c++ make pkg-config openssl-devel git curl
            ;;
        yum)
            yum install -y gcc gcc-c++ make pkg-config openssl-devel git curl
            ;;
        pacman)
            pacman -Sy --noconfirm base-devel openssl git curl
            ;;
        zypper)
            zypper install -y gcc gcc-c++ make pkg-config libopenssl-devel git curl
            ;;
        *)
            error "Unsupported package manager. Please install dependencies manually."
            ;;
    esac

    success "Dependencies installed"
}

install_rust() {
    if command_exists cargo; then
        success "Rust is already installed"
        return
    fi

    # Check in common location
    if [ -f "$HOME/.cargo/bin/cargo" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
        success "Rust found at ~/.cargo/bin"
        return
    fi

    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    export PATH="$HOME/.cargo/bin:$PATH"
    success "Rust installed"
}

# Main installation
banner

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root. Use: curl ... | sudo bash"
fi

# Detect package manager
pm=$(detect_package_manager)
if [ -z "$pm" ]; then
    error "Could not detect package manager. Supported: apt, dnf, yum, pacman, zypper"
fi
info "Detected package manager: $pm"

# Install dependencies
install_dependencies "$pm"

# Install Rust
install_rust

# Clone or download repository
INSTALL_DIR="/opt/wolfproxy"
REPO_URL="https://github.com/wolfsoftwaresystemsltd/wolfproxy.git"

if [ -d "$INSTALL_DIR" ]; then
    info "Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull
    success "Updated to latest version"
else
    info "Cloning WolfProxy repository..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    success "Repository cloned"
fi

# Build
info "Building WolfProxy (this may take a few minutes)..."
cd "$INSTALL_DIR"

CARGO="cargo"
if [ -f "$HOME/.cargo/bin/cargo" ]; then
    CARGO="$HOME/.cargo/bin/cargo"
fi

$CARGO build --release
success "Build complete"

# Install service
if [ -f "$INSTALL_DIR/install_service.sh" ]; then
    info "Installing systemd service..."
    chmod +x "$INSTALL_DIR/install_service.sh"
    
    # Create systemd service file directly
    cat > /etc/systemd/system/wolfproxy.service << 'EOF'
[Unit]
Description=WolfProxy - High Performance Reverse Proxy
After=network.target

[Service]
Type=simple
ExecStart=/opt/wolfproxy/target/release/wolfproxy
WorkingDirectory=/opt/wolfproxy
Restart=always
RestartSec=5
User=root
Environment=RUST_LOG=info

# File descriptor limit - critical for a reverse proxy
LimitNOFILE=65536

# OOM protection - prefer killing other processes
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    success "Service installed"
fi

# Create default config if not exists
if [ ! -f "$INSTALL_DIR/wolfproxy.toml" ]; then
    cat > "$INSTALL_DIR/wolfproxy.toml" << 'EOF'
[server]
host = "0.0.0.0"
http_port = 80
https_port = 443

[nginx]
config_dir = "/etc/nginx"
auto_reload = false

[monitoring]
enabled = true
port = 5001
username = "admin"
password = "admin"
EOF
    success "Default configuration created"
fi

echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  WolfProxy has been installed successfully!${RESET}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Installation directory: ${CYAN}/opt/wolfproxy${RESET}"
echo -e "  Configuration file:     ${CYAN}/opt/wolfproxy/wolfproxy.toml${RESET}"
echo ""
echo "  Commands:"
echo -e "    Start:   ${YELLOW}sudo systemctl start wolfproxy${RESET}"
echo -e "    Stop:    ${YELLOW}sudo systemctl stop wolfproxy${RESET}"
echo -e "    Status:  ${YELLOW}sudo systemctl status wolfproxy${RESET}"
echo -e "    Enable:  ${YELLOW}sudo systemctl enable wolfproxy${RESET}"
echo -e "    Logs:    ${YELLOW}journalctl -u wolfproxy -f${RESET}"
echo ""
echo -e "  ${BOLD}Before starting, stop nginx:${RESET}"
echo -e "    ${YELLOW}sudo systemctl stop nginx && sudo systemctl disable nginx${RESET}"
echo ""
echo -e "  Documentation: ${CYAN}https://github.com/wolfsoftwaresystemsltd/wolfproxy${RESET}"
echo ""
