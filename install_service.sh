#!/bin/bash
# WolfProxy Service Installation Script
# (C) 2025 Wolf Software Systems Ltd
#
# This script installs wolfproxy as a systemd service

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/wolfproxy"
BINARY_PATH="$INSTALL_DIR/wolfproxy"
CONFIG_PATH="$INSTALL_DIR/wolfproxy.toml"
SERVICE_NAME="wolfproxy"

echo "Installing WolfProxy..."

# Create installation directory
mkdir -p "$INSTALL_DIR"

# Check if binary exists
if [ -f "$SCRIPT_DIR/target/release/wolfproxy" ]; then
    cp "$SCRIPT_DIR/target/release/wolfproxy" "$BINARY_PATH"
elif [ -f "$SCRIPT_DIR/wolfproxy" ]; then
    cp "$SCRIPT_DIR/wolfproxy" "$BINARY_PATH"
else
    echo "Binary not found. Please build first with: cargo build --release"
    exit 1
fi

chmod +x "$BINARY_PATH"

# Copy configuration if not exists
if [ ! -f "$CONFIG_PATH" ]; then
    if [ -f "$SCRIPT_DIR/wolfproxy.toml" ]; then
        cp "$SCRIPT_DIR/wolfproxy.toml" "$CONFIG_PATH"
    else
        cat > "$CONFIG_PATH" << 'EOF'
[server]
host = "0.0.0.0"
http_port = 80
https_port = 443

[nginx]
config_dir = "/etc/nginx"
auto_reload = false
EOF
    fi
fi

# Create systemd service file
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=WolfProxy - Nginx Proxy Replacement
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BINARY_PATH}
Restart=always
RestartSec=5
Environment=RUST_LOG=info

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log
ReadOnlyPaths=/etc/nginx /etc/letsencrypt

# Capability for binding to privileged ports
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo ""
echo "Installation complete!"
echo ""
echo "Configuration file: $CONFIG_PATH"
echo ""
echo "Commands:"
echo "  Start:   systemctl start $SERVICE_NAME"
echo "  Stop:    systemctl stop $SERVICE_NAME"
echo "  Status:  systemctl status $SERVICE_NAME"
echo "  Enable:  systemctl enable $SERVICE_NAME"
echo "  Logs:    journalctl -u $SERVICE_NAME -f"
echo ""
echo "IMPORTANT: Before starting, make sure nginx is stopped:"
echo "  systemctl stop nginx"
echo "  systemctl disable nginx"
echo ""

# Ask if user wants to enable and start
read -p "Would you like to enable and start WolfProxy now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Stop nginx if running
    if systemctl is-active --quiet nginx; then
        echo "Stopping nginx..."
        systemctl stop nginx
    fi
    
    systemctl enable $SERVICE_NAME
    systemctl start $SERVICE_NAME
    echo ""
    echo "WolfProxy is now running!"
    systemctl status $SERVICE_NAME --no-pager
fi
