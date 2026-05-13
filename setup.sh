#!/bin/bash
#
# WolfProxy installer — downloads the latest precompiled binary from
# GitHub releases. Pre-v0.4.4 this script cargo-built from source,
# which made every install dependent on a working rustup toolchain on
# the operator's box; that meant a stale `rustup default` (or no
# default at all) would break the install half-way through.
#
# (C) 2026 Wolf Software Systems Ltd - http://wolf.uk.com
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfproxy/main/setup.sh | sudo bash
#   wget -qO- https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfproxy/main/setup.sh | sudo bash
#

set -euo pipefail

# Colors
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
RESET='\033[0m'
BOLD='\033[1m'

REPO="wolfsoftwaresystemsltd/wolfproxy"
INSTALL_DIR="/opt/wolfproxy"
BIN_PATH="/usr/local/bin/wolfproxy"
CONFIG_DIR="/etc/wolfproxy"

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
    echo ""
}

info()    { echo -e "${BLUE}[INFO]${RESET} $1"; }
success() { echo -e "${GREEN}[OK]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $1"; }
error()   { echo -e "${RED}[ERROR]${RESET} $1"; exit 1; }

command_exists() { command -v "$1" &>/dev/null; }

# ─── Pre-flight ─────────────────────────────────────────────────────────

banner

if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root. Use: curl ... | sudo bash"
fi

# Map uname output to the artefact suffix the release workflow ships.
# Only x86_64 and aarch64 ship today — anyone else builds from source
# (`cargo install --git ...`) or asks for their arch in an issue.
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
    x86_64|amd64)        ARCH="x86_64"  ;;
    aarch64|arm64)       ARCH="aarch64" ;;
    *) error "Unsupported architecture '$ARCH_RAW' — precompiled binaries ship for x86_64 and aarch64 only. Build from source with: cargo install --git https://github.com/${REPO}.git" ;;
esac
info "Detected architecture: $ARCH"

# curl is the only hard dependency — everything else is shipped in the
# binary. If the box doesn't have curl, the operator's distro is so
# stripped that they'll need to install one prerequisite anyway.
if ! command_exists curl; then
    error "curl is required to download the binary. Install with your package manager (e.g. 'apt install curl', 'pacman -S curl', 'dnf install curl') and re-run."
fi

# ─── Stop any running instance before swapping the binary ──────────────

if systemctl is-active --quiet wolfproxy 2>/dev/null; then
    info "Stopping running WolfProxy instance…"
    systemctl stop wolfproxy
fi

# ─── Download latest release ───────────────────────────────────────────

info "Resolving latest release from GitHub…"
# Use the GitHub API's "latest release" alias rather than parsing tags —
# avoids accidentally grabbing a pre-release.
ASSET_URL="https://github.com/${REPO}/releases/latest/download/wolfproxy-${ARCH}"
SUMS_URL="https://github.com/${REPO}/releases/latest/download/SHA256SUMS"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Download to the arch-suffixed name so sha256sum -c can resolve the
# filename it reads out of SHA256SUMS directly (the workflow emits
# lines like "<hash>  wolfproxy-x86_64").
info "Downloading wolfproxy-${ARCH}…"
if ! curl -fsSL -o "$TMPDIR/wolfproxy-${ARCH}" "$ASSET_URL"; then
    error "Download failed: $ASSET_URL — check network access and that the release exists."
fi

# Verify the checksum if SHA256SUMS is published. Older releases may
# not have it; treat that as a soft failure (warn but continue) rather
# than blocking installs of v0.4.3 and below.
info "Verifying SHA-256 checksum…"
if curl -fsSL -o "$TMPDIR/SHA256SUMS" "$SUMS_URL"; then
    cd "$TMPDIR"
    # sha256sum's canonical format is "<hash><two spaces><filename>" —
    # use a fixed-string grep with the exact filename so weird hash
    # collisions or extra files in SHA256SUMS can't slip past. Then
    # feed only that one line into `sha256sum -c`, which resolves the
    # filename relative to cwd (hence the cd above).
    if grep -F "  wolfproxy-${ARCH}" SHA256SUMS | sha256sum -c - >/dev/null 2>&1; then
        success "Checksum verified."
    else
        error "Checksum mismatch — the download may be corrupted or tampered with. Refusing to install."
    fi
    cd - >/dev/null
else
    warn "No SHA256SUMS for this release — skipping checksum verification."
fi

# Install the binary.
install -m 755 "$TMPDIR/wolfproxy-${ARCH}" "$BIN_PATH"
mkdir -p "$INSTALL_DIR"
# Maintain a stable path symlink so old documentation and scripts
# pointing at /opt/wolfproxy/target/release/wolfproxy still work after
# the precompiled-binary cutover.
mkdir -p "$INSTALL_DIR/target/release"
ln -sf "$BIN_PATH" "$INSTALL_DIR/target/release/wolfproxy"
success "Installed $BIN_PATH"

# ─── Config + service unit ─────────────────────────────────────────────

mkdir -p "$CONFIG_DIR"
if [ ! -f "$INSTALL_DIR/wolfproxy.toml" ]; then
    cat > "$INSTALL_DIR/wolfproxy.toml" <<'EOF'
[server]
host = "0.0.0.0"
http_port = 80
https_port = 443

[nginx]
# WolfProxy reads nginx-format config from this dir. Sites land in
# `conf.d/` and `sites-enabled/`; both are picked up.
config_dir = "/etc/nginx"
auto_reload = false

[monitoring]
enabled = true
port = 5001
username = "admin"
password = "admin"
EOF
    success "Default configuration written to $INSTALL_DIR/wolfproxy.toml"
fi

# Drop the systemd unit — pointed at /usr/local/bin/wolfproxy so it
# survives a manual `cargo install` from a source checkout overwriting
# /opt/wolfproxy/target/release/wolfproxy without anyone touching the
# unit file.
cat > /etc/systemd/system/wolfproxy.service <<EOF
[Unit]
Description=WolfProxy — High Performance Reverse Proxy
After=network.target

[Service]
Type=simple
ExecStart=${BIN_PATH}
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=5
User=root
Environment=RUST_LOG=info

# A reverse proxy at any real scale will saturate the default fd cap.
LimitNOFILE=65536

# Prefer killing other processes under memory pressure — losing the
# edge proxy takes the whole node off the public internet.
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
success "systemd unit installed"

# ─── Start (and shoulder past nginx if present) ────────────────────────

if systemctl is-active --quiet nginx 2>/dev/null; then
    info "nginx is running — stopping it because WolfProxy binds the same ports."
    systemctl stop nginx
    systemctl disable nginx 2>/dev/null || true
fi

systemctl enable wolfproxy 2>/dev/null || true
systemctl start wolfproxy

sleep 2
if ! systemctl is-active --quiet wolfproxy; then
    error "WolfProxy failed to start. Inspect: journalctl -u wolfproxy -n 50"
fi

# ─── Banner out ───────────────────────────────────────────────────────

VERSION_LINE="$("$BIN_PATH" --version 2>/dev/null || echo "wolfproxy installed")"

echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ${VERSION_LINE} — installed and running.${RESET}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Binary:        ${CYAN}${BIN_PATH}${RESET}"
echo -e "  Config:        ${CYAN}${INSTALL_DIR}/wolfproxy.toml${RESET}"
echo -e "  Service:       ${CYAN}systemctl status wolfproxy${RESET}"
echo -e "  Logs:          ${CYAN}journalctl -u wolfproxy -f${RESET}"
echo -e "  Monitoring:    ${CYAN}http://<this-host>:5001/${RESET}"
echo -e "  Docs:          ${CYAN}https://github.com/${REPO}${RESET}"
echo ""
