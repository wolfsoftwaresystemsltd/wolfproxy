#!/bin/bash
# WolfProxy Installation Script
# (C) 2026 Wolf Software Systems Ltd - http://wolf.uk.com
#
# WolfProxy is distributed as a PREBUILT BINARY built by GitHub CI — there is no
# need to compile it from source. This script used to run `cargo build
# --release`, which failed for anyone who ran it outside a source checkout
# (klasSponsor 2026-06: "could not find Cargo.toml in /root"). It is kept only so
# that older links and docs keep working: it now just runs setup.sh, which
# downloads the right prebuilt binary for this machine's architecture, installs
# it to /opt/wolfproxy, writes a default config, and sets up the systemd
# service — exactly like WolfStack's installer.

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
echo " WolfProxy now ships as a prebuilt binary — fetching the installer..."
echo ""

# Hand off to the canonical binary installer on main. Using curl|bash means this
# works whether install.sh is run from a clone or piped straight from GitHub.
if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required. Install it (e.g. 'apt install curl', 'dnf install curl', 'pacman -S curl') and re-run." >&2
    exit 1
fi

curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfproxy/main/setup.sh | bash
