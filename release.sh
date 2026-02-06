#!/bin/bash
# WolfProxy Release Script - v0.4.0
# Run this to commit, tag, and push the new release

set -e

cd /home/paulc/NetBeansProjects/wolfproxy

echo "=== WolfProxy Release Script ==="
echo ""

# Check for changes
echo "1. Checking for changes..."
git add setup.php README.md Cargo.toml Cargo.lock 2>/dev/null || true

# Commit
echo "2. Committing changes..."
git commit -m "Add one-line PHP installer for easy installation

- Created setup.php that detects apt/dnf/yum and installs dependencies
- Installs Rust automatically if not present
- Clones, builds, and sets up systemd service
- Added Quick Install section to README
- Bumped version to 0.4.0" 2>/dev/null || echo "   (Already committed or nothing to commit)"

# Tag the release
echo "3. Creating release tag v0.4.0..."
git tag -a v0.4.0 -m "Release v0.4.0 - One-line PHP installer" 2>/dev/null || echo "   (Tag already exists)"

# Show remote
echo "4. Remote configured as:"
git remote -v

echo ""
echo "5. Ready to push. Run these commands:"
echo "   git push origin main"
echo "   git push origin v0.4.0"
echo ""
echo "Or push everything with:"
echo "   git push origin main --tags"
echo ""
echo "=== Script Complete ==="
