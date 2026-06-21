#!/usr/bin/env bash
# WRAITH Cell Installer — Linux / macOS
# One-liner: curl -fsSL https://wraith.one/install | bash
set -euo pipefail

WRAITH_HOME="${WRAITH_HOME:-$HOME/.wraith}"
GITHUB_USER="${WRAITH_GITHUB_USER:-kebron-wraith}"
GITHUB_REPO="${WRAITH_GITHUB_REPO:-wraith-install}"
CELL_CORE="cell_core.py"

echo "🦅 WRAITH Cell Installer"
echo "========================"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux*)     PLATFORM="linux" ;;
    Darwin*)    PLATFORM="macos" ;;
    *)          PLATFORM="unknown" ;;
esac

echo "[*] Platform: $PLATFORM"
echo "[*] WRAITH_HOME: $WRAITH_HOME"

# Create directory
mkdir -p "$WRAITH_HOME/cell"

# Download cell code
echo "[*] Downloading WRAITH Cell..."
curl -fsSL "https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/main/cell/$CELL_CORE" -o "$WRAITH_HOME/cell/$CELL_CORE"

# Download all cell files
for f in anti_tampering.py auto_update.py cell_auth.py device_discovery.py \
          rotating_honeypot.py self_evolution.py setup_wizard.py \
          tracker_client.py wire_protocol.py; do
    curl -fsSL "https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/main/cell/$f" \
        -o "$WRAITH_HOME/cell/$f" 2>/dev/null || true
done

# Download agents
mkdir -p "$WRAITH_HOME/cell/wraith_agents"
curl -fsSL "https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/main/cell/wraith_agents/__init__.py" \
    -o "$WRAITH_HOME/cell/wraith_agents/__init__.py" 2>/dev/null || true

echo "[✓] WRAITH Cell installed to $WRAITH_HOME/cell/"
echo "[✓] Run: cd $WRAITH_HOME/cell && python $CELL_CORE"
echo ""
echo "🦅 WRAITH is watching."
