#!/usr/bin/env bash
# config.sh — set up the experiment_ble project on this machine.
#
# Auto-detects: aarch64/armv7l → RPi (server side)
#               x86_64         → laptop (client side)
#
# Override: config.sh --server   or   config.sh --client
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Detect side ───────────────────────────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
    aarch64|armv7l) SIDE="server" ;;
    *)              SIDE="client" ;;
esac

for arg in "$@"; do
    case "$arg" in
        --server) SIDE="server" ;;
        --client) SIDE="client" ;;
    esac
done

echo "Architecture : $ARCH"
echo "Setting up   : $SIDE"
echo ""

# ── Client setup (laptop) ─────────────────────────────────────────────────────
if [[ "$SIDE" == "client" ]]; then
    TARGET="$SCRIPT_DIR/client"
    cd "$TARGET"
    echo "Creating venv in $TARGET/.venv …"
    python3 -m venv .venv
    .venv/bin/pip install -q --upgrade pip
    .venv/bin/pip install -r requirements.txt
    echo ""
    echo "Client ready.  Run experiments:"
    echo ""
    echo "  # By MAC address:"
    echo "  $TARGET/.venv/bin/python experiment_client.py --address B8:27:EB:07:01:22"
    echo ""
    echo "  # By advertised name:"
    echo "  $TARGET/.venv/bin/python experiment_client.py --name AWAKE-EXP"
    echo ""
    echo "  # Full run:"
    echo "  $TARGET/.venv/bin/python experiment_client.py --address B8:27:EB:07:01:22 --trials 30 --action STAND_UP"
fi

# ── Server setup (RPi) ────────────────────────────────────────────────────────
if [[ "$SIDE" == "server" ]]; then
    TARGET="$SCRIPT_DIR/server"
    cd "$TARGET"
    echo "Creating venv in $TARGET/.venv …"
    python3 -m venv .venv
    .venv/bin/pip install -q --upgrade pip
    .venv/bin/pip install -r requirements.txt
    echo ""
    echo "Server ready.  Start the BLE server:"
    echo ""
    echo "  $TARGET/.venv/bin/python ble_server.py"
    echo ""
    echo "  # With custom CSV path:"
    echo "  EXPERIMENT_SERVER_CSV_PATH=/home/awake/server.csv $TARGET/.venv/bin/python ble_server.py"
    echo ""
    echo "Note: make sure bluetoothd is running and your user is in the 'bluetooth' group:"
    echo "  sudo usermod -aG bluetooth \$USER   (then log out / back in)"
fi
