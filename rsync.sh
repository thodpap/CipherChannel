#!/usr/bin/env bash
# Sync experiment_ble/ to the RPi and run config.sh (server side) if needed.
# Run from the repo root: bash rsync_new.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
REMOTE="awake@192.168.1.25"
REMOTE_DIR="/home/awake/experiment_ble"

echo "Syncing $REPO_ROOT/ → $REMOTE:$REMOTE_DIR/"
rsync -avz --progress \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude '.venv' \
    "$REPO_ROOT/" \
    "$REMOTE:$REMOTE_DIR/"

echo ""
echo "Sync done."
echo ""
echo "On the RPi, run once to install deps:"
echo "  ssh $REMOTE"
echo "  cd $REMOTE_DIR && bash config.sh --server"
echo ""
echo "Then start the server:"
echo "  $REMOTE_DIR/server/.venv/bin/python $REMOTE_DIR/server/ble_server.py"
