#!/usr/bin/env bash
# run_trials.sh — Build client and run DTLS cold-start benchmark.
#
# Run on the LAPTOP (client side).  The server must already be running on the RPi.
#
# Usage:
#   # Smoke test (10 trials):
#   DRY_RUN=1 SERVER_HOST=192.168.1.50 ./scripts/run_trials.sh
#
#   # Full run (500 trials):
#   SERVER_HOST=192.168.1.50 ./scripts/run_trials.sh
#
#   # Custom trial count:
#   SERVER_HOST=192.168.1.50 TRIALS=300 ./scripts/run_trials.sh
#
# Environment overrides (all optional):
#   SERVER_HOST   — RPi IP address (required; no default)
#   SERVER_PORT   — UDP port (default: from config)
#   TRIALS        — number of trials (default: from config)
#   INTER_MS      — inter-trial sleep ms (default: from config)
#   TIMEOUT_MS    — per-trial timeout ms (default: from config)
#   DRY_RUN       — set to 1 for a 10-trial smoke test
#   PSK_IDENTITY  — override PSK identity
#   PSK_HEX       — override PSK hex key

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG="$ROOT_DIR/config/psk_config.cfg"

# ── Load config file ──────────────────────────────────────────────────────────
# shellcheck disable=SC1090
if [[ -f "$CONFIG" ]]; then
    while IFS='=' read -r key val; do
        # Skip comments and blanks
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]]               && continue
        key="$(echo "$key" | tr -d '[:space:]')"
        val="$(echo "$val" | sed 's/#.*//' | tr -d '[:space:]')"
        export "CFG_${key}=${val}"
    done < "$CONFIG"
fi

# ── Resolve parameters (env > config > hardcoded fallback) ────────────────────
SERVER_HOST="${SERVER_HOST:-${CFG_SERVER_HOST:-}}"
SERVER_PORT="${SERVER_PORT:-${CFG_SERVER_PORT:-4433}}"
TRIALS="${TRIALS:-${CFG_TRIALS:-500}}"
INTER_MS="${INTER_MS:-${CFG_INTER_TRIAL_MS:-250}}"
TIMEOUT_MS="${TIMEOUT_MS:-${CFG_TIMEOUT_MS:-5000}}"
PSK_IDENTITY="${PSK_IDENTITY:-${CFG_PSK_IDENTITY:-exo-dtls-client}}"
PSK_HEX="${PSK_HEX:-${CFG_PSK_HEX:-deadbeef0102030405060708090a0b0c}}"
DRY_RUN="${DRY_RUN:-0}"

if [[ -z "$SERVER_HOST" ]]; then
    echo "ERROR: SERVER_HOST is not set."
    echo "  Set it via environment: SERVER_HOST=<rpi-ip> $0"
    exit 1
fi

# ── Build the client if needed ────────────────────────────────────────────────
CLIENT_BIN="$ROOT_DIR/client/dtls_client"
if [[ ! -f "$CLIENT_BIN" ]] || [[ "$ROOT_DIR/client/dtls_client.c" -nt "$CLIENT_BIN" ]]; then
    echo "Building client..."
    make -C "$ROOT_DIR/client" --no-print-directory
    echo ""
fi

# ── Prepare results directory ─────────────────────────────────────────────────
RESULTS_DIR="$ROOT_DIR/results"
mkdir -p "$RESULTS_DIR"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
CSV_PATH="$RESULTS_DIR/dtls_trials_${TIMESTAMP}.csv"
JSON_PATH="$RESULTS_DIR/dtls_summary_${TIMESTAMP}.json"
MD_PATH="$RESULTS_DIR/dtls_summary_${TIMESTAMP}.md"

# ── Build argument list ───────────────────────────────────────────────────────
CLIENT_ARGS=(
    "--host"       "$SERVER_HOST"
    "--port"       "$SERVER_PORT"
    "--trials"     "$TRIALS"
    "--inter-ms"   "$INTER_MS"
    "--timeout-ms" "$TIMEOUT_MS"
    "--psk-id"     "$PSK_IDENTITY"
    "--psk-hex"    "$PSK_HEX"
    "--output"     "$CSV_PATH"
)

if [[ "$DRY_RUN" == "1" ]]; then
    CLIENT_ARGS+=("--dry-run")
    echo "=== DTLS Baseline — DRY RUN (10 trials) ==="
else
    echo "=== DTLS Baseline — ${TRIALS} cold-start trials ==="
fi

echo "  Server    : ${SERVER_HOST}:${SERVER_PORT}"
echo "  PSK id    : ${PSK_IDENTITY}"
echo "  Inter-ms  : ${INTER_MS}"
echo "  Output    : ${CSV_PATH}"
echo ""

# ── Run client ────────────────────────────────────────────────────────────────
"$CLIENT_BIN" "${CLIENT_ARGS[@]}"

echo ""
echo "=== Running analysis ==="
python3 "$SCRIPT_DIR/analyze_results.py" \
    --input    "$CSV_PATH"  \
    --json     "$JSON_PATH" \
    --markdown "$MD_PATH"

echo ""
echo "Files written:"
echo "  CSV      : $CSV_PATH"
echo "  JSON     : $JSON_PATH"
echo "  Markdown : $MD_PATH"
