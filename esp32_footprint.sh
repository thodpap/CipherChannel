#!/usr/bin/env bash
# esp32_footprint.sh — compile the ESP32 sketch and capture flash/RAM usage.
#
# Parses Arduino CLI compiler output for:
#   "Sketch uses X bytes (Y%) of program storage space."
#   "Global variables use X bytes (Y%) of dynamic memory."
#
# Output:
#   results/final/raw/esp32_build_output.txt
#   results/final/summary/esp32_footprint_summary.json
#
# Usage:
#   bash esp32_footprint.sh                    # auto-detect sketch dir
#   SKETCH_DIR=/path/to/esp32 bash esp32_footprint.sh
#   ARDUINO_CLI=~/.local/bin/arduino-cli bash esp32_footprint.sh
#
# Requirements:
#   arduino-cli  (https://arduino.github.io/arduino-cli/)
#   Board package: esp32:esp32  (install via: arduino-cli core install esp32:esp32)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/results/final"
RAW_DIR="${OUT_DIR}/raw"
SUMMARY_DIR="${OUT_DIR}/summary"
mkdir -p "$RAW_DIR" "$SUMMARY_DIR"

BUILD_LOG="${RAW_DIR}/esp32_build_output.txt"
JSON_OUT="${SUMMARY_DIR}/esp32_footprint_summary.json"

# ── Locate sketch ─────────────────────────────────────────────────────────────
SKETCH_DIR="${SKETCH_DIR:-${SCRIPT_DIR}/awake-esp32/esp32}"
if [[ ! -f "${SKETCH_DIR}/esp32.ino" ]]; then
    echo "ERROR: esp32.ino not found in ${SKETCH_DIR}"
    echo "Set SKETCH_DIR= to override."
    exit 1
fi

# ── Locate arduino-cli ────────────────────────────────────────────────────────
ARDUINO_CLI="${ARDUINO_CLI:-arduino-cli}"
if ! command -v "$ARDUINO_CLI" &>/dev/null; then
    echo "ERROR: arduino-cli not found.  Install from https://arduino.github.io/arduino-cli/"
    echo "Or set ARDUINO_CLI=/path/to/arduino-cli"
    exit 1
fi

BOARD="${BOARD:-esp32:esp32:esp32}"   # adjust if your board variant differs
echo "Sketch : ${SKETCH_DIR}"
echo "Board  : ${BOARD}"
echo "Compiling…"

# ── Compile ───────────────────────────────────────────────────────────────────
"$ARDUINO_CLI" compile \
    --fqbn "$BOARD" \
    --warnings default \
    "$SKETCH_DIR" 2>&1 | tee "$BUILD_LOG"

echo ""
echo "Build output saved → ${BUILD_LOG}"

# ── Parse output ──────────────────────────────────────────────────────────────
FLASH_LINE=$(grep -i "Sketch uses" "$BUILD_LOG" || true)
RAM_LINE=$(grep -i "Global variables use" "$BUILD_LOG" || true)

FLASH_BYTES=""
FLASH_PCT=""
RAM_BYTES=""
RAM_PCT=""

if [[ -n "$FLASH_LINE" ]]; then
    FLASH_BYTES=$(echo "$FLASH_LINE" | grep -oP '\d+(?= bytes \(.*\) of program)')
    FLASH_PCT=$(echo "$FLASH_LINE" | grep -oP '\d+(?=%) of program' | head -1)
fi

if [[ -n "$RAM_LINE" ]]; then
    RAM_BYTES=$(echo "$RAM_LINE" | grep -oP '\d+(?= bytes \(.*\) of dynamic)')
    RAM_PCT=$(echo "$RAM_LINE" | grep -oP '\d+(?=%) of dynamic' | head -1)
fi

# ── Write JSON ────────────────────────────────────────────────────────────────
python3 - <<PYEOF
import json, os

summary = {
    "description": "ESP32 resource footprint — Arduino CLI compile output",
    "board": "${BOARD}",
    "sketch_dir": "${SKETCH_DIR}",
    "flash_bytes": int("${FLASH_BYTES}") if "${FLASH_BYTES}" else None,
    "flash_percent_of_available": float("${FLASH_PCT}") if "${FLASH_PCT}" else None,
    "static_ram_bytes": int("${RAM_BYTES}") if "${RAM_BYTES}" else None,
    "static_ram_percent_of_available": float("${RAM_PCT}") if "${RAM_PCT}" else None,
    "notes": [
        "Enable #define CIPHERCHANNEL_FOOTPRINT_EXPERIMENT in BLEProtocol.cpp to print stack/heap during send/receive/write.",
        "Read uxTaskGetStackHighWaterMark(NULL) and ESP.getFreeHeap() output from Serial at 115200 baud.",
        "Flash and RAM figures are from the Arduino CLI linker output — they include all libraries.",
    ],
    "build_log": "${BUILD_LOG}",
}
with open("${JSON_OUT}", "w") as f:
    json.dump(summary, f, indent=2)
print(f"Summary → ${JSON_OUT}")
PYEOF

echo ""
echo "Flash  : ${FLASH_BYTES} bytes  (${FLASH_PCT}%)"
echo "RAM    : ${RAM_BYTES} bytes  (${RAM_PCT}%)"
