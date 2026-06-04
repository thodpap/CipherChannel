#!/usr/bin/env bash
# Run all cipher tests and benchmarks on the RPi.
# Creates .venv on first run and installs pycryptodome.
#
# Usage:
#   bash run_all.sh                          # tests + bench (tmpfs only)
#   BENCH_DISK_DIR=/home/awake bash run_all.sh   # include disk vs tmpfs comparison
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$DIR/.venv"

if [[ ! -x "$VENV/bin/python" ]]; then
    echo "Creating venv in $VENV …"
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q --upgrade pip
    "$VENV/bin/pip" install -r "$DIR/requirements.txt"
    echo ""
fi

echo "==================================================================="
echo "  CipherChannel — correctness & security tests"
echo "==================================================================="
"$VENV/bin/python" "$DIR/test_cipher.py" "$@"
TEST_RC=$?

echo ""
echo "==================================================================="
echo "  CipherChannel — performance benchmarks"
echo "==================================================================="
"$VENV/bin/python" "$DIR/bench_cipher.py"

echo ""
if [[ $TEST_RC -eq 0 ]]; then
    echo "All tests passed. Benchmark complete."
else
    echo "WARNING: $TEST_RC test(s) failed. See output above."
    exit $TEST_RC
fi
