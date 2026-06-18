#!/usr/bin/env python3
"""
Compute summary statistics for Experiment H (gateway internal timing).

Reads:  gateway_internal_server_raw.csv  (from RPi after experiment H)
Writes: gateway_internal_summary.json

Run after fetching the server CSV:
  python3 results/canonical/latency/gateway_internal/compute_gateway_summary.py
"""

import csv
import json
import os
import statistics
import sys

_THIS_DIR  = os.path.dirname(os.path.abspath(__file__))
INPUT_CSV  = os.path.join(_THIS_DIR, 'gateway_internal_server_raw.csv')
OUTPUT_JSON = os.path.join(_THIS_DIR, 'gateway_internal_summary.json')

_PHASE_COLS = [
    ('parse_ms',           'packet parse (nonce extract + seq decode)'),
    ('freshness_valid_ms', 'freshness + direction-parity validation'),
    ('crypto_ms',          'AES-256-GCM auth + decryption'),
    ('persistence_ms',     'receive counter fsync to state file'),
    ('json_parse_ms',      'JSON parse + action identification'),
    ('ack_set_ms',         'ack_char.value set (plaintext BLE char write)'),
    ('gateway_total_ms',   'gateway total (T0 callback to T7 char.value set)'),
]


def _stats(vals: list[float]) -> dict | None:
    if not vals:
        return None
    s = sorted(vals)
    n = len(s)
    return {
        'n':      n,
        'mean':   round(statistics.mean(vals), 4),
        'median': round(statistics.median(vals), 4),
        'stdev':  round(statistics.stdev(vals), 4) if n > 1 else 0.0,
        'p95':    round(s[int(0.95 * n)], 4),
        'p99':    round(s[int(0.99 * n)], 4),
        'min':    round(s[0], 4),
        'max':    round(s[-1], 4),
    }


def main() -> None:
    if not os.path.exists(INPUT_CSV):
        sys.exit(
            f"ERROR: {INPUT_CSV} not found.\n"
            f"Fetch from RPi first:\n"
            f"  ssh rpi 'cat /tmp/gateway_internal.csv' > {INPUT_CSV}"
        )

    phase_data: dict[str, list[float]] = {col: [] for col, _ in _PHASE_COLS}

    with open(INPUT_CSV, newline='') as f:
        reader = csv.DictReader(f)
        n_total = 0
        for row in reader:
            n_total += 1
            for col, _ in _PHASE_COLS:
                v = row.get(col, '')
                if v not in ('', None):
                    try:
                        phase_data[col].append(float(v))
                    except ValueError:
                        pass

    print(f"\nExperiment H — Gateway internal stage timing")
    print(f"Input   : {INPUT_CSV}")
    print(f"Rows    : {n_total}\n")
    print(f"{'─' * 80}")
    hdr = f"  {'Stage':<36} {'N':>5} {'Mean':>8} {'Median':>8} {'p95':>8} {'Max':>8}  (ms)"
    print(hdr)
    print(f"  {'─' * 76}")

    phases: dict = {}
    for col, label in _PHASE_COLS:
        st = _stats(phase_data[col])
        phases[col] = {'label': label, 'stats': st}
        if st:
            print(
                f"  {label:<36} {st['n']:>5} {st['mean']:>8.4f} {st['median']:>8.4f}"
                f" {st['p95']:>8.4f} {st['max']:>8.4f}"
            )

    note = (
        "Stage ordering in cipher.py receive(): parse → validate (T3) → crypto (T2) → persist (T4). "
        "T3 (freshness/direction validation) precedes T2 (AES-GCM) — the user-facing label order "
        "in the experiment spec differs from execution order. "
        "ACK is plaintext (ack_encrypt_ms = 0 by design). "
        "BLE notification delivery latency (NOT measured here) dominates end-to-end latency."
    )

    summary = {
        'n_rows':   n_total,
        'input':    INPUT_CSV,
        'note':     note,
        'phases':   phases,
    }
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\nSummary → {OUTPUT_JSON}")


if __name__ == '__main__':
    main()
