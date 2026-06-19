#!/usr/bin/env python3
"""
Final experiment aggregator — reads all JSON summaries and generates paper-ready
markdown tables.

Usage:
    python3 final_summarize.py
    python3 final_summarize.py --input-dir results/final/summary \
                               --output results/final/summary/final_experiment_tables.md
"""

import argparse
import json
import os
import sys

DEFAULT_SUMMARY_DIR = os.path.join(os.path.dirname(__file__), 'results', 'final', 'summary')
DEFAULT_OUTPUT      = os.path.join(DEFAULT_SUMMARY_DIR, 'final_experiment_tables.md')

_MISSING = '—'


def _load(path: str) -> dict | None:
    if not os.path.exists(path):
        print(f"  [skip] {os.path.basename(path)} — not found", file=sys.stderr)
        return None
    with open(path) as f:
        return json.load(f)


def _pct(num, denom) -> str:
    if not denom:
        return _MISSING
    return f"{100 * num / denom:.1f}%"


# ── Table builders ─────────────────────────────────────────────────────────────

def table_adversarial(d: dict) -> str:
    lines = [
        "## Table: Adversarial / Restart Validation",
        "",
        f"Total: **{d['passed']}/{d['total']} passed** in {d['total_duration_ms']:.0f} ms",
        "",
        "| # | Test | Result | Duration (ms) |",
        "|---|------|--------|---------------|",
    ]
    for r in d.get('tests', []):
        name   = r.get('test', '')
        result = r.get('result', '')
        ms     = r.get('duration_ms', '')
        mark   = '✓' if result == 'PASS' else '✗'
        lines.append(f"| {mark} | {name} | {result} | {ms} |")
    if d.get('failed_tests'):
        lines += ["", "**Failed tests:**"]
        for t in d['failed_tests']:
            lines.append(f"- {t}")
    return "\n".join(lines)


def table_mtu(d: dict) -> str:
    mtu_val = d.get('negotiated_mtu') or 'not exposed by backend'
    all_large_ok = d.get('above_default_att_mtu_all_ok')
    max_plain = d.get('max_successful_plaintext_bytes', _MISSING)
    max_enc   = d.get('max_successful_encrypted_bytes', _MISSING)

    lines = [
        "## Table: MTU / Long-Write Confirmation",
        "",
        f"- Negotiated ATT MTU: **{mtu_val}**",
        f"- All packets above 20-byte default ATT payload accepted: **{'Yes' if all_large_ok else 'No'}**",
        f"- Max successful plaintext: **{max_plain} B**  →  encrypted: **{max_enc} B**",
        "",
        "| Plaintext (B) | Encrypted (B) | Above 20B ATT? | Result |",
        "|--------------|--------------|----------------|--------|",
    ]

    # Reconstruct per-row from successes/failures lists
    probe_sizes = d.get('probe_sizes_bytes', [])
    successes   = set(d.get('successes_bytes', []))
    failures    = set(d.get('failures_bytes', []))
    for sz in probe_sizes:
        enc = 12 + sz + 16   # nonce(12) + plaintext + tag(16)
        above = enc > 20
        result = 'OK' if sz in successes else ('FAIL' if sz in failures else _MISSING)
        mark   = '✓' if result == 'OK' else ('✗' if result == 'FAIL' else '?')
        lines.append(f"| {sz} | {enc} | {'Yes' if above else 'No'} | {mark} {result} |")

    note = d.get('note', '')
    if note:
        lines += ["", f"> {note}"]
    return "\n".join(lines)


def table_concurrent(d: dict) -> str:
    laptop_sent    = d.get('laptop_sent', _MISSING)
    laptop_ok      = d.get('laptop_accepted', _MISSING)
    laptop_fail    = d.get('laptop_failed', _MISSING)
    cane_obs       = d.get('cane_observed_or_sent', _MISSING)
    replay_run     = d.get('replay_tests_run', _MISSING)
    replay_rej     = d.get('replay_rejected', _MISSING)
    isolation      = d.get('counter_isolation_result', _MISSING)
    window_s       = d.get('experiment_window_seconds', _MISSING)

    lines = [
        "## Table: Concurrent Endpoint Validation",
        "",
        f"Experiment window: {window_s} s",
        "",
        "| Endpoint | Sent | Accepted | Failed | Notes |",
        "|----------|------|----------|--------|-------|",
        f"| Laptop (supervisory) | {laptop_sent} | {laptop_ok} | {laptop_fail} | Fedora/Bleak, substitutes for Android app |",
        "",
        f"**Replay rejection**: {replay_rej}/{replay_run} replayed packets rejected by server counter check",
        "",
        f"**Counter isolation**: {isolation}",
        "",
        "**Notes:**",
    ]
    for note in d.get('notes', []):
        lines.append(f"- {note}")
    return "\n".join(lines)


def table_esp32(d: dict) -> str:
    lines = [
        "## Table: ESP32 Resource Footprint",
        "",
        "| Resource | Value | Method |",
        "|----------|-------|--------|",
    ]
    for k, v in d.items():
        if k in ('description', 'build_command', 'notes'):
            continue
        lines.append(f"| {k} | {v} | — |")
    notes = d.get('notes', [])
    if notes:
        lines += ["", "**Notes:**"]
        for n in notes:
            lines.append(f"- {n}")
    return "\n".join(lines)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Aggregate final experiment summaries into markdown tables.")
    p.add_argument('--input-dir', default=DEFAULT_SUMMARY_DIR)
    p.add_argument('--output',    default=DEFAULT_OUTPUT)
    args = p.parse_args()

    idir = args.input_dir
    sections = [
        "# CipherChannel — Final Experiment Tables",
        f"",
        f"Generated from: `{idir}`",
        "",
    ]

    adv  = _load(os.path.join(idir, 'final_restart_adversarial_summary.json'))
    mtu  = _load(os.path.join(idir, 'final_mtu_check_summary.json'))
    conc = _load(os.path.join(idir, 'final_concurrent_endpoints_summary.json'))
    esp  = _load(os.path.join(idir, 'esp32_footprint_summary.json'))

    if adv:
        sections.append(table_adversarial(adv))
        sections.append("")
    if mtu:
        sections.append(table_mtu(mtu))
        sections.append("")
    if conc:
        sections.append(table_concurrent(conc))
        sections.append("")
    if esp:
        sections.append(table_esp32(esp))
        sections.append("")

    if not any([adv, mtu, conc, esp]):
        print("No summary files found.  Run the individual experiment scripts first.", file=sys.stderr)
        sys.exit(1)

    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w') as f:
        f.write("\n".join(sections))

    print(f"Tables written → {args.output}")


if __name__ == '__main__':
    main()
