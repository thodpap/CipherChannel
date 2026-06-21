#!/usr/bin/env python3
"""
analyze_results.py — Statistical analysis of DTLS cold-start benchmark CSV.

Reads the CSV produced by dtls_client, prints a console summary, and writes
a JSON summary and a Markdown table.

Usage:
    python3 analyze_results.py --input results/dtls_trials_YYYYMMDD_HHMMSS.csv
    python3 analyze_results.py --input FILE --json FILE.json --markdown FILE.md
"""

import argparse
import csv
import json
import math
import random
import sys
from pathlib import Path


# ── Percentile (linear interpolation) ─────────────────────────────────────────

def percentile(sorted_data: list, p: float) -> float:
    if not sorted_data:
        return float("nan")
    n = len(sorted_data)
    idx = (n - 1) * p / 100.0
    lo = int(idx)
    hi = lo + 1
    frac = idx - lo
    if hi >= n:
        return sorted_data[lo]
    return sorted_data[lo] + frac * (sorted_data[hi] - sorted_data[lo])


# ── Bootstrap 95% CI for the median ───────────────────────────────────────────

def bootstrap_median_ci(
    data: list,
    n_boot: int = 2000,
    confidence: float = 0.95,
    seed: int = 42,
) -> tuple:
    if len(data) < 2:
        return float("nan"), float("nan")
    rng = random.Random(seed)
    medians = sorted(
        percentile(sorted(rng.choices(data, k=len(data))), 50)
        for _ in range(n_boot)
    )
    lo_idx = int((1.0 - confidence) / 2.0 * n_boot)
    hi_idx = int((1.0 + confidence) / 2.0 * n_boot) - 1
    hi_idx = min(hi_idx, len(medians) - 1)
    return medians[lo_idx], medians[hi_idx]


# ── Per-metric statistics ──────────────────────────────────────────────────────

def compute_stats(values: list) -> dict:
    if not values:
        return {"n": 0}
    sv = sorted(values)
    ci_lo, ci_hi = bootstrap_median_ci(values)
    return {
        "n":       len(sv),
        "min":     sv[0],
        "max":     sv[-1],
        "mean":    sum(sv) / len(sv),
        "median":  percentile(sv, 50),
        "p90":     percentile(sv, 90),
        "p95":     percentile(sv, 95),
        "p99":     percentile(sv, 99),
        "ci95_lo": ci_lo,
        "ci95_hi": ci_hi,
    }


# ── CSV loading ────────────────────────────────────────────────────────────────

def load_csv(path: str) -> list:
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows


def safe_float(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ── Formatting helpers ─────────────────────────────────────────────────────────

def fmt(v, decimals: int = 2) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "—"
    return f"{v:.{decimals}f}"


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input",    required=True, help="Input CSV path")
    parser.add_argument("--json",     default=None,  help="Output JSON summary path")
    parser.add_argument("--markdown", default=None,  help="Output Markdown table path")
    args = parser.parse_args()

    rows = load_csv(args.input)
    if not rows:
        print("ERROR: CSV is empty or has no data rows.", file=sys.stderr)
        sys.exit(1)

    ok_rows   = [r for r in rows if r.get("success") == "true"]
    fail_rows = [r for r in rows if r.get("success") != "true"]

    total        = len(rows)
    n_ok         = len(ok_rows)
    n_fail       = len(fail_rows)
    success_rate = 100.0 * n_ok / total if total else 0.0

    metrics = ["socket_setup_ms", "handshake_ms", "command_ack_ms", "total_ms"]

    metric_stats: dict[str, dict] = {}
    for m in metrics:
        vals = [v for r in ok_rows if (v := safe_float(r.get(m))) is not None]
        metric_stats[m] = compute_stats(vals)

    # ── Console output ─────────────────────────────────────────────────────────
    fname = Path(args.input).name
    sep = "=" * 68
    print(f"\n{sep}")
    print(f"  DTLS Baseline Experiment — {fname}")
    print(sep)
    print(f"  Total trials : {total}")
    print(f"  Successful   : {n_ok}")
    print(f"  Failed       : {n_fail}")
    print(f"  Success rate : {success_rate:.1f}%")
    print()

    col_w = [20, 7, 8, 8, 8, 8, 8, 16]
    header = (f"{'Metric':<{col_w[0]}} {'min':>{col_w[1]}} {'median':>{col_w[2]}} "
              f"{'p90':>{col_w[3]}} {'p95':>{col_w[4]}} {'p99':>{col_w[5]}} "
              f"{'max':>{col_w[6]}}  {'CI-95 [lo, hi]':^{col_w[7]}}")
    print(header)
    print("-" * len(header))

    for m in metrics:
        s = metric_stats[m]
        if s.get("n", 0) == 0:
            print(f"  {m:<18}  (no data)")
            continue
        ci = f"[{fmt(s['ci95_lo'])}, {fmt(s['ci95_hi'])}]"
        print(f"{m:<{col_w[0]}} {fmt(s['min']):>{col_w[1]}} "
              f"{fmt(s['median']):>{col_w[2]}} {fmt(s['p90']):>{col_w[3]}} "
              f"{fmt(s['p95']):>{col_w[4]}} {fmt(s['p99']):>{col_w[5]}} "
              f"{fmt(s['max']):>{col_w[6]}}  {ci:^{col_w[7]}}")

    print()
    print("  All times in milliseconds (ms).")

    # ── Failure breakdown ──────────────────────────────────────────────────────
    if fail_rows:
        from collections import Counter
        errors = Counter(r.get("error", "unknown") for r in fail_rows)
        print(f"\n  Failure reasons ({n_fail} total):")
        for msg, cnt in errors.most_common(5):
            short = msg[:70] + "..." if len(msg) > 70 else msg
            print(f"    {cnt:4d}x  {short}")

    # ── JSON output ────────────────────────────────────────────────────────────
    def _clean(v):
        if isinstance(v, float) and math.isnan(v):
            return None
        if isinstance(v, float):
            return round(v, 4)
        return v

    summary = {
        "input":            str(args.input),
        "total_trials":     total,
        "n_ok":             n_ok,
        "n_fail":           n_fail,
        "success_rate_pct": round(success_rate, 2),
        "metrics": {
            m: {k: _clean(v) for k, v in s.items()}
            for m, s in metric_stats.items()
        },
    }

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"\n  JSON  : {args.json}")

    # ── Markdown output ────────────────────────────────────────────────────────
    if args.markdown:
        lines = [
            "# DTLS Baseline Experiment — Results Summary",
            "",
            f"**Input:** `{fname}`",
            "",
            "## Trial counts",
            "",
            "| | Value |",
            "|---|---:|",
            f"| Total trials | {total} |",
            f"| Successful | {n_ok} |",
            f"| Failed | {n_fail} |",
            f"| Success rate | {success_rate:.1f}% |",
            "",
            "## Latency (ms) — successful trials only",
            "",
            "| Metric | min | median | p90 | p95 | p99 | max | CI-95 |",
            "|--------|----:|-------:|----:|----:|----:|----:|-------|",
        ]
        for m in metrics:
            s = metric_stats[m]
            if s.get("n", 0) == 0:
                lines.append(f"| {m} | — | — | — | — | — | — | — |")
                continue
            ci = f"[{fmt(s['ci95_lo'])}, {fmt(s['ci95_hi'])}]"
            lines.append(
                f"| {m} "
                f"| {fmt(s['min'])} "
                f"| {fmt(s['median'])} "
                f"| {fmt(s['p90'])} "
                f"| {fmt(s['p95'])} "
                f"| {fmt(s['p99'])} "
                f"| {fmt(s['max'])} "
                f"| {ci} |"
            )
        lines += [
            "",
            "> All times in milliseconds.",
            "> CI-95 = bootstrap 95% confidence interval for the median (2000 resamples).",
            "",
            "## Column definitions",
            "",
            "| Column | Meaning |",
            "|--------|---------|",
            "| `socket_setup_ms` | UDP socket creation + connect (`t1 - t0`) |",
            "| `handshake_ms` | Full DTLS 1.2 handshake including PSK key derivation (`t2 - t1`) |",
            "| `command_ack_ms` | Time from command send to ACK received (`t4 - t3`) |",
            "| `total_ms` | End-to-end trial latency (`t4 - t0`) |",
        ]

        Path(args.markdown).parent.mkdir(parents=True, exist_ok=True)
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"  MD    : {args.markdown}")

    print()


if __name__ == "__main__":
    main()
