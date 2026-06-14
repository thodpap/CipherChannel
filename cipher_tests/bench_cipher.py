#!/usr/bin/env python3
"""
RPi-only performance benchmarks for the counter-nonce CipherChannel.

Measures:
  1. send() latency     — AES-256-GCM encrypt + counter increment + atomic file write
  2. receive() latency  — counter validation + AES-256-GCM decrypt + atomic file write
  3. round-trip latency — send() + receive() back-to-back
  4. Storage comparison — tmpfs (/tmp) vs persistent disk (BENCH_DISK_DIR env var)
  5. Sustained throughput at 64-byte payload

No BLE, ESP32, or phone required — pure Python, runs standalone on RPi.

Usage:
    python3 bench_cipher.py
    BENCH_DISK_DIR=/home/awake python3 bench_cipher.py
"""

import csv
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from cipher import CipherChannel
from Crypto.Random import get_random_bytes

BENCH_CSV      = os.environ.get('BENCH_CSV',      '/tmp/bench_cipher.csv')
BENCH_DISK_DIR = os.environ.get('BENCH_DISK_DIR', '/home/awake')
TMPFS_DIR      = '/tmp'

N             = 10000  # trials per configuration (after warmup)
WARMUP        = 30     # discarded warm-up rounds
PAYLOAD_SIZES = [16, 64, 128, 256, 512, 1024]
THROUGHPUT_N  = 1000
THROUGHPUT_SZ = 64

_uid = 0


def _pair(state_dir: str, tag: str = '') -> tuple[CipherChannel, CipherChannel]:
    global _uid
    _uid += 1
    pfx = os.path.join(state_dir, f'_bench_{os.getpid()}_{_uid}')
    key = get_random_bytes(32)
    ini = CipherChannel.create(key, True,  f'{pfx}_i{tag}')
    res = CipherChannel.create(key, False, f'{pfx}_r{tag}')
    return ini, res


def _pct(data: list[float], p: float) -> float:
    s = sorted(data)
    idx = (len(s) - 1) * p / 100
    lo, hi = int(idx), min(int(idx) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (idx - lo)


def _stats(samples: list[float]) -> dict:
    return {
        'n':        len(samples),
        'min_ms':   round(min(samples), 4),
        'mean_ms':  round(statistics.mean(samples), 4),
        'p50_ms':   round(_pct(samples, 50), 4),
        'p95_ms':   round(_pct(samples, 95), 4),
        'p99_ms':   round(_pct(samples, 99), 4),
        'max_ms':   round(max(samples), 4),
        'stdev_ms': round(statistics.stdev(samples), 4),
    }


# ── Individual benchmark functions ────────────────────────────────────────────

def bench_send(state_dir: str, size: int) -> list[float]:
    ini, _ = _pair(state_dir)
    payload = get_random_bytes(size)
    for _ in range(WARMUP):
        ini.send(payload)
    return [
        (lambda: (t := time.perf_counter_ns(), ini.send(payload), time.perf_counter_ns() - t)[2])()
        / 1e6
        for _ in range(N)
    ]


def bench_receive(state_dir: str, size: int) -> list[float]:
    ini, res = _pair(state_dir)
    payload  = get_random_bytes(size)
    pkts     = [ini.send(payload) for _ in range(N + WARMUP)]
    for p in pkts[:WARMUP]:
        res.receive(p)
    samples = []
    for p in pkts[WARMUP:]:
        t0 = time.perf_counter_ns()
        res.receive(p)
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    return samples


def bench_roundtrip(state_dir: str, size: int) -> list[float]:
    ini, res = _pair(state_dir)
    payload  = get_random_bytes(size)
    for _ in range(WARMUP):
        res.receive(ini.send(payload))
    samples = []
    for _ in range(N):
        t0 = time.perf_counter_ns()
        pkt = ini.send(payload)
        res.receive(pkt)
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    return samples


# ── Output helpers ────────────────────────────────────────────────────────────

_HDR = f"  {'size':>6}  {'n':>4}  {'min':>8}  {'mean':>8}  {'p50':>8}  {'p95':>8}  {'p99':>8}  {'max':>8}  {'stdev':>7}  ms"
_SEP = f"  {'─'*6}  {'─'*4}  {'─'*8}  {'─'*8}  {'─'*8}  {'─'*8}  {'─'*8}  {'─'*8}  {'─'*7}"


def _print_section(title: str):
    print(f"\n{title}")
    print(_HDR)
    print(_SEP)


def _print_row(size: int, s: dict):
    print(
        f"  {size:>6}  {s['n']:>4}  "
        f"{s['min_ms']:>8.4f}  {s['mean_ms']:>8.4f}  {s['p50_ms']:>8.4f}  "
        f"{s['p95_ms']:>8.4f}  {s['p99_ms']:>8.4f}  {s['max_ms']:>8.4f}  {s['stdev_ms']:>7.4f}"
    )


_CSV_COLS = ['benchmark', 'storage', 'payload_bytes', 'n',
             'min_ms', 'mean_ms', 'p50_ms', 'p95_ms', 'p99_ms', 'max_ms', 'stdev_ms']


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    rows: list[dict] = []
    disk_available = os.path.isdir(BENCH_DISK_DIR) and os.access(BENCH_DISK_DIR, os.W_OK)

    print("CipherChannel benchmark — counter-nonce AES-256-GCM")
    print(f"N={N} per configuration  warmup={WARMUP}")
    print(f"tmpfs state dir : {TMPFS_DIR}")
    print(f"disk  state dir : {BENCH_DISK_DIR}" + ("  (not writable — skipped)" if not disk_available else ""))

    # ── 1. send() ─────────────────────────────────────────────────────────────
    _print_section("send() — encrypt + increment counter + atomic file write  [tmpfs]")
    for sz in PAYLOAD_SIZES:
        s = _stats(bench_send(TMPFS_DIR, sz))
        _print_row(sz, s)
        rows.append({'benchmark': 'send', 'storage': 'tmpfs', 'payload_bytes': sz, **s})

    # ── 2. receive() ──────────────────────────────────────────────────────────
    _print_section("receive() — validate counter + decrypt + atomic file write  [tmpfs]")
    for sz in PAYLOAD_SIZES:
        s = _stats(bench_receive(TMPFS_DIR, sz))
        _print_row(sz, s)
        rows.append({'benchmark': 'receive', 'storage': 'tmpfs', 'payload_bytes': sz, **s})

    # ── 3. round-trip ─────────────────────────────────────────────────────────
    _print_section("round-trip: send() + receive()  [tmpfs]")
    for sz in PAYLOAD_SIZES:
        s = _stats(bench_roundtrip(TMPFS_DIR, sz))
        _print_row(sz, s)
        rows.append({'benchmark': 'roundtrip', 'storage': 'tmpfs', 'payload_bytes': sz, **s})

    # ── 4. Storage comparison at 64 B ─────────────────────────────────────────
    if disk_available:
        _print_section(f"round-trip at 64 B: tmpfs vs disk ({BENCH_DISK_DIR})")
        for label, state_dir in [('tmpfs', TMPFS_DIR), ('disk', BENCH_DISK_DIR)]:
            s = _stats(bench_roundtrip(state_dir, 64))
            print(f"  {label:<8}  n={s['n']}  "
                  f"mean={s['mean_ms']:.4f}  p50={s['p50_ms']:.4f}  "
                  f"p95={s['p95_ms']:.4f}  p99={s['p99_ms']:.4f}  max={s['max_ms']:.4f}  ms")
            rows.append({'benchmark': 'roundtrip_storage_cmp', 'storage': label,
                         'payload_bytes': 64, **s})

    # ── 5. Sustained throughput ───────────────────────────────────────────────
    print(f"\nSustained throughput at {THROUGHPUT_SZ} B payload  ({THROUGHPUT_N} round-trips, tmpfs)")
    ini, res = _pair(TMPFS_DIR)
    payload  = get_random_bytes(THROUGHPUT_SZ)
    for _ in range(WARMUP):
        res.receive(ini.send(payload))

    t_start = time.perf_counter()
    for _ in range(THROUGHPUT_N):
        res.receive(ini.send(payload))
    elapsed = time.perf_counter() - t_start

    pps      = THROUGHPUT_N / elapsed
    ms_per   = 1000 / pps
    print(f"  {THROUGHPUT_N} round-trips in {elapsed:.3f} s → {pps:.1f} pkt/s  ({ms_per:.3f} ms/pkt)")
    rows.append({
        'benchmark': 'throughput', 'storage': 'tmpfs',
        'payload_bytes': THROUGHPUT_SZ, 'n': THROUGHPUT_N,
        'min_ms': '', 'mean_ms': round(ms_per, 4),
        'p50_ms': '', 'p95_ms': '', 'p99_ms': '', 'max_ms': '', 'stdev_ms': '',
    })

    # ── CSV ───────────────────────────────────────────────────────────────────
    with open(BENCH_CSV, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=_CSV_COLS)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, '') for k in _CSV_COLS})
    print(f"\nCSV → {BENCH_CSV}")


if __name__ == '__main__':
    main()
