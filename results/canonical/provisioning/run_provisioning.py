#!/usr/bin/env python3
"""
Provisioning gate tests — canonical run.

Tests the ProvisioningGate (physical-presence gated) and
BenchmarkProvisioningGate state machines in isolation.

No BLE, GPIO, asyncio, or hardware required.

Run:
    python3.14 results/canonical/provisioning/run_provisioning.py
"""

import csv
import json
import os
import sys
import threading
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.insert(0, os.path.join(REPO_ROOT, 'shared'))

from provisioning_gate import ProvisioningGate, BenchmarkProvisioningGate

GIT_COMMIT = os.popen(f'git -C {REPO_ROOT} rev-parse HEAD 2>/dev/null').read().strip()

_results: list[dict] = []


def record(test_id: str, description: str, expected: str, actual: str,
           passed: bool, note: str = ''):
    mark = 'PASS' if passed else 'FAIL'
    print(f'  {mark}  {test_id:<18}  {description}')
    _results.append({
        'test_id':     test_id,
        'description': description,
        'expected':    expected,
        'actual':      actual,
        'pass':        passed,
        'note':        note,
    })


# ══════════════════════════════════════════════════════════════════════════════
# ProvisioningGate — Section 10 of PROTOCOL.md
# ══════════════════════════════════════════════════════════════════════════════

def prov_gate_tests():
    print('\nProvisioningGate (physical-presence gated)')

    # P01 Default state is CLOSED
    g = ProvisioningGate()
    r = g.try_provision('phone')
    record('P01', 'closed gate rejects phone', 'False', str(r), r is False)

    # P02 Closed gate rejects cane
    g = ProvisioningGate()
    r = g.try_provision('cane')
    record('P02', 'closed gate rejects cane', 'False', str(r), r is False)

    # P03 Active window allows correct endpoint
    g = ProvisioningGate()
    g.open('phone')
    r = g.try_provision('phone')
    record('P03', 'active window allows correct endpoint', 'True', str(r), r is True)

    # P04 Active window rejects wrong endpoint, allows correct
    g = ProvisioningGate()
    g.open('phone')
    r_wrong = g.try_provision('cane')
    r_ok    = g.try_provision('phone')
    record('P04a', 'active window rejects wrong endpoint (cane)', 'False', str(r_wrong), r_wrong is False)
    record('P04b', 'active window still allows correct (phone)', 'True', str(r_ok), r_ok is True)

    # P05 One-shot: second request in same window rejected
    g = ProvisioningGate()
    g.open('phone')
    r1 = g.try_provision('phone')
    r2 = g.try_provision('phone')
    record('P05a', 'one-shot: first request accepted', 'True', str(r1), r1 is True)
    record('P05b', 'one-shot: second request in same window rejected', 'False', str(r2), r2 is False)

    # P06 Window closed after successful provision
    g = ProvisioningGate()
    g.open('phone')
    g.try_provision('phone')
    record('P06', 'window closed after successful provision', 'False', str(g.is_open), g.is_open is False)

    # P07 Timeout: window expires immediately (duration_s=0)
    g = ProvisioningGate()
    g.open('phone', duration_s=0)
    time.sleep(0.02)
    r = g.try_provision('phone')
    record('P07', 'expired window rejects provision', 'False', str(r), r is False)

    # P08 is_open False on default
    g = ProvisioningGate()
    record('P08', 'is_open False on default (closed)', 'False', str(g.is_open), g.is_open is False)

    # P09 is_open True after open()
    g = ProvisioningGate()
    g.open('phone')
    record('P09', 'is_open True after open()', 'True', str(g.is_open), g.is_open is True)

    # P10 is_open False after close()
    g = ProvisioningGate()
    g.open('phone')
    g.close()
    record('P10', 'is_open False after close()', 'False', str(g.is_open), g.is_open is False)

    # P11 is_open False after timeout
    g = ProvisioningGate()
    g.open('phone', duration_s=0)
    time.sleep(0.02)
    record('P11', 'is_open False after timeout', 'False', str(g.is_open), g.is_open is False)

    # P12-P14 close() simulates disconnect / STOP_SHARING / shutdown
    for pid, endpoint, desc in [
        ('P12', 'phone', 'disconnect'),
        ('P13', 'cane',  'STOP_SHARING'),
        ('P14', 'phone', 'server shutdown'),
    ]:
        g = ProvisioningGate()
        g.open(endpoint)
        g.close()
        r = g.try_provision(endpoint)
        record(pid, f'close() simulates {desc} → reject', 'False', str(r), r is False)

    # P15 close() on already-closed gate is no-op
    g = ProvisioningGate()
    try:
        g.close()
        record('P15', 'close() on closed gate is no-op (no exception)', 'no-exception', 'no-exception', True)
    except Exception as e:
        record('P15', 'close() on closed gate is no-op', 'no-exception', str(e), False)

    # P16 Re-open after successful provision
    g = ProvisioningGate()
    g.open('phone'); g.try_provision('phone')
    g.open('phone')
    r = g.try_provision('phone')
    record('P16', 're-open after successful provision works', 'True', str(r), r is True)

    # P17 Separate gates are independent
    pg = ProvisioningGate(); cg = ProvisioningGate()
    pg.open('phone')
    r_cane  = cg.try_provision('cane')
    r_phone = pg.try_provision('phone')
    record('P17a', 'cane gate still closed while phone gate open', 'False', str(r_cane), r_cane is False)
    record('P17b', 'phone gate independent of cane gate', 'True', str(r_phone), r_phone is True)

    # P18 Thread safety: exactly one win under concurrency
    g = ProvisioningGate()
    g.open('phone')
    wins: list[bool] = []
    lock = threading.Lock()
    def attempt():
        rv = g.try_provision('phone')
        with lock: wins.append(rv)
    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    n_wins = sum(1 for w in wins if w)
    record('P18', 'concurrent try_provision: exactly one wins', '1', str(n_wins), n_wins == 1)

    # P19 REQUEST_KEY while window is CLOSED returns False without key material
    g = ProvisioningGate()
    r = g.try_provision('phone')
    record('P19', 'REQUEST_KEY while CLOSED → False (no key material)', 'False', str(r), r is False)


# ══════════════════════════════════════════════════════════════════════════════
# BenchmarkProvisioningGate — test-only bypass (PROTOCOL.md §10)
# ══════════════════════════════════════════════════════════════════════════════

def benchmark_gate_tests():
    print('\nBenchmarkProvisioningGate (test-only bypass)')

    # B01-B02 Always allows
    for bid, endpoint in [('B01', 'phone'), ('B02', 'cane')]:
        g = BenchmarkProvisioningGate()
        r = g.try_provision(endpoint)
        record(bid, f'always allows {endpoint!r}', 'True', str(r), r is True)

    # B03 Allows multiple times (not one-shot)
    g = BenchmarkProvisioningGate()
    results = [g.try_provision('phone') for _ in range(10)]
    all_ok = all(results)
    record('B03', 'allows multiple times (not one-shot)', 'all True', str(results[:3]) + '…', all_ok)

    # B04 open() is no-op
    g = BenchmarkProvisioningGate()
    try:
        g.open('phone')
        r = g.try_provision('phone')
        record('B04', 'open() is no-op', 'True', str(r), r is True)
    except Exception as e:
        record('B04', 'open() is no-op', 'True', str(e), False)

    # B05 close() does not block provisioning
    g = BenchmarkProvisioningGate()
    g.close()
    r = g.try_provision('phone')
    record('B05', 'close() does not block provisioning', 'True', str(r), r is True)

    # B06 close() after provision does not block next provision
    g = BenchmarkProvisioningGate()
    g.try_provision('phone')
    g.close()
    r = g.try_provision('phone')
    record('B06', 'close() after provision: still allows next provision', 'True', str(r), r is True)


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    t0 = time.perf_counter()

    print('Provisioning Gate Tests')
    print(f'Git commit : {GIT_COMMIT}')
    print('=' * 72)

    prov_gate_tests()
    benchmark_gate_tests()

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    passed = sum(1 for r in _results if r['pass'])
    failed = sum(1 for r in _results if not r['pass'])
    total  = len(_results)

    csv_path = os.path.join(out_dir, 'raw.csv')
    with open(csv_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['test_id', 'description', 'expected', 'actual', 'pass', 'note'])
        w.writeheader()
        w.writerows(_results)

    summary = {
        'experiment': 'Provisioning Gate',
        'git_commit': GIT_COMMIT,
        'total': total, 'passed': passed, 'failed': failed,
        'elapsed_ms': elapsed_ms,
        'results': _results,
        'failed_tests': [r['test_id'] for r in _results if not r['pass']],
    }
    json_path = os.path.join(out_dir, 'summary.json')
    with open(json_path, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f'\n{"─" * 72}')
    print(f'Result: {passed}/{total} passed' + (f'   ({failed} FAILED)' if failed else '   — all passed'))
    print(f'Elapsed: {elapsed_ms} ms')
    print(f'raw    → {csv_path}')
    print(f'summary→ {json_path}')
    if failed:
        for r in _results:
            if not r['pass']:
                print(f'  FAIL: {r["test_id"]}  {r["description"]}')
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
