#!/usr/bin/env python3
"""
Unit tests for ProvisioningGate and BenchmarkProvisioningGate.

Tests the physical-presence-gated provisioning state machine in complete
isolation from BLE, GPIO, and asyncio.  All tests are deterministic and
require no hardware.

Usage:
    python3 cipher_tests/test_provisioning.py
    python3 cipher_tests/test_provisioning.py -v
"""

import os
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from provisioning_gate import ProvisioningGate, BenchmarkProvisioningGate

VERBOSE = '-v' in sys.argv

_pass = _fail = 0
_failures: list[str] = []


def run(name: str, fn) -> None:
    global _pass, _fail
    try:
        t0 = time.perf_counter()
        fn()
        ms = (time.perf_counter() - t0) * 1000
        print(f"  PASS  {name:<62}  {ms:5.1f} ms")
        _pass += 1
    except Exception as e:
        print(f"  FAIL  {name}")
        print(f"        {e}")
        if VERBOSE:
            traceback.print_exc()
        _fail += 1
        _failures.append(name)


# ── ProvisioningGate — closed gate ────────────────────────────────────────────

def p01_closed_gate_rejects_phone():
    gate = ProvisioningGate()
    assert gate.try_provision('phone') is False

def p02_closed_gate_rejects_cane():
    gate = ProvisioningGate()
    assert gate.try_provision('cane') is False


# ── ProvisioningGate — active window ──────────────────────────────────────────

def p03_active_window_allows_correct_endpoint():
    gate = ProvisioningGate()
    gate.open('phone')
    assert gate.try_provision('phone') is True

def p04_active_window_rejects_wrong_endpoint():
    gate = ProvisioningGate()
    gate.open('phone')
    assert gate.try_provision('cane') is False       # wrong endpoint rejected
    assert gate.try_provision('phone') is True       # correct endpoint still works

def p05_one_shot_second_request_rejected():
    gate = ProvisioningGate()
    gate.open('phone')
    assert gate.try_provision('phone') is True
    assert gate.try_provision('phone') is False      # second request in same window

def p06_window_closed_after_successful_provision():
    gate = ProvisioningGate()
    gate.open('phone')
    gate.try_provision('phone')
    assert gate.is_open is False


# ── ProvisioningGate — timeout ────────────────────────────────────────────────

def p07_timeout_rejects_provision():
    gate = ProvisioningGate()
    gate.open('phone', duration_s=0)    # window expires immediately
    time.sleep(0.01)
    assert gate.try_provision('phone') is False


# ── ProvisioningGate — is_open property ───────────────────────────────────────

def p08_is_open_false_on_default():
    gate = ProvisioningGate()
    assert gate.is_open is False

def p09_is_open_true_after_open():
    gate = ProvisioningGate()
    gate.open('phone')
    assert gate.is_open is True

def p10_is_open_false_after_close():
    gate = ProvisioningGate()
    gate.open('phone')
    gate.close()
    assert gate.is_open is False

def p11_is_open_false_after_timeout():
    gate = ProvisioningGate()
    gate.open('phone', duration_s=0)
    time.sleep(0.01)
    assert gate.is_open is False


# ── ProvisioningGate — disconnect / STOP_SHARING / shutdown ───────────────────

def p12_close_simulates_disconnect():
    gate = ProvisioningGate()
    gate.open('phone')
    gate.close()    # simulates client disconnect
    assert gate.try_provision('phone') is False

def p13_close_simulates_stop_sharing():
    gate = ProvisioningGate()
    gate.open('cane')
    gate.close()    # simulates STOP_SHARING
    assert gate.try_provision('cane') is False

def p14_close_simulates_server_shutdown():
    gate = ProvisioningGate()
    gate.open('phone')
    gate.close()    # called in shutdown finally block
    assert gate.is_open is False

def p15_close_on_closed_gate_is_noop():
    gate = ProvisioningGate()
    gate.close()    # must not raise
    assert gate.is_open is False


# ── ProvisioningGate — lifecycle ──────────────────────────────────────────────

def p16_reopen_after_successful_provision():
    gate = ProvisioningGate()
    gate.open('phone')
    gate.try_provision('phone')   # first cycle: window consumed
    gate.open('phone')            # second cycle: re-open for next provisioning
    assert gate.try_provision('phone') is True

def p17_separate_gates_are_independent():
    phone_gate = ProvisioningGate()
    cane_gate  = ProvisioningGate()
    phone_gate.open('phone')
    assert cane_gate.try_provision('cane') is False      # cane gate still closed
    assert phone_gate.try_provision('phone') is True     # phone gate independent


# ── ProvisioningGate — thread safety ──────────────────────────────────────────

def p18_concurrent_try_provision_exactly_one_wins():
    gate = ProvisioningGate()
    gate.open('phone')
    results = []
    lock    = threading.Lock()

    def attempt():
        r = gate.try_provision('phone')
        with lock:
            results.append(r)

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()

    wins = sum(1 for r in results if r)
    assert wins == 1, f"expected exactly 1 win under concurrency, got {wins}"


# ── BenchmarkProvisioningGate ─────────────────────────────────────────────────

def b01_always_allows_phone():
    gate = BenchmarkProvisioningGate()
    assert gate.try_provision('phone') is True

def b02_always_allows_cane():
    gate = BenchmarkProvisioningGate()
    assert gate.try_provision('cane') is True

def b03_allows_multiple_times_not_one_shot():
    gate = BenchmarkProvisioningGate()
    for _ in range(10):
        assert gate.try_provision('phone') is True

def b04_open_is_noop():
    gate = BenchmarkProvisioningGate()
    gate.open('phone')    # must not raise
    assert gate.try_provision('phone') is True

def b05_close_is_noop():
    gate = BenchmarkProvisioningGate()
    gate.close()          # must not block provisioning
    assert gate.try_provision('phone') is True

def b06_close_does_not_block_after_provision():
    gate = BenchmarkProvisioningGate()
    gate.try_provision('phone')
    gate.close()          # no-op
    assert gate.try_provision('phone') is True   # still works


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("ProvisioningGate test suite\n")

    print("Closed gate")
    run("P01 closed gate rejects 'phone'",                          p01_closed_gate_rejects_phone)
    run("P02 closed gate rejects 'cane'",                           p02_closed_gate_rejects_cane)

    print("\nActive window")
    run("P03 active window allows correct endpoint",                p03_active_window_allows_correct_endpoint)
    run("P04 active window rejects wrong endpoint",                 p04_active_window_rejects_wrong_endpoint)
    run("P05 one-shot: second request in same window rejected",     p05_one_shot_second_request_rejected)
    run("P06 window closed after successful provision",             p06_window_closed_after_successful_provision)

    print("\nTimeout")
    run("P07 expired window rejects provision",                     p07_timeout_rejects_provision)

    print("\nis_open property")
    run("P08 is_open False on default (closed)",                    p08_is_open_false_on_default)
    run("P09 is_open True after open()",                            p09_is_open_true_after_open)
    run("P10 is_open False after close()",                          p10_is_open_false_after_close)
    run("P11 is_open False after timeout",                          p11_is_open_false_after_timeout)

    print("\nDisconnect / STOP_SHARING / shutdown")
    run("P12 close() simulates client disconnect",                  p12_close_simulates_disconnect)
    run("P13 close() simulates STOP_SHARING",                       p13_close_simulates_stop_sharing)
    run("P14 close() simulates server shutdown",                    p14_close_simulates_server_shutdown)
    run("P15 close() on already-closed gate is no-op",             p15_close_on_closed_gate_is_noop)

    print("\nLifecycle")
    run("P16 re-open after successful provision",                   p16_reopen_after_successful_provision)
    run("P17 separate phone/cane gates are independent",            p17_separate_gates_are_independent)

    print("\nThread safety")
    run("P18 concurrent try_provision: exactly one wins",           p18_concurrent_try_provision_exactly_one_wins)

    print("\nBenchmarkProvisioningGate")
    run("B01 always allows 'phone'",                                b01_always_allows_phone)
    run("B02 always allows 'cane'",                                 b02_always_allows_cane)
    run("B03 allows multiple times (not one-shot)",                 b03_allows_multiple_times_not_one_shot)
    run("B04 open() is a no-op",                                    b04_open_is_noop)
    run("B05 close() is a no-op",                                   b05_close_is_noop)
    run("B06 close() does not block subsequent provisions",         b06_close_does_not_block_after_provision)

    total = _pass + _fail
    print(f"\n{'─' * 72}")
    print(f"Result: {_pass}/{total} passed" + (f"   ({_fail} FAILED)" if _fail else "   — all passed"))
    for name in _failures:
        print(f"  FAIL: {name}")
    sys.exit(0 if _fail == 0 else 1)
