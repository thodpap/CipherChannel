#!/usr/bin/env python3
"""
Experiment A — Protocol Correctness
Canonical run script for CipherChannel experimental evaluation.

Tests:
  A1. Packet-length invariants across all specified plaintext sizes
  A2. Counter behaviour at boundary and exhaustion values
  A3. Malformed-input rejection

Outputs:
  raw.csv     — one row per test case
  summary.json — aggregated pass/fail counts with metadata

Usage:
    python3 run_correctness.py
    python3 run_correctness.py --verbose
"""

import argparse
import csv
import json
import os
import sys
import time
import traceback

# ── Path bootstrap ─────────────────────────────────────────────────────────────
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.insert(0, os.path.join(REPO_ROOT, 'shared'))

from cipher import (
    CipherChannel, ChannelException,
    NONCE_LEN, MAC_LEN, MAX_PLAINTEXT_SIZE, MAX_PACKET_SIZE,
    PROTOCOL_VERSION, STATE_FORMAT_VERSION,
)
from Crypto.Random import get_random_bytes

# ── Globals ────────────────────────────────────────────────────────────────────
GIT_COMMIT = os.popen(
    f'git -C {REPO_ROOT} rev-parse HEAD 2>/dev/null'
).read().strip()

VERBOSE = False
_uid = 0
_results: list[dict] = []


def _pair(tag: str = '', key: bytes | None = None) -> tuple[CipherChannel, CipherChannel]:
    global _uid
    _uid += 1
    pfx = f'/tmp/_cc_canon_{os.getpid()}_{_uid}'
    k = key if key is not None else get_random_bytes(32)
    ini = CipherChannel.create(k, True,  f'{pfx}_i{tag}')
    res = CipherChannel.create(k, False, f'{pfx}_r{tag}')
    return ini, res


def _nonce_val(pkt: bytes) -> int:
    return int.from_bytes(pkt[:NONCE_LEN], 'little')


def record(test_id: str, description: str, expected: str, actual: str,
           passed: bool, note: str = '') -> None:
    status = 'PASS' if passed else 'FAIL'
    mark = 'PASS' if passed else 'FAIL'
    print(f'  {mark}  {test_id:<10}  {description}')
    if not passed:
        print(f'           expected={expected!r}  actual={actual!r}  note={note}')
    _results.append({
        'test_id':     test_id,
        'description': description,
        'expected':    expected,
        'actual':      actual,
        'pass':        passed,
        'note':        note,
    })


# ══════════════════════════════════════════════════════════════════════════════
# A1 — Packet-length invariants
# ══════════════════════════════════════════════════════════════════════════════

def a1_packet_lengths():
    print('\nA1 — Packet-length invariants')
    sizes = [0, 1, 15, 16, 17, 31, 32, 63, 64, 127, 128,
             MAX_PLAINTEXT_SIZE - 1, MAX_PLAINTEXT_SIZE]
    for pt_size in sizes:
        ini, res = _pair()
        pt = get_random_bytes(pt_size) if pt_size > 0 else b''
        try:
            pkt = ini.send(pt)
            pkt_len     = len(pkt)
            nonce_bytes = pkt[:NONCE_LEN]
            ct_bytes    = pkt[NONCE_LEN:-MAC_LEN]
            tag_bytes   = pkt[-MAC_LEN:]
            ct_len      = len(ct_bytes)
            expected_pkt_len = pt_size + 28

            ok_nonce  = len(nonce_bytes) == 12
            ok_tag    = len(tag_bytes) == 16
            ok_ct_len = ct_len == pt_size
            ok_pkt    = pkt_len == expected_pkt_len
            ok_recv   = res.receive(pkt) == pt
            all_ok = ok_nonce and ok_tag and ok_ct_len and ok_pkt and ok_recv

            actual_str = (f'pkt={pkt_len} nonce={len(nonce_bytes)} '
                          f'ct={ct_len} tag={len(tag_bytes)} recv={"ok" if ok_recv else "FAIL"}')
            record(f'A1.{pt_size:03d}', f'plaintext_size={pt_size}',
                   f'pkt={expected_pkt_len} nonce=12 ct={pt_size} tag=16 recv=ok',
                   actual_str, all_ok)
        except Exception as e:
            record(f'A1.{pt_size:03d}', f'plaintext_size={pt_size}',
                   f'pkt={pt_size+28} nonce=12 ct={pt_size} tag=16 recv=ok',
                   f'EXCEPTION: {e}', False, str(e))

    # Oversized plaintext: send must raise ChannelException
    try:
        ini, _ = _pair()
        ini.send(b'\x00' * (MAX_PLAINTEXT_SIZE + 1))
        record('A1.over', f'plaintext_size=MAX+1={MAX_PLAINTEXT_SIZE+1}',
               'ChannelException', 'no exception raised', False)
    except ChannelException:
        record('A1.over', f'plaintext_size=MAX+1={MAX_PLAINTEXT_SIZE+1}',
               'ChannelException', 'ChannelException', True)

    # Oversized received packet: receive must return None
    ini, res = _pair()
    oversized_rx = (b'\x02' + b'\x00' * (NONCE_LEN - 1) +
                    b'\xAA' * (MAX_PLAINTEXT_SIZE + 1) +
                    b'\x00' * MAC_LEN)
    got = res.receive(oversized_rx)
    record('A1.rxover', f'receive packet len={len(oversized_rx)} > MAX_PACKET_SIZE',
           'None', str(got), got is None)


# ══════════════════════════════════════════════════════════════════════════════
# A2 — Counter behaviour
# ══════════════════════════════════════════════════════════════════════════════

def a2_counter_behaviour():
    print('\nA2 — Counter behaviour')

    # ── A2.1 First initiator send nonce = 2 ───────────────────────────────────
    ini, res = _pair()
    pkt = ini.send(b'x')
    n = _nonce_val(pkt)
    record('A2.first_ini', 'first initiator send nonce=2', '2', str(n), n == 2)

    # ── A2.2 First responder send nonce = 3 ───────────────────────────────────
    ini, res = _pair()
    pkt = res.send(b'x')
    n = _nonce_val(pkt)
    record('A2.first_res', 'first responder send nonce=3', '3', str(n), n == 3)

    # ── A2.3 Increment by 2 ───────────────────────────────────────────────────
    ini, res = _pair()
    pkts   = [ini.send(b'x') for _ in range(5)]
    nonces = [_nonce_val(p) for p in pkts]
    diffs  = [nonces[i] - nonces[i-1] for i in range(1, len(nonces))]
    all_2  = all(d == 2 for d in diffs)
    record('A2.incr2', 'initiator nonce increments by 2 each send',
           'diffs=[2,2,2,2]', f'diffs={diffs}', all_2)

    # ── A2.4 Direction parity ─────────────────────────────────────────────────
    ini, res = _pair()
    ini_nonces = [_nonce_val(ini.send(b'x')) for _ in range(10)]
    res_nonces = [_nonce_val(res.send(b'x')) for _ in range(10)]
    ini_even   = all(n % 2 == 0 for n in ini_nonces)
    res_odd    = all(n % 2 == 1 for n in res_nonces)
    record('A2.parity_ini', 'initiator nonces all even', 'all even',
           f'parities={[n%2 for n in ini_nonces[:5]]}', ini_even)
    record('A2.parity_res', 'responder nonces all odd', 'all odd',
           f'parities={[n%2 for n in res_nonces[:5]]}', res_odd)

    # ── A2.5 12-byte little-endian serialisation ───────────────────────────────
    # Counter 2 → bytes 02 00 00 00 00 00 00 00 00 00 00 00
    ini, res = _pair()
    pkt = ini.send(b'probe')
    nonce_bytes = pkt[:NONCE_LEN]
    expected_nonce = b'\x02' + b'\x00' * 11
    record('A2.le12', 'counter=2 serialises to 12-byte LE (02 + 11 zeros)',
           expected_nonce.hex(), nonce_bytes.hex(), nonce_bytes == expected_nonce)

    # ── A2.6 Strict comparison: replay rejected ─────────────────────────────
    ini, res = _pair()
    pkt = ini.send(b'once')
    assert res.receive(pkt) == b'once'
    got = res.receive(pkt)
    record('A2.strict_cmp', 'replay rejected (same counter, strict >)',
           'None', str(got), got is None)

    # ── A2.7 Rewind to lower counter → rejected ────────────────────────────
    ini, res = _pair()
    pkt_a = ini.send(b'first')   # nonce=2
    pkt_b = ini.send(b'second')  # nonce=4
    res.receive(pkt_b)
    got = res.receive(pkt_a)
    record('A2.rewind', 'older packet after newer accepted → rejected',
           'None', str(got), got is None)

    # ── A2.8 Large counter values — 12-byte LE serialisation ──────────────────
    test_counters = [255, 256, 65535, 65536, 2**32 - 1, 2**32, 2**64 - 1, 2**64]
    for cval in test_counters:
        # Verify serialisation round-trip
        serialised   = cval.to_bytes(NONCE_LEN, 'little')
        deserialised = int.from_bytes(serialised, 'little')
        ok = (len(serialised) == 12) and (deserialised == cval)
        record(f'A2.ser.{hex(cval)}', f'counter={hex(cval)} 12B LE round-trip',
               f'len=12 val={hex(cval)}', f'len={len(serialised)} val={hex(deserialised)}', ok)

    # ── A2.9 No wraparound — counter must not exceed 2^96-1 ───────────────────
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_canon_{os.getpid()}_{_uid}'
    k = get_random_bytes(32)
    ini_ex = CipherChannel.create(k, True, pfx)
    # Set seqSend to (2^96 - 4) — one send away from max (even, initiator)
    ini_ex._seq_send = (1 << 96) - 4
    ini_ex._write_state()
    pkt_pen = ini_ex.send(b'penultimate')  # nonce = (2^96 - 2) ≤ COUNTER_MAX
    try:
        ini_ex.send(b'overflow')
        record('A2.exhaust', 'counter exhaustion at 2^96 raises ChannelException',
               'ChannelException', 'no exception', False)
    except ChannelException:
        record('A2.exhaust', 'counter exhaustion at 2^96 raises ChannelException',
               'ChannelException', 'ChannelException', True)

    # Verify penultimate nonce is correct
    n_pen = _nonce_val(pkt_pen)
    expected_pen = (1 << 96) - 2
    record('A2.exhaust_nonce', f'penultimate nonce = 2^96-2 = {hex(expected_pen)}',
           hex(expected_pen), hex(n_pen), n_pen == expected_pen)

    # ── A2.10 Missed packets — higher valid same-parity counter accepted ───────
    ini, res = _pair()
    pkts = [ini.send(f'msg{i}'.encode()) for i in range(5)]
    # Send 2(idx0), 4(idx1), 6(idx2), 8(idx3), 10(idx4)
    # Accept 6 directly (skip 2 and 4)
    r6 = res.receive(pkts[2])  # nonce=6
    r4 = res.receive(pkts[1])  # nonce=4 — stale after 6
    r8 = res.receive(pkts[3])  # nonce=8 — should be accepted
    record('A2.skip_ok', 'higher valid counter accepted after skip (nonce=6 after seqRecv=1)',
           f'msg2', str(r6), r6 == b'msg2')
    record('A2.skip_stale', 'lower counter after skip rejected (nonce=4 after seqRecv=6)',
           'None', str(r4), r4 is None)
    record('A2.skip_next', 'next valid counter accepted after skip (nonce=8)',
           'msg3', str(r8), r8 == b'msg3')


# ══════════════════════════════════════════════════════════════════════════════
# A3 — Malformed input
# ══════════════════════════════════════════════════════════════════════════════

def a3_malformed_input():
    print('\nA3 — Malformed-input rejection')

    ini, res = _pair()

    # Empty packet
    got = res.receive(b'')
    record('A3.empty', 'empty packet rejected', 'None', str(got), got is None)

    # Nonce shorter than 12 bytes (packet 10 bytes < 28 minimum)
    got = res.receive(b'\x02' + b'\x00' * 9)
    record('A3.short_nonce', 'packet with 10-byte nonce (< 28B total) rejected',
           'None', str(got), got is None)

    # Packet shorter than 28 bytes (27 bytes = NONCE+TAG-1)
    got = res.receive(b'\x00' * 27)
    record('A3.short27', '27-byte packet (one short of minimum) rejected',
           'None', str(got), got is None)

    # Exactly 28 bytes with empty plaintext — VALID (must accept)
    pkt28 = ini.send(b'')
    assert len(pkt28) == 28
    got28 = res.receive(pkt28)
    record('A3.min28', '28-byte packet (empty plaintext) accepted',
           "b''", str(got28), got28 == b'')

    # Missing tag (only nonce + ciphertext, no tag)
    ini2, res2 = _pair()
    pkt_full = ini2.send(b'data')
    pkt_no_tag = pkt_full[:NONCE_LEN + 4]  # nonce + ciphertext, truncated
    got = res2.receive(pkt_no_tag)
    record('A3.no_tag', 'packet with truncated/missing tag rejected',
           'None', str(got), got is None)

    # Truncated ciphertext
    ini3, res3 = _pair()
    pkt_full = ini3.send(b'hello world')
    pkt_trunc = pkt_full[:-5]  # remove last 5 bytes (cuts into tag)
    got = res3.receive(pkt_trunc)
    record('A3.trunc_ct', 'packet with truncated ciphertext rejected',
           'None', str(got), got is None)

    # Oversized packet
    ini4, res4 = _pair()
    oversized = (b'\x02' + b'\x00' * (NONCE_LEN - 1) +
                 b'\xAA' * (MAX_PLAINTEXT_SIZE + 1) + b'\x00' * MAC_LEN)
    got = res4.receive(oversized)
    record('A3.oversized', f'packet > MAX_PACKET_SIZE={MAX_PACKET_SIZE} rejected',
           'None', str(got), got is None)

    # Incompatible protocol version — corrupted state file
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_canon_{os.getpid()}_{_uid}'
    k = get_random_bytes(32)
    CipherChannel.create(k, True, pfx)
    with open(pfx, 'r+b') as f:
        data = bytearray(f.read())
        data[1] = 99  # corrupt PROTOCOL_VERSION byte
        f.seek(0); f.write(data)
    try:
        CipherChannel.load(pfx)
        record('A3.bad_pv', 'incompatible protocol version raises ChannelException',
               'ChannelException', 'no exception', False)
    except ChannelException:
        record('A3.bad_pv', 'incompatible protocol version raises ChannelException',
               'ChannelException', 'ChannelException', True)

    # Corrupted state (all zeros, unrecognised format version)
    path_corrupt = f'/tmp/_cc_corrupt_{os.getpid()}'
    with open(path_corrupt, 'wb') as f:
        f.write(b'\x00' * 8)
    try:
        CipherChannel.load(path_corrupt)
        record('A3.corrupt', 'corrupted state file raises ChannelException',
               'ChannelException', 'no exception', False)
    except ChannelException:
        record('A3.corrupt', 'corrupted state file raises ChannelException',
               'ChannelException', 'ChannelException', True)

    # Wrong endpoint state (endpoint_id mismatch)
    _uid += 1
    pfx2 = f'/tmp/_cc_canon_{os.getpid()}_{_uid}'
    k2 = get_random_bytes(32)
    CipherChannel.create(k2, True, pfx2, endpoint_id='phone')
    try:
        CipherChannel.load(pfx2, endpoint_id='cane')
        record('A3.eid_mismatch', 'endpoint_id mismatch raises ChannelException',
               'ChannelException', 'no exception', False)
    except ChannelException:
        record('A3.eid_mismatch', 'endpoint_id mismatch raises ChannelException',
               'ChannelException', 'ChannelException', True)

    # Tampered ciphertext → GCM auth fails
    ini5, res5 = _pair()
    pkt = bytearray(ini5.send(b'integrity test'))
    pkt[NONCE_LEN] ^= 0xFF
    got = res5.receive(bytes(pkt))
    record('A3.tamper_ct', 'tampered ciphertext byte → None (GCM auth failure)',
           'None', str(got), got is None)

    # Tampered tag → GCM auth fails
    ini6, res6 = _pair()
    pkt6 = bytearray(ini6.send(b'tag tamper'))
    pkt6[-1] ^= 0x01
    got6 = res6.receive(bytes(pkt6))
    record('A3.tamper_tag', 'tampered GCM tag byte → None',
           'None', str(got6), got6 is None)

    # Tampered nonce → parity or freshness check first, then GCM fail
    ini7, res7 = _pair()
    pkt7 = bytearray(ini7.send(b'nonce tamper'))
    pkt7[0] ^= 0x01  # flip LSB of nonce → changes parity
    got7 = res7.receive(bytes(pkt7))
    record('A3.tamper_nonce', 'tampered nonce (parity flip) → None',
           'None', str(got7), got7 is None)


# ══════════════════════════════════════════════════════════════════════════════
# A4 — Test vector
# ══════════════════════════════════════════════════════════════════════════════

def a4_test_vector():
    print('\nA4 — Protocol test vector (PROTOCOL.md §15)')
    EXPECTED_NONCE = bytes.fromhex('020000000000000000000000')
    EXPECTED_CT    = bytes.fromhex('bb3af9b4')
    EXPECTED_TAG   = bytes.fromhex('d81a74113b0c7c232afe5b00cac5095a')
    EXPECTED_PKT   = EXPECTED_NONCE + EXPECTED_CT + EXPECTED_TAG

    global _uid; _uid += 1
    pfx = f'/tmp/_cc_canon_{os.getpid()}_{_uid}'
    key = b'\x00' * 32
    ini = CipherChannel.create(key, True, pfx)
    pkt = ini.send(b'test')

    record('A4.vec_pkt', 'zero-key initiator pt=b"test" → exact test vector packet',
           EXPECTED_PKT.hex(), pkt.hex(), pkt == EXPECTED_PKT)

    pfx2 = f'/tmp/_cc_canon_{os.getpid()}_{_uid}_r'
    res = CipherChannel.create(key, False, pfx2)
    got = res.receive(EXPECTED_PKT)
    record('A4.vec_recv', 'responder decrypts test vector → b"test"',
           "b'test'", str(got), got == b'test')

    replay = res.receive(EXPECTED_PKT)
    record('A4.vec_replay', 'test vector replay rejected',
           'None', str(replay), replay is None)


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global VERBOSE
    p = argparse.ArgumentParser(description='Experiment A — Protocol Correctness')
    p.add_argument('--verbose', '-v', action='store_true')
    args = p.parse_args()
    VERBOSE = args.verbose

    out_dir = os.path.dirname(os.path.abspath(__file__))
    t0 = time.perf_counter()

    print(f'Experiment A — Protocol Correctness')
    print(f'Git commit : {GIT_COMMIT}')
    print(f'Protocol   : version={PROTOCOL_VERSION}  state_format={STATE_FORMAT_VERSION}')
    print(f'Limits     : MAX_PLAINTEXT_SIZE={MAX_PLAINTEXT_SIZE}  MAX_PACKET_SIZE={MAX_PACKET_SIZE}')
    print('=' * 72)

    a1_packet_lengths()
    a2_counter_behaviour()
    a3_malformed_input()
    a4_test_vector()

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    passed = sum(1 for r in _results if r['pass'])
    failed = sum(1 for r in _results if not r['pass'])
    total  = len(_results)

    # ── CSV ───────────────────────────────────────────────────────────────────
    csv_path = os.path.join(out_dir, 'raw.csv')
    with open(csv_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['test_id', 'description', 'expected', 'actual', 'pass', 'note'])
        w.writeheader()
        w.writerows(_results)

    # ── JSON ──────────────────────────────────────────────────────────────────
    summary = {
        'experiment': 'A — Protocol Correctness',
        'git_commit': GIT_COMMIT,
        'protocol_version': PROTOCOL_VERSION,
        'state_format_version': STATE_FORMAT_VERSION,
        'max_plaintext_size': MAX_PLAINTEXT_SIZE,
        'max_packet_size': MAX_PACKET_SIZE,
        'total': total,
        'passed': passed,
        'failed': failed,
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
