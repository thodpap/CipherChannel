#!/usr/bin/env python3
"""
RPi-only correctness and security tests for the counter-nonce CipherChannel.

Protocol under test (Björn's counter-nonce scheme):
  - AES-256-GCM; 16-byte little-endian monotonic counter used as nonce
  - Packet = nonce(16) || ciphertext || tag(16)
  - Initiator sends even counters (0→2→4…), responder sends odd (1→3→5…)
  - Receiver enforces: counter > last_received AND same parity as last_received
  - State (counters + key) persisted atomically to file before exposing plaintext

No BLE, ESP32, or phone required — pure Python, runs standalone on RPi.

Usage:
    python3 test_cipher.py          # run all tests
    python3 test_cipher.py -v       # verbose (show tracebacks on failure)
"""

import os
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from cipher import CipherChannel, ChannelException
from Crypto.Random import get_random_bytes

VERBOSE = '-v' in sys.argv

# ── Minimal test runner ────────────────────────────────────────────────────────

_pass = _fail = 0
_failures: list[str] = []


def run(name: str, fn):
    global _pass, _fail
    try:
        t0 = time.perf_counter()
        fn()
        ms = (time.perf_counter() - t0) * 1000
        print(f"  PASS  {name:<58}  {ms:6.1f} ms")
        _pass += 1
    except Exception as e:
        print(f"  FAIL  {name}")
        print(f"        {e}")
        if VERBOSE:
            traceback.print_exc()
        _fail += 1
        _failures.append(name)


# ── Helpers ────────────────────────────────────────────────────────────────────

_uid = 0


def _pair(tag: str = '') -> tuple[CipherChannel, CipherChannel]:
    global _uid
    _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    ini = CipherChannel.create(key, True,  f'{pfx}_i{tag}')
    res = CipherChannel.create(key, False, f'{pfx}_r{tag}')
    return ini, res


def _nonce(pkt: bytes) -> int:
    return int.from_bytes(pkt[:16], 'little')


# ── Correctness ────────────────────────────────────────────────────────────────

def t01_basic_ini_to_res():
    ini, res = _pair()
    msg = b'hello from initiator'
    got = res.receive(ini.send(msg))
    assert got == msg, f"got {got!r}"

def t02_basic_res_to_ini():
    ini, res = _pair()
    msg = b'hello from responder'
    got = ini.receive(res.send(msg))
    assert got == msg, f"got {got!r}"

def t03_bidirectional_alternating():
    ini, res = _pair()
    for i in range(20):
        msg = f'msg-{i:04d}'.encode()
        if i % 2 == 0:
            assert res.receive(ini.send(msg)) == msg, f"i→r failed at {i}"
        else:
            assert ini.receive(res.send(msg)) == msg, f"r→i failed at {i}"

def t04_large_payload_4096():
    ini, res = _pair()
    msg = get_random_bytes(4096)
    assert res.receive(ini.send(msg)) == msg

def t05_one_byte_payload():
    ini, res = _pair()
    assert res.receive(ini.send(b'\x42')) == b'\x42'

def t06_exact_block_boundary_16():
    ini, res = _pair()
    msg = b'A' * 16
    assert res.receive(ini.send(msg)) == msg

def t07_exactly_block_minus_one_15():
    ini, res = _pair()
    msg = b'B' * 15
    assert res.receive(ini.send(msg)) == msg

def t08_100_sequential_messages():
    ini, res = _pair()
    for i in range(100):
        msg = f'trial-{i:04d}'.encode()
        got = res.receive(ini.send(msg))
        assert got == msg, f"failed at i={i}"

def t09_binary_payload_with_null_bytes():
    ini, res = _pair()
    msg = bytes(range(256))
    assert res.receive(ini.send(msg)) == msg

def t10_all_zeros_payload():
    ini, res = _pair()
    msg = b'\x00' * 64
    assert res.receive(ini.send(msg)) == msg


# ── Security ───────────────────────────────────────────────────────────────────

def t20_replay_attack():
    ini, res = _pair()
    pkt = ini.send(b'once')
    assert res.receive(pkt) == b'once'
    assert res.receive(pkt) is None, "replay must return None"

def t21_wrong_direction_ini_receives_own():
    # Initiator's seq_receive starts odd → sending even nonce must be rejected
    ini, res = _pair()
    pkt = ini.send(b'data')
    assert ini.receive(pkt) is None, "parity check: ini must reject own packet"

def t22_wrong_direction_res_receives_own():
    # Responder's seq_receive starts even → sending odd nonce must be rejected
    ini, res = _pair()
    pkt = res.send(b'data')
    assert res.receive(pkt) is None, "parity check: res must reject own packet"

def t23_tampered_ciphertext():
    ini, res = _pair()
    pkt = bytearray(ini.send(b'integrity'))
    pkt[16] ^= 0xFF          # flip byte in ciphertext (after nonce)
    assert res.receive(bytes(pkt)) is None, "tampered ciphertext must be rejected"

def t24_tampered_tag():
    ini, res = _pair()
    pkt = bytearray(ini.send(b'integrity'))
    pkt[-1] ^= 0x01           # flip last byte of GCM tag
    assert res.receive(bytes(pkt)) is None, "tampered tag must be rejected"

def t25_tampered_nonce():
    ini, res = _pair()
    pkt = bytearray(ini.send(b'integrity'))
    pkt[0] ^= 0x02            # flip bit in nonce → GCM auth fails + counter check
    assert res.receive(bytes(pkt)) is None, "tampered nonce must be rejected"

def t26_out_of_order_stale_after_newer():
    ini, res = _pair()
    pkt_a = ini.send(b'first')    # nonce=2
    pkt_b = ini.send(b'second')   # nonce=4
    assert res.receive(pkt_b) == b'second', "newer packet must be accepted first"
    assert res.receive(pkt_a) is None, "older packet after newer must be rejected"

def t27_future_then_replay():
    ini, res = _pair()
    pkts = [ini.send(f'p{i}'.encode()) for i in range(5)]
    # Deliver last one first → accepted (seq jumps forward)
    assert res.receive(pkts[-1]) is not None
    # Now deliver any earlier one → rejected (too old)
    for p in pkts[:-1]:
        assert res.receive(p) is None, "earlier packet after jump must be rejected"

def t28_wrong_key():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key_a, key_b = get_random_bytes(32), get_random_bytes(32)
    ini = CipherChannel.create(key_a, True,  f'{pfx}_i')
    res = CipherChannel.create(key_b, False, f'{pfx}_r')
    pkt = ini.send(b'secret')
    assert res.receive(pkt) is None, "wrong key must fail GCM auth → None"

def t29_truncated_packet_too_short():
    ini, res = _pair()
    pkt = ini.send(b'data')
    assert res.receive(pkt[:10]) is None, "truncated packet must be rejected"

def t30_empty_packet():
    ini, res = _pair()
    assert res.receive(b'') is None, "empty packet must be rejected"

def t31_non_block_aligned_length():
    ini, res = _pair()
    # nonce(16) + 1 byte ciphertext + tag(16) → ciphertext portion not block-aligned
    pkt = ini.send(b'data')
    fake = pkt[:16] + b'\xAA' + pkt[-16:]   # inject 1-byte ciphertext between nonce and tag
    assert res.receive(fake) is None, "non-block-aligned ciphertext must be rejected"


# ── Counter / parity invariants ────────────────────────────────────────────────

def t40_initiator_nonces_always_even():
    ini, res = _pair()
    for _ in range(20):
        n = _nonce(ini.send(b'x'))
        assert n % 2 == 0, f"initiator emitted odd nonce {n}"

def t41_responder_nonces_always_odd():
    ini, res = _pair()
    for _ in range(20):
        n = _nonce(res.send(b'x'))
        assert n % 2 == 1, f"responder emitted even nonce {n}"

def t42_nonces_strictly_increasing():
    ini, res = _pair()
    prev = 0
    for _ in range(30):
        n = _nonce(ini.send(b'x'))
        assert n > prev, f"nonce not strictly increasing: {n} <= {prev}"
        prev = n

def t43_nonce_increment_exactly_two():
    ini, res = _pair()
    pkts = [ini.send(b'x') for _ in range(10)]
    nonces = [_nonce(p) for p in pkts]
    for i in range(1, len(nonces)):
        diff = nonces[i] - nonces[i-1]
        assert diff == 2, f"expected increment 2, got {diff} (nonces={nonces})"

def t44_first_send_nonce_is_2():
    # Initiator starts at seq_send=0, first send increments to 2
    ini, res = _pair()
    n = _nonce(ini.send(b'x'))
    assert n == 2, f"expected first initiator nonce=2, got {n}"

def t45_first_responder_nonce_is_3():
    # Responder starts at seq_send=1, first send increments to 3
    ini, res = _pair()
    n = _nonce(res.send(b'x'))
    assert n == 3, f"expected first responder nonce=3, got {n}"


# ── Persistence ────────────────────────────────────────────────────────────────

def t50_send_counter_persists_across_reload():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    ini = CipherChannel.create(key, True,  f'{pfx}_i')
    _   = CipherChannel.create(key, False, f'{pfx}_r')

    for _ in range(5):
        ini.send(b'ping')
    last_pkt = ini.send(b'six')
    n_before = _nonce(last_pkt)

    ini2 = CipherChannel.load(f'{pfx}_i')
    next_pkt = ini2.send(b'seven')
    n_after = _nonce(next_pkt)

    assert n_after > n_before, f"counter regressed after reload: {n_before} → {n_after}"
    assert n_after % 2 == 0,   f"parity lost after reload (nonce={n_after})"

def t51_recv_counter_persists_across_reload():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    ini = CipherChannel.create(key, True,  f'{pfx}_i')
    res = CipherChannel.create(key, False, f'{pfx}_r')

    for i in range(5):
        res.receive(ini.send(f'm{i}'.encode()))

    pkt_fresh = ini.send(b'after reload')

    res2 = CipherChannel.load(f'{pfx}_r')
    got = res2.receive(pkt_fresh)
    assert got == b'after reload', f"got {got!r}"

def t52_replay_rejected_after_receiver_reload():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    ini = CipherChannel.create(key, True,  f'{pfx}_i')
    res = CipherChannel.create(key, False, f'{pfx}_r')
    pkt = ini.send(b'old')
    res.receive(pkt)

    res2 = CipherChannel.load(f'{pfx}_r')
    assert res2.receive(pkt) is None, "replay must be rejected even after reload"

def t53_state_file_is_valid_after_write():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    ini = CipherChannel.create(key, True, f'{pfx}_i')
    for _ in range(10):
        ini.send(b'x')
    # File must be loadable without error
    ini2 = CipherChannel.load(f'{pfx}_i')
    assert ini2 is not None

def t54_corrupted_state_file_raises():
    path = f'/tmp/_cc_{os.getpid()}_corrupt'
    with open(path, 'wb') as f:
        f.write(b'\x00' * 8)
    try:
        CipherChannel.load(path)
        raise AssertionError("expected ChannelException, got none")
    except ChannelException:
        pass

def t55_truncated_state_file_raises():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    CipherChannel.create(key, True, pfx)
    with open(pfx, 'r+b') as f:
        f.truncate(4)
    try:
        CipherChannel.load(pfx)
        raise AssertionError("expected ChannelException, got none")
    except ChannelException:
        pass

def t56_key_survives_reload():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    ini  = CipherChannel.create(key, True,  f'{pfx}_i')
    res  = CipherChannel.create(key, False, f'{pfx}_r')
    ini.send(b'warmup'); res.receive(ini.send(b'warmup'))

    # reload both and exchange a message
    ini2 = CipherChannel.load(f'{pfx}_i')
    res2 = CipherChannel.load(f'{pfx}_r')
    msg = b'post-reload message'
    assert res2.receive(ini2.send(msg)) == msg


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f"CipherChannel test suite — counter-nonce AES-256-GCM\n")

    print("Correctness")
    run("T01 initiator→responder basic round-trip",         t01_basic_ini_to_res)
    run("T02 responder→initiator basic round-trip",         t02_basic_res_to_ini)
    run("T03 bidirectional alternating (20 msgs)",          t03_bidirectional_alternating)
    run("T04 large payload (4096 B)",                       t04_large_payload_4096)
    run("T05 one-byte payload",                             t05_one_byte_payload)
    run("T06 exact block-boundary payload (16 B)",          t06_exact_block_boundary_16)
    run("T07 payload one byte under block boundary (15 B)", t07_exactly_block_minus_one_15)
    run("T08 100 sequential messages same direction",       t08_100_sequential_messages)
    run("T09 binary payload with null bytes (0x00–0xFF)",   t09_binary_payload_with_null_bytes)
    run("T10 all-zeros payload",                            t10_all_zeros_payload)

    print("\nSecurity")
    run("T20 replay attack → None",                         t20_replay_attack)
    run("T21 initiator receives own packet → None",         t21_wrong_direction_ini_receives_own)
    run("T22 responder receives own packet → None",         t22_wrong_direction_res_receives_own)
    run("T23 tampered ciphertext byte → None",              t23_tampered_ciphertext)
    run("T24 tampered GCM tag byte → None",                 t24_tampered_tag)
    run("T25 tampered nonce byte → None",                   t25_tampered_nonce)
    run("T26 stale packet after newer → None",              t26_out_of_order_stale_after_newer)
    run("T27 all earlier packets after seq-jump → None",    t27_future_then_replay)
    run("T28 wrong key → None",                             t28_wrong_key)
    run("T29 truncated packet (10 B) → None",               t29_truncated_packet_too_short)
    run("T30 empty packet → None",                          t30_empty_packet)
    run("T31 non-block-aligned ciphertext length → None",   t31_non_block_aligned_length)

    print("\nCounter / parity invariants")
    run("T40 initiator nonces always even",                 t40_initiator_nonces_always_even)
    run("T41 responder nonces always odd",                  t41_responder_nonces_always_odd)
    run("T42 nonces strictly increasing per direction",     t42_nonces_strictly_increasing)
    run("T43 nonce increment is exactly 2",                 t43_nonce_increment_exactly_two)
    run("T44 first initiator nonce = 2",                    t44_first_send_nonce_is_2)
    run("T45 first responder nonce = 3",                    t45_first_responder_nonce_is_3)

    print("\nPersistence")
    run("T50 send counter survives reload",                 t50_send_counter_persists_across_reload)
    run("T51 recv counter survives reload",                 t51_recv_counter_persists_across_reload)
    run("T52 replay rejected after receiver reload",        t52_replay_rejected_after_receiver_reload)
    run("T53 state file is loadable after write",           t53_state_file_is_valid_after_write)
    run("T54 corrupted state file → ChannelException",      t54_corrupted_state_file_raises)
    run("T55 truncated state file → ChannelException",      t55_truncated_state_file_raises)
    run("T56 key survives reload — can still exchange",     t56_key_survives_reload)

    total = _pass + _fail
    print(f"\n{'─' * 72}")
    print(f"Result: {_pass}/{total} passed" + (f"   ({_fail} FAILED)" if _fail else "   — all passed"))
    for name in _failures:
        print(f"  FAIL: {name}")
    sys.exit(0 if _fail == 0 else 1)
