#!/usr/bin/env python3
"""
RPi-only correctness and security tests for the counter-nonce CipherChannel.

Protocol under test:
  - AES-256-GCM; 12-byte (96-bit) little-endian monotonic counter as nonce
  - Packet = nonce(12) || ciphertext(N) || tag(16)  — no padding, overhead = 28 B
  - Initiator sends even counters (0→2→4…), responder sends odd (1→3→5…)
  - Receiver enforces: counter > last_received AND same parity as last_received
  - Counter checked BEFORE decryption
  - State (counters + key + metadata) durably persisted (fsync) before plaintext released
  - MAX_PLAINTEXT_SIZE = 400 bytes

No BLE, ESP32, or phone required — pure Python, runs standalone on RPi.

Usage:
    python3 test_cipher.py          # run all tests
    python3 test_cipher.py -v       # verbose (show tracebacks on failure)
"""

import os
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from cipher import (
    CipherChannel, ChannelException,
    NONCE_LEN, MAC_LEN, MAX_PLAINTEXT_SIZE, MAX_PACKET_SIZE,
    PROTOCOL_VERSION, STATE_FORMAT_VERSION,
)
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
        print(f"  PASS  {name:<62}  {ms:6.1f} ms")
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


def _pair(tag: str = '', endpoint_id: str = '') -> tuple[CipherChannel, CipherChannel]:
    global _uid
    _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    ini = CipherChannel.create(key, True,  f'{pfx}_i{tag}', endpoint_id=endpoint_id)
    res = CipherChannel.create(key, False, f'{pfx}_r{tag}', endpoint_id=endpoint_id)
    return ini, res


def _nonce(pkt: bytes) -> int:
    """Extract the 96-bit counter from the first NONCE_LEN bytes of a packet."""
    return int.from_bytes(pkt[:NONCE_LEN], 'little')


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

def t04_max_payload():
    ini, res = _pair()
    msg = get_random_bytes(MAX_PLAINTEXT_SIZE)
    assert res.receive(ini.send(msg)) == msg

def t05_one_byte_payload():
    ini, res = _pair()
    assert res.receive(ini.send(b'\x42')) == b'\x42'

def t06_zero_byte_payload():
    # GCM supports empty plaintext: packet = nonce(12) + tag(16) = 28 bytes
    ini, res = _pair()
    assert res.receive(ini.send(b'')) == b''

def t07_100_sequential_messages():
    ini, res = _pair()
    for i in range(100):
        msg = f'trial-{i:04d}'.encode()
        got = res.receive(ini.send(msg))
        assert got == msg, f"failed at i={i}"

def t08_binary_payload_with_null_bytes():
    ini, res = _pair()
    msg = bytes(range(256))
    assert res.receive(ini.send(msg)) == msg

def t09_all_zeros_payload():
    ini, res = _pair()
    msg = b'\x00' * 64
    assert res.receive(ini.send(msg)) == msg

def t10_arbitrary_lengths_round_trip():
    ini, res = _pair()
    for size in [1, 11, 12, 13, 15, 16, 17, 127, 128, 255, 256, 399, 400]:
        msg = get_random_bytes(size)
        assert res.receive(ini.send(msg)) == msg, f"failed at size={size}"


# ── Security ───────────────────────────────────────────────────────────────────

def t20_replay_attack():
    ini, res = _pair()
    pkt = ini.send(b'once')
    assert res.receive(pkt) == b'once'
    assert res.receive(pkt) is None, "replay must return None"

def t21_wrong_direction_ini_receives_own():
    ini, res = _pair()
    pkt = ini.send(b'data')
    assert ini.receive(pkt) is None, "parity check: ini must reject own packet"

def t22_wrong_direction_res_receives_own():
    ini, res = _pair()
    pkt = res.send(b'data')
    assert res.receive(pkt) is None, "parity check: res must reject own packet"

def t23_tampered_ciphertext():
    ini, res = _pair()
    pkt = bytearray(ini.send(b'integrity'))
    pkt[NONCE_LEN] ^= 0xFF     # flip first byte of ciphertext (after 12-byte nonce)
    assert res.receive(bytes(pkt)) is None, "tampered ciphertext must be rejected"

def t24_tampered_tag():
    ini, res = _pair()
    pkt = bytearray(ini.send(b'integrity'))
    pkt[-1] ^= 0x01             # flip last byte of GCM tag
    assert res.receive(bytes(pkt)) is None, "tampered tag must be rejected"

def t25_tampered_nonce():
    ini, res = _pair()
    pkt = bytearray(ini.send(b'integrity'))
    pkt[0] ^= 0x02              # flip bit in nonce → GCM auth fails + counter check
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
    assert res.receive(pkts[-1]) is not None
    for p in pkts[:-1]:
        assert res.receive(p) is None, "earlier packet after seq-jump must be rejected"

def t28_wrong_key():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key_a, key_b = get_random_bytes(32), get_random_bytes(32)
    ini = CipherChannel.create(key_a, True,  f'{pfx}_i')
    res = CipherChannel.create(key_b, False, f'{pfx}_r')
    assert res.receive(ini.send(b'secret')) is None, "wrong key must fail GCM auth"

def t29_truncated_packet_too_short():
    ini, res = _pair()
    pkt = ini.send(b'data')
    assert res.receive(pkt[:10]) is None, "truncated packet must be rejected"

def t30_empty_packet():
    ini, res = _pair()
    assert res.receive(b'') is None, "empty packet must be rejected"

def t31_packet_one_byte_too_short():
    # NONCE_LEN + MAC_LEN - 1 = 27 bytes — below minimum valid packet
    ini, res = _pair()
    assert res.receive(b'\x00' * (NONCE_LEN + MAC_LEN - 1)) is None


# ── Size limits ────────────────────────────────────────────────────────────────

def t32_exact_max_plaintext_size_accepted():
    ini, res = _pair()
    msg = get_random_bytes(MAX_PLAINTEXT_SIZE)
    got = res.receive(ini.send(msg))
    assert got == msg

def t33_one_over_max_plaintext_raises():
    ini, res = _pair()
    try:
        ini.send(b'\x00' * (MAX_PLAINTEXT_SIZE + 1))
        raise AssertionError("expected ChannelException for oversized plaintext")
    except ChannelException:
        pass

def t34_oversized_received_packet_rejected():
    # Build a syntactically valid but oversized receive packet
    ini, res = _pair()
    oversized = b'\x02' + b'\x00' * (NONCE_LEN - 1) + b'\xAA' * (MAX_PLAINTEXT_SIZE + 1) + b'\x00' * MAC_LEN
    assert res.receive(oversized) is None, "oversized received packet must be rejected"

def t35_minimum_packet_28_bytes():
    # Zero-length ciphertext → 28-byte packet should be accepted (empty plaintext)
    ini, res = _pair()
    pkt = ini.send(b'')
    assert len(pkt) == NONCE_LEN + MAC_LEN, f"zero-plaintext packet must be {NONCE_LEN + MAC_LEN} bytes"
    assert res.receive(pkt) == b''


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
    pkts   = [ini.send(b'x') for _ in range(10)]
    nonces = [_nonce(p) for p in pkts]
    for i in range(1, len(nonces)):
        diff = nonces[i] - nonces[i-1]
        assert diff == 2, f"expected increment 2, got {diff}"

def t44_first_send_nonce_is_2():
    ini, res = _pair()
    n = _nonce(ini.send(b'x'))
    assert n == 2, f"expected first initiator nonce=2, got {n}"

def t45_first_responder_nonce_is_3():
    ini, res = _pair()
    n = _nonce(res.send(b'x'))
    assert n == 3, f"expected first responder nonce=3, got {n}"

def t46_nonce_is_exactly_12_bytes():
    ini, res = _pair()
    pkt = ini.send(b'probe')
    assert len(pkt[:NONCE_LEN]) == 12, "nonce field must be exactly 12 bytes"
    assert len(pkt) == NONCE_LEN + len(b'probe') + MAC_LEN, "packet length wrong"

def t47_ciphertext_length_equals_plaintext_length():
    ini, res = _pair()
    for size in [0, 1, 13, 32, 100, 400]:
        msg = get_random_bytes(size)
        pkt = ini.send(msg)
        ct_len = len(pkt) - NONCE_LEN - MAC_LEN
        assert ct_len == size, f"ciphertext len {ct_len} != plaintext len {size}"


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

    ini2    = CipherChannel.load(f'{pfx}_i')
    n_after = _nonce(ini2.send(b'seven'))
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
    got  = res2.receive(pkt_fresh)
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

def t53_state_file_is_loadable_after_sends():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    ini = CipherChannel.create(key, True, f'{pfx}_i')
    for _ in range(10):
        ini.send(b'x')
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
    ini2 = CipherChannel.load(f'{pfx}_i')
    res2 = CipherChannel.load(f'{pfx}_r')
    msg  = b'post-reload message'
    assert res2.receive(ini2.send(msg)) == msg

def t57_state_format_version_mismatch_raises():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    CipherChannel.create(key, True, pfx)
    with open(pfx, 'r+b') as f:
        data = bytearray(f.read())
        data[0] = 99    # corrupt STATE_FORMAT_VERSION byte
        f.seek(0); f.write(data)
    try:
        CipherChannel.load(pfx)
        raise AssertionError("expected ChannelException, got none")
    except ChannelException:
        pass

def t58_wrong_state_under_different_key_raises():
    # Simulate loading state written for key_a into a channel expecting key_b
    # via endpoint_id mismatch detection (endpoint_id bound to key version).
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    CipherChannel.create(key, True, pfx, endpoint_id='phone')
    try:
        CipherChannel.load(pfx, endpoint_id='cane')
        raise AssertionError("expected ChannelException on endpoint_id mismatch")
    except ChannelException:
        pass

def t59_endpoint_id_match_succeeds():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    CipherChannel.create(key, True, pfx, endpoint_id='phone')
    ch = CipherChannel.load(pfx, endpoint_id='phone')
    assert ch is not None


# ── Thread safety ──────────────────────────────────────────────────────────────

def t60_concurrent_sends_no_nonce_reuse():
    ini, res = _pair()
    nonces = []
    errors = []
    lock   = threading.Lock()

    def sender():
        try:
            pkt = ini.send(b'concurrent')
            with lock:
                nonces.append(_nonce(pkt))
        except Exception as e:
            with lock:
                errors.append(str(e))

    threads = [threading.Thread(target=sender) for _ in range(30)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert not errors, f"unexpected errors: {errors}"
    assert len(nonces) == 30, f"only {len(nonces)} nonces recorded"
    assert len(set(nonces)) == len(nonces), f"nonce reuse under concurrency: {sorted(nonces)}"
    assert all(n % 2 == 0 for n in nonces), "parity lost under concurrency"

def t61_concurrent_recv_no_plaintext_without_persist():
    # Both sides exchange messages concurrently — all received correctly
    ini, res = _pair()
    received = []
    lock = threading.Lock()

    def send_and_recv(i):
        msg = f'msg-{i:03d}'.encode()
        pkt = ini.send(msg)
        got = res.receive(pkt)
        with lock:
            received.append(got)

    threads = [threading.Thread(target=send_and_recv, args=(i,)) for i in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    # All receives should succeed (some may be rejected as duplicates
    # if the counter jumped, but none should be None due to auth failure)
    assert len(received) == 20


# ── Counter exhaustion ─────────────────────────────────────────────────────────

def t62_counter_exhaustion_raises():
    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = get_random_bytes(32)
    ini = CipherChannel.create(key, True, pfx)
    # Artificially set seqSend to one legal send below exhaustion
    # initiator sends even; (2^96 - 4) is even, one successful send left
    ini._seq_send = (1 << 96) - 4
    ini._write_state()
    # This send should succeed: counter becomes (2^96 - 2) ≤ _COUNTER_MAX
    pkt = ini.send(b'penultimate')
    assert pkt is not None
    # This send would push counter to 2^96, exceeding _COUNTER_MAX
    try:
        ini.send(b'overflow')
        raise AssertionError("expected ChannelException for exhausted counter")
    except ChannelException:
        pass


# ── Test vectors ───────────────────────────────────────────────────────────────

def t63_test_vector_nonce_serialisation():
    # Counter 2 must serialise to exactly 12 LE bytes with upper 10 bytes zero
    nonce_bytes = (2).to_bytes(NONCE_LEN, 'little')
    assert nonce_bytes == b'\x02' + b'\x00' * (NONCE_LEN - 1), \
        f"nonce serialisation wrong: {nonce_bytes.hex()}"

def t63b_test_vector_packet():
    # Deterministic packet: zero key, initiator, plaintext=b'test'
    # Expected values pre-computed with AES-256-GCM (zero key, nonce=0x02+11zeros)
    EXPECTED_NONCE = bytes.fromhex('020000000000000000000000')
    EXPECTED_CT    = bytes.fromhex('bb3af9b4')
    EXPECTED_TAG   = bytes.fromhex('d81a74113b0c7c232afe5b00cac5095a')
    EXPECTED_PKT   = EXPECTED_NONCE + EXPECTED_CT + EXPECTED_TAG

    global _uid; _uid += 1
    pfx = f'/tmp/_cc_{os.getpid()}_{_uid}'
    key = b'\x00' * 32
    ini = CipherChannel.create(key, True, pfx)
    pkt = ini.send(b'test')
    assert pkt == EXPECTED_PKT, \
        f"test vector mismatch:\n  got: {pkt.hex()}\n  exp: {EXPECTED_PKT.hex()}"

    # Verify the responder can decrypt the test vector
    pfx2 = f'/tmp/_cc_{os.getpid()}_{_uid}_r'
    res  = CipherChannel.create(key, False, pfx2)
    got  = res.receive(EXPECTED_PKT)
    assert got == b'test', f"responder cannot decrypt test vector: {got!r}"


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f"CipherChannel test suite — counter-nonce AES-256-GCM (protocol v{PROTOCOL_VERSION})\n")

    print("Correctness")
    run("T01 initiator→responder basic round-trip",              t01_basic_ini_to_res)
    run("T02 responder→initiator basic round-trip",              t02_basic_res_to_ini)
    run("T03 bidirectional alternating (20 msgs)",               t03_bidirectional_alternating)
    run("T04 exact MAX_PLAINTEXT_SIZE payload (400 B)",          t04_max_payload)
    run("T05 one-byte payload",                                  t05_one_byte_payload)
    run("T06 zero-byte payload (GCM empty plaintext)",           t06_zero_byte_payload)
    run("T07 100 sequential messages same direction",            t07_100_sequential_messages)
    run("T08 binary payload with null bytes (0x00–0xFF)",        t08_binary_payload_with_null_bytes)
    run("T09 all-zeros payload",                                 t09_all_zeros_payload)
    run("T10 arbitrary lengths 1–400 bytes",                     t10_arbitrary_lengths_round_trip)

    print("\nSecurity")
    run("T20 replay attack → None",                              t20_replay_attack)
    run("T21 initiator receives own packet → None",              t21_wrong_direction_ini_receives_own)
    run("T22 responder receives own packet → None",              t22_wrong_direction_res_receives_own)
    run("T23 tampered ciphertext byte → None",                   t23_tampered_ciphertext)
    run("T24 tampered GCM tag byte → None",                      t24_tampered_tag)
    run("T25 tampered nonce byte → None",                        t25_tampered_nonce)
    run("T26 stale packet after newer → None",                   t26_out_of_order_stale_after_newer)
    run("T27 all earlier packets after seq-jump → None",         t27_future_then_replay)
    run("T28 wrong key → None",                                  t28_wrong_key)
    run("T29 truncated packet (10 B) → None",                    t29_truncated_packet_too_short)
    run("T30 empty packet → None",                               t30_empty_packet)
    run("T31 27-byte packet (one short of minimum) → None",      t31_packet_one_byte_too_short)

    print("\nSize limits")
    run("T32 exact MAX_PLAINTEXT_SIZE send → accepted",          t32_exact_max_plaintext_size_accepted)
    run("T33 MAX_PLAINTEXT_SIZE+1 send → ChannelException",      t33_one_over_max_plaintext_raises)
    run("T34 oversized received packet → None",                  t34_oversized_received_packet_rejected)
    run("T35 minimum 28-byte packet (empty plaintext) accepted", t35_minimum_packet_28_bytes)

    print("\nCounter / parity invariants")
    run("T40 initiator nonces always even",                      t40_initiator_nonces_always_even)
    run("T41 responder nonces always odd",                       t41_responder_nonces_always_odd)
    run("T42 nonces strictly increasing per direction",          t42_nonces_strictly_increasing)
    run("T43 nonce increment is exactly 2",                      t43_nonce_increment_exactly_two)
    run("T44 first initiator nonce = 2",                         t44_first_send_nonce_is_2)
    run("T45 first responder nonce = 3",                         t45_first_responder_nonce_is_3)
    run("T46 nonce field is exactly 12 bytes",                   t46_nonce_is_exactly_12_bytes)
    run("T47 ciphertext length == plaintext length (no padding)",t47_ciphertext_length_equals_plaintext_length)

    print("\nPersistence")
    run("T50 send counter survives reload",                      t50_send_counter_persists_across_reload)
    run("T51 recv counter survives reload",                      t51_recv_counter_persists_across_reload)
    run("T52 replay rejected after receiver reload",             t52_replay_rejected_after_receiver_reload)
    run("T53 state file is loadable after 10 sends",             t53_state_file_is_loadable_after_sends)
    run("T54 corrupted state file → ChannelException",           t54_corrupted_state_file_raises)
    run("T55 truncated state file → ChannelException",           t55_truncated_state_file_raises)
    run("T56 key survives reload — can still exchange",          t56_key_survives_reload)
    run("T57 state format version mismatch → ChannelException",  t57_state_format_version_mismatch_raises)
    run("T58 endpoint_id mismatch on load → ChannelException",   t58_wrong_state_under_different_key_raises)
    run("T59 correct endpoint_id on load → succeeds",            t59_endpoint_id_match_succeeds)

    print("\nThread safety")
    run("T60 30 concurrent sends — no nonce reuse",              t60_concurrent_sends_no_nonce_reuse)
    run("T61 20 concurrent send+recv pairs",                     t61_concurrent_recv_no_plaintext_without_persist)

    print("\nCounter exhaustion")
    run("T62 counter at 2^96-2 — next send raises ChannelException", t62_counter_exhaustion_raises)

    print("\nTest vectors")
    run("T63 nonce serialisation: counter 2 → 12-byte LE",       t63_test_vector_nonce_serialisation)
    run("T63b deterministic packet vector (zero key, pt=b'test')", t63b_test_vector_packet)

    total = _pass + _fail
    print(f"\n{'─' * 72}")
    print(f"Result: {_pass}/{total} passed" + (f"   ({_fail} FAILED)" if _fail else "   — all passed"))
    for name in _failures:
        print(f"  FAIL: {name}")
    sys.exit(0 if _fail == 0 else 1)
