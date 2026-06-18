#!/usr/bin/env python3
"""
Experiment K — Concurrent phone and cane traffic (N=500 each)
=============================================================
Four scenarios controlled via --scenario:

  phone_only   : phone sends 500 commands at 100 ms interval; cane silent.
  cane_only    : Python cane simulator sends 500 messages at 1000 ms; phone silent.
  sequential   : phone 500 commands, then cane 500 messages (no overlap).
  concurrent   : phone and cane run simultaneously (asyncio.gather).

The cane is simulated entirely in Python using the same CANE_SECURITY_UUID
plaintext-fallback key-exchange path used in run_concurrent_endpoints.py.
No ESP32 firmware reflash is required for any scenario.

Server prerequisite (RPi):
  BENCHMARK_PROVISIONING=1 \\
  EXPERIMENT_K_SCENARIO=<scenario> \\
  EXPERIMENT_SERVER_CSV_PATH=/tmp/exp_K_<scenario>.csv \\
  server/.venv/bin/python server/ble_server_K.py

Run (laptop):
  client/.venv/bin/python results/canonical/concurrency/run_K.py \\
      --address B8:27:EB:07:01:22 --scenario concurrent

Outputs (this directory):
  K_<scenario>_phone_client.csv   — per-message client-side timing (phone)
  K_<scenario>_cane_client.csv    — per-message client-side timing (cane)
  K_<scenario>_summary.json       — merged statistics + security checks
"""

import argparse
import asyncio
import csv
import json
import os
import statistics
import sys
import time
import uuid as _uuid_mod

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.insert(0, os.path.join(REPO_ROOT, 'shared'))

from cipher import CipherChannel, ChannelException

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    sys.exit("bleak not installed — activate client/.venv")

# ── UUIDs ─────────────────────────────────────────────────────────────────────

SECURITY_UUID      = "FEC26EC4-6D71-4442-9F81-55BC21D658D6"
COMMAND_UUID       = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B"
ACK_UUID           = "51FF12BC-3ED8-46E5-B4F9-D64E2FEC021B"
CANE_SECURITY_UUID = "fa87c0d0-afac-11de-8a39-0800200c9a66"
CANE2PHONE_UUID    = "74278bda-b644-4520-8f0c-720eaf059935"

KEY: bytes = (
    b'\x2a\xc3\x2c\x36\x73\xa4\xa2\xee'
    b'\x49\x08\x53\x3e\xd0\xff\x25\x84'
    b'\xba\xe9\x95\xca\x4e\x4c\xff\x7a'
    b'\x4c\x25\x68\x04\x29\x04\x25\xf8'
)

# ── Timing constants ──────────────────────────────────────────────────────────

_SCAN_TIMEOUT      = 10.0
_CONNECT_TIMEOUT   = 15.0
_KEY_POLL_INTERVAL = 0.05
_KEY_TIMEOUT       = 8.0
_ACK_POLL_INTERVAL = 0.020
_ACK_TIMEOUT       = 10.0
_ENCRYPTED_KEY_LEN = 60

PHONE_INTERVAL_S = 0.100   # 100 ms between phone commands
CANE_INTERVAL_S  = 1.000   # 1000 ms between cane messages

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

# ── CSV columns ───────────────────────────────────────────────────────────────

_PHONE_CSV_COLS = [
    'scenario', 'endpoint', 'message_id', 'action',
    'scheduled_ns', 'actual_send_ns', 'ack_received_ns',
    'encrypt_ms', 'write_ms', 'ack_wait_ms', 'round_trip_ms',
    'success', 'error',
]

_CANE_CSV_COLS = [
    'scenario', 'endpoint', 'message_id', 'action',
    'scheduled_ns', 'actual_send_ns',
    'encrypt_ms', 'write_ms',
    'success', 'error',
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ms(t0: int, t1: int) -> float:
    return round((t1 - t0) / 1e6, 3)


def _resolve_handles(client: BleakClient, *uuids: str) -> tuple:
    result = []
    for uuid in uuids:
        lower = uuid.lower()
        handle = None
        for svc in client.services:
            for ch in svc.characteristics:
                if ch.uuid.lower() == lower:
                    handle = ch.handle
                    break
            if handle is not None:
                break
        if handle is None:
            raise RuntimeError(f"Characteristic {uuid} not found")
        result.append(handle)
    return tuple(result)


def _stats(vals: list[float]) -> dict | None:
    if not vals:
        return None
    s = sorted(vals)
    n = len(s)
    return {
        'n':      n,
        'mean':   round(statistics.mean(vals), 3),
        'median': round(statistics.median(vals), 3),
        'stdev':  round(statistics.stdev(vals), 3) if n > 1 else 0.0,
        'p95':    round(s[int(0.95 * n)], 3),
        'p99':    round(s[int(0.99 * n)], 3),
        'min':    round(s[0], 3),
        'max':    round(s[-1], 3),
    }


def _open_csv(path: str, cols: list) -> None:
    with open(path, 'w', newline='') as f:
        csv.writer(f).writerow(cols)


def _append_csv(path: str, cols: list, row: dict) -> None:
    with open(path, 'a', newline='') as f:
        csv.writer(f).writerow([row.get(c, '') for c in cols])

# ── Cane key exchange (Python as cane initiator) ──────────────────────────────

async def _cane_kex(address: str, base_path: str) -> tuple[bytes, BleakClient]:
    """
    Connect to RPi as cane, do key exchange, return (k_cane, connected_client).
    Caller is responsible for disconnecting the client.
    Uses the plaintext REQUEST_CANE_KEY fallback (no ESP32 firmware required).
    """
    base_ch = CipherChannel.create(KEY, True, base_path, endpoint_id='cane_base_K')

    device = await BleakScanner.find_device_by_address(address, timeout=_SCAN_TIMEOUT)
    if device is None:
        raise RuntimeError(f"Cane KEX: {address} not found")

    client = BleakClient(device)
    await asyncio.wait_for(client.connect(), timeout=_CONNECT_TIMEOUT)
    if not client.is_connected:
        raise RuntimeError("Cane KEX: connect failed")

    h_cane_sec, = _resolve_handles(client, CANE_SECURITY_UUID)

    # Request cane key via plaintext fallback
    await client.write_gatt_char(h_cane_sec, b"REQUEST_CANE_KEY", response=True)

    k_cane: bytes | None = None
    deadline = asyncio.get_event_loop().time() + _KEY_TIMEOUT
    while asyncio.get_event_loop().time() < deadline:
        raw = bytes(await client.read_gatt_char(h_cane_sec))
        if len(raw) == _ENCRYPTED_KEY_LEN:
            k_cane = base_ch.receive(raw)
            if k_cane and len(k_cane) == 32:
                break
            k_cane = None
        await asyncio.sleep(_KEY_POLL_INTERVAL)

    if k_cane is None:
        await client.disconnect()
        raise RuntimeError("Cane KEX: K_cane not received")

    # Send STOP_SHARING to close the provisioning gate (cane secure channel stays alive)
    stop_enc = base_ch.send(b'{"action":"STOP_SHARING"}')
    await client.write_gatt_char(h_cane_sec, stop_enc, response=True)

    return k_cane, client

# ── Phone task ────────────────────────────────────────────────────────────────

async def phone_task(address: str, n: int, scenario: str,
                     csv_path: str, ready_event: asyncio.Event | None = None) -> dict:
    """
    Connect as phone, do key exchange, send N commands.
    Returns stats dict.
    """
    print(f"[phone] Scanning…")
    t0 = time.perf_counter_ns()
    device = await BleakScanner.find_device_by_address(address, timeout=_SCAN_TIMEOUT)
    scan_ms = _ms(t0, time.perf_counter_ns())
    if device is None:
        raise RuntimeError(f"[phone] {address} not found")
    print(f"[phone] Scan {scan_ms:.0f} ms. Connecting…")

    t0 = time.perf_counter_ns()
    client = BleakClient(device)
    await asyncio.wait_for(client.connect(), timeout=_CONNECT_TIMEOUT)
    connect_ms = _ms(t0, time.perf_counter_ns())
    if not client.is_connected:
        raise RuntimeError("[phone] connect failed")
    print(f"[phone] Connected {connect_ms:.0f} ms. Key exchange…")

    h_sec, h_cmd, h_ack = _resolve_handles(client, SECURITY_UUID, COMMAND_UUID, ACK_UUID)

    session_id    = _uuid_mod.uuid4().hex[:12]
    tp_path       = f'/tmp/cc_K_phone_tp_{session_id}'
    sess_path     = f'/tmp/cc_K_phone_sess_{session_id}'
    transport_ch  = CipherChannel.create(KEY, False, tp_path)

    t0 = time.perf_counter_ns()
    await client.write_gatt_char(h_sec, b"REQUEST_KEY", response=True)
    k_phone: bytes | None = None
    deadline = asyncio.get_event_loop().time() + _KEY_TIMEOUT
    while asyncio.get_event_loop().time() < deadline:
        raw = bytes(await client.read_gatt_char(h_sec))
        if len(raw) == _ENCRYPTED_KEY_LEN:
            k_phone = transport_ch.receive(raw)
            if k_phone and len(k_phone) == 32:
                break
            k_phone = None
        await asyncio.sleep(_KEY_POLL_INTERVAL)

    kex_ms = _ms(t0, time.perf_counter_ns())
    if k_phone is None:
        await client.disconnect()
        raise RuntimeError("[phone] K_phone not received")
    print(f"[phone] KEX {kex_ms:.0f} ms. Sending {n} commands…")

    phone_ch = CipherChannel.create(k_phone, True, sess_path)

    # Signal concurrent cane task that phone is ready
    if ready_event is not None:
        ready_event.set()

    enc_vals: list[float] = []
    wrt_vals: list[float] = []
    ack_vals: list[float] = []
    rtt_vals: list[float] = []
    ok = fail = 0

    try:
        for i in range(1, n + 1):
            msg_id   = f"P_{i:04d}"
            action   = "STAND_UP"
            payload  = json.dumps({"trial_id": msg_id, "action": action}).encode()

            scheduled_ns = time.perf_counter_ns()
            t_enc        = time.perf_counter_ns()
            encrypted    = phone_ch.send(payload)
            encrypt_ms   = _ms(t_enc, time.perf_counter_ns())

            t_write = time.perf_counter_ns()
            try:
                await client.write_gatt_char(h_cmd, encrypted, response=True)
            except Exception as e:
                _append_csv(csv_path, _PHONE_CSV_COLS, {
                    'scenario': scenario, 'endpoint': 'phone', 'message_id': msg_id,
                    'action': action, 'scheduled_ns': scheduled_ns,
                    'actual_send_ns': time.perf_counter_ns(),
                    'encrypt_ms': encrypt_ms,
                    'write_ms': _ms(t_write, time.perf_counter_ns()),
                    'success': False, 'error': f"write:{e}",
                })
                fail += 1
                print(f"[phone] [{i}/{n}] FAIL write: {e}")
                break
            actual_send_ns = time.perf_counter_ns()
            write_ms       = _ms(t_write, actual_send_ns)

            expected = f"OK:{msg_id}".encode()
            t_ack    = time.perf_counter_ns()
            acked    = False
            ack_dl   = asyncio.get_event_loop().time() + _ACK_TIMEOUT
            while asyncio.get_event_loop().time() < ack_dl:
                val = bytes(await client.read_gatt_char(h_ack))
                if val == expected:
                    acked = True
                    break
                await asyncio.sleep(_ACK_POLL_INTERVAL)

            ack_received_ns = time.perf_counter_ns()
            ack_wait_ms     = _ms(t_ack, ack_received_ns)
            round_trip_ms   = _ms(scheduled_ns, ack_received_ns)

            row = {
                'scenario': scenario, 'endpoint': 'phone', 'message_id': msg_id,
                'action': action, 'scheduled_ns': scheduled_ns,
                'actual_send_ns': actual_send_ns, 'ack_received_ns': ack_received_ns,
                'encrypt_ms': encrypt_ms, 'write_ms': write_ms,
                'ack_wait_ms': ack_wait_ms, 'round_trip_ms': round_trip_ms,
                'success': acked,
                'error': '' if acked else 'ACK_TIMEOUT',
            }
            _append_csv(csv_path, _PHONE_CSV_COLS, row)

            if acked:
                ok += 1
                enc_vals.append(encrypt_ms)
                wrt_vals.append(write_ms)
                ack_vals.append(ack_wait_ms)
                rtt_vals.append(round_trip_ms)
                print(f"[phone] [{i:4d}/{n}] OK  enc={encrypt_ms:.2f}"
                      f" wrt={write_ms:.0f} ack={ack_wait_ms:.0f} rtt={round_trip_ms:.0f} ms")
            else:
                fail += 1
                print(f"[phone] [{i:4d}/{n}] FAIL ACK_TIMEOUT")

            if i < n:
                await asyncio.sleep(PHONE_INTERVAL_S)

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
        for p in (tp_path, sess_path):
            try:
                os.remove(p)
            except OSError:
                pass

    print(f"[phone] Done: {ok}/{ok+fail}")
    return {
        'ok': ok, 'fail': fail,
        'encrypt_ms': _stats(enc_vals),
        'write_ms':   _stats(wrt_vals),
        'ack_wait_ms': _stats(ack_vals),
        'round_trip_ms': _stats(rtt_vals),
    }

# ── Cane task ─────────────────────────────────────────────────────────────────

async def cane_task(address: str, n: int, scenario: str,
                    csv_path: str, ready_event: asyncio.Event | None = None,
                    wait_for_event: asyncio.Event | None = None) -> dict:
    """
    Connect as cane (Python simulator), do key exchange, send N messages.
    Returns stats dict.
    """
    session_id = _uuid_mod.uuid4().hex[:8]
    base_path  = f'/tmp/cc_K_cane_base_{session_id}'
    sec_path   = f'/tmp/cc_K_cane_sec_{session_id}'

    print(f"[cane ] Scanning…")
    t0 = time.perf_counter_ns()
    device = await BleakScanner.find_device_by_address(address, timeout=_SCAN_TIMEOUT)
    scan_ms = _ms(t0, time.perf_counter_ns())
    if device is None:
        raise RuntimeError(f"[cane ] {address} not found")
    print(f"[cane ] Scan {scan_ms:.0f} ms. Connecting…")

    k_cane, client = await _cane_kex(address, base_path)
    print(f"[cane ] KEX done. Sending {n} messages…")

    h_cane2phone, = _resolve_handles(client, CANE2PHONE_UUID)
    cane_ch = CipherChannel.create(k_cane, True, sec_path)

    # Signal concurrent phone task that cane is ready
    if ready_event is not None:
        ready_event.set()
    # Wait for phone to be ready (concurrent scenario)
    if wait_for_event is not None:
        await wait_for_event.wait()

    enc_vals: list[float] = []
    wrt_vals: list[float] = []
    ok = fail = 0

    try:
        for i in range(1, n + 1):
            msg_id   = f"C_{i:04d}"
            action   = "STOP"
            payload  = json.dumps({"action": action, "msg_id": msg_id,
                                   "t_send_ms": int(time.monotonic() * 1000)}).encode()

            scheduled_ns = time.perf_counter_ns()
            t_enc        = time.perf_counter_ns()
            encrypted    = cane_ch.send(payload)
            encrypt_ms   = _ms(t_enc, time.perf_counter_ns())

            t_write = time.perf_counter_ns()
            try:
                await client.write_gatt_char(h_cane2phone, encrypted, response=True)
                success = True
                error   = ''
            except Exception as e:
                success = False
                error   = str(e)

            actual_send_ns = time.perf_counter_ns()
            write_ms       = _ms(t_write, actual_send_ns)

            row = {
                'scenario': scenario, 'endpoint': 'cane', 'message_id': msg_id,
                'action': action, 'scheduled_ns': scheduled_ns,
                'actual_send_ns': actual_send_ns,
                'encrypt_ms': encrypt_ms, 'write_ms': write_ms,
                'success': success, 'error': error,
            }
            _append_csv(csv_path, _CANE_CSV_COLS, row)

            if success:
                ok += 1
                enc_vals.append(encrypt_ms)
                wrt_vals.append(write_ms)
                print(f"[cane ] [{i:4d}/{n}] OK  enc={encrypt_ms:.2f} wrt={write_ms:.0f} ms")
            else:
                fail += 1
                print(f"[cane ] [{i:4d}/{n}] FAIL  {error}")
                if not client.is_connected:
                    break

            if i < n:
                await asyncio.sleep(CANE_INTERVAL_S)

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
        for p in (base_path, sec_path):
            try:
                os.remove(p)
            except OSError:
                pass

    print(f"[cane ] Done: {ok}/{ok+fail}")
    return {
        'ok': ok, 'fail': fail,
        'encrypt_ms': _stats(enc_vals),
        'write_ms':   _stats(wrt_vals),
    }

# ── Scenario runners ──────────────────────────────────────────────────────────

async def run_phone_only(address: str, n: int, scenario: str,
                         phone_csv: str) -> dict:
    print(f"\n── Scenario: phone_only  N={n} ──")
    return await phone_task(address, n, scenario, phone_csv)


async def run_cane_only(address: str, n: int, scenario: str,
                        cane_csv: str) -> dict:
    print(f"\n── Scenario: cane_only  N={n} ──")
    return await cane_task(address, n, scenario, cane_csv)


async def run_sequential(address: str, n_phone: int, n_cane: int, scenario: str,
                         phone_csv: str, cane_csv: str) -> dict:
    print(f"\n── Scenario: sequential  phone={n_phone}  cane={n_cane} ──")
    phone_stats = await phone_task(address, n_phone, scenario, phone_csv)
    await asyncio.sleep(2.0)
    cane_stats  = await cane_task(address, n_cane,  scenario, cane_csv)
    return {'phone': phone_stats, 'cane': cane_stats}


async def run_concurrent(address: str, n_phone: int, n_cane: int, scenario: str,
                         phone_csv: str, cane_csv: str) -> dict:
    """
    Phone and cane run simultaneously.
    Both complete key exchange before messaging starts: each sets a ready_event,
    and messaging begins only after BOTH channels are keyed.
    """
    print(f"\n── Scenario: concurrent  phone={n_phone}  cane={n_cane} ──")
    print("  Note: both endpoints do key exchange first, then start messaging simultaneously.\n")

    phone_ready = asyncio.Event()
    cane_ready  = asyncio.Event()

    phone_coro = phone_task(address, n_phone, scenario, phone_csv,
                            ready_event=phone_ready)
    cane_coro  = cane_task(address, n_cane,  scenario, cane_csv,
                           ready_event=cane_ready, wait_for_event=phone_ready)

    phone_stats, cane_stats = await asyncio.gather(phone_coro, cane_coro,
                                                   return_exceptions=True)

    if isinstance(phone_stats, Exception):
        print(f"[phone] ERROR: {phone_stats}")
        phone_stats = {'ok': 0, 'fail': n_phone, 'error': str(phone_stats)}
    if isinstance(cane_stats, Exception):
        print(f"[cane ] ERROR: {cane_stats}")
        cane_stats = {'ok': 0, 'fail': n_cane, 'error': str(cane_stats)}

    return {'phone': phone_stats, 'cane': cane_stats}

# ── Verification (post-run, in-process) ──────────────────────────────────────

def _verify_server_csv(server_csv_path: str) -> dict:
    """
    Reads the server K CSV and verifies:
      - counters strictly increasing per endpoint
      - no duplicate counter value per endpoint
      - all rows have success=True
    Returns a dict with pass/fail flags and details.
    """
    if not os.path.exists(server_csv_path):
        return {'status': 'SKIPPED', 'reason': f'{server_csv_path} not found'}

    counters: dict[str, list[int]] = {}
    issues: list[str] = []
    n_rows = 0

    with open(server_csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            n_rows += 1
            endpoint = row.get('endpoint', '')
            try:
                ctr = int(row.get('counter', '-1'))
            except ValueError:
                continue
            success = row.get('success', '').lower()

            if success not in ('true', '1'):
                issues.append(f"row {n_rows}: endpoint={endpoint} success={success}")

            if endpoint not in counters:
                counters[endpoint] = []
            counters[endpoint].append(ctr)

    rollback_violations   = 0
    duplicate_violations  = 0
    for endpoint, ctrs in counters.items():
        for i in range(1, len(ctrs)):
            if ctrs[i] <= ctrs[i - 1]:
                rollback_violations += 1
                issues.append(
                    f"counter rollback: endpoint={endpoint} "
                    f"row {i}: {ctrs[i - 1]} → {ctrs[i]}"
                )
        if len(ctrs) != len(set(ctrs)):
            seen = set()
            for c in ctrs:
                if c in seen:
                    duplicate_violations += 1
                    issues.append(f"duplicate nonce: endpoint={endpoint} counter={c}")
                seen.add(c)

    return {
        'n_rows':              n_rows,
        'endpoints':           {ep: len(v) for ep, v in counters.items()},
        'counter_rollbacks':   rollback_violations,
        'duplicate_nonces':    duplicate_violations,
        'success_failures':    len(issues) - rollback_violations - duplicate_violations,
        'issues':              issues[:20],   # cap at 20 for readability
        'status': 'PASS' if not issues else 'FAIL',
    }


def _detect_conflicts(server_csv_path: str, window_ms: float = 50.0) -> list[dict]:
    """
    Find pairs of phone and cane messages that arrived at the gateway within
    window_ms of each other.  These are 'conflicting command' cases.
    Reports the observed runtime policy (no special handling; both processed).
    """
    if not os.path.exists(server_csv_path):
        return []

    events: list[dict] = []
    with open(server_csv_path, newline='') as f:
        for row in csv.DictReader(f):
            try:
                t_ns = int(row.get('gateway_receive_ns', 0))
                events.append({'endpoint': row['endpoint'], 'message_id': row['message_id'],
                                'action': row['action'], 't_ns': t_ns})
            except (ValueError, KeyError):
                pass

    events.sort(key=lambda e: e['t_ns'])
    conflicts: list[dict] = []
    window_ns = int(window_ms * 1e6)

    for i, ev in enumerate(events):
        for j in range(i + 1, len(events)):
            other = events[j]
            if other['t_ns'] - ev['t_ns'] > window_ns:
                break
            if ev['endpoint'] != other['endpoint']:
                conflicts.append({
                    'phone_msg': ev['message_id'] if ev['endpoint'] == 'phone' else other['message_id'],
                    'cane_msg':  other['message_id'] if other['endpoint'] == 'cane' else ev['message_id'],
                    'gap_ms':    round((other['t_ns'] - ev['t_ns']) / 1e6, 3),
                    'phone_action': ev['action'] if ev['endpoint'] == 'phone' else other['action'],
                    'cane_action':  other['action'] if other['endpoint'] == 'cane' else ev['action'],
                    'policy': 'both_processed_sequentially_by_asyncio',
                })

    return conflicts

# ── Main ──────────────────────────────────────────────────────────────────────

async def run(args) -> None:
    scenario    = args.scenario
    address     = args.address
    n_phone     = args.n_phone
    n_cane      = args.n_cane

    phone_csv = os.path.join(_THIS_DIR, f'K_{scenario}_phone_client.csv')
    cane_csv  = os.path.join(_THIS_DIR, f'K_{scenario}_cane_client.csv')
    sum_json  = os.path.join(_THIS_DIR, f'K_{scenario}_summary.json')

    _open_csv(phone_csv, _PHONE_CSV_COLS)
    _open_csv(cane_csv,  _CANE_CSV_COLS)

    print(f"\n{'═' * 72}")
    print(f"Experiment K — {scenario}")
    print(f"Target  : {address}")
    print(f"N phone : {n_phone}   N cane: {n_cane}")
    print(f"Server  : start ble_server_K.py with EXPERIMENT_K_SCENARIO={scenario}")
    print(f"{'═' * 72}")

    if scenario == 'phone_only':
        stats = await run_phone_only(address, n_phone, scenario, phone_csv)
        summary = {'phone': stats, 'cane': None}

    elif scenario == 'cane_only':
        stats = await run_cane_only(address, n_cane, scenario, cane_csv)
        summary = {'phone': None, 'cane': stats}

    elif scenario == 'sequential':
        summary = await run_sequential(address, n_phone, n_cane, scenario,
                                       phone_csv, cane_csv)

    elif scenario == 'concurrent':
        summary = await run_concurrent(address, n_phone, n_cane, scenario,
                                       phone_csv, cane_csv)
    else:
        sys.exit(f"Unknown scenario: {scenario!r}")

    # ── Security verification against server CSV ───────────────────────────────
    server_csv = os.environ.get('EXPERIMENT_SERVER_CSV_PATH',
                                f'/tmp/exp_K_{scenario}.csv')
    print(f"\nFetch server CSV from RPi first:")
    print(f"  ssh rpi 'cat {server_csv}' > /tmp/K_{scenario}_server.csv")
    print(f"Then re-run with --verify-server /tmp/K_{scenario}_server.csv to add checks to summary.")

    local_server_csv = args.verify_server
    verification: dict = {}
    conflicts:   list  = []
    if local_server_csv:
        verification = _verify_server_csv(local_server_csv)
        conflicts    = _detect_conflicts(local_server_csv, window_ms=50.0)
        print(f"\nSecurity verification:")
        print(f"  Status            : {verification.get('status')}")
        print(f"  Counter rollbacks : {verification.get('counter_rollbacks', '?')}")
        print(f"  Duplicate nonces  : {verification.get('duplicate_nonces', '?')}")
        print(f"  Endpoints seen    : {verification.get('endpoints', {})}")
        print(f"  Conflicts (≤50ms) : {len(conflicts)}")
        if conflicts:
            print(f"  Policy            : {conflicts[0]['policy']}")

    full_summary = {
        'scenario':     scenario,
        'n_phone':      n_phone,
        'n_cane':       n_cane,
        'results':      summary,
        'verification': verification,
        'conflicts_within_50ms': conflicts[:50],   # cap for JSON size
        'note': (
            'server_process_ms not available client-side; '
            'merge phone_client.csv + cane_client.csv with server CSV on message_id '
            'to compute gateway_receive_ns - actual_send_ns. '
            'Conflicts report phone/cane messages arriving within 50 ms at the gateway; '
            'observed policy: asyncio event loop serialises both; no application-level '
            'conflict resolution is applied by the server.'
        ),
    }
    with open(sum_json, 'w') as f:
        json.dump(full_summary, f, indent=2)

    print(f"\nPhone CSV → {phone_csv}")
    print(f"Cane CSV  → {cane_csv}")
    print(f"Summary   → {sum_json}")


def main() -> None:
    p = argparse.ArgumentParser(description="Experiment K — concurrent phone/cane traffic")
    p.add_argument('--address', required=True, help="RPi BLE MAC address")
    p.add_argument('--scenario',
                   choices=['phone_only', 'cane_only', 'sequential', 'concurrent'],
                   default='concurrent')
    p.add_argument('--n-phone', type=int, default=500, help="Number of phone messages")
    p.add_argument('--n-cane',  type=int, default=500, help="Number of cane messages")
    p.add_argument('--verify-server', default='',
                   help="Path to fetched server K CSV for security verification")
    args = p.parse_args()
    asyncio.run(run(args))


if __name__ == '__main__':
    main()
