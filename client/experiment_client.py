#!/usr/bin/env python3
"""
BLE experiment client — runs on the laptop (Fedora/macOS/Ubuntu).

Experiment A — per-trial reconnect (default):
  Each trial: scan → connect → key exchange → write command → poll ACK → disconnect.
  Measures provisioning / cold-start latency.

Experiment B — steady-state (--connect-once):
  Scan once, connect once, key exchange once.
  Then send N commands over the same connection.
  Measures pure write/ACK latency with no connection overhead.

Experiment C — reconnect with persistent session (--key-once):
  Key exchange only on the first connection (or if no persisted session exists).
  Every trial: scan → connect → send → disconnect, reusing the same session key.
  Measures reconnect latency without key exchange overhead.
  The session channel state is persisted at KEY_ONCE_SESSION_PATH between runs.
  Pass --reset-key to force a fresh key exchange on the next run.

Note: This script runs on a Fedora laptop (x86_64) as the supervisory client.
  It substitutes for the Android phone app in experiments, using the same
  CipherChannel packet format and BLE/GATT command path.

Output CSV (default /tmp/experiment_client.csv):
  trial_id, action, t_sent_ns,
  t_scan_ms, t_connect_ms, t_key_exchange_ms,
  t_write_ms, t_ack_ms, t_total_ms,
  success, error

  In --connect-once mode, t_scan_ms / t_connect_ms / t_key_exchange_ms are
  recorded only on trial 1; empty on subsequent trials.
  In --key-once mode, t_key_exchange_ms is recorded only on the trial where
  the key exchange actually happens (trial 1, or after --reset-key).

Usage:
    # Experiment A (reconnect per trial):
    python3 experiment_client.py --address B8:27:EB:07:01:22 --trials 30 --action STAND_UP

    # Experiment B (steady-state, connect once):
    python3 experiment_client.py --address B8:27:EB:07:01:22 --connect-once --trials 500 --action STAND_UP
    python3 experiment_client.py --address B8:27:EB:07:01:22 --connect-once --trials 500 --delay 0.2 --action START_WALKING

    # Experiment C (reconnect, key exchange only on first connection):
    python3 experiment_client.py --address B8:27:EB:07:01:22 --key-once --trials 30 --action STAND_UP
    python3 experiment_client.py --address B8:27:EB:07:01:22 --key-once --reset-key --trials 30 --action STAND_UP
"""

import argparse
import asyncio
import csv
import json
import os
import subprocess
import sys
import time
import uuid as _uuid_mod

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from cipher import CipherChannel, ChannelException, PROVISION_TAG_PHONE

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    sys.exit("bleak not installed.  Run: pip install bleak")

# ── Characteristic UUIDs (must match ble_server.py) ──────────────────────────

SECURITY_UUID = "FEC26EC4-6D71-4442-9F81-55BC21D658D6"
COMMAND_UUID  = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B"
ACK_UUID      = "51FF12BC-3ED8-46E5-B4F9-D64E2FEC021B"

KEY: bytes = b'*\xc3,6s\xa4\xa2\xeeI\x08S>\xd0\xff%\x84\xba\xe9\x95\xcaNL\xffzL%h\x04)\x04%\xf8'

CLIENT_CSV: str = os.environ.get('EXPERIMENT_CLIENT_CSV_PATH', '/tmp/experiment_client.csv')
_KEY_ONCE_SESSION_PATH: str = os.environ.get('KEY_ONCE_SESSION_PATH',
                                              '/tmp/cc_session_client_keyonce')

# K_T is static and shared with the cane endpoint, so this side's send/receive
# counter state under K_T must persist across provisioning sessions at a
# fixed path -- a fresh per-session path would reset the counter and, on the
# server's initiator side, reuse a nonce under K_T on every provisioning.
_PHONE_TRANSPORT_PATH: str = os.environ.get('PHONE_TRANSPORT_PATH',
                                             '/tmp/cc_transport_client_phone')

_CSV_COLUMNS = [
    'trial_id', 'action', 't_sent_ns',
    't_scan_ms', 't_connect_ms', 't_key_exchange_ms',
    't_write_ms', 't_ack_ms', 't_total_ms',
    'success', 'error',
]

_ACK_POLL_INTERVAL = 0.05   # seconds between read_gatt_char polls for ACK
_ACK_TIMEOUT       = 10.0   # seconds to wait for ACK before giving up
_KEY_POLL_INTERVAL = 0.1    # seconds between polls for SECURE_KEY
_KEY_TIMEOUT       = 10.0   # seconds to wait for SECURE_KEY

# Encrypted 32-byte key: nonce(12) + ciphertext(32) + tag(16) = 60 bytes
_ENCRYPTED_KEY_LEN = 60


# ── CSV helpers ───────────────────────────────────────────────────────────────

def _init_csv() -> None:
    with open(CLIENT_CSV, 'w', newline='') as f:
        csv.writer(f).writerow(_CSV_COLUMNS)
    print(f"Client CSV: {CLIENT_CSV}")


def _append_row(row: dict) -> None:
    with open(CLIENT_CSV, 'a', newline='') as f:
        csv.writer(f).writerow([row.get(c, '') for c in _CSV_COLUMNS])


# ── BLE helpers ───────────────────────────────────────────────────────────────

def _clear_br_edr_cache(address: str) -> None:
    """Remove device from BlueZ cache so next connect goes via LE, not BR/EDR."""
    try:
        subprocess.run(
            ['bluetoothctl', 'remove', address],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass


async def _key_exchange(client: BleakClient, session_id: str) -> bytes:
    """
    Write REQUEST_KEY to SECURITY char, then poll-read until the server puts
    the CipherChannel-encrypted SECURE_KEY there.  Returns raw 32-byte SECURE_KEY.

    Wire format: nonce(12) || ciphertext(32) || tag(16) = 60 bytes.
    Client is responder on the transport channel (server sends even nonces, client receives).

    The transport channel is keyed by the static, shared K_T, so its state
    is loaded from a fixed path and persists across sessions rather than
    being recreated fresh each time (session_id only names the operational
    session channel below, which is keyed by a freshly issued K_phone).
    """
    try:
        transport_ch = CipherChannel.load(_PHONE_TRANSPORT_PATH, endpoint_id='phone_transport')
    except ChannelException:
        transport_ch = CipherChannel.create(KEY, False, _PHONE_TRANSPORT_PATH,
                                             endpoint_id='phone_transport')

    await client.write_gatt_char(SECURITY_UUID, b"REQUEST_KEY", response=True)

    deadline = asyncio.get_event_loop().time() + _KEY_TIMEOUT
    while asyncio.get_event_loop().time() < deadline:
        raw = bytes(await client.read_gatt_char(SECURITY_UUID))
        if len(raw) == _ENCRYPTED_KEY_LEN:
            result = transport_ch.receive(raw, associated_data=PROVISION_TAG_PHONE)
            if result is not None and len(result) == 32:
                return result
        await asyncio.sleep(_KEY_POLL_INTERVAL)

    raise RuntimeError("Timed out waiting for SECURE_KEY from server")


# ── Per-trial logic ───────────────────────────────────────────────────────────

async def run_single_trial(
    address: str | None,
    name: str | None,
    trial_id: str,
    action: str,
) -> dict:
    r: dict = {c: '' for c in _CSV_COLUMNS}
    r.update({'trial_id': trial_id, 'action': action, 'success': False})
    t_trial_start = time.perf_counter_ns()

    try:
        # ── 1. Scan ───────────────────────────────────────────────────────────
        t0 = time.perf_counter_ns()
        if address:
            ble_device = await BleakScanner.find_device_by_address(address, timeout=8.0)
        else:
            ble_device = await BleakScanner.find_device_by_name(name, timeout=8.0)
        r['t_scan_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)

        if ble_device is None:
            r['error'] = f'device not found ({address or name})'
            r['t_total_ms'] = round((time.perf_counter_ns() - t_trial_start) / 1e6, 1)
            return r

        # ── 2. Connect ────────────────────────────────────────────────────────
        t0     = time.perf_counter_ns()
        client = BleakClient(ble_device)
        await client.connect()
        r['t_connect_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)

        try:
            if not client.is_connected:
                r['error'] = 'connection failed'
                return r

            # ── 3. Key exchange ───────────────────────────────────────────────
            session_id = _uuid_mod.uuid4().hex[:12]
            t0 = time.perf_counter_ns()
            secure_key = await _key_exchange(client, session_id)
            r['t_key_exchange_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)

            # ── 4. Send encrypted command ─────────────────────────────────────
            # Client is initiator on the session channel (sends even nonces)
            session_path = f'/tmp/cc_session_client_{session_id}'
            secure_ch = CipherChannel.create(secure_key, True, session_path)

            payload = json.dumps({"trial_id": trial_id, "action": action}).encode()
            enc = secure_ch.send(payload)

            r['t_sent_ns'] = time.perf_counter_ns()
            t0             = time.perf_counter_ns()
            try:
                await client.write_gatt_char(COMMAND_UUID, enc, response=True)
            except Exception as e:
                r['error'] = f"write:{e}"
                return r
            r['t_write_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)

            # ── 5. Poll ACK char until "OK:<trial_id>" ────────────────────────
            expected = f"OK:{trial_id}".encode()
            deadline = asyncio.get_event_loop().time() + _ACK_TIMEOUT
            t0       = time.perf_counter_ns()
            while asyncio.get_event_loop().time() < deadline:
                try:
                    val = bytes(await client.read_gatt_char(ACK_UUID))
                except Exception as e:
                    r['error'] = f"ack_read:{e}"
                    return r
                if val == expected:
                    r['t_ack_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)
                    r['success']  = True
                    break
                await asyncio.sleep(_ACK_POLL_INTERVAL)
            else:
                r['error'] = 'ACK timeout'

        finally:
            await client.disconnect()

    except Exception as e:
        r['error'] = str(e)

    r['t_total_ms'] = round((time.perf_counter_ns() - t_trial_start) / 1e6, 1)
    return r


# ── Trial loop ────────────────────────────────────────────────────────────────

async def run_trials(
    address: str | None,
    name: str | None,
    trials: int,
    action: str,
    delay: float,
    prefix: str,
) -> None:
    _init_csv()

    target = address or name
    print(f"Target      : {target}")
    print(f"Trials      : {trials}  action={action!r}  delay={delay} s\n")

    ok = fail = 0
    for i in range(1, trials + 1):
        trial_id = f"{prefix}{i:04d}"
        r = None

        for attempt in range(1, 4):
            label = f"[{i:4d}/{trials}]  {trial_id}"
            if attempt > 1:
                label += f"  (retry {attempt}/3)"
            print(f"  {label} …", end='', flush=True)

            r = await run_single_trial(address, name, trial_id, action)

            if r['success']:
                break
            if r['t_sent_ns']:
                break
            if address and 'br-connection-key-missing' in r.get('error', ''):
                _clear_br_edr_cache(address)
            print(f"  ✗  {r['error']} — backing off 3 s")
            if attempt < 3:
                await asyncio.sleep(3.0)

        _append_row(r)
        if r['success']:
            ok += 1
            print(
                f"  ✓  "
                f"scan={r['t_scan_ms']} ms  "
                f"conn={r['t_connect_ms']} ms  "
                f"kex={r['t_key_exchange_ms']} ms  "
                f"write={r['t_write_ms']} ms  "
                f"ack={r['t_ack_ms']} ms  "
                f"total={r['t_total_ms']} ms"
            )
        else:
            fail += 1
            print(f"  ✗  {r['error']}  (total={r['t_total_ms']} ms)")

        if i < trials:
            await asyncio.sleep(delay)

    print(f"\n{'─' * 60}")
    print(f"Results: {ok} ok  /  {fail} failed  /  {trials} total")
    print(f"\nClient CSV  → {CLIENT_CSV}")
    print(f"Server CSV  → /tmp/experiment_server.csv  (on RPi)")
    print(f"\nJoin on 'trial_id' for end-to-end latency breakdown.")


# ── Experiment B: steady-state (connect once, key exchange once) ──────────────

async def run_trials_steady_state(
    address: str | None,
    name: str | None,
    trials: int,
    action: str,
    delay: float,
    prefix: str,
) -> None:
    _init_csv()

    target = address or name
    print(f"Target      : {target}")
    print(f"Mode        : connect-once  (Experiment B — steady-state)")
    print(f"Trials      : {trials}  action={action!r}  delay={delay} s\n")

    ok = fail = 0
    t_scan_ms = t_connect_ms = t_kex_ms = 0.0

    # ── 1. Scan ───────────────────────────────────────────────────────────────
    print("Scanning…", end='', flush=True)
    t0 = time.perf_counter_ns()
    if address:
        ble_device = await BleakScanner.find_device_by_address(address, timeout=8.0)
    else:
        ble_device = await BleakScanner.find_device_by_name(name, timeout=8.0)
    t_scan_ms = round((time.perf_counter_ns() - t0) / 1e6, 1)

    if ble_device is None:
        print(f"  ✗  device not found ({target})")
        return
    print(f"  found in {t_scan_ms} ms")

    # ── 2. Connect ────────────────────────────────────────────────────────────
    print("Connecting…", end='', flush=True)
    t0 = time.perf_counter_ns()
    client = BleakClient(ble_device)
    await client.connect()
    t_connect_ms = round((time.perf_counter_ns() - t0) / 1e6, 1)

    if not client.is_connected:
        print("  ✗  connection failed")
        return
    print(f"  connected in {t_connect_ms} ms")

    try:
        # ── 3. Key exchange (once for all trials) ─────────────────────────────
        print("Key exchange…", end='', flush=True)
        session_id = _uuid_mod.uuid4().hex[:12]
        t0 = time.perf_counter_ns()
        secure_key = await _key_exchange(client, session_id)
        t_kex_ms = round((time.perf_counter_ns() - t0) / 1e6, 1)
        print(f"  done in {t_kex_ms} ms\n")

        # One session channel for all trials — counter persists across sends
        session_path = f'/tmp/cc_session_client_{session_id}'
        secure_ch = CipherChannel.create(secure_key, True, session_path)  # initiator

        # ── 4. Trial loop ─────────────────────────────────────────────────────
        for i in range(1, trials + 1):
            trial_id = f"{prefix}{i:04d}"
            r: dict = {c: '' for c in _CSV_COLUMNS}
            r.update({'trial_id': trial_id, 'action': action, 'success': False})

            if i == 1:
                r['t_scan_ms']         = t_scan_ms
                r['t_connect_ms']      = t_connect_ms
                r['t_key_exchange_ms'] = t_kex_ms

            print(f"  [{i:4d}/{trials}]  {trial_id} …", end='', flush=True)
            t_trial_start = time.perf_counter_ns()

            payload = json.dumps({"trial_id": trial_id, "action": action}).encode()
            enc = secure_ch.send(payload)

            r['t_sent_ns'] = time.perf_counter_ns()
            t0 = time.perf_counter_ns()
            try:
                await client.write_gatt_char(COMMAND_UUID, enc, response=True)
            except Exception as e:
                r['error'] = f"write:{e}"
                r['t_total_ms'] = round((time.perf_counter_ns() - t_trial_start) / 1e6, 1)
                _append_row(r)
                fail += 1
                print(f"  ✗  {r['error']}  (connection lost — stopping)")
                break
            r['t_write_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)

            expected = f"OK:{trial_id}".encode()
            deadline = asyncio.get_event_loop().time() + _ACK_TIMEOUT
            t0 = time.perf_counter_ns()
            connection_lost = False
            while asyncio.get_event_loop().time() < deadline:
                try:
                    val = bytes(await client.read_gatt_char(ACK_UUID))
                except Exception as e:
                    r['error'] = f"ack_read:{e}"
                    connection_lost = True
                    break
                if val == expected:
                    r['t_ack_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)
                    r['success'] = True
                    break
                await asyncio.sleep(_ACK_POLL_INTERVAL)
            else:
                if not r['error']:
                    r['error'] = 'ACK timeout'

            r['t_total_ms'] = round((time.perf_counter_ns() - t_trial_start) / 1e6, 1)
            _append_row(r)

            if r['success']:
                ok += 1
                print(
                    f"  ✓  "
                    f"write={r['t_write_ms']} ms  "
                    f"ack={r['t_ack_ms']} ms  "
                    f"total={r['t_total_ms']} ms"
                )
            else:
                fail += 1
                print(f"  ✗  {r['error']}  (total={r['t_total_ms']} ms)")
                if connection_lost:
                    break

            if i < trials:
                await asyncio.sleep(delay)

    finally:
        await client.disconnect()

    print(f"\n{'─' * 60}")
    print(f"Setup       : scan={t_scan_ms} ms  connect={t_connect_ms} ms  kex={t_kex_ms} ms")
    print(f"Results     : {ok} ok  /  {fail} failed  /  {trials} total")
    print(f"\nClient CSV  → {CLIENT_CSV}")
    print(f"Server CSV  → /tmp/experiment_server.csv  (on RPi)")
    print(f"\nJoin on 'trial_id' for end-to-end latency breakdown.")


# ── Experiment C: reconnect with persistent session (key exchange only once) ──

async def _run_key_once_trial(
    address: str | None,
    name: str | None,
    trial_id: str,
    action: str,
    secure_ch: CipherChannel | None,
) -> tuple[dict, CipherChannel | None]:
    """
    Single trial for --key-once mode.  Returns (row_dict, secure_ch).

    secure_ch is None on entry when no session exists yet; in that case a
    full key exchange is performed and the new channel is returned for reuse
    by subsequent trials.  The channel's state file is written to
    _KEY_ONCE_SESSION_PATH so it survives reconnects and process restarts.
    """
    r: dict = {c: '' for c in _CSV_COLUMNS}
    r.update({'trial_id': trial_id, 'action': action, 'success': False})
    t_trial_start = time.perf_counter_ns()

    try:
        # 1. Scan
        t0 = time.perf_counter_ns()
        if address:
            ble_device = await BleakScanner.find_device_by_address(address, timeout=8.0)
        else:
            ble_device = await BleakScanner.find_device_by_name(name, timeout=8.0)
        r['t_scan_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)

        if ble_device is None:
            r['error'] = f'device not found ({address or name})'
            r['t_total_ms'] = round((time.perf_counter_ns() - t_trial_start) / 1e6, 1)
            return r, secure_ch

        # 2. Connect
        t0     = time.perf_counter_ns()
        client = BleakClient(ble_device)
        await client.connect()
        r['t_connect_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)

        try:
            if not client.is_connected:
                r['error'] = 'connection failed'
                r['t_total_ms'] = round((time.perf_counter_ns() - t_trial_start) / 1e6, 1)
                return r, secure_ch

            # 3. Key exchange — only if no session exists yet
            if secure_ch is None:
                session_id = _uuid_mod.uuid4().hex[:12]
                t0 = time.perf_counter_ns()
                secure_key = await _key_exchange(client, session_id)
                r['t_key_exchange_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)
                # Persist channel to fixed path; counter survives reconnects
                secure_ch = CipherChannel.create(secure_key, True, _KEY_ONCE_SESSION_PATH)

            # 4. Send encrypted command
            payload = json.dumps({"trial_id": trial_id, "action": action}).encode()
            enc = secure_ch.send(payload)

            r['t_sent_ns'] = time.perf_counter_ns()
            t0             = time.perf_counter_ns()
            try:
                await client.write_gatt_char(COMMAND_UUID, enc, response=True)
            except Exception as e:
                r['error'] = f"write:{e}"
                r['t_total_ms'] = round((time.perf_counter_ns() - t_trial_start) / 1e6, 1)
                return r, secure_ch
            r['t_write_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)

            # 5. Poll ACK char until "OK:<trial_id>"
            expected = f"OK:{trial_id}".encode()
            deadline = asyncio.get_event_loop().time() + _ACK_TIMEOUT
            t0       = time.perf_counter_ns()
            while asyncio.get_event_loop().time() < deadline:
                try:
                    val = bytes(await client.read_gatt_char(ACK_UUID))
                except Exception as e:
                    r['error'] = f"ack_read:{e}"
                    break
                if val == expected:
                    r['t_ack_ms'] = round((time.perf_counter_ns() - t0) / 1e6, 1)
                    r['success']  = True
                    break
                await asyncio.sleep(_ACK_POLL_INTERVAL)
            else:
                if not r['error']:
                    r['error'] = 'ACK timeout'

        finally:
            await client.disconnect()

    except Exception as e:
        r['error'] = str(e)

    r['t_total_ms'] = round((time.perf_counter_ns() - t_trial_start) / 1e6, 1)
    return r, secure_ch


async def run_trials_key_once(
    address: str | None,
    name: str | None,
    trials: int,
    action: str,
    delay: float,
    prefix: str,
    reset_key: bool,
) -> None:
    _init_csv()

    if reset_key and os.path.exists(_KEY_ONCE_SESSION_PATH):
        os.unlink(_KEY_ONCE_SESSION_PATH)
        print(f"Cleared persisted session state ({_KEY_ONCE_SESSION_PATH})")

    # Try to resume a session from a previous run
    secure_ch: CipherChannel | None = None
    try:
        secure_ch = CipherChannel.load(_KEY_ONCE_SESSION_PATH)
        print(f"Resumed persisted session from {_KEY_ONCE_SESSION_PATH}")
    except (ChannelException, FileNotFoundError):
        pass

    target = address or name
    print(f"Target      : {target}")
    print(f"Mode        : key-once  (Experiment C — key exchange on first connection only)")
    print(f"Trials      : {trials}  action={action!r}  delay={delay} s")
    if secure_ch:
        print(f"Session     : loaded — skipping key exchange on trial 1")
    else:
        print(f"Session     : none — key exchange will happen on trial 1")
    print()

    ok = fail = 0
    for i in range(1, trials + 1):
        trial_id = f"{prefix}{i:04d}"
        print(f"  [{i:4d}/{trials}]  {trial_id} …", end='', flush=True)

        r, secure_ch = await _run_key_once_trial(
            address, name, trial_id, action, secure_ch)

        _append_row(r)
        if r['success']:
            ok += 1
            parts = [f"scan={r['t_scan_ms']} ms", f"conn={r['t_connect_ms']} ms"]
            if r.get('t_key_exchange_ms'):
                parts.append(f"kex={r['t_key_exchange_ms']} ms")
            parts += [f"write={r['t_write_ms']} ms",
                      f"ack={r['t_ack_ms']} ms",
                      f"total={r['t_total_ms']} ms"]
            print(f"  ✓  " + "  ".join(parts))
        else:
            fail += 1
            print(f"  ✗  {r['error']}  (total={r['t_total_ms']} ms)")

        if i < trials:
            await asyncio.sleep(delay)

    print(f"\n{'─' * 60}")
    print(f"Results: {ok} ok  /  {fail} failed  /  {trials} total")
    print(f"Session : {_KEY_ONCE_SESSION_PATH}  (reuse with --key-once on next run)")
    print(f"\nClient CSV  → {CLIENT_CSV}")
    print(f"Server CSV  → /tmp/experiment_server.csv  (on RPi)")
    print(f"\nJoin on 'trial_id' for end-to-end latency breakdown.")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="BLE experiment client — sends encrypted commands, waits for ACK.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument('--address', help="RPi BLE MAC address (e.g. B8:27:EB:07:01:22)")
    target.add_argument('--name',    help="BLE advertised name (e.g. AWAKE-EXP)")
    p.add_argument('--trials',  type=int,   default=30,       help="Number of trials.")
    p.add_argument('--action',  default='STAND_UP',           help="Action payload.")
    p.add_argument('--delay',   type=float, default=2.0,      help="Seconds between trials.")
    p.add_argument('--prefix',  default='t',                  help="Trial ID prefix.")
    p.add_argument('--connect-once', action='store_true',
                   help="Experiment B: scan/connect/key-exchange once; run all trials over the same connection.")
    p.add_argument('--key-exchange-once', action='store_true',
                   help="Alias for --connect-once.")
    p.add_argument('--key-once', action='store_true',
                   help="Experiment C: key exchange on first connection only; "
                        "subsequent trials reconnect and reuse the persisted session. "
                        f"Session state stored at KEY_ONCE_SESSION_PATH "
                        f"(default {_KEY_ONCE_SESSION_PATH}).")
    p.add_argument('--reset-key', action='store_true',
                   help="With --key-once: delete persisted session state and force a "
                        "fresh key exchange on the first trial. "
                        "Also use this after the server has been restarted.")
    args = p.parse_args()

    if args.key_once:
        asyncio.run(run_trials_key_once(
            args.address, args.name,
            args.trials, args.action, args.delay, args.prefix,
            args.reset_key,
        ))
    elif args.connect_once or args.key_exchange_once:
        asyncio.run(run_trials_steady_state(
            args.address, args.name,
            args.trials, args.action, args.delay, args.prefix,
        ))
    else:
        asyncio.run(run_trials(
            args.address, args.name,
            args.trials, args.action, args.delay, args.prefix,
        ))


if __name__ == '__main__':
    main()
