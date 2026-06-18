#!/usr/bin/env python3
"""
Experiment J (steady) — Distance reliability with persistent connection
=======================================================================
Connect once, exchange keys once, send N commands without disconnecting.
This is the practical scenario: a single BLE session at a given distance.

Per-trial metrics (no scan/connect per trial — those happen once):
  write_success, write_ms
  ack_success, ack_wait_ms
  total_success, total_ms
  failure_reason

If the connection drops mid-run the failure is recorded and the run stops.

Outputs land in the same condition directory as run_J.py:
  results/canonical/distance/<condition>/steady_raw.csv
  results/canonical/distance/<condition>/steady_summary.json

Server (RPi — same instance as run_J.py, no restart needed):
  BENCHMARK_PROVISIONING=1 \\
  EXPERIMENT_SERVER_CSV_PATH=/tmp/exp_J_server.csv \\
  server/.venv/bin/python server/ble_server.py

Run:
  client/.venv/bin/python results/canonical/distance/run_J_steady.py \\
      --address B8:27:EB:07:01:22 \\
      --condition 2m_los \\
      --description "RPi on desk. Laptop 2 m away, clear line of sight." \\
      --trials 500
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

# ── Configuration ─────────────────────────────────────────────────────────────

SECURITY_UUID = "FEC26EC4-6D71-4442-9F81-55BC21D658D6"
COMMAND_UUID  = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B"
ACK_UUID      = "51FF12BC-3ED8-46E5-B4F9-D64E2FEC021B"

KEY: bytes = (
    b'\x2a\xc3\x2c\x36\x73\xa4\xa2\xee'
    b'\x49\x08\x53\x3e\xd0\xff\x25\x84'
    b'\xba\xe9\x95\xca\x4e\x4c\xff\x7a'
    b'\x4c\x25\x68\x04\x29\x04\x25\xf8'
)

_ENCRYPTED_KEY_LEN = 60
_SCAN_TIMEOUT      = 12.0
_CONNECT_TIMEOUT   = 20.0
_KEY_POLL_INTERVAL = 0.05
_KEY_TIMEOUT       = 10.0
_ACK_POLL_INTERVAL = 0.020
_ACK_TIMEOUT       = 15.0
_INTER_CMD_DELAY   = float(os.environ.get('EXPERIMENT_J_INTER_DELAY', '0.1'))

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

# ── CSV ───────────────────────────────────────────────────────────────────────

_CSV_COLUMNS = [
    'trial_id', 'condition',
    'write_success', 'write_ms',
    'ack_success',   'ack_wait_ms',
    'total_success', 'total_ms',
    'failure_reason',
]


def _ms(t0: int, t1: int) -> float:
    return round((t1 - t0) / 1e6, 3)


def _resolve_handles(client: BleakClient, *uuids: str) -> tuple:
    result = []
    for uuid in uuids:
        lower  = uuid.lower()
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


async def run(address: str, condition: str, description: str,
              trials: int, prefix: str) -> None:

    out_dir  = os.path.join(_THIS_DIR, condition)
    os.makedirs(out_dir, exist_ok=True)
    raw_csv  = os.path.join(out_dir, 'steady_raw.csv')
    sum_json = os.path.join(out_dir, 'steady_summary.json')

    with open(raw_csv, 'w', newline='') as f:
        csv.writer(f).writerow(_CSV_COLUMNS)

    print(f"\n{'═' * 72}")
    print(f"Experiment J (steady) — persistent connection at distance")
    print(f"Condition   : {condition}")
    print(f"Description : {description}")
    print(f"Target      : {address}   Trials: {trials}")
    print(f"Output      : {out_dir}")
    print(f"{'═' * 72}\n")

    # ── Setup: scan → connect → key exchange ──────────────────────────────────
    session_id   = _uuid_mod.uuid4().hex[:8]
    tp_path      = f'/tmp/cc_Jst_tp_{session_id}'
    sess_path    = f'/tmp/cc_Jst_sess_{session_id}'

    print("Scanning…", end=' ', flush=True)
    t0     = time.perf_counter_ns()
    device = await BleakScanner.find_device_by_address(address, timeout=_SCAN_TIMEOUT)
    scan_ms = _ms(t0, time.perf_counter_ns())
    if device is None:
        sys.exit(f"Device {address} not found")
    print(f"found in {scan_ms:.0f} ms")

    print("Connecting…", end=' ', flush=True)
    t0     = time.perf_counter_ns()
    client = BleakClient(device)
    await asyncio.wait_for(client.connect(), timeout=_CONNECT_TIMEOUT)
    connect_ms = _ms(t0, time.perf_counter_ns())
    if not client.is_connected:
        sys.exit("Connect failed")
    print(f"connected in {connect_ms:.0f} ms")

    h_sec, h_cmd, h_ack = _resolve_handles(client, SECURITY_UUID, COMMAND_UUID, ACK_UUID)

    print("Key exchange…", end=' ', flush=True)
    transport_ch = CipherChannel.create(KEY, False, tp_path)
    t0           = time.perf_counter_ns()
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
        sys.exit("Key exchange failed — K_phone not received")
    print(f"done in {kex_ms:.0f} ms\n")

    phone_ch = CipherChannel.create(k_phone, True, sess_path)

    for p in (tp_path,):
        try:
            os.remove(p)
        except OSError:
            pass

    # ── Trials ────────────────────────────────────────────────────────────────
    write_vals: list[float] = []
    ack_vals:   list[float] = []
    total_vals: list[float] = []
    ok = fail = 0
    disconnected = False

    try:
        for i in range(1, trials + 1):
            trial_id = f"{prefix}{i:04d}"
            row: dict = {c: '' for c in _CSV_COLUMNS}
            row.update({'trial_id': trial_id, 'condition': condition,
                        'write_success': False, 'ack_success': False,
                        'total_success': False})

            if not client.is_connected:
                row['failure_reason'] = 'connection_lost'
                with open(raw_csv, 'a', newline='') as f:
                    csv.writer(f).writerow([row.get(c, '') for c in _CSV_COLUMNS])
                fail += 1
                print(f"  [{i:4d}/{trials}]  {trial_id}  FAIL — connection lost")
                disconnected = True
                # Fill remaining rows as connection_lost
                for j in range(i + 1, trials + 1):
                    tid = f"{prefix}{j:04d}"
                    r = {c: '' for c in _CSV_COLUMNS}
                    r.update({'trial_id': tid, 'condition': condition,
                              'write_success': False, 'ack_success': False,
                              'total_success': False,
                              'failure_reason': 'connection_lost_earlier'})
                    with open(raw_csv, 'a', newline='') as f:
                        csv.writer(f).writerow([r.get(c, '') for c in _CSV_COLUMNS])
                    fail += 1
                break

            print(f"  [{i:4d}/{trials}]  {trial_id}", end='  ', flush=True)

            payload   = json.dumps({"trial_id": trial_id, "action": "STAND_UP"}).encode()
            encrypted = phone_ch.send(payload)
            t_start   = time.perf_counter_ns()

            # Write
            t_write = time.perf_counter_ns()
            try:
                await client.write_gatt_char(h_cmd, encrypted, response=True)
                row['write_ms']      = _ms(t_write, time.perf_counter_ns())
                row['write_success'] = True
            except Exception as e:
                row['write_ms']      = _ms(t_write, time.perf_counter_ns())
                row['failure_reason'] = f"write:{e}"
                row['total_ms']      = _ms(t_start, time.perf_counter_ns())
                with open(raw_csv, 'a', newline='') as f:
                    csv.writer(f).writerow([row.get(c, '') for c in _CSV_COLUMNS])
                fail += 1
                print(f"FAIL write: {e}")
                continue

            # ACK
            expected = f"OK:{trial_id}".encode()
            t_ack    = time.perf_counter_ns()
            acked    = False
            ack_dl   = asyncio.get_event_loop().time() + _ACK_TIMEOUT
            while asyncio.get_event_loop().time() < ack_dl:
                try:
                    val = bytes(await client.read_gatt_char(h_ack))
                except Exception as e:
                    row['ack_wait_ms']    = _ms(t_ack, time.perf_counter_ns())
                    row['failure_reason'] = f"ack_read:{e}"
                    break
                if val == expected:
                    acked = True
                    break
                await asyncio.sleep(_ACK_POLL_INTERVAL)

            row['ack_wait_ms'] = _ms(t_ack, time.perf_counter_ns())
            row['total_ms']    = _ms(t_start, time.perf_counter_ns())

            if acked:
                row['ack_success']   = True
                row['total_success'] = True
                ok += 1
                write_vals.append(float(row['write_ms']))
                ack_vals.append(float(row['ack_wait_ms']))
                total_vals.append(float(row['total_ms']))
                print(f"OK  wrt={row['write_ms']:.0f}  "
                      f"ack={row['ack_wait_ms']:.0f}  "
                      f"tot={row['total_ms']:.0f} ms")
            else:
                if not row.get('failure_reason'):
                    row['failure_reason'] = 'ack_timeout'
                fail += 1
                print(f"FAIL  {row['failure_reason']}")

            with open(raw_csv, 'a', newline='') as f:
                csv.writer(f).writerow([row.get(c, '') for c in _CSV_COLUMNS])

            if i < trials:
                await asyncio.sleep(_INTER_CMD_DELAY)

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
        try:
            os.remove(sess_path)
        except OSError:
            pass

    # ── Summary ───────────────────────────────────────────────────────────────
    n_total = ok + fail
    print(f"\n{'═' * 72}")
    print(f"Condition : {condition}   {ok}/{n_total} success ({100*ok/n_total:.1f}%)" if n_total else "")
    if disconnected:
        print("  NOTE: connection was lost mid-run — remaining trials recorded as failed")

    summary = {
        'condition':       condition,
        'description':     description,
        'mode':            'persistent_connection',
        'n_trials':        n_total,
        'n_success':       ok,
        'success_rate':    f'{100*ok/n_total:.1f}%' if n_total else '0%',
        'disconnected':    disconnected,
        'setup': {
            'scan_ms':    scan_ms,
            'connect_ms': connect_ms,
            'kex_ms':     kex_ms,
        },
        'latency_ms': {
            'write_ms':   _stats(write_vals),
            'ack_wait_ms': _stats(ack_vals),
            'total_ms':   _stats(total_vals),
        },
    }
    with open(sum_json, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\nRaw CSV → {raw_csv}")
    print(f"Summary → {sum_json}")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Experiment J (steady) — persistent connection at distance")
    p.add_argument('--address',     required=True)
    p.add_argument('--condition',   required=True)
    p.add_argument('--description', required=True)
    p.add_argument('--trials',  type=int, default=500)
    p.add_argument('--prefix',  default='JS_')
    args = p.parse_args()
    asyncio.run(run(args.address, args.condition, args.description,
                    args.trials, args.prefix))


if __name__ == '__main__':
    main()
