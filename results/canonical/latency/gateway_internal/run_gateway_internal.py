#!/usr/bin/env python3
"""
Experiment H — Gateway internal stage timing (client side, N=1000)
===================================================================
Sends N=1000 commands to the INSTRUMENTED server (ble_server_instrumented.py)
over a single steady-state BLE connection.  The server records per-stage
nanosecond timestamps (T0–T7) in /tmp/gateway_internal.csv.

This client is functionally identical to Experiment G's steady-state client.
The difference is which server binary runs on the RPi.

Steps:
  1. Run ble_server_instrumented.py on the RPi (see prerequisite below)
  2. Run this client on the laptop
  3. After completion, fetch the server gateway CSV:
       ssh rpi 'cat /tmp/gateway_internal.csv' > \
         results/canonical/latency/gateway_internal/gateway_internal_server_raw.csv
  4. Run the summary script to compute gateway statistics:
       python3 results/canonical/latency/gateway_internal/compute_gateway_summary.py

Prerequisite — instrumented server on RPi:
  BENCHMARK_PROVISIONING=1 \
  EXPERIMENT_GATEWAY_CSV_PATH=/tmp/gateway_internal.csv \
  EXPERIMENT_SERVER_CSV_PATH=/tmp/exp_H_server.csv \
  server/.venv/bin/python server/ble_server_instrumented.py

Run:
  client/.venv/bin/python \
    results/canonical/latency/gateway_internal/run_gateway_internal.py \
    --address B8:27:EB:07:01:22 --trials 1000
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

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
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
_SCAN_TIMEOUT      = 10.0


def _resolve_handles(client: BleakClient, *uuids: str) -> tuple:
    """Return GATT handles for each uuid, picking first match to survive BlueZ duplicate registrations."""
    result = []
    for uuid in uuids:
        uuid_lower = uuid.lower()
        handle = None
        for service in client.services:
            for char in service.characteristics:
                if char.uuid.lower() == uuid_lower:
                    handle = char.handle
                    break
            if handle is not None:
                break
        if handle is None:
            raise RuntimeError(f"Characteristic {uuid} not found")
        result.append(handle)
    return tuple(result)
_CONNECT_TIMEOUT   = 15.0
_KEY_POLL_INTERVAL = 0.05
_KEY_TIMEOUT       = 8.0
_ACK_POLL_INTERVAL = 0.020
_ACK_TIMEOUT       = 10.0
_INTER_CMD_DELAY   = 0.10

_THIS_DIR  = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV = os.environ.get(
    'EXPERIMENT_H_CLIENT_CSV_PATH',
    os.path.join(_THIS_DIR, 'gateway_client_raw.csv'),
)

_CSV_HEADER = [
    'trial_id', 'action', 't_sent_ns',
    'scan_ms', 'connect_ms', 'key_exchange_ms',
    'client_encrypt_ms', 'client_write_ms', 'ack_wait_ms',
    'command_to_ack_ms', 'success', 'error',
]


def _ms(t0: int, t1: int) -> float:
    return round((t1 - t0) / 1e6, 3)


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


async def run(address: str, trials: int, action: str, prefix: str) -> None:
    with open(OUTPUT_CSV, 'w', newline='') as f:
        csv.writer(f).writerow(_CSV_HEADER)

    print(f"\nExperiment H — Gateway internal timing client  (N={trials})")
    print(f"Target  : {address}")
    print(f"IMPORTANT: ensure ble_server_instrumented.py is running on the RPi!")
    print(f"Output  : {OUTPUT_CSV}\n")

    # Scan
    print("Scanning…", end=' ', flush=True)
    t0 = time.perf_counter_ns()
    device = await BleakScanner.find_device_by_address(address, timeout=_SCAN_TIMEOUT)
    scan_ms = _ms(t0, time.perf_counter_ns())
    if device is None:
        print(f"FAIL — not found within {_SCAN_TIMEOUT} s"); return
    print(f"found in {scan_ms:.0f} ms")

    # Connect
    print("Connecting…", end=' ', flush=True)
    t0 = time.perf_counter_ns()
    client = BleakClient(device)
    try:
        await asyncio.wait_for(client.connect(), timeout=_CONNECT_TIMEOUT)
    except asyncio.TimeoutError:
        print(f"FAIL — timeout"); return
    connect_ms = _ms(t0, time.perf_counter_ns())
    if not client.is_connected:
        print("FAIL — not connected"); return
    print(f"connected in {connect_ms:.0f} ms")

    # Resolve handles — avoids BleakError on stale BlueZ duplicate UUIDs
    h_security, h_command, h_ack = _resolve_handles(
        client, SECURITY_UUID, COMMAND_UUID, ACK_UUID)

    try:
        # Key exchange (once)
        print("Key exchange…", end=' ', flush=True)
        session_id     = _uuid_mod.uuid4().hex[:12]
        transport_path = f'/tmp/cc_H_tp_{session_id}'
        session_path   = f'/tmp/cc_H_sess_{session_id}'

        t0 = time.perf_counter_ns()
        transport_ch = CipherChannel.create(KEY, False, transport_path)
        await client.write_gatt_char(h_security, b"REQUEST_KEY", response=True)

        k_phone = None
        deadline = asyncio.get_event_loop().time() + _KEY_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            raw = bytes(await client.read_gatt_char(h_security))
            if len(raw) == _ENCRYPTED_KEY_LEN:
                k_phone = transport_ch.receive(raw)
                if k_phone and len(k_phone) == 32:
                    break
                k_phone = None
            await asyncio.sleep(_KEY_POLL_INTERVAL)

        kex_ms = _ms(t0, time.perf_counter_ns())
        if k_phone is None:
            print(f"FAIL — no K_phone"); return
        print(f"done in {kex_ms:.0f} ms\n")

        phone_ch = CipherChannel.create(k_phone, True, session_path)
        setup_written = False

        ok = fail = 0
        enc_vals: list[float] = []
        wrt_vals: list[float] = []
        ack_vals: list[float] = []
        c2a_vals: list[float] = []

        for i in range(1, trials + 1):
            trial_id = f"{prefix}{i:04d}"
            row: dict = {'trial_id': trial_id, 'action': action, 'success': False}
            print(f"  [{i:4d}/{trials}]  {trial_id}", end='  ', flush=True)

            payload   = json.dumps({"trial_id": trial_id, "action": action}).encode()
            t_enc     = time.perf_counter_ns()
            encrypted = phone_ch.send(payload)
            row['t_sent_ns']         = time.perf_counter_ns()
            row['client_encrypt_ms'] = _ms(t_enc, time.perf_counter_ns())

            t_write = time.perf_counter_ns()
            try:
                await client.write_gatt_char(h_command, encrypted, response=True)
            except Exception as e:
                row['client_write_ms'] = _ms(t_write, time.perf_counter_ns())
                row['error'] = f"write:{e}"
                _append_csv_row(OUTPUT_CSV, row, _CSV_HEADER,
                                scan_ms if not setup_written else None,
                                connect_ms if not setup_written else None,
                                kex_ms if not setup_written else None)
                setup_written = True
                fail += 1
                print(f"FAIL  {e}"); break
            row['client_write_ms'] = _ms(t_write, time.perf_counter_ns())

            expected = f"OK:{trial_id}".encode()
            deadline = asyncio.get_event_loop().time() + _ACK_TIMEOUT
            t_ack    = time.perf_counter_ns()
            acked    = False
            while asyncio.get_event_loop().time() < deadline:
                try:
                    val = bytes(await client.read_gatt_char(h_ack))
                except Exception as e:
                    row['ack_wait_ms'] = _ms(t_ack, time.perf_counter_ns())
                    row['error'] = f"ack:{e}"
                    break
                if val == expected:
                    row['ack_wait_ms']       = _ms(t_ack, time.perf_counter_ns())
                    row['command_to_ack_ms'] = _ms(t_enc, time.perf_counter_ns())
                    row['success']           = True
                    acked = True
                    break
                await asyncio.sleep(_ACK_POLL_INTERVAL)

            if not acked and not row.get('error'):
                row['ack_wait_ms'] = _ms(t_ack, time.perf_counter_ns())
                row['error'] = 'ACK timeout'

            _append_csv_row(OUTPUT_CSV, row, _CSV_HEADER,
                            scan_ms if not setup_written else None,
                            connect_ms if not setup_written else None,
                            kex_ms if not setup_written else None)
            setup_written = True

            if row['success']:
                ok += 1
                enc_vals.append(row['client_encrypt_ms'])
                wrt_vals.append(row['client_write_ms'])
                ack_vals.append(row['ack_wait_ms'])
                c2a_vals.append(row['command_to_ack_ms'])
                print(
                    f"OK  enc={row['client_encrypt_ms']:.2f}  "
                    f"wrt={row['client_write_ms']:.0f}  "
                    f"ack={row['ack_wait_ms']:.0f}  "
                    f"c2a={row['command_to_ack_ms']:.0f} ms"
                )
            else:
                fail += 1
                print(f"FAIL  {row.get('error', '?')}")

            if i < trials:
                await asyncio.sleep(_INTER_CMD_DELAY)

    finally:
        try:
            os.remove(transport_path)
        except OSError:
            pass
        try:
            await client.disconnect()
        except Exception:
            pass

    print(f"\n{'═' * 70}")
    print(f"Results : {ok}/{ok+fail} successful")
    for label, vals in [('client_encrypt_ms', enc_vals), ('client_write_ms', wrt_vals),
                         ('ack_wait_ms', ack_vals), ('command_to_ack_ms', c2a_vals)]:
        st = _stats(vals)
        if st:
            print(f"  {label:<22} median={st['median']:6.2f} mean={st['mean']:6.2f}"
                  f" p95={st['p95']:6.2f} ms")

    import json as _json
    summary = {'setup': {'scan_ms': scan_ms, 'connect_ms': connect_ms, 'kex_ms': kex_ms},
               'trials': {'total': ok+fail, 'success': ok, 'failure': fail},
               'phases': {'client_encrypt_ms': _stats(enc_vals),
                           'client_write_ms': _stats(wrt_vals),
                           'ack_wait_ms': _stats(ack_vals),
                           'command_to_ack_ms': _stats(c2a_vals)}}
    sp = OUTPUT_CSV.replace('.csv', '_summary.json')
    with open(sp, 'w') as f:
        _json.dump(summary, f, indent=2)

    print(f"\nClient CSV  → {OUTPUT_CSV}")
    print(f"Summary     → {sp}")
    print(f"\nNow fetch the gateway CSV from the RPi:")
    print(f"  ssh rpi 'cat /tmp/gateway_internal.csv' > \\")
    print(f"    results/canonical/latency/gateway_internal/gateway_internal_server_raw.csv")
    print(f"\nThen run:")
    print(f"  python3 results/canonical/latency/gateway_internal/compute_gateway_summary.py")


def _append_csv_row(path: str, row: dict, header: list,
                     scan_ms, connect_ms, kex_ms) -> None:
    with open(path, 'a', newline='') as f:
        csv.writer(f).writerow([
            row.get('trial_id', ''),
            row.get('action', ''),
            row.get('t_sent_ns', ''),
            scan_ms    if scan_ms    is not None else '',
            connect_ms if connect_ms is not None else '',
            kex_ms     if kex_ms     is not None else '',
            row.get('client_encrypt_ms', ''),
            row.get('client_write_ms', ''),
            row.get('ack_wait_ms', ''),
            row.get('command_to_ack_ms', ''),
            row.get('success', False),
            row.get('error', ''),
        ])


def main() -> None:
    p = argparse.ArgumentParser(description="Experiment H client — gateway internal timing")
    p.add_argument('--address', required=True)
    p.add_argument('--trials',  type=int, default=1000)
    p.add_argument('--action',  default='STAND_UP')
    p.add_argument('--prefix',  default='H_')
    args = p.parse_args()
    asyncio.run(run(args.address, args.trials, args.action, args.prefix))


if __name__ == '__main__':
    main()
