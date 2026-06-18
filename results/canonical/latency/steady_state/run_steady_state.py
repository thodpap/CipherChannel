#!/usr/bin/env python3
"""
Experiment G — Steady-state command/ACK latency (N=1000)
=========================================================
Connection already established, operational key already provisioned.
Sends N commands over a single BLE connection and measures per-command latency.

Per-command timing:
  client_encrypt_ms : CipherChannel.send() — AES-256-GCM encryption + fsync state
                      persist (inseparable via public API; fsync on tmpfs ≈ 0 ms).
  client_write_ms   : write_gatt_char() RTT — BLE ATT Write Request + Write Response.
  ack_wait_ms       : from after write_gatt_char returns until "OK:{trial_id}" is seen
                      in ACK_UUID (polled at 20 ms intervals).
  command_to_ack_ms : from encrypt_start to ACK received (client_encrypt_ms +
                      client_write_ms + ack_wait_ms, plus OS scheduling jitter).
  success           : True if "OK:{trial_id}" received within ACK_TIMEOUT seconds.

Fixed inter-command interval: 100 ms after ACK is received (same as Experiment B).

Run:
  EXPERIMENT_G_CSV_PATH=results/canonical/latency/steady_state/steady_state_raw.csv \
  client/.venv/bin/python results/canonical/latency/steady_state/run_steady_state.py \
    --address B8:27:EB:07:01:22 --trials 1000

Server must be running (BENCHMARK_PROVISIONING=1 on RPi):
  BENCHMARK_PROVISIONING=1 \
  EXPERIMENT_SERVER_CSV_PATH=/tmp/exp_G_server.csv \
  server/.venv/bin/python server/ble_server.py
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
    sys.exit("bleak not installed — run: pip install bleak  (or activate client/.venv)")

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

_ENCRYPTED_KEY_LEN  = 60
_SCAN_TIMEOUT       = 10.0


def _resolve_handles(client: BleakClient, *uuids: str) -> tuple:
    """
    Return GATT characteristic handles for each uuid.
    Works even when BlueZ has stale duplicate registrations from a previous server
    run — picks the first match and uses the integer handle, bypassing the UUID
    uniqueness check that raises BleakError.
    """
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
            raise RuntimeError(f"Characteristic {uuid} not found in discovered services")
        result.append(handle)
    return tuple(result)
_CONNECT_TIMEOUT    = 15.0
_KEY_POLL_INTERVAL  = 0.05
_KEY_TIMEOUT        = 8.0
_ACK_POLL_INTERVAL  = 0.020   # 20 ms
_ACK_TIMEOUT        = 10.0
_INTER_CMD_DELAY    = 0.10    # 100 ms between commands (same as Exp B)

_THIS_DIR  = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV = os.environ.get(
    'EXPERIMENT_G_CSV_PATH',
    os.path.join(_THIS_DIR, 'steady_state_raw.csv'),
)

_CSV_COLUMNS = [
    'trial_id', 'action', 't_sent_ns',
    'client_encrypt_ms', 'client_write_ms', 'ack_wait_ms',
    'command_to_ack_ms',
    'success', 'error',
]
_SETUP_COLUMNS = ['scan_ms', 'connect_ms', 'key_exchange_ms']


def _ms(t0: int, t1: int) -> float:
    return round((t1 - t0) / 1e6, 3)


def _init_csv() -> None:
    header = ['trial_id', 'action', 't_sent_ns',
               'scan_ms', 'connect_ms', 'key_exchange_ms',
               'client_encrypt_ms', 'client_write_ms', 'ack_wait_ms',
               'command_to_ack_ms', 'success', 'error']
    with open(OUTPUT_CSV, 'w', newline='') as f:
        csv.writer(f).writerow(header)


def _append_setup_row(trial_id: str, action: str, t_sent_ns: int,
                       scan_ms: float, connect_ms: float, kex_ms: float) -> None:
    """Write trial 1 row with setup columns populated."""
    with open(OUTPUT_CSV, 'a', newline='') as f:
        csv.writer(f).writerow([
            trial_id, action, t_sent_ns,
            scan_ms, connect_ms, kex_ms,
            '', '', '', '', '', '',
        ])


def _append_cmd_row(row: dict) -> None:
    with open(OUTPUT_CSV, 'a', newline='') as f:
        csv.writer(f).writerow([
            row.get('trial_id', ''), row.get('action', ''), row.get('t_sent_ns', ''),
            '', '', '',
            row.get('client_encrypt_ms', ''), row.get('client_write_ms', ''),
            row.get('ack_wait_ms', ''), row.get('command_to_ack_ms', ''),
            row.get('success', False), row.get('error', ''),
        ])


# ── Summary ───────────────────────────────────────────────────────────────────

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


# ── Main experiment ───────────────────────────────────────────────────────────

async def run(address: str, trials: int, action: str, prefix: str) -> None:
    _init_csv()

    print(f"\nExperiment G — Steady-state command/ACK latency  (N={trials})")
    print(f"Target  : {address}")
    print(f"Action  : {action!r}")
    print(f"Output  : {OUTPUT_CSV}")
    print(f"Inter-command delay: {_INTER_CMD_DELAY * 1000:.0f} ms\n")

    # ── 1. Scan ───────────────────────────────────────────────────────────────
    print("Scanning…", end=' ', flush=True)
    t0 = time.perf_counter_ns()
    device = await BleakScanner.find_device_by_address(address, timeout=_SCAN_TIMEOUT)
    scan_ms = _ms(t0, time.perf_counter_ns())
    if device is None:
        print(f"FAIL — device not found within {_SCAN_TIMEOUT} s")
        return
    print(f"found in {scan_ms:.0f} ms")

    # ── 2. Connect ────────────────────────────────────────────────────────────
    print("Connecting…", end=' ', flush=True)
    t0 = time.perf_counter_ns()
    client = BleakClient(device)
    try:
        await asyncio.wait_for(client.connect(), timeout=_CONNECT_TIMEOUT)
    except asyncio.TimeoutError:
        print(f"FAIL — connect timeout after {_CONNECT_TIMEOUT} s")
        return
    connect_ms = _ms(t0, time.perf_counter_ns())
    if not client.is_connected:
        print("FAIL — is_connected=False after connect()")
        return
    print(f"connected in {connect_ms:.0f} ms")

    # Resolve handles once — avoids BleakError when BlueZ has stale duplicate UUIDs
    h_security, h_command, h_ack = _resolve_handles(
        client, SECURITY_UUID, COMMAND_UUID, ACK_UUID)

    try:
        # ── 3. Key exchange (once) ────────────────────────────────────────────
        print("Key exchange…", end=' ', flush=True)
        session_id   = _uuid_mod.uuid4().hex[:12]
        transport_path = f'/tmp/cc_G_transport_{session_id}'
        session_path   = f'/tmp/cc_G_session_{session_id}'

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
            print(f"FAIL — no K_phone within {_KEY_TIMEOUT} s")
            return
        print(f"done in {kex_ms:.0f} ms\n")

        phone_ch = CipherChannel.create(k_phone, True, session_path)

        # Write setup row (trial_id placeholder; we record setup on trial 1 row)
        setup_written = False

        # ── 4. Command loop ───────────────────────────────────────────────────
        ok = fail = 0
        enc_times: list[float] = []
        wrt_times: list[float] = []
        ack_times: list[float] = []
        c2a_times: list[float] = []

        for i in range(1, trials + 1):
            trial_id = f"{prefix}{i:04d}"
            row: dict = {'trial_id': trial_id, 'action': action, 'success': False}

            print(f"  [{i:4d}/{trials}]  {trial_id}", end='  ', flush=True)

            payload = json.dumps({"trial_id": trial_id, "action": action}).encode()

            # Encrypt + state persist
            t_enc = time.perf_counter_ns()
            try:
                encrypted = phone_ch.send(payload)
            except ChannelException as e:
                row['error'] = f"encrypt:{e}"
                _append_cmd_row(row)
                fail += 1
                print(f"FAIL  encrypt: {e}")
                break
            row['t_sent_ns']         = time.perf_counter_ns()
            row['client_encrypt_ms'] = _ms(t_enc, time.perf_counter_ns())

            # BLE write
            t_write = time.perf_counter_ns()
            try:
                await client.write_gatt_char(h_command, encrypted, response=True)
            except Exception as e:
                row['client_write_ms'] = _ms(t_write, time.perf_counter_ns())
                row['error'] = f"write:{e}"
                _append_cmd_row(row)
                fail += 1
                print(f"FAIL  write: {e}")
                break
            row['client_write_ms'] = _ms(t_write, time.perf_counter_ns())

            # ACK poll
            expected = f"OK:{trial_id}".encode()
            deadline = asyncio.get_event_loop().time() + _ACK_TIMEOUT
            t_ack    = time.perf_counter_ns()
            acked    = False
            while asyncio.get_event_loop().time() < deadline:
                try:
                    val = bytes(await client.read_gatt_char(h_ack))
                except Exception as e:
                    row['ack_wait_ms'] = _ms(t_ack, time.perf_counter_ns())
                    row['error'] = f"ack_read:{e}"
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
                row['error'] = f'ACK timeout after {_ACK_TIMEOUT} s'

            # Write row (setup cols only on first trial)
            if not setup_written:
                _append_setup_row(trial_id, action, row.get('t_sent_ns', ''),
                                   scan_ms, connect_ms, kex_ms)
                setup_written = True
            else:
                _append_cmd_row(row)

            if row['success']:
                ok += 1
                enc_times.append(row['client_encrypt_ms'])
                wrt_times.append(row['client_write_ms'])
                ack_times.append(row['ack_wait_ms'])
                c2a_times.append(row['command_to_ack_ms'])
                print(
                    f"OK  "
                    f"enc={row['client_encrypt_ms']:.2f}  "
                    f"wrt={row['client_write_ms']:.0f}  "
                    f"ack={row['ack_wait_ms']:.0f}  "
                    f"c2a={row['command_to_ack_ms']:.0f} ms"
                )
            else:
                fail += 1
                print(f"FAIL  {row.get('error', '?')}")
                if row.get('error', '').startswith(('write:', 'ack_read:')):
                    break  # likely disconnected — stop

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

    # ── Summary ───────────────────────────────────────────────────────────────
    total = ok + fail
    print(f"\n{'═' * 70}")
    print(f"Setup   : scan={scan_ms:.0f} ms  connect={connect_ms:.0f} ms  kex={kex_ms:.0f} ms")
    print(f"Trials  : {ok}/{total} successful")
    if enc_times:
        for label, vals in [
            ('encrypt+persist', enc_times),
            ('write (ATT)',     wrt_times),
            ('ack wait',        ack_times),
            ('command-to-ack',  c2a_times),
        ]:
            st = _stats(vals)
            if st:
                print(
                    f"  {label:<22} mean={st['mean']:6.2f}  median={st['median']:6.2f}"
                    f"  p95={st['p95']:6.2f}  max={st['max']:6.2f} ms"
                )

    import json as _json
    summary = {
        'setup': {'scan_ms': scan_ms, 'connect_ms': connect_ms, 'kex_ms': kex_ms},
        'trials': {'total': total, 'success': ok, 'failure': fail},
        'phases': {
            'client_encrypt_ms': _stats(enc_times),
            'client_write_ms':   _stats(wrt_times),
            'ack_wait_ms':       _stats(ack_times),
            'command_to_ack_ms': _stats(c2a_times),
        },
    }
    summary_path = OUTPUT_CSV.replace('.csv', '_summary.json')
    with open(summary_path, 'w') as f:
        _json.dump(summary, f, indent=2)

    print(f"\nCSV     → {OUTPUT_CSV}")
    print(f"Summary → {summary_path}")
    print(f"Server CSV (on RPi): /tmp/exp_G_server.csv")
    print(f"  Fetch: ssh rpi 'cat /tmp/exp_G_server.csv' > "
          f"results/canonical/latency/steady_state/steady_state_server_raw.csv")


def main() -> None:
    p = argparse.ArgumentParser(description="Experiment G — steady-state command/ACK latency")
    p.add_argument('--address', required=True, help="RPi BLE MAC address")
    p.add_argument('--trials',  type=int, default=1000)
    p.add_argument('--action',  default='STAND_UP')
    p.add_argument('--prefix',  default='G_')
    args = p.parse_args()
    asyncio.run(run(args.address, args.trials, args.action, args.prefix))


if __name__ == '__main__':
    main()
