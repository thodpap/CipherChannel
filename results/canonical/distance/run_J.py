#!/usr/bin/env python3
"""
Experiment J — Distance and reliability
========================================
Key exchange is performed ONCE at the start (do this at close range before
moving to the test position).  Each trial then does:

  scan → connect → write encrypted command → poll ACK → disconnect

This isolates BLE connection reliability and command delivery at distance.
The server retains _phone_channel across disconnects so no re-keying is needed.

Per-trial metrics:
  scan_success, scan_ms
  connect_success, connect_ms
  write_success, write_ms
  ack_success, ack_wait_ms
  total_success, total_ms
  failure_stage, failure_reason

Server (RPi — start once, leave running across ALL conditions):
  BENCHMARK_PROVISIONING=1 \\
  EXPERIMENT_SERVER_CSV_PATH=/tmp/exp_J_server.csv \\
  server/.venv/bin/python server/ble_server.py

Run (laptop):
  client/.venv/bin/python results/canonical/distance/run_J.py \\
      --address B8:27:EB:07:01:22 \\
      --condition 2m_los \\
      --description "RPi on desk. Laptop 2 m away, clear line of sight." \\
      --trials 100

Important: the script does key exchange first, then prompts you to move to the
test position before starting trials.  Do NOT restart the server between conditions
— that would clear the server's phone channel and break encryption.

Resume: if raw.csv already exists, existing rows are counted and trials continue
from where they left off (key exchange is skipped on resume).
"""

import argparse
import asyncio
import csv
import json
import os
import statistics
import sys
import time
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
_INTER_TRIAL_DELAY = float(os.environ.get('EXPERIMENT_J_INTER_DELAY', '1.5'))

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

# ── CSV ───────────────────────────────────────────────────────────────────────

_CSV_COLUMNS = [
    'trial_id', 'condition',
    'scan_success',    'scan_ms',
    'connect_success', 'connect_ms',
    'write_success',   'write_ms',
    'ack_success',     'ack_wait_ms',
    'total_success',   'total_ms',
    'failure_stage',   'failure_reason',
]


class _TrialError(Exception):
    def __init__(self, stage: str, reason: str):
        self.stage  = stage
        self.reason = reason


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

# ── One-time key exchange ─────────────────────────────────────────────────────

async def _do_key_exchange(address: str, sess_path: str) -> CipherChannel:
    """Connect, exchange keys, disconnect. Returns ready phone_ch."""
    print("Key exchange — connecting at close range…")
    tp_path = sess_path + '_tp'

    device = await BleakScanner.find_device_by_address(address, timeout=_SCAN_TIMEOUT)
    if device is None:
        sys.exit(f"KEX: device {address} not found")

    client = BleakClient(device)
    await asyncio.wait_for(client.connect(), timeout=_CONNECT_TIMEOUT)
    if not client.is_connected:
        sys.exit("KEX: connect failed")

    h_sec, = _resolve_handles(client, SECURITY_UUID)
    transport_ch = CipherChannel.create(KEY, False, tp_path)

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

    await client.disconnect()
    try:
        os.remove(tp_path)
    except OSError:
        pass

    if k_phone is None:
        sys.exit("KEX: K_phone not received")

    phone_ch = CipherChannel.create(k_phone, True, sess_path)
    print("Key exchange done. Phone channel ready.\n")
    return phone_ch

# ── Single trial ──────────────────────────────────────────────────────────────

async def _run_trial(address: str, trial_id: str, condition: str,
                     phone_ch: CipherChannel) -> dict:
    row: dict = {c: '' for c in _CSV_COLUMNS}
    row.update({'trial_id': trial_id, 'condition': condition,
                'scan_success': False, 'connect_success': False,
                'write_success': False, 'ack_success': False,
                'total_success': False})

    _client: BleakClient | None = None
    t_start = time.perf_counter_ns()

    try:
        # ── Scan ──────────────────────────────────────────────────────────────
        t0     = time.perf_counter_ns()
        device = await BleakScanner.find_device_by_address(address, timeout=_SCAN_TIMEOUT)
        row['scan_ms'] = _ms(t0, time.perf_counter_ns())
        if device is None:
            raise _TrialError('scan', f'not found within {_SCAN_TIMEOUT} s')
        row['scan_success'] = True

        # ── Connect ───────────────────────────────────────────────────────────
        t0      = time.perf_counter_ns()
        _client = BleakClient(device)
        try:
            await asyncio.wait_for(_client.connect(), timeout=_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            row['connect_ms'] = _ms(t0, time.perf_counter_ns())
            raise _TrialError('connect', f'timeout after {_CONNECT_TIMEOUT} s')
        row['connect_ms'] = _ms(t0, time.perf_counter_ns())
        if not _client.is_connected:
            raise _TrialError('connect', 'is_connected=False after connect()')
        row['connect_success'] = True

        h_command, h_ack = _resolve_handles(_client, COMMAND_UUID, ACK_UUID)

        # ── Command write ─────────────────────────────────────────────────────
        payload   = json.dumps({"trial_id": trial_id, "action": "STAND_UP"}).encode()
        encrypted = phone_ch.send(payload)

        t0 = time.perf_counter_ns()
        try:
            await _client.write_gatt_char(h_command, encrypted, response=True)
        except Exception as e:
            row['write_ms'] = _ms(t0, time.perf_counter_ns())
            raise _TrialError('write', str(e))
        row['write_ms']      = _ms(t0, time.perf_counter_ns())
        row['write_success'] = True

        # ── ACK ───────────────────────────────────────────────────────────────
        expected = f"OK:{trial_id}".encode()
        t0       = time.perf_counter_ns()
        deadline = asyncio.get_event_loop().time() + _ACK_TIMEOUT
        acked    = False
        while asyncio.get_event_loop().time() < deadline:
            try:
                val = bytes(await _client.read_gatt_char(h_ack))
            except Exception as e:
                row['ack_wait_ms'] = _ms(t0, time.perf_counter_ns())
                raise _TrialError('ack', f'read error: {e}')
            if val == expected:
                acked = True
                break
            await asyncio.sleep(_ACK_POLL_INTERVAL)

        row['ack_wait_ms'] = _ms(t0, time.perf_counter_ns())
        if not acked:
            raise _TrialError('ack', f'timeout after {_ACK_TIMEOUT} s')
        row['ack_success']   = True
        row['total_success'] = True

    except _TrialError as e:
        row['failure_stage']  = e.stage
        row['failure_reason'] = e.reason

    except Exception as e:
        row['failure_stage']  = row.get('failure_stage') or 'unexpected'
        row['failure_reason'] = str(e)

    finally:
        row['total_ms'] = _ms(t_start, time.perf_counter_ns())
        if _client is not None:
            try:
                await _client.disconnect()
            except Exception:
                pass

    return row

# ── Main ──────────────────────────────────────────────────────────────────────

async def run(address: str, condition: str, description: str,
              trials: int, prefix: str) -> None:

    out_dir   = os.path.join(_THIS_DIR, condition)
    os.makedirs(out_dir, exist_ok=True)

    raw_csv   = os.path.join(out_dir, 'raw.csv')
    sum_json  = os.path.join(out_dir, 'summary.json')
    cond_json = os.path.join(out_dir, 'condition.json')
    sess_path = os.path.join(out_dir, 'phone_channel_state')

    # Resume support
    existing = 0
    if os.path.exists(raw_csv):
        with open(raw_csv, newline='') as f:
            existing = max(0, sum(1 for _ in f) - 1)
        if existing > 0:
            print(f"Resuming from trial {existing + 1} ({existing} rows exist)")
    else:
        with open(raw_csv, 'w', newline='') as f:
            csv.writer(f).writerow(_CSV_COLUMNS)

    with open(cond_json, 'w') as f:
        json.dump({
            'condition':   condition,
            'description': description,
            'address':     address,
            'n_trials':    trials,
            'date':        time.strftime('%Y-%m-%d'),
        }, f, indent=2)

    print(f"\n{'═' * 72}")
    print(f"Experiment J — Distance and reliability")
    print(f"Condition   : {condition}")
    print(f"Description : {description}")
    print(f"Target      : {address}")
    print(f"Trials      : {trials}")
    print(f"Output      : {out_dir}")
    print(f"{'═' * 72}\n")

    # Key exchange (skip on resume — channel state file already exists)
    if existing == 0 or not os.path.exists(sess_path):
        phone_ch = await _do_key_exchange(address, sess_path)
        input("Move to test position, then press ENTER to start trials…")
    else:
        print("Resuming — loading existing phone channel state…")
        phone_ch = CipherChannel.load(sess_path)
        if phone_ch is None:
            sys.exit("Failed to load phone channel state. Delete raw.csv and restart.")

    # Per-stage accumulators
    stage_ms: dict[str, list[float]] = {
        'scan': [], 'connect': [], 'write': [], 'ack': [], 'total': []
    }
    stage_ok: dict[str, int]        = {s: 0 for s in stage_ms}
    stage_att: dict[str, int]       = {s: 0 for s in stage_ms}
    failure_counts: dict[str, int]  = {}

    for i in range(existing + 1, trials + 1):
        trial_id = f"{prefix}{i:04d}"
        print(f"  [{i:4d}/{trials}]  {trial_id}", end='  ', flush=True)

        row = await _run_trial(address, trial_id, condition, phone_ch)

        with open(raw_csv, 'a', newline='') as f:
            csv.writer(f).writerow([row.get(c, '') for c in _CSV_COLUMNS])

        for stage, ms_col, ok_col in [
            ('scan',    'scan_ms',    'scan_success'),
            ('connect', 'connect_ms', 'connect_success'),
            ('write',   'write_ms',   'write_success'),
            ('ack',     'ack_wait_ms','ack_success'),
        ]:
            v = row.get(ms_col, '')
            if v not in ('', None):
                stage_att[stage] += 1
                stage_ms[stage].append(float(v))
            if row.get(ok_col):
                stage_ok[stage] += 1

        stage_att['total'] += 1
        if row.get('total_success'):
            stage_ok['total'] += 1
            v = row.get('total_ms', '')
            if v not in ('', None):
                stage_ms['total'].append(float(v))
        else:
            fs = row.get('failure_stage') or 'unknown'
            failure_counts[fs] = failure_counts.get(fs, 0) + 1

        if row.get('total_success'):
            print(
                f"OK  scan={row.get('scan_ms','?'):.0f}  "
                f"conn={row.get('connect_ms','?'):.0f}  "
                f"wrt={row.get('write_ms','?'):.0f}  "
                f"ack={row.get('ack_wait_ms','?'):.0f}  "
                f"tot={row.get('total_ms','?'):.0f} ms"
            )
        else:
            print(f"FAIL [{row.get('failure_stage','?')}] {row.get('failure_reason','?')}")

        if i < trials:
            await asyncio.sleep(_INTER_TRIAL_DELAY)

    # ── Summary ───────────────────────────────────────────────────────────────
    n_total   = stage_att['total']
    n_success = stage_ok['total']

    print(f"\n{'═' * 72}")
    print(f"Condition: {condition}   {n_success}/{n_total} total success "
          f"({100*n_success/n_total:.1f}%)" if n_total else "")

    stages_out: dict = {}
    for stage in ['scan', 'connect', 'write', 'ack', 'total']:
        att = stage_att[stage]
        ok  = stage_ok[stage]
        st  = _stats(stage_ms[stage])
        stages_out[stage] = {
            'attempted':  att,
            'success':    ok,
            'rate':       f'{100*ok/att:.1f}%' if att else 'N/A',
            'latency_ms': st,
        }

    summary = {
        'condition':        condition,
        'description':      description,
        'n_trials':         n_total,
        'n_success':        n_success,
        'success_rate':     f'{100*n_success/n_total:.1f}%' if n_total else '0%',
        'stages':           stages_out,
        'failures_by_stage': failure_counts,
    }
    with open(sum_json, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\nRaw CSV → {raw_csv}")
    print(f"Summary → {sum_json}")

    # Clean up phone channel state file after completing all trials
    try:
        os.remove(sess_path)
    except OSError:
        pass


def main() -> None:
    p = argparse.ArgumentParser(description="Experiment J — distance and reliability")
    p.add_argument('--address',     required=True)
    p.add_argument('--condition',   required=True,
                   help="Label for this condition, e.g. 2m_los or 4m_wall")
    p.add_argument('--description', required=True,
                   help="Setup description for reproducibility")
    p.add_argument('--trials',  type=int, default=100)
    p.add_argument('--prefix',  default='J_')
    args = p.parse_args()
    asyncio.run(run(args.address, args.condition, args.description,
                    args.trials, args.prefix))


if __name__ == '__main__':
    main()
