#!/usr/bin/env python3
"""
Experiment I — Key-exchange latency (N=500)
===========================================
Measures per-stage timing of the phone key exchange for every trial.
ESP32 auto-send is off; BENCHMARK_PROVISIONING=1 is required on the server.
Physical button reaction time is excluded by design — the benchmark gate
opens immediately without human input.

Per-trial pipeline:
  scan → connect → key exchange → disconnect  (no command/ACK sent)

Key-exchange stages timed on the client side:
  request_write_ms   : write_gatt_char(SECURITY_UUID, b"REQUEST_KEY") RTT
  server_process_ms  : from REQUEST_KEY write completion until the first poll
                       that returns 60 bytes (includes server crypto + BLE char
                       notification latency — cannot be split without RPi instrumentation)
  decrypt_ms         : transport_ch.receive(raw) — AES-256-GCM auth+decrypt +
                       state fsync on client
  state_init_ms      : CipherChannel.create(k_phone, True, path) — AES state file write
  kex_total_ms       : from t_request_sent to secure_channel_ready
                       (= request_write + server_process + decrypt + state_init)

Stage definitions:
  t_request_sent     : after write_gatt_char(REQUEST_KEY) returns (request delivered)
  t_key_available    : first poll read that returns 60 bytes (encrypted K_phone in char)
                       ≡ "encrypted_key_available" and "encrypted_key_received" — cannot
                       distinguish via polling; poll interval is 20 ms
  t_key_decrypted    : after transport_ch.receive() returns K_phone
  t_state_initialized: after CipherChannel.create(k_phone, ...) completes
  t_secure_channel_ready ≡ t_state_initialized

Note on excluded button latency: BenchmarkProvisioningGate.try_provision() returns
True immediately.  Production latency would add the physical button press delay
(human reaction time, typically 200–500 ms) on top of kex_total_ms.

Resume support: if the output CSV exists, the script counts existing rows and
restarts from that index (append mode).

Run:
  client/.venv/bin/python results/canonical/latency/key_exchange/run_key_exchange.py \
    --address B8:27:EB:07:01:22 --trials 500

Server (RPi):
  BENCHMARK_PROVISIONING=1 \
  EXPERIMENT_SERVER_CSV_PATH=/tmp/exp_I_server.csv \
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
    sys.exit("bleak not installed — activate client/.venv")

# ── Configuration ─────────────────────────────────────────────────────────────

SECURITY_UUID = "FEC26EC4-6D71-4442-9F81-55BC21D658D6"

KEY: bytes = (
    b'\x2a\xc3\x2c\x36\x73\xa4\xa2\xee'
    b'\x49\x08\x53\x3e\xd0\xff\x25\x84'
    b'\xba\xe9\x95\xca\x4e\x4c\xff\x7a'
    b'\x4c\x25\x68\x04\x29\x04\x25\xf8'
)

_ENCRYPTED_KEY_LEN = 60
_SCAN_TIMEOUT      = 10.0


def _resolve_handle(client: BleakClient, uuid: str) -> int:
    """Return GATT handle for uuid, picking first match to survive BlueZ duplicate registrations."""
    uuid_lower = uuid.lower()
    for service in client.services:
        for char in service.characteristics:
            if char.uuid.lower() == uuid_lower:
                return char.handle
    raise RuntimeError(f"Characteristic {uuid} not found")
_CONNECT_TIMEOUT   = 15.0
_KEY_POLL_INTERVAL = 0.020   # 20 ms — short for accurate t_key_available timing
_KEY_TIMEOUT       = 8.0
_INTER_TRIAL_DELAY = 1.0

_THIS_DIR  = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV = os.environ.get(
    'EXPERIMENT_I_CSV_PATH',
    os.path.join(_THIS_DIR, 'key_exchange_raw.csv'),
)

_CSV_COLUMNS = [
    'trial_id',
    'scan_ms', 'connect_ms',
    'request_write_ms', 'server_process_ms',
    'decrypt_ms', 'state_init_ms',
    'kex_total_ms',
    't_request_sent_ns', 't_key_available_ns',
    't_key_decrypted_ns', 't_state_initialized_ns',
    'success', 'failure_stage', 'failure_reason',
]


def _ms(t0: int, t1: int) -> float:
    return round((t1 - t0) / 1e6, 3)


def _init_csv() -> None:
    with open(OUTPUT_CSV, 'w', newline='') as f:
        csv.writer(f).writerow(_CSV_COLUMNS)


def _append_row(row: dict) -> None:
    with open(OUTPUT_CSV, 'a', newline='') as f:
        csv.writer(f).writerow([row.get(c, '') for c in _CSV_COLUMNS])


def _count_existing() -> int:
    if not os.path.exists(OUTPUT_CSV):
        return 0
    with open(OUTPUT_CSV, newline='') as f:
        return max(0, sum(1 for _ in f) - 1)


class _TrialError(Exception):
    def __init__(self, stage: str, reason: str) -> None:
        self.stage  = stage
        self.reason = reason


async def _run_trial(address: str, trial_id: str) -> dict:
    row: dict = {c: '' for c in _CSV_COLUMNS}
    row.update({'trial_id': trial_id, 'success': False})

    transport_path = f'/tmp/cc_I_tp_{_uuid_mod.uuid4().hex[:8]}'
    session_path   = f'/tmp/cc_I_sess_{_uuid_mod.uuid4().hex[:8]}'
    _client: BleakClient | None = None

    t_kex_start = time.perf_counter_ns()   # for kex_total_ms denominator

    try:
        # ── Scan ──────────────────────────────────────────────────────────────
        t0 = time.perf_counter_ns()
        device = await BleakScanner.find_device_by_address(address, timeout=_SCAN_TIMEOUT)
        row['scan_ms'] = _ms(t0, time.perf_counter_ns())
        if device is None:
            raise _TrialError('scan', f'not found within {_SCAN_TIMEOUT} s')

        # ── Connect ───────────────────────────────────────────────────────────
        t0 = time.perf_counter_ns()
        _client = BleakClient(device)
        try:
            await asyncio.wait_for(_client.connect(), timeout=_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            row['connect_ms'] = _ms(t0, time.perf_counter_ns())
            raise _TrialError('connect', f'timeout after {_CONNECT_TIMEOUT} s')
        row['connect_ms'] = _ms(t0, time.perf_counter_ns())
        if not _client.is_connected:
            raise _TrialError('connect', 'is_connected=False after connect()')

        # Resolve handle — avoids BleakError on stale BlueZ duplicate UUIDs
        h_security = _resolve_handle(_client, SECURITY_UUID)

        # ── Key exchange — stage 1: write REQUEST_KEY ─────────────────────────
        transport_ch = CipherChannel.create(KEY, False, transport_path)

        t_req_start = time.perf_counter_ns()
        await _client.write_gatt_char(h_security, b"REQUEST_KEY", response=True)
        t_request_sent = time.perf_counter_ns()
        row['t_request_sent_ns']  = t_request_sent
        row['request_write_ms']   = _ms(t_req_start, t_request_sent)

        # ── Key exchange — stage 2: poll until 60-byte encrypted K_phone ──────
        k_phone: bytes | None = None
        deadline = asyncio.get_event_loop().time() + _KEY_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            raw = bytes(await _client.read_gatt_char(h_security))
            if len(raw) == _ENCRYPTED_KEY_LEN:
                # Don't decrypt yet — just record the availability timestamp
                t_key_available = time.perf_counter_ns()
                row['t_key_available_ns'] = t_key_available
                row['server_process_ms']  = _ms(t_request_sent, t_key_available)
                # Now decrypt
                t_dec_start = time.perf_counter_ns()
                k_phone = transport_ch.receive(raw)
                t_key_decrypted = time.perf_counter_ns()
                row['t_key_decrypted_ns'] = t_key_decrypted
                row['decrypt_ms']          = _ms(t_dec_start, t_key_decrypted)
                if k_phone and len(k_phone) == 32:
                    break
                # Rare: wrong length or auth fail — keep polling
                k_phone = None
            await asyncio.sleep(_KEY_POLL_INTERVAL)

        if k_phone is None:
            raise _TrialError('key_exchange', f'no valid K_phone within {_KEY_TIMEOUT} s')

        # ── Key exchange — stage 3: initialise secure channel ─────────────────
        t_init_start = time.perf_counter_ns()
        phone_ch = CipherChannel.create(k_phone, True, session_path)
        t_state_initialized = time.perf_counter_ns()
        row['t_state_initialized_ns'] = t_state_initialized
        row['state_init_ms']           = _ms(t_init_start, t_state_initialized)

        # kex_total_ms: from REQUEST_KEY write start to secure_channel_ready
        row['kex_total_ms'] = _ms(t_req_start, t_state_initialized)
        row['success']      = True

    except _TrialError as e:
        row['failure_stage']  = e.stage
        row['failure_reason'] = e.reason

    except Exception as e:
        row['failure_stage']  = row.get('failure_stage') or 'unexpected'
        row['failure_reason'] = str(e)

    finally:
        if _client is not None:
            try:
                await _client.disconnect()
            except Exception:
                pass
        for p in (transport_path, session_path):
            try:
                os.remove(p)
            except OSError:
                pass

    return row


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


async def run(address: str, trials: int, prefix: str) -> None:
    existing = _count_existing()
    if existing > 0:
        print(f"Resuming from trial {existing + 1} ({existing} rows in {OUTPUT_CSV})")
    else:
        _init_csv()

    print(f"\nExperiment I — Key-exchange latency  (N={trials})")
    print(f"Target       : {address}")
    print(f"Poll interval: {_KEY_POLL_INTERVAL * 1000:.0f} ms (for t_key_available accuracy)")
    print(f"Note: physical button latency excluded — BenchmarkProvisioningGate required")
    print(f"Output       : {OUTPUT_CSV}\n")

    ok = fail = 0
    cols: dict[str, list[float]] = {
        c: [] for c in ['scan_ms', 'connect_ms', 'request_write_ms',
                         'server_process_ms', 'decrypt_ms', 'state_init_ms',
                         'kex_total_ms']
    }

    for i in range(existing + 1, trials + 1):
        trial_id = f"{prefix}{i:04d}"
        print(f"  [{i:4d}/{trials}]  {trial_id}", end='  ', flush=True)

        row = await _run_trial(address, trial_id)
        _append_row(row)

        if row['success']:
            ok += 1
            for c in cols:
                v = row.get(c, '')
                if v not in ('', None):
                    cols[c].append(float(v))
            print(
                f"OK  "
                f"scan={float(row['scan_ms']):.0f}  "
                f"conn={float(row['connect_ms']):.0f}  "
                f"req_write={float(row['request_write_ms']):.1f}  "
                f"srv={float(row['server_process_ms']):.0f}  "
                f"dec={float(row['decrypt_ms']):.2f}  "
                f"init={float(row['state_init_ms']):.2f}  "
                f"kex_total={float(row['kex_total_ms']):.0f} ms"
            )
        else:
            fail += 1
            print(f"FAIL  [{row['failure_stage']}] {row['failure_reason']}")

        if i < trials:
            await asyncio.sleep(_INTER_TRIAL_DELAY)

    # ── Summary ───────────────────────────────────────────────────────────────
    total = ok + fail
    print(f"\n{'═' * 72}")
    print(f"Experiment I summary — {ok}/{total} successful ({100*ok/total:.1f}%)")
    print(f"\n{'─' * 72}")
    hdr = f"  {'Stage':<22} {'N':>5} {'Mean':>8} {'Median':>8} {'p95':>8} {'Max':>8}  (ms)"
    print(hdr)
    print(f"  {'─' * 68}")
    stage_labels = [
        ('scan_ms',           'scan'),
        ('connect_ms',        'connect'),
        ('request_write_ms',  'request_write (ATT)'),
        ('server_process_ms', 'server_process'),
        ('decrypt_ms',        'decrypt (AES+fsync)'),
        ('state_init_ms',     'state_init (fsync)'),
        ('kex_total_ms',      'kex_total'),
    ]
    summary_phases: dict = {}
    for col, label in stage_labels:
        st = _stats(cols[col])
        summary_phases[col] = st
        if st:
            print(
                f"  {label:<22} {st['n']:>5} {st['mean']:>8.1f} {st['median']:>8.1f}"
                f" {st['p95']:>8.1f} {st['max']:>8.1f}"
            )

    import json as _json
    summary = {
        'n_trials': total,
        'n_success': ok,
        'n_failure': fail,
        'success_rate': f'{100*ok/total:.1f}%' if total else '0%',
        'note': (
            'Physical button latency excluded (BenchmarkProvisioningGate). '
            'server_process_ms ≈ server crypto + BLE char write latency; '
            'poll resolution = 20 ms.'
        ),
        'phases': summary_phases,
    }
    summary_path = OUTPUT_CSV.replace('.csv', '_summary.json')
    with open(summary_path, 'w') as f:
        _json.dump(summary, f, indent=2)

    print(f"\nCSV     → {OUTPUT_CSV}")
    print(f"Summary → {summary_path}")
    print(f"\nServer CSV (on RPi): /tmp/exp_I_server.csv")
    print(f"  Fetch: ssh rpi 'cat /tmp/exp_I_server.csv' > "
          f"results/canonical/latency/key_exchange/key_exchange_server_raw.csv")


def main() -> None:
    p = argparse.ArgumentParser(description="Experiment I — key-exchange latency")
    p.add_argument('--address', required=True, help="RPi BLE MAC address")
    p.add_argument('--trials',  type=int, default=500)
    p.add_argument('--prefix',  default='I_')
    args = p.parse_args()
    asyncio.run(run(args.address, args.trials, args.prefix))


if __name__ == '__main__':
    main()
