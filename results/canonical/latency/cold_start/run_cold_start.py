#!/usr/bin/env python3
"""
Experiment F — Cold-start BLE pipeline latency (N=500)
=======================================================
Full end-to-end pipeline from idle (disconnected, no key) per trial.

Per-trial pipeline:
  1. BLE scan   (BleakScanner.find_device_by_address)
  2. Connect    (BleakClient.connect — includes GATT service discovery;
                 Bleak 3.0.2 / BlueZ 5.86 do not expose discovery separately)
  3. Key exch   (REQUEST_KEY → poll SECURITY_UUID → decrypt K_phone → init channel)
  4. Encrypt    (CipherChannel.send — AES-256-GCM + fsync state persistence)
  5. Write      (write_gatt_char COMMAND_UUID, response=True)
  6. ACK poll   (read_gatt_char ACK_UUID until "OK:{trial_id}")

Timing notes:
  connect_ms        : L2CAP connection + GATT service discovery (inseparable via Bleak API)
  command_encrypt_ms: CipherChannel.send() duration — AES-256-GCM encryption plus one
                      atomic fsync to the state file.  On tmpfs (/tmp) the fsync overhead
                      is near-zero; on ext4 expect 1–5 ms.  Not separable without modifying
                      cipher.py (which is excluded from instrumentation).
  command_to_ack_ms : from encrypt-start to ACK received (full crypto+BLE write+server
                      processing+BLE read round-trip).

Script supports resuming interrupted runs: if the output CSV already exists the script
counts existing data rows and starts from that trial index.

Prerequisite — server running on RPi:
  BENCHMARK_PROVISIONING=1 \
  EXPERIMENT_SERVER_CSV_PATH=/tmp/exp_F_server.csv \
  server/.venv/bin/python server/ble_server.py

Run:
  client/.venv/bin/python results/canonical/latency/cold_start/run_cold_start.py \
    --address B8:27:EB:07:01:22 --trials 500

Environment overrides:
  EXPERIMENT_F_CSV_PATH   — output CSV path (default: cold_start_raw.csv next to this file)
  EXPERIMENT_F_INTER_DELAY — seconds between trials (default 1.0)
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

_ENCRYPTED_KEY_LEN  = 60     # nonce(12) + ciphertext(32) + tag(16)
_SCAN_TIMEOUT       = 10.0   # s


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
_CONNECT_TIMEOUT    = 15.0   # s
_KEY_POLL_INTERVAL  = 0.05   # s — short to minimize artificial polling delay
_KEY_TIMEOUT        = 8.0    # s
_ACK_POLL_INTERVAL  = 0.020  # s
_ACK_TIMEOUT        = 10.0   # s
_INTER_TRIAL_DELAY  = float(os.environ.get('EXPERIMENT_F_INTER_DELAY', '1.0'))

_THIS_DIR  = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV = os.environ.get(
    'EXPERIMENT_F_CSV_PATH',
    os.path.join(_THIS_DIR, 'cold_start_raw.csv'),
)

_CSV_COLUMNS = [
    'trial_id', 'action',
    'scan_ms', 'connect_ms', 'key_exchange_ms',
    'command_encrypt_ms', 'write_ms', 'ack_wait_ms',
    'command_to_ack_ms', 'total_ms',
    'success', 'failure_stage', 'failure_reason',
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ms(t0: int, t1: int) -> float:
    return round((t1 - t0) / 1e6, 3)


def _init_csv() -> None:
    with open(OUTPUT_CSV, 'w', newline='') as f:
        csv.writer(f).writerow(_CSV_COLUMNS)


def _append_row(row: dict) -> None:
    with open(OUTPUT_CSV, 'a', newline='') as f:
        csv.writer(f).writerow([row.get(c, '') for c in _CSV_COLUMNS])


def _count_existing_rows() -> int:
    if not os.path.exists(OUTPUT_CSV):
        return 0
    with open(OUTPUT_CSV, newline='') as f:
        return max(0, sum(1 for _ in f) - 1)  # subtract header


# ── Per-trial logic ───────────────────────────────────────────────────────────

class _TrialError(Exception):
    def __init__(self, stage: str, reason: str) -> None:
        self.stage  = stage
        self.reason = reason
        super().__init__(f"[{stage}] {reason}")


async def _run_trial(address: str, trial_id: str, action: str) -> dict:
    row: dict = {c: '' for c in _CSV_COLUMNS}
    row.update({'trial_id': trial_id, 'action': action, 'success': False})

    t_total_start  = time.perf_counter_ns()
    transport_path = f'/tmp/cc_F_tp_{_uuid_mod.uuid4().hex[:8]}'
    session_path   = f'/tmp/cc_F_sess_{_uuid_mod.uuid4().hex[:8]}'
    _client: BleakClient | None = None

    try:
        # ── 1. Scan ───────────────────────────────────────────────────────────
        t0 = time.perf_counter_ns()
        device = await BleakScanner.find_device_by_address(address, timeout=_SCAN_TIMEOUT)
        row['scan_ms'] = _ms(t0, time.perf_counter_ns())
        if device is None:
            raise _TrialError('scan', f'not found within {_SCAN_TIMEOUT} s')

        # ── 2. Connect (L2CAP + GATT service discovery, inseparable) ─────────
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

        # Resolve handles — avoids BleakError on stale BlueZ duplicate UUIDs
        h_security, h_command, h_ack = _resolve_handles(
            _client, SECURITY_UUID, COMMAND_UUID, ACK_UUID)

        # ── 3. Key exchange ───────────────────────────────────────────────────
        t_kex = time.perf_counter_ns()
        transport_ch = CipherChannel.create(KEY, False, transport_path)
        await _client.write_gatt_char(h_security, b"REQUEST_KEY", response=True)

        k_phone = None
        deadline = asyncio.get_event_loop().time() + _KEY_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            raw = bytes(await _client.read_gatt_char(h_security))
            if len(raw) == _ENCRYPTED_KEY_LEN:
                k_phone = transport_ch.receive(raw)
                if k_phone and len(k_phone) == 32:
                    break
                k_phone = None
            await asyncio.sleep(_KEY_POLL_INTERVAL)

        row['key_exchange_ms'] = _ms(t_kex, time.perf_counter_ns())
        if k_phone is None:
            raise _TrialError('key_exchange', f'no K_phone within {_KEY_TIMEOUT} s')

        phone_ch = CipherChannel.create(k_phone, True, session_path)

        # ── 4. Encrypt command (AES-256-GCM + fsync state persist) ───────────
        payload = json.dumps({"trial_id": trial_id, "action": action}).encode()
        t_enc = time.perf_counter_ns()
        encrypted = phone_ch.send(payload)
        row['command_encrypt_ms'] = _ms(t_enc, time.perf_counter_ns())

        # ── 5. GATT write ─────────────────────────────────────────────────────
        t_write = time.perf_counter_ns()
        try:
            await _client.write_gatt_char(h_command, encrypted, response=True)
        except Exception as e:
            row['write_ms'] = _ms(t_write, time.perf_counter_ns())
            raise _TrialError('write', str(e))
        row['write_ms'] = _ms(t_write, time.perf_counter_ns())

        # ── 6. ACK poll ───────────────────────────────────────────────────────
        expected = f"OK:{trial_id}".encode()
        deadline = asyncio.get_event_loop().time() + _ACK_TIMEOUT
        t_ack    = time.perf_counter_ns()
        while asyncio.get_event_loop().time() < deadline:
            try:
                val = bytes(await _client.read_gatt_char(h_ack))
            except Exception as e:
                row['ack_wait_ms'] = _ms(t_ack, time.perf_counter_ns())
                raise _TrialError('ack_read', str(e))
            if val == expected:
                row['ack_wait_ms']       = _ms(t_ack, time.perf_counter_ns())
                row['command_to_ack_ms'] = _ms(t_enc, time.perf_counter_ns())
                row['success']           = True
                return row
            await asyncio.sleep(_ACK_POLL_INTERVAL)

        row['ack_wait_ms'] = _ms(t_ack, time.perf_counter_ns())
        raise _TrialError('ack_wait', f'timeout after {_ACK_TIMEOUT} s')

    except _TrialError as e:
        row['failure_stage']  = e.stage
        row['failure_reason'] = e.reason

    except Exception as e:
        row['failure_stage']  = row.get('failure_stage') or 'unexpected'
        row['failure_reason'] = str(e)

    finally:
        row['total_ms'] = _ms(t_total_start, time.perf_counter_ns())
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


# ── Summary stats ─────────────────────────────────────────────────────────────

def _summarise(rows: list[dict]) -> dict:
    ok_rows = [r for r in rows if r.get('success') in (True, 'True')]
    N       = len(rows)
    N_ok    = len(ok_rows)

    def _col(key: str) -> list[float]:
        vals = []
        for r in ok_rows:
            v = r.get(key, '')
            if v not in ('', None):
                try:
                    vals.append(float(v))
                except (ValueError, TypeError):
                    pass
        return vals

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

    metrics = ['scan_ms', 'connect_ms', 'key_exchange_ms',
               'command_encrypt_ms', 'write_ms', 'ack_wait_ms',
               'command_to_ack_ms', 'total_ms']

    failure_stages: dict[str, int] = {}
    for r in rows:
        if r.get('success') not in (True, 'True'):
            stage = r.get('failure_stage', 'unknown') or 'unknown'
            failure_stages[stage] = failure_stages.get(stage, 0) + 1

    return {
        'n_trials':       N,
        'n_success':      N_ok,
        'n_failure':      N - N_ok,
        'success_rate':   f'{100 * N_ok / N:.1f}%' if N else '0%',
        'failure_stages': failure_stages,
        'phases': {m: _stats(_col(m)) for m in metrics},
    }


def _print_summary(s: dict) -> None:
    print(f"\n{'═' * 70}")
    print(f"Experiment F — Cold-start summary")
    print(f"Trials: {s['n_trials']}   Success: {s['n_success']} ({s['success_rate']})"
          f"   Failures: {s['n_failure']}")
    if s['failure_stages']:
        print(f"Failure stages: {s['failure_stages']}")
    print(f"\n{'─' * 70}")
    hdr = f"{'Phase':<22} {'N':>5} {'Mean':>8} {'Median':>8} {'Stdev':>8}"
    hdr += f" {'p95':>8} {'p99':>8} {'Min':>8} {'Max':>8}"
    print(hdr + '  (ms)')
    print('─' * 70)
    for phase, st in s['phases'].items():
        if st is None:
            continue
        name = phase.replace('_ms', '')
        print(
            f"  {name:<20} {st['n']:>5} {st['mean']:>8.1f} {st['median']:>8.1f}"
            f" {st['stdev']:>8.1f} {st['p95']:>8.1f} {st['p99']:>8.1f}"
            f" {st['min']:>8.1f} {st['max']:>8.1f}"
        )


# ── Main run loop ─────────────────────────────────────────────────────────────

async def run(address: str, trials: int, action: str, prefix: str) -> None:
    # Resume support: count rows already in the CSV
    existing = _count_existing_rows()
    if existing > 0:
        print(f"Resuming: found {existing} existing row(s) in {OUTPUT_CSV}")
        print(f"Starting from trial {existing + 1}")
    else:
        _init_csv()

    start_i = existing + 1

    print(f"\nExperiment F — Cold-start BLE pipeline  (N={trials})")
    print(f"Target  : {address}")
    print(f"Action  : {action!r}")
    print(f"Output  : {OUTPUT_CSV}")
    print(f"Inter-trial delay: {_INTER_TRIAL_DELAY} s\n")

    rows: list[dict] = []
    ok = fail = 0

    for i in range(start_i, trials + 1):
        trial_id = f"{prefix}{i:04d}"
        print(f"  [{i:4d}/{trials}]  {trial_id}", end='  ', flush=True)

        row = await _run_trial(address, trial_id, action)
        _append_row(row)
        rows.append(row)

        if row['success']:
            ok += 1
            print(
                f"OK  "
                f"scan={row['scan_ms']:.0f}  "
                f"conn={row['connect_ms']:.0f}  "
                f"kex={row['key_exchange_ms']:.0f}  "
                f"enc={row['command_encrypt_ms']:.2f}  "
                f"wrt={row['write_ms']:.0f}  "
                f"ack={row['ack_wait_ms']:.0f}  "
                f"tot={row['total_ms']:.0f} ms"
            )
        else:
            fail += 1
            print(f"FAIL  [{row['failure_stage']}] {row['failure_reason']}"
                  f"  (total={row['total_ms']:.0f} ms)")

        if i < trials:
            await asyncio.sleep(_INTER_TRIAL_DELAY)

    # Load all rows for summary (including any pre-existing from resume)
    all_rows: list[dict] = []
    with open(OUTPUT_CSV, newline='') as f:
        for r in csv.DictReader(f):
            all_rows.append(r)

    summary = _summarise(all_rows)
    _print_summary(summary)

    import json as _json
    summary_path = OUTPUT_CSV.replace('.csv', '_summary.json')
    with open(summary_path, 'w') as f:
        _json.dump(summary, f, indent=2)
    print(f"\nCSV     → {OUTPUT_CSV}")
    print(f"Summary → {summary_path}")
    print(f"\nServer CSV (on RPi): /tmp/exp_F_server.csv")
    print(f"  Fetch with: ssh rpi 'cat /tmp/exp_F_server.csv' > "
          f"results/canonical/latency/cold_start/cold_start_server_raw.csv")


def main() -> None:
    p = argparse.ArgumentParser(description="Experiment F — cold-start BLE pipeline")
    p.add_argument('--address', required=True, help="RPi BLE MAC address")
    p.add_argument('--trials',  type=int, default=500)
    p.add_argument('--action',  default='STAND_UP')
    p.add_argument('--prefix',  default='F_')
    args = p.parse_args()
    asyncio.run(run(args.address, args.trials, args.action, args.prefix))


if __name__ == '__main__':
    main()
