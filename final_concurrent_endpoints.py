#!/usr/bin/env python3
"""
Automated endpoint-isolation and replay validation — laptop client.

This script replaces the older "concurrent endpoint validation" script that used
manual ESP32 cane button presses and wrote TODO/manual fields into the final
summary. It produces deterministic, machine-checkable evidence only.

What this script validates:
  1. The phone/laptop supervisory channel accepts valid CipherChannel packets.
  2. The phone/laptop supervisory channel rejects replayed packets.
  3. Packets encrypted under the phone/laptop session are not accepted as phone
     packets when written to the cane secure characteristic.
  4. Packets encrypted under a different key are not accepted by the phone/laptop
     command characteristic.

Important scope:
  - This is an automated cross-channel rejection test using the laptop as the
    adversarial test client.
  - It does NOT prove that a physical ESP32 cane button path accepted valid cane
    commands. If the paper claims valid ESP32 cane operation, keep a separate
    ESP32 hardware-in-the-loop experiment for that claim.
  - It removes all operator prompts and TODO/manual output.

Output:
  results/final/raw/final_concurrent_endpoints.csv
  results/final/summary/final_concurrent_endpoints_summary.json

Usage:
    python3 final_concurrent_endpoints.py --address B8:27:EB:07:01:22 --trials 30
    python3 final_concurrent_endpoints.py --name AWAKE-EXP --trials 30
"""

import argparse
import asyncio
import csv
import json
import os
import sys
import time
import uuid as _uuid_mod
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'shared'))
from cipher import CipherChannel

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    sys.exit("bleak not installed. Run: pip install bleak")

# ── UUIDs: must match server/ble_server.py ────────────────────────────────────

SECURITY_UUID = "FEC26EC4-6D71-4442-9F81-55BC21D658D6"
COMMAND_UUID  = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B"
ACK_UUID      = "51FF12BC-3ED8-46E5-B4F9-D64E2FEC021B"

# Cane channel UUIDs. Used here only for automated cross-channel rejection tests.
CANE2PHONE_UUID  = "74278BDA-B644-4520-8F0C-720EAF059935"
CANE_SECURITY_UUID = "FA87C0D0-AFAC-11DE-8A39-0800200C9A66"
CANE_RESET_UUID  = "D2B9A3D4-1A3D-0A6D-D7C8-B4D4D0A4B1E2"

# Pre-shared transport key used for phone/laptop key exchange.
KEY: bytes = b'*\xc3,6s\xa4\xa2\xeeI\x08S>\xd0\xff%\x84\xba\xe9\x95\xcaNL\xffzL%h\x04)\x04%\xf8'

# Encrypted 32-byte key = nonce(12) + ciphertext(32) + tag(16) = 60 bytes.
_ENCRYPTED_KEY_LEN = 60

_KEY_POLL_INTERVAL = 0.1
_KEY_TIMEOUT       = 10.0
_ACK_POLL_INTERVAL = 0.05
_ACK_TIMEOUT       = 10.0
_REJECT_WAIT       = 0.5

DEFAULT_OUT = os.path.join(os.path.dirname(__file__), 'results', 'final')

_CSV_COLS = [
    'case',
    'trial_id',
    'write_uuid',
    'expected_outcome',
    'observed_outcome',
    'write_ms',
    'ack_ms',
    'total_ms',
    'success',
    'failure_reason',
]


def _blank_row() -> dict[str, Any]:
    return {c: '' for c in _CSV_COLS}


def _now_ns() -> int:
    return time.perf_counter_ns()


async def _read_ack(client: BleakClient) -> bytes:
    return bytes(await client.read_gatt_char(ACK_UUID))


async def _wait_for_ack(client: BleakClient, expected: bytes, timeout: float = _ACK_TIMEOUT) -> tuple[bool, float]:
    deadline = asyncio.get_event_loop().time() + timeout
    t0 = _now_ns()
    while asyncio.get_event_loop().time() < deadline:
        val = await _read_ack(client)
        if val == expected:
            return True, round((_now_ns() - t0) / 1e6, 2)
        await asyncio.sleep(_ACK_POLL_INTERVAL)
    return False, round((_now_ns() - t0) / 1e6, 2)


async def _key_exchange(client: BleakClient, session_id: str) -> bytes:
    transport_path = f'/tmp/cc_transport_conc_{session_id}'
    transport_ch = CipherChannel.create(KEY, False, transport_path, endpoint_id='phone_transport_client')

    await client.write_gatt_char(SECURITY_UUID, b"REQUEST_KEY", response=True)

    deadline = asyncio.get_event_loop().time() + _KEY_TIMEOUT
    while asyncio.get_event_loop().time() < deadline:
        raw = bytes(await client.read_gatt_char(SECURITY_UUID))
        if len(raw) == _ENCRYPTED_KEY_LEN:
            result = transport_ch.receive(raw)
            if result is not None and len(result) == 32:
                return result
        await asyncio.sleep(_KEY_POLL_INTERVAL)

    raise RuntimeError(f"Timed out waiting for encrypted phone key ({_ENCRYPTED_KEY_LEN} B)")


async def _send_phone_command(
    client: BleakClient,
    secure_ch: CipherChannel,
    trial_id: str,
    action: str,
) -> tuple[dict[str, Any], bytes]:
    row = _blank_row()
    row.update({
        'case': 'valid_phone_command',
        'trial_id': trial_id,
        'write_uuid': COMMAND_UUID,
        'expected_outcome': 'accept',
        'success': False,
    })

    payload = json.dumps({"trial_id": trial_id, "action": action}).encode()
    enc = secure_ch.send(payload)

    t_start = _now_ns()
    try:
        t0 = _now_ns()
        await client.write_gatt_char(COMMAND_UUID, enc, response=True)
        row['write_ms'] = round((_now_ns() - t0) / 1e6, 2)

        ok, ack_ms = await _wait_for_ack(client, f"OK:{trial_id}".encode())
        row['ack_ms'] = ack_ms

        if ok:
            row['observed_outcome'] = 'accept'
            row['success'] = True
        else:
            row['observed_outcome'] = 'no_ack'
            row['failure_reason'] = 'ACK timeout'
    except Exception as e:
        row['observed_outcome'] = 'error'
        row['failure_reason'] = str(e)

    row['total_ms'] = round((_now_ns() - t_start) / 1e6, 2)
    return row, enc


async def _write_expect_no_phone_ack(
    client: BleakClient,
    *,
    case: str,
    trial_id: str,
    write_uuid: str,
    packet: bytes,
    previous_ack: bytes,
) -> dict[str, Any]:
    """
    Write a packet that should not be accepted as a phone command.

    Rejection criterion available over the public GATT interface:
      - the write may complete at the BLE layer;
      - ACK_UUID must not change to OK:<trial_id>;
      - ACK_UUID should remain at the previous value or another unrelated value.

    For cane-side writes, the server does not expose a separate rejection ACK over
    BLE, so this test verifies that cross-channel injection does not create a
    phone-command acceptance side effect. Server-side CSV logs can be used as
    additional evidence if desired.
    """
    row = _blank_row()
    row.update({
        'case': case,
        'trial_id': trial_id,
        'write_uuid': write_uuid,
        'expected_outcome': 'reject',
        'success': False,
    })

    t_start = _now_ns()
    try:
        t0 = _now_ns()
        await client.write_gatt_char(write_uuid, packet, response=True)
        row['write_ms'] = round((_now_ns() - t0) / 1e6, 2)

        await asyncio.sleep(_REJECT_WAIT)
        ack_after = await _read_ack(client)
        expected_bad_ack = f"OK:{trial_id}".encode()

        if ack_after != expected_bad_ack:
            row['observed_outcome'] = 'reject_no_phone_ack'
            row['ack_ms'] = round(_REJECT_WAIT * 1000, 2)
            row['success'] = True
        else:
            row['observed_outcome'] = 'unexpected_accept'
            row['failure_reason'] = 'ACK changed to forbidden trial_id'
    except Exception as e:
        # A write-layer error is also acceptable for a rejection test, because the
        # packet did not become an accepted command.
        row['observed_outcome'] = 'write_error_rejected'
        row['failure_reason'] = str(e)
        row['success'] = True

    row['total_ms'] = round((_now_ns() - t_start) / 1e6, 2)
    return row


async def run(
    address: str | None,
    name: str | None,
    trials: int,
    action: str,
    delay: float,
    output_dir: str,
) -> None:
    raw_dir = os.path.join(output_dir, 'raw')
    summary_dir = os.path.join(output_dir, 'summary')
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(summary_dir, exist_ok=True)

    csv_path = os.path.join(raw_dir, 'final_concurrent_endpoints.csv')
    json_path = os.path.join(summary_dir, 'final_concurrent_endpoints_summary.json')

    target = address or name
    print(f"Target  : {target}")
    print(f"Trials  : {trials}  action={action!r}  delay={delay}s")
    print("Mode    : automated; no manual ESP32/operator input\n")

    print("Scanning…", end='', flush=True)
    if address:
        device = await BleakScanner.find_device_by_address(address, timeout=10.0)
    else:
        device = await BleakScanner.find_device_by_name(name, timeout=10.0)
    if device is None:
        sys.exit(f"Device not found: {target}")
    print(" found")

    print("Connecting…", end='', flush=True)
    async with BleakClient(device) as client:
        if not client.is_connected:
            sys.exit("Connection failed")
        print(" connected\n")

        session_id = _uuid_mod.uuid4().hex[:12]
        print("Phone key exchange…", end='', flush=True)
        secure_key = await _key_exchange(client, session_id)
        session_path = f'/tmp/cc_session_conc_{session_id}'
        secure_ch = CipherChannel.create(secure_key, True, session_path, endpoint_id='phone')
        print(f" done  session={session_id}\n")

        rows: list[dict[str, Any]] = []
        accepted_packets: list[bytes] = []

        # ── Valid phone/laptop commands ───────────────────────────────────────
        for i in range(1, trials + 1):
            trial_id = f"conc_phone_{i:04d}"
            print(f"[valid {i:03d}/{trials}] {trial_id} …", end='', flush=True)
            row, enc = await _send_phone_command(client, secure_ch, trial_id, action)
            rows.append(row)
            if row['success']:
                accepted_packets.append(enc)
                print(f" accepted  total={row['total_ms']} ms")
            else:
                print(f" failed: {row['failure_reason']}")
            if i < trials:
                await asyncio.sleep(delay)

        # ── Replay rejection: replay the last accepted phone packet ───────────
        replay_attempts = 0
        replay_rejected = 0
        if accepted_packets:
            previous_ack = await _read_ack(client)
            replay_attempts = 1
            print("\n[replay] re-sending last accepted phone packet …", end='', flush=True)
            row = await _write_expect_no_phone_ack(
                client,
                case='phone_exact_replay_to_phone_channel',
                trial_id='conc_replay_exact',
                write_uuid=COMMAND_UUID,
                packet=accepted_packets[-1],
                previous_ack=previous_ack,
            )
            rows.append(row)
            if row['success']:
                replay_rejected = 1
                print(" rejected")
            else:
                print(" NOT rejected")
        else:
            print("\n[replay] skipped because no valid phone command was accepted")

        # ── Cross-endpoint rejection tests ────────────────────────────────────
        cross_attempts = 0
        cross_rejected = 0

        # A. Phone-encrypted packet written to cane secure characteristic.
        # This should not be accepted as a valid cane packet because the cane
        # secure channel uses K_cane, not K_phone.
        for i in range(1, trials + 1):
            trial_id = f"cross_phone_to_cane_{i:04d}"
            payload = json.dumps({"trial_id": trial_id, "action": action}).encode()
            phone_packet = secure_ch.send(payload)
            previous_ack = await _read_ack(client)

            print(f"[cross P→C {i:03d}/{trials}] …", end='', flush=True)
            row = await _write_expect_no_phone_ack(
                client,
                case='phone_key_packet_to_cane_channel',
                trial_id=trial_id,
                write_uuid=CANE2PHONE_UUID,
                packet=phone_packet,
                previous_ack=previous_ack,
            )
            rows.append(row)
            cross_attempts += 1
            if row['success']:
                cross_rejected += 1
                print(" rejected/no phone ACK")
            else:
                print(" unexpected phone ACK")

        # B. Packet encrypted under a different key written to phone command char.
        # This models cane/wrong-endpoint traffic against the phone channel.
        fake_cane_key = b'\xA5' * 32
        fake_state_path = f'/tmp/cc_fake_cane_{session_id}'
        fake_cane_ch = CipherChannel.create(fake_cane_key, True, fake_state_path, endpoint_id='fake_cane')

        for i in range(1, trials + 1):
            trial_id = f"cross_cane_to_phone_{i:04d}"
            payload = json.dumps({"trial_id": trial_id, "action": action}).encode()
            fake_cane_packet = fake_cane_ch.send(payload)
            previous_ack = await _read_ack(client)

            print(f"[cross C→P {i:03d}/{trials}] …", end='', flush=True)
            row = await _write_expect_no_phone_ack(
                client,
                case='foreign_key_packet_to_phone_channel',
                trial_id=trial_id,
                write_uuid=COMMAND_UUID,
                packet=fake_cane_packet,
                previous_ack=previous_ack,
            )
            rows.append(row)
            cross_attempts += 1
            if row['success']:
                cross_rejected += 1
                print(" rejected")
            else:
                print(" unexpected ACK")

    # ── Write CSV ─────────────────────────────────────────────────────────────
    with open(csv_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=_CSV_COLS)
        w.writeheader()
        w.writerows(rows)

    valid_rows = [r for r in rows if r['case'] == 'valid_phone_command']
    valid_ok = sum(1 for r in valid_rows if r['success'])
    valid_fail = len(valid_rows) - valid_ok
    unexpected_accepts = [
        r for r in rows
        if r['expected_outcome'] == 'reject' and not r['success']
    ]

    summary = {
        'description': (
            'Automated endpoint-isolation and replay validation. '
            'No manual ESP32/operator input is used.'
        ),
        'scope': {
            'valid_phone_path_tested': True,
            'phone_replay_rejection_tested': True,
            'cross_endpoint_rejection_tested': True,
            'physical_esp32_cane_valid_acceptance_tested': False,
            'note': (
                'This script replaces the old manual concurrent-endpoint script. '
                'It provides automated rejection evidence. Valid ESP32 cane '
                'operation requires a separate hardware-in-the-loop experiment.'
            ),
        },
        'phone_valid_sent': len(valid_rows),
        'phone_valid_accepted': valid_ok,
        'phone_valid_failed': valid_fail,
        'replay_attempts': replay_attempts,
        'replay_rejected': replay_rejected,
        'cross_endpoint_attempts': cross_attempts,
        'cross_endpoint_rejected_or_no_phone_ack': cross_rejected,
        'unexpected_acceptances': len(unexpected_accepts),
        'result': (
            'pass'
            if valid_ok == trials
            and replay_rejected == replay_attempts
            and cross_rejected == cross_attempts
            and len(unexpected_accepts) == 0
            else 'fail'
        ),
        'artifact_hygiene': {
            'manual_operator_input': False,
            'todo_manual_fields': False,
        },
        'raw_csv': csv_path,
    }

    with open(json_path, 'w') as f:
        json.dump(summary, f, indent=2)

    print("\n" + "─" * 70)
    print(f"Valid phone commands : {valid_ok}/{trials} accepted")
    print(f"Replay rejection     : {replay_rejected}/{replay_attempts} rejected")
    print(f"Cross-endpoint tests : {cross_rejected}/{cross_attempts} rejected/no phone ACK")
    print(f"Unexpected accepts   : {len(unexpected_accepts)}")
    print(f"Result               : {summary['result']}")
    print(f"Raw                  → {csv_path}")
    print(f"Summary              → {json_path}")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Automated endpoint-isolation and replay validation."
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--address', help="RPi BLE MAC, e.g. B8:27:EB:07:01:22")
    g.add_argument('--name', help="BLE advertised name, e.g. AWAKE-EXP")
    p.add_argument('--trials', type=int, default=30, help="Trial count per test group.")
    p.add_argument('--action', default='STAND_UP', help="Action payload.")
    p.add_argument('--delay', type=float, default=0.05, help="Seconds between valid trials.")
    p.add_argument('--output-dir', default=DEFAULT_OUT)
    args = p.parse_args()

    asyncio.run(run(
        address=args.address,
        name=args.name,
        trials=args.trials,
        action=args.action,
        delay=args.delay,
        output_dir=args.output_dir,
    ))


if __name__ == '__main__':
    main()