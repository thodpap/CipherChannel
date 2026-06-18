#!/usr/bin/env python3
"""
MTU / long-write confirmation — runs on the laptop.

Sends CipherChannel-encrypted payloads of increasing plaintext size to the RPi
GATT server and records whether each write succeeds.  Reports negotiated ATT MTU
if the BlueZ/Bleak backend exposes it, otherwise records null.

The goal is to confirm that BlueZ / Bleak handles long writes (packets above the
default 20-byte ATT PDU payload) correctly for the encrypted frame sizes used in
the steady-state experiments.

Output:
  results/final/raw/final_mtu_check.csv
  results/final/summary/final_mtu_check_summary.json

Usage:
    python3 final_mtu_check.py --address B8:27:EB:07:01:22
    python3 final_mtu_check.py --name AWAKE-EXP --output-dir results/final
"""

import argparse
import asyncio
import csv
import json
import os
import sys
import time
import uuid as _uuid_mod

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'shared'))
from cipher import CipherChannel

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    sys.exit("bleak not installed.  Run: pip install bleak")

# ── UUIDs — must match ble_server.py ─────────────────────────────────────────

SECURITY_UUID = "FEC26EC4-6D71-4442-9F81-55BC21D658D6"
COMMAND_UUID  = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B"
ACK_UUID      = "51FF12BC-3ED8-46E5-B4F9-D64E2FEC021B"

KEY: bytes = b'*\xc3,6s\xa4\xa2\xeeI\x08S>\xd0\xff%\x84\xba\xe9\x95\xcaNL\xffzL%h\x04)\x04%\xf8'

# Plaintext sizes to probe
PROBE_SIZES = [1, 8, 16, 20, 32, 50, 64, 100, 128, 200, 256, 400, 512]

# Encrypted 32-byte key = nonce(12) + ciphertext(32) + tag(16) = 60 bytes
_ENCRYPTED_KEY_LEN = 60
_KEY_POLL_INTERVAL = 0.1
_KEY_TIMEOUT       = 10.0
_ACK_POLL_INTERVAL = 0.05
_ACK_TIMEOUT       = 10.0

DEFAULT_OUT = os.path.join(os.path.dirname(__file__), 'results', 'final')


def _encrypted_size(plaintext_len: int) -> int:
    """Wire-format packet size for a given plaintext length."""
    return 12 + plaintext_len + 16   # nonce(12) + ciphertext + tag(16)


async def _key_exchange(client: BleakClient, session_id: str) -> bytes:
    transport_path = f'/tmp/cc_transport_mtu_{session_id}'
    transport_ch = CipherChannel.create(KEY, False, transport_path)
    await client.write_gatt_char(SECURITY_UUID, b"REQUEST_KEY", response=True)

    deadline = asyncio.get_event_loop().time() + _KEY_TIMEOUT
    while asyncio.get_event_loop().time() < deadline:
        raw = bytes(await client.read_gatt_char(SECURITY_UUID))
        if len(raw) == _ENCRYPTED_KEY_LEN:
            result = transport_ch.receive(raw)
            if result is not None and len(result) == 32:
                return result
        await asyncio.sleep(_KEY_POLL_INTERVAL)
    raise RuntimeError("Timed out waiting for SECURE_KEY")


def _get_mtu(client: BleakClient) -> int | None:
    """Try to extract negotiated ATT MTU from the Bleak client object."""
    # Bleak exposes MTU differently depending on backend version.
    # Try common attribute names; return None if not available.
    for attr in ('_mtu_size', 'mtu_size', '_backend._mtu_size'):
        try:
            parts = attr.split('.')
            obj = client
            for part in parts:
                obj = getattr(obj, part, None)
                if obj is None:
                    break
            if isinstance(obj, int) and obj > 0:
                return obj
        except Exception:
            pass
    return None


async def run_mtu_check(
    address: str | None,
    name: str | None,
    output_dir: str,
) -> None:
    raw_dir     = os.path.join(output_dir, 'raw')
    summary_dir = os.path.join(output_dir, 'summary')
    os.makedirs(raw_dir,     exist_ok=True)
    os.makedirs(summary_dir, exist_ok=True)

    csv_path  = os.path.join(raw_dir,     'final_mtu_check.csv')
    json_path = os.path.join(summary_dir, 'final_mtu_check_summary.json')

    # ── Scan & connect ────────────────────────────────────────────────────────
    target = address or name
    print(f"Scanning for {target} …")
    if address:
        device = await BleakScanner.find_device_by_address(address, timeout=10.0)
    else:
        device = await BleakScanner.find_device_by_name(name, timeout=10.0)

    if device is None:
        sys.exit(f"Device not found: {target}")

    print(f"Connecting …")
    async with BleakClient(device) as client:
        negotiated_mtu = _get_mtu(client)
        print(f"Connected.  Negotiated ATT MTU: {negotiated_mtu if negotiated_mtu else 'not exposed by backend'}")

        # ── Key exchange ──────────────────────────────────────────────────────
        session_id = _uuid_mod.uuid4().hex[:12]
        secure_key = await _key_exchange(client, session_id)
        session_path = f'/tmp/cc_session_mtu_{session_id}'
        secure_ch = CipherChannel.create(secure_key, True, session_path)

        print(f"\n{'─' * 70}")
        print(f"{'Plaintext (B)':>14}  {'Encrypted (B)':>14}  {'Default ATT?':>12}  {'Result':>8}  {'Write ms':>8}")
        print(f"{'─' * 70}")

        rows = []
        successes = []
        failures  = []

        for size in PROBE_SIZES:
            trial_id  = f"mtu_{size:04d}"

            # Embed trial_id in JSON so the server can parse and ACK correctly.
            # Pad with spaces to reach the target size (json.loads ignores trailing
            # whitespace, so the server still parses the JSON cleanly).
            base      = json.dumps({"trial_id": trial_id, "action": "MTU_CHECK"}).encode()
            plaintext = base + b' ' * max(0, size - len(base))
            enc_size  = _encrypted_size(len(plaintext))
            above_default = enc_size > 20   # default ATT MTU payload is 20 bytes

            try:
                enc = secure_ch.send(plaintext)
                assert len(enc) == enc_size, f"unexpected enc size {len(enc)} != {enc_size}"

                t0 = time.perf_counter_ns()
                await client.write_gatt_char(COMMAND_UUID, enc, response=True)
                write_ms = round((time.perf_counter_ns() - t0) / 1e6, 2)

                # Poll ACK to confirm the server received and decrypted it
                expected = f"OK:{trial_id}".encode()
                deadline = asyncio.get_event_loop().time() + _ACK_TIMEOUT
                ack_ok = False
                while asyncio.get_event_loop().time() < deadline:
                    val = bytes(await client.read_gatt_char(ACK_UUID))
                    if val == expected:
                        ack_ok = True
                        break
                    await asyncio.sleep(_ACK_POLL_INTERVAL)

                success = ack_ok
                error   = '' if ack_ok else 'ACK timeout — server may not have decrypted'

            except Exception as e:
                write_ms = 0.0
                success  = False
                error    = str(e)

            actual_size = len(plaintext)
            marker = '>' if above_default else ' '
            status = 'OK' if success else 'FAIL'
            print(f"{actual_size:>14}  {enc_size:>14}  {marker:>12}  {status:>8}  {write_ms:>8.1f}  {error if error else ''}")

            row = {
                'requested_plaintext_bytes': size,
                'actual_plaintext_bytes': actual_size,
                'encrypted_frame_size_bytes': enc_size,
                'above_default_att_mtu': above_default,
                'success': success,
                'write_duration_ms': write_ms,
                'ack_received': success,
                'observed_client_mtu': negotiated_mtu,
                'error': error,
            }
            rows.append(row)
            (successes if success else failures).append(size)

        print(f"{'─' * 70}")

        # ── Write CSV ─────────────────────────────────────────────────────────
        with open(csv_path, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

        # ── Write JSON summary ────────────────────────────────────────────────
        max_success = max(successes) if successes else 0
        summary = {
            'description': 'MTU / long-write confirmation (laptop → RPi via BlueZ/Bleak)',
            'target': target,
            'negotiated_mtu': negotiated_mtu,
            'mtu_observation': (
                'exposed_by_backend' if negotiated_mtu else 'not_exposed_by_backend'
            ),
            'probe_sizes_bytes': PROBE_SIZES,
            'successes_bytes': successes,
            'failures_bytes': failures,
            'max_successful_plaintext_bytes': max_success,
            'max_successful_encrypted_bytes': _encrypted_size(max_success) if max_success else 0,
            'above_default_att_mtu_all_ok': all(
                r['success'] for r in rows if r['above_default_att_mtu']
            ),
            'note': (
                'All packets above the 20-byte default ATT MTU payload were accepted — '
                'BlueZ/Bleak long-write handling is transparent to the application layer.'
                if all(r['success'] for r in rows if r['above_default_att_mtu'])
                else 'Some large packets failed — see failures_bytes.'
            ),
        }
        with open(json_path, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"\nMax successful plaintext : {max_success} B  →  {_encrypted_size(max_success)} B encrypted")
        print(f"Raw    → {csv_path}")
        print(f"Summary→ {json_path}")


def main() -> None:
    p = argparse.ArgumentParser(description="MTU / long-write confirmation via BLE.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--address', help="RPi BLE MAC (e.g. B8:27:EB:07:01:22)")
    g.add_argument('--name',    help="BLE advertised name (e.g. AWAKE-EXP)")
    p.add_argument('--output-dir', default=DEFAULT_OUT)
    args = p.parse_args()

    asyncio.run(run_mtu_check(args.address, args.name, args.output_dir))


if __name__ == '__main__':
    main()
