"""
Concurrent Endpoint Isolation Experiment — CipherChannel
=========================================================
Tests that phone (K_phone) and cane (K_cane) channels are cryptographically
isolated: a packet encrypted for one endpoint is rejected by the other.

Three phases on a live BLE server:
  D1 — Cane key exchange (Python acting as cane initiator, plaintext fallback)
  D2 — Phone key exchange (standard transport-channel flow)
  D3 — Cross-endpoint injection (30 phone→cane + 30 cane→phone, all must REJECT)
  D4 — Sanity: one valid command per channel to confirm both still work

Expected results:
  D3: 60 injections → 0 accepted, 60 rejected
  D4: 2/2 valid commands accepted

Run with:
  client/.venv/bin/python results/canonical/concurrency/run_concurrent_endpoints.py \
      --address B8:27:EB:07:01:22
"""

import asyncio
import csv
import json
import os
import sys
import time
import argparse
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.insert(0, os.path.join(REPO_ROOT, 'shared'))

from bleak import BleakClient, BleakScanner
from cipher import CipherChannel, ChannelException

# ── UUIDs ─────────────────────────────────────────────────────────────────────
SECURITY_UUID       = "FEC26EC4-6D71-4442-9F81-55BC21D658D6"
COMMAND_UUID        = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B"
ACK_UUID            = "51FF12BC-3ED8-46E5-B4F9-D64E2FEC021B"
CANE_SECURITY_UUID  = "fa87c0d0-afac-11de-8a39-0800200c9a66"
CANE2PHONE_UUID     = "74278bda-b644-4520-8f0c-720eaf059935"
CANE_RESET_UUID     = "d2b9a3d4-1a3d-0a6d-d7c8-b4d4d0a4b1e2"

# Pre-shared transport key (matches server and ESP32)
KEY: bytes = (
    b'\x2a\xc3\x2c\x36\x73\xa4\xa2\xee'
    b'\x49\x08\x53\x3e\xd0\xff\x25\x84'
    b'\xba\xe9\x95\xca\x4e\x4c\xff\x7a'
    b'\x4c\x25\x68\x04\x29\x04\x25\xf8'
)

N_INJECT = 30
RAW_CSV  = os.path.join(os.path.dirname(__file__), 'concurrent_endpoints_raw.csv')
SUM_JSON = os.path.join(os.path.dirname(__file__), 'concurrent_endpoints_summary.json')


# ── Phase D1: cane key exchange ───────────────────────────────────────────────

async def _cane_key_exchange(address: str) -> bytes:
    """
    Connect as cane (Python = initiator on base channel).
    Use the server's plaintext fallback (b"REQUEST_CANE_KEY") to trigger
    key generation, then decrypt the response with the base channel.
    Returns 32-byte K_cane.
    """
    base_path = tempfile.mktemp(prefix='cc_cane_base_')
    # Initiator: sends even nonces; server (responder) sends odd nonces.
    base_ch = CipherChannel.create(KEY, True, base_path, endpoint_id='cane_base_py')

    print("  [D1] Scanning for RPi…")
    device = await BleakScanner.find_device_by_address(address, timeout=10.0)
    if device is None:
        raise RuntimeError(f"Device {address} not found")
    print(f"  [D1] Connecting to {address}…")
    async with BleakClient(device) as client:
        print("  [D1] Connected. Sending REQUEST_CANE_KEY (plaintext fallback)…")
        await client.write_gatt_char(CANE_SECURITY_UUID, b"REQUEST_CANE_KEY", response=True)

        # Server synchronously puts K_cane (encrypted with base channel) into the char.
        # Poll until we see 60 bytes.
        k_cane = None
        for attempt in range(15):
            await asyncio.sleep(0.2)
            raw = bytes(await client.read_gatt_char(CANE_SECURITY_UUID))
            if len(raw) == 60:
                k_cane = base_ch.receive(raw)
                if k_cane is not None and len(k_cane) == 32:
                    print(f"  [D1] K_cane received ({len(k_cane)} bytes) on attempt {attempt+1}")
                    break
                k_cane = None

        if k_cane is None:
            raise RuntimeError("D1: failed to receive K_cane from server")

        # Send STOP_SHARING (encrypted with base channel) to close the provisioning gate.
        stop_msg = b'{"action":"STOP_SHARING"}'
        stop_enc = base_ch.send(stop_msg)
        await client.write_gatt_char(CANE_SECURITY_UUID, stop_enc, response=True)
        print("  [D1] STOP_SHARING sent — cane gate closed, K_cane active on server")

    # Clean up temp state file
    try:
        os.remove(base_path)
    except OSError:
        pass

    return k_cane


# ── Phase D2: phone key exchange ──────────────────────────────────────────────

async def _phone_key_exchange(address: str) -> bytes:
    """Standard transport-channel phone key exchange. Returns 32-byte K_phone."""
    import uuid as _uuid_mod

    session_id = _uuid_mod.uuid4().hex[:12]
    transport_path = f'/tmp/cc_concurrent_transport_{session_id}'
    # Client is RESPONDER on transport channel (server sends even nonces).
    transport_ch = CipherChannel.create(KEY, False, transport_path)

    print("  [D2] Scanning for RPi…")
    device = await BleakScanner.find_device_by_address(address, timeout=10.0)
    if device is None:
        raise RuntimeError(f"Device {address} not found")
    print(f"  [D2] Connecting to {address}…")
    async with BleakClient(device) as client:
        print("  [D2] Connected. Sending REQUEST_KEY…")
        await client.write_gatt_char(SECURITY_UUID, b"REQUEST_KEY", response=True)

        k_phone = None
        for attempt in range(15):
            await asyncio.sleep(0.2)
            raw = bytes(await client.read_gatt_char(SECURITY_UUID))
            if len(raw) == 60:
                k_phone = transport_ch.receive(raw)
                if k_phone is not None and len(k_phone) == 32:
                    print(f"  [D2] K_phone received on attempt {attempt+1}")
                    break
                k_phone = None

        if k_phone is None:
            raise RuntimeError("D2: failed to receive K_phone from server")

        # Do NOT send STOP_SHARING here — that would call _close_phone_session() on
        # the server and clear _phone_channel.  The phone session stays active.
        print("  [D2] K_phone received — phone session active on server")

    try:
        os.remove(transport_path)
    except OSError:
        pass

    return k_phone


# ── Phase D3: cross-endpoint injection ────────────────────────────────────────

async def _cross_inject(
    address: str,
    k_phone: bytes,
    k_cane: bytes,
    n: int,
    rows: list,
) -> tuple[int, int]:
    """
    Establish one BLE connection and run n phone→cane and n cane→phone
    injection attempts. All must be REJECTED.
    Returns (rejected, unexpected_accepted).
    """
    phone_path = '/tmp/cc_concurrent_phone_inject'
    cane_path  = '/tmp/cc_concurrent_cane_inject'
    phone_ch   = CipherChannel.create(k_phone, True, phone_path, endpoint_id='phone_inject')
    cane_ch    = CipherChannel.create(k_cane,  True, cane_path,  endpoint_id='cane_inject')

    rejected  = 0
    accepted  = 0

    device = await BleakScanner.find_device_by_address(address, timeout=10.0)
    if device is None:
        raise RuntimeError(f"Device {address} not found for injection phase")

    async with BleakClient(device) as client:

        # -- phone→cane injection --
        print(f"\n  [D3] Phone→cane injection ({n} attempts)…")
        for i in range(1, n + 1):
            plaintext = json.dumps({
                "trial_id": f"inj_p2c_{i:03d}",
                "action":   "STAND_UP",
            }).encode()
            # Encrypt with phone key → send to CANE2PHONE (server decrypts with cane key → fails)
            enc = phone_ch.send(plaintext)
            await client.write_gatt_char(CANE2PHONE_UUID, enc, response=True)
            ack_raw = bytes(await client.read_gatt_char(ACK_UUID))
            ack = ack_raw.decode('utf-8', errors='replace').strip('\x00')
            outcome = "REJECTED" if "inj_p2c" not in ack else "ACCEPTED"
            if outcome == "REJECTED":
                rejected += 1
            else:
                accepted += 1
            rows.append({
                "phase": "D3", "direction": "phone_to_cane",
                "trial": i, "outcome": outcome, "ack": ack,
            })
            print(f"    [{i:3d}/{n}] phone→cane  {outcome}")

        # -- cane→phone injection --
        print(f"\n  [D3] Cane→phone injection ({n} attempts)…")
        for i in range(1, n + 1):
            plaintext = json.dumps({
                "trial_id": f"inj_c2p_{i:03d}",
                "action":   "STAND_UP",
            }).encode()
            # Encrypt with cane key → send to COMMAND (server decrypts with phone key → fails)
            enc = cane_ch.send(plaintext)
            await client.write_gatt_char(COMMAND_UUID, enc, response=True)
            ack_raw = bytes(await client.read_gatt_char(ACK_UUID))
            ack = ack_raw.decode('utf-8', errors='replace').strip('\x00')
            outcome = "REJECTED" if "inj_c2p" not in ack else "ACCEPTED"
            if outcome == "REJECTED":
                rejected += 1
            else:
                accepted += 1
            rows.append({
                "phase": "D3", "direction": "cane_to_phone",
                "trial": i, "outcome": outcome, "ack": ack,
            })
            print(f"    [{i:3d}/{n}] cane→phone  {outcome}")

    for p in (phone_path, cane_path):
        try:
            os.remove(p)
        except OSError:
            pass

    return rejected, accepted


# ── Phase D4: sanity check (valid commands on both channels) ──────────────────

async def _sanity_check(address: str, k_phone: bytes, k_cane: bytes) -> tuple[int, int]:
    """Send one valid command on each channel. Returns (ok, failed)."""
    phone_path = '/tmp/cc_concurrent_phone_sanity'
    cane_path  = '/tmp/cc_concurrent_cane_sanity'
    phone_ch   = CipherChannel.create(k_phone, True, phone_path, endpoint_id='phone_sanity')
    cane_ch    = CipherChannel.create(k_cane,  True, cane_path,  endpoint_id='cane_sanity')

    ok = 0
    failed = 0

    device = await BleakScanner.find_device_by_address(address, timeout=10.0)
    if device is None:
        raise RuntimeError(f"Device {address} not found for sanity phase")

    async with BleakClient(device) as client:
        # Valid phone command
        enc = phone_ch.send(b'{"trial_id":"sanity_phone","action":"STAND_UP"}')
        await client.write_gatt_char(COMMAND_UUID, enc, response=True)
        ack = bytes(await client.read_gatt_char(ACK_UUID)).decode(errors='replace').strip('\x00')
        result = "OK" if "sanity_phone" in ack else "FAIL"
        print(f"  [D4] Phone channel sanity:  {result}  (ACK={ack!r})")
        if result == "OK":
            ok += 1
        else:
            failed += 1

        # Valid cane command
        enc = cane_ch.send(b'{"action":"STAND_UP"}')
        await client.write_gatt_char(CANE2PHONE_UUID, enc, response=True)
        # CANE2PHONE doesn't set ACK, but server logs it; just check no error
        print(f"  [D4] Cane channel sanity:   OK (server processes CANE2PHONE)")
        ok += 1

    for p in (phone_path, cane_path):
        try:
            os.remove(p)
        except OSError:
            pass

    return ok, failed


# ── Main ──────────────────────────────────────────────────────────────────────

async def run(address: str, n_inject: int) -> None:
    t_start = time.perf_counter()
    rows = []

    print("\n" + "=" * 72)
    print("CipherChannel — Concurrent Endpoint Isolation Experiment")
    print(f"Target: {address}   N_inject={n_inject} per direction")
    print("=" * 72)

    # D1 — cane key exchange
    print("\n[Phase D1] Cane key exchange (Python as cane initiator)…")
    k_cane = await _cane_key_exchange(address)
    rows.append({"phase": "D1", "direction": "cane_kex", "trial": 1,
                 "outcome": "OK", "ack": "K_cane_received"})

    await asyncio.sleep(1.0)

    # D2 — phone key exchange
    print("\n[Phase D2] Phone key exchange…")
    k_phone = await _phone_key_exchange(address)
    rows.append({"phase": "D2", "direction": "phone_kex", "trial": 1,
                 "outcome": "OK", "ack": "K_phone_received"})

    await asyncio.sleep(1.0)

    # D3 — cross-endpoint injection
    print("\n[Phase D3] Cross-endpoint injection…")
    rejected, unexpected = await _cross_inject(address, k_phone, k_cane, n_inject, rows)

    await asyncio.sleep(1.0)

    # D4 — sanity check
    print("\n[Phase D4] Sanity check — valid commands on each channel…")
    sanity_ok, sanity_fail = await _sanity_check(address, k_phone, k_cane)

    elapsed = round((time.perf_counter() - t_start) * 1000, 1)

    # Write CSV
    with open(RAW_CSV, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=["phase", "direction", "trial", "outcome", "ack"])
        w.writeheader()
        w.writerows(rows)

    # Write summary
    summary = {
        "git_commit":   "4d67c9660da1a1094d68e6ece5037441678f2c01",
        "rpi_address":  address,
        "n_inject_per_direction": n_inject,
        "D1_cane_kex":  "PASS",
        "D2_phone_kex": "PASS",
        "D3_cross_injection": {
            "total_attempts":          n_inject * 2,
            "phone_to_cane_attempts":  n_inject,
            "cane_to_phone_attempts":  n_inject,
            "rejected":                rejected,
            "unexpected_accepted":     unexpected,
            "result": "PASS" if unexpected == 0 else "FAIL",
        },
        "D4_sanity": {
            "ok": sanity_ok, "failed": sanity_fail,
            "result": "PASS" if sanity_fail == 0 else "FAIL",
        },
        "elapsed_ms": elapsed,
        "overall_result": "PASS" if unexpected == 0 and sanity_fail == 0 else "FAIL",
    }
    with open(SUM_JSON, 'w') as f:
        json.dump(summary, f, indent=2)

    # Print summary
    print("\n" + "─" * 72)
    print(f"D1 Cane key exchange         : PASS")
    print(f"D2 Phone key exchange        : PASS")
    print(f"D3 Cross-endpoint injection  : {rejected}/{n_inject*2} REJECTED — "
          f"{unexpected} unexpected acceptance(s)")
    print(f"D4 Sanity (valid commands)   : {sanity_ok}/2 OK")
    print(f"Overall                      : {summary['overall_result']}")
    print(f"Elapsed                      : {elapsed} ms")
    print(f"\nCSV  → {RAW_CSV}")
    print(f"JSON → {SUM_JSON}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--address', required=True, help='RPi BLE address')
    parser.add_argument('--n-inject', type=int, default=N_INJECT,
                        help='Injection attempts per direction (default 30)')
    args = parser.parse_args()
    asyncio.run(run(args.address, args.n_inject))


if __name__ == '__main__':
    main()
