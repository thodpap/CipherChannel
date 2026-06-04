#!/usr/bin/env python3
"""
BLE GATT experiment server — runs on the RPi.

Characteristics (all in SERVICE_UUID):

  Phone/laptop supervisory channel:
    SECURITY_UUID  (read+write): key exchange — client writes "REQUEST_KEY",
                   server puts encrypted SECURE_KEY in characteristic, client reads.
    COMMAND_UUID   (write): encrypted commands from phone/laptop.
    ACK_UUID       (read):  "OK:<trial_id>" polled by phone/laptop after each write.

  Cane (ESP32) channel:
    CANE_SECURITY_UUID (read+write+notify):
                   Cane writes encrypted {"action":"REQUEST_KEY"} (base channel).
                   Server responds by putting encrypted 32-byte cane key here.
                   Cane reads (or receives notify) and calls setSecureKey().
    CANE2PHONE_UUID    (read+write+notify):
                   Cane writes encrypted messages (secure channel) → server decrypts & logs.
                   Server can put encrypted commands here for cane to read/notify.
    CANE_RESET_UUID    (read+write):
                   Cane writes encrypted {"action":"RESET"} (secure channel) → server logs.
                   Server can put encrypted reset ACKs here.

Note on notifications:
  bless 0.3.0 has a bug with _notifying=True.  Characteristic values are set
  directly; if a future bless version fixes the bug, notify() calls can be added.
  The ESP32 firmware should fall back to polling if notifications are unavailable.

Wire format (new CipherChannel): nonce(16) || ciphertext || tag(16) — raw binary.

Logs to SERVER_CSV (default /tmp/experiment_server.csv):
  endpoint, trial_id, action, t_received_ns, t_ack_set_ns

Usage:
    python3 ble_server.py
    EXPERIMENT_SERVER_CSV_PATH=/data/server.csv python3 ble_server.py
"""

import asyncio
import csv
import json
import os
import pathlib
import subprocess
import sys
import time
import uuid as _uuid_mod

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from cipher import CipherChannel, ChannelException

try:
    from bless import (
        BlessServer,
        BlessGATTCharacteristic,
        GATTCharacteristicProperties,
        GATTAttributePermissions,
    )
except ImportError:
    sys.exit("bless not installed.  Run: pip install bless")

# ── Configuration ─────────────────────────────────────────────────────────────

# Pre-shared transport key (same on ESP32 firmware and all clients)
KEY: bytes = b'*\xc3,6s\xa4\xa2\xeeI\x08S>\xd0\xff%\x84\xba\xe9\x95\xcaNL\xffzL%h\x04)\x04%\xf8'

DEVICE_NAME  = "AWAKE-EXP"
SERVICE_UUID = "12345678-0000-1000-8000-00805f9b34fb"

# Phone/laptop supervisory channel
SECURITY_UUID = "fec26ec4-6d71-4442-9f81-55bc21d658d6"
COMMAND_UUID  = "51ff12bb-3ed8-46e5-b4f9-d64e2fec021b"
ACK_UUID      = "51ff12bc-3ed8-46e5-b4f9-d64e2fec021b"

# Cane (ESP32) channel
CANE2PHONE_UUID    = "74278bda-b644-4520-8f0c-720eaf059935"
CANE_SECURITY_UUID = "fa87c0d0-afac-11de-8a39-0800200c9a66"
CANE_RESET_UUID    = "d2b9a3d4-1a3d-0a6d-d7c8-b4d4d0a4b1e2"

SERVER_CSV = os.environ.get('EXPERIMENT_SERVER_CSV_PATH', '/tmp/experiment_server.csv')

# Persistent state directory for cane channel counters (survives server restart)
_STATE_DIR = pathlib.Path(os.environ.get('AWAKE_STATE_DIR', '/tmp/awake_exp_state'))
_CANE_BASE_PATH   = str(_STATE_DIR / 'cc_cane_base')
_CANE_SECURE_PATH = str(_STATE_DIR / 'cc_cane_secure')



# ── State ─────────────────────────────────────────────────────────────────────
_server: BlessServer = None             # type: ignore

# Phone/laptop session
_secure_key: bytes | None = None
_channel: CipherChannel | None = None

# Cane (ESP32) session
_cane_key: bytes | None = None
_cane_base_channel: CipherChannel | None = None    # base channel: server=responder
_cane_secure_channel: CipherChannel | None = None  # secure channel: server=responder


# ── CSV ───────────────────────────────────────────────────────────────────────

_CSV_COLUMNS = ['endpoint', 'trial_id', 'action', 't_received_ns', 't_ack_set_ns']


def _init_csv() -> None:
    with open(SERVER_CSV, 'w', newline='') as f:
        csv.writer(f).writerow(_CSV_COLUMNS)
    print(f"Server CSV: {SERVER_CSV}")


def _append_row(
    endpoint: str,
    trial_id: str,
    action: str,
    t_received_ns: int,
    t_ack_set_ns: int = 0,
) -> None:
    with open(SERVER_CSV, 'a', newline='') as f:
        csv.writer(f).writerow([endpoint, trial_id, action, t_received_ns, t_ack_set_ns])


# ── Cane channel helpers ───────────────────────────────────────────────────────

def _load_or_create_cane_base() -> CipherChannel:
    """
    Load the cane base channel from persistent state, or create fresh if missing.
    Server is always responder (ESP32 is initiator: sends even, receives odd).
    """
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        ch = CipherChannel.load(_CANE_BASE_PATH)
        if ch is not None:
            print(f"[{_ts()}] Cane base channel loaded from {_CANE_BASE_PATH}")
            return ch
    except ChannelException:
        pass
    ch = CipherChannel.create(KEY, False, _CANE_BASE_PATH)  # False = responder
    print(f"[{_ts()}] Cane base channel created (fresh) at {_CANE_BASE_PATH}")
    return ch


def _put_encrypted_to_cane(char_uuid: str, plaintext: bytes, channel: CipherChannel) -> bool:
    """
    Encrypt plaintext and put it into a cane characteristic value.
    The cane reads or receives a notify.  Returns True on success.
    """
    if _server is None:
        return False
    try:
        enc = channel.send(plaintext)
        char = _server.get_characteristic(char_uuid)
        char.value = bytearray(enc)
        return True
    except Exception as e:
        print(f"[{_ts()}] Failed to encrypt for cane char {char_uuid}: {e}")
        return False


# ── GATT request handlers ─────────────────────────────────────────────────────

def read_request(characteristic: BlessGATTCharacteristic, **kwargs) -> bytearray:
    return characteristic.value or bytearray()


def write_request(characteristic: BlessGATTCharacteristic, value: any, **kwargs) -> None:
    global _secure_key, _channel, _server
    global _cane_key, _cane_base_channel, _cane_secure_channel

    uuid = str(characteristic.uuid).lower()
    data = bytes(value)

    # ═══════════════════════════════════════════════════════════════════════════
    # Phone / laptop supervisory channel
    # ═══════════════════════════════════════════════════════════════════════════

    if uuid == SECURITY_UUID:
        # ── Phone key exchange ────────────────────────────────────────────────
        if data != b"REQUEST_KEY":
            return
        _secure_key = os.urandom(32)
        session_id  = _uuid_mod.uuid4().hex[:12]

        transport_path = f'/tmp/cc_transport_server_{session_id}'
        transport_ch = CipherChannel.create(KEY, True, transport_path)  # initiator: sends even

        session_path = f'/tmp/cc_session_server_{session_id}'
        _channel = CipherChannel.create(_secure_key, False, session_path)  # responder

        encrypted = transport_ch.send(_secure_key)
        characteristic.value = bytearray(encrypted)
        print(f"[{_ts()}] [phone] Key exchange: session={session_id} ({len(encrypted)} B)")
        return

    if uuid == COMMAND_UUID:
        # ── Phone encrypted command ───────────────────────────────────────────
        t_received = time.perf_counter_ns()
        if _channel is None:
            print(f"[{_ts()}] [phone] COMMAND but no session channel — skip key exchange?")
            return
        payload_bytes = _channel.receive(data)
        if payload_bytes is None:
            print(f"[{_ts()}] [phone] Decrypt/replay failed — packet rejected")
            return
        try:
            payload  = json.loads(payload_bytes)
            trial_id = str(payload.get('trial_id', 'unknown'))
            action   = str(payload.get('action',   'unknown'))
        except Exception as e:
            print(f"[{_ts()}] [phone] JSON parse error: {e}")
            return

        print(f"[{_ts()}] [phone] Received  trial={trial_id}  action={action}")

        ack_char = _server.get_characteristic(ACK_UUID)
        ack_char.value = bytearray(f"OK:{trial_id}".encode())
        t_ack_set = time.perf_counter_ns()

        _append_row('phone', trial_id, action, t_received, t_ack_set)
        print(f"[{_ts()}] [phone] ACK set   trial={trial_id}  "
              f"rx→ack={(t_ack_set - t_received) / 1e6:.2f} ms")
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # Cane (ESP32) channel
    # ═══════════════════════════════════════════════════════════════════════════

    if uuid == CANE_SECURITY_UUID:
        # ── Cane key exchange request ─────────────────────────────────────────
        # ESP32 encrypts {"action":"REQUEST_KEY"} or {"action":"STOP_SHARING"}
        # with channel (base key, initiator=true).
        # Server decrypts with _cane_base_channel (responder).
        #
        # Fallback: plaintext "REQUEST_CANE_KEY" for experiment-only testing.

        if _cane_base_channel is None:
            _cane_base_channel = _load_or_create_cane_base()

        payload_bytes = _cane_base_channel.receive(data)

        # Plaintext fallback for experiment scripts that don't use the ESP32
        if payload_bytes is None and data == b"REQUEST_CANE_KEY":
            payload_bytes = b'{"action":"REQUEST_KEY"}'

        if payload_bytes is None:
            print(f"[{_ts()}] [cane] CANE_SECURITY: decrypt failed — rejected")
            return

        try:
            msg = json.loads(payload_bytes)
            action = msg.get('action', '')
        except (json.JSONDecodeError, UnicodeDecodeError):
            action = payload_bytes.decode('utf-8', errors='replace')

        if action == 'REQUEST_KEY':
            # Generate new cane secure key and create cane secure channel
            _STATE_DIR.mkdir(parents=True, exist_ok=True)
            _cane_key = os.urandom(32)
            _cane_secure_channel = CipherChannel.create(_cane_key, False, _CANE_SECURE_PATH)

            # Encrypt cane key with base channel and put in characteristic
            # (cane reads it or receives notify)
            ok = _put_encrypted_to_cane(CANE_SECURITY_UUID, _cane_key, _cane_base_channel)
            if ok:
                print(f"[{_ts()}] [cane] Key exchange: new cane key ready in CANE_SECURITY_UUID")
            else:
                print(f"[{_ts()}] [cane] Key exchange: failed to put key in characteristic")
            _append_row('cane', 'key_exchange', 'REQUEST_KEY', time.perf_counter_ns())

        elif action == 'STOP_SHARING':
            print(f"[{_ts()}] [cane] STOP_SHARING received — cane key invalidated")
            _cane_key            = None
            _cane_secure_channel = None
            characteristic.value = bytearray(b"")
            _append_row('cane', 'key_exchange', 'STOP_SHARING', time.perf_counter_ns())

        else:
            print(f"[{_ts()}] [cane] CANE_SECURITY: unknown action={action!r}")
        return

    if uuid == CANE2PHONE_UUID:
        # ── Cane → RPi encrypted message (via secure channel) ─────────────────
        # ESP32 calls transmitMessage() which encrypts with secureChannel.
        t_received = time.perf_counter_ns()
        if _cane_secure_channel is None:
            print(f"[{_ts()}] [cane] CANE2PHONE but no secure channel — cane key exchange pending")
            return
        payload_bytes = _cane_secure_channel.receive(data)
        if payload_bytes is None:
            print(f"[{_ts()}] [cane] CANE2PHONE: decrypt/replay failed — rejected")
            return
        try:
            payload_str = payload_bytes.decode('utf-8', errors='replace')
        except Exception:
            payload_str = repr(payload_bytes)

        print(f"[{_ts()}] [cane] CANE2PHONE: {payload_str}")
        _append_row('cane', 'cane2phone', payload_str, t_received)
        return

    if uuid == CANE_RESET_UUID:
        # ── Cane → RPi reset command (via secure channel) ─────────────────────
        # ESP32 calls sendResetCommand() which encrypts {"action":"RESET"} with secureChannel.
        t_received = time.perf_counter_ns()
        if _cane_secure_channel is None:
            print(f"[{_ts()}] [cane] CANE_RESET but no secure channel — rejected")
            return
        payload_bytes = _cane_secure_channel.receive(data)
        if payload_bytes is None:
            print(f"[{_ts()}] [cane] CANE_RESET: decrypt/replay failed — rejected")
            return
        try:
            msg    = json.loads(payload_bytes)
            action = msg.get('action', 'unknown')
        except Exception:
            action = payload_bytes.decode('utf-8', errors='replace')

        print(f"[{_ts()}] [cane] CANE_RESET: action={action}")
        _append_row('cane', 'cane_reset', action, t_received)

        if action == 'RESET':
            # Acknowledge reset: put encrypted "ACK" into CANE_RESET_UUID so cane can read it
            if _cane_base_channel is not None:
                _put_encrypted_to_cane(CANE_RESET_UUID, b'{"action":"RESET_ACK"}', _cane_base_channel)
                print(f"[{_ts()}] [cane] RESET_ACK written to CANE_RESET_UUID")
        return


def _ts() -> str:
    return time.strftime('%H:%M:%S')


# ── Public helpers (call from Python REPL or another coroutine if needed) ─────

def send_command_to_cane(plaintext: bytes) -> bool:
    """
    Encrypt plaintext with the cane base channel and put it in CANE2PHONE_UUID
    so the cane can read or receive a notify.
    """
    if _cane_base_channel is None:
        print("No cane base channel — cane key exchange not complete")
        return False
    return _put_encrypted_to_cane(CANE2PHONE_UUID, plaintext, _cane_base_channel)


def send_reset_to_cane() -> bool:
    """
    Send an encrypted {"action":"RESET"} to the cane via CANE_RESET_UUID.
    The cane polls or receives notify, decrypts with secureChannel, and resets.
    """
    if _cane_secure_channel is None:
        print("No cane secure channel — cane key exchange not complete")
        return False
    ok = _put_encrypted_to_cane(CANE_RESET_UUID, b'{"action":"RESET"}', _cane_secure_channel)
    if ok:
        print(f"[{_ts()}] Reset command written to CANE_RESET_UUID")
    return ok


# ── Main ──────────────────────────────────────────────────────────────────────

def _disable_br_edr_scan() -> None:
    try:
        subprocess.run(['sudo', 'hciconfig', 'hci0', 'noscan'], check=True, capture_output=True)
        print(f"[{_ts()}] Classic BT scan disabled (hci0 noscan)")
    except Exception as e:
        print(f"[{_ts()}] Warning: could not disable classic BT scan: {e}")


async def main() -> None:
    global _server, _cane_base_channel

    _disable_br_edr_scan()
    _init_csv()

    # Pre-load cane base channel (persistent counters survive server restart)
    _cane_base_channel = _load_or_create_cane_base()

    loop    = asyncio.get_event_loop()
    _server = BlessServer(name=DEVICE_NAME, loop=loop)
    _server.read_request_func  = read_request
    _server.write_request_func = write_request

    RW  = GATTCharacteristicProperties.read  | GATTCharacteristicProperties.write
    W   = GATTCharacteristicProperties.write | GATTCharacteristicProperties.write_without_response
    RWN = RW | GATTCharacteristicProperties.notify
    RP  = GATTAttributePermissions.readable | GATTAttributePermissions.writeable

    gatt = {
        SERVICE_UUID: {
            # ── Phone / laptop supervisory channel ──────────────────────────────
            SECURITY_UUID: {
                "Properties": RW,
                "Permissions": RP,
                "Value": bytearray(b""),
            },
            COMMAND_UUID: {
                "Properties": W,
                "Permissions": GATTAttributePermissions.writeable,
                "Value": None,
            },
            ACK_UUID: {
                "Properties": GATTCharacteristicProperties.read,
                "Permissions": GATTAttributePermissions.readable,
                "Value": bytearray(b"READY"),
            },
            # ── Cane (ESP32) channel ────────────────────────────────────────────
            # Key exchange: cane writes encrypted REQUEST_KEY; server responds
            # by putting encrypted cane key in value (cane reads/notifies).
            CANE_SECURITY_UUID: {
                "Properties": RWN,
                "Permissions": RP,
                "Value": bytearray(b""),
            },
            # Cane→RPi: cane writes encrypted messages (secure ch); also used
            # for RPi→cane encrypted commands (cane reads/notifies, base ch).
            CANE2PHONE_UUID: {
                "Properties": RWN,
                "Permissions": RP,
                "Value": bytearray(b""),
            },
            # Cane→RPi: cane writes encrypted {"action":"RESET"} (secure ch).
            # RPi→cane: server writes encrypted RESET_ACK (base ch).
            CANE_RESET_UUID: {
                "Properties": RW,
                "Permissions": RP,
                "Value": bytearray(b""),
            },
        }
    }

    await _server.add_gatt(gatt)
    await _server.start()
    print(f"[{_ts()}] {DEVICE_NAME!r} advertising — {len(gatt[SERVICE_UUID])} characteristics.")
    print(f"[{_ts()}] Phone channel: SECURITY / COMMAND / ACK")
    print(f"[{_ts()}] Cane channel : CANE_SECURITY / CANE2PHONE / CANE_RESET")
    print(f"[{_ts()}] Cane state   : {_STATE_DIR}")
    print(f"[{_ts()}] Waiting for connections…\n")

    stop = asyncio.Event()
    try:
        await stop.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        print(f"\n[{_ts()}] Shutting down.")
        await _server.stop()
        print(f"[{_ts()}] Server CSV → {SERVER_CSV}")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
