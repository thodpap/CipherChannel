#!/usr/bin/env python3
"""
BLE GATT experiment server — runs on the RPi.

Characteristics (all in SERVICE_UUID):

  Phone/laptop supervisory channel:
    SECURITY_UUID  (read+write): key exchange — client writes "REQUEST_KEY",
                   server puts encrypted SECURE_KEY in characteristic, client reads.
                   Client may also write "STOP_SHARING" to invalidate the session.
    COMMAND_UUID   (write): encrypted commands from phone/laptop.
    ACK_UUID       (read):  "OK:<trial_id>" polled by phone/laptop after each write.

  Cane (ESP32) channel:
    CANE_SECURITY_UUID (read+write+notify):
                   Cane writes encrypted {"action":"REQUEST_KEY"} (base channel).
                   Server responds by putting encrypted 32-byte cane key here.
                   Cane reads (or receives notify) and calls setSecureKey().
    CANE2PHONE_UUID    (read+write+notify):
                   Cane writes encrypted messages (secure channel) → server decrypts & logs.
    CANE_RESET_UUID    (read+write):
                   Cane writes encrypted {"action":"RESET"} (secure channel) → server logs.

Provisioning gate:
  REQUEST_KEY is only fulfilled while a provisioning window is open.
  In production, the window is opened by pressing a GPIO button on the RPi:
    - BCM pin 17 (default) → phone provisioning window
    - BCM pin 27 (default) → cane  provisioning window
  Configure via env vars: PHONE_GATE_PIN=17  CANE_GATE_PIN=27
  For automated experiments, set BENCHMARK_PROVISIONING=1 (NOT for production).

Wire format: nonce(12) || ciphertext(N) || tag(16) — raw binary, overhead = 28 bytes.
MAX_PLAINTEXT_SIZE = 400 bytes; MAX_PACKET_SIZE = 428 bytes.

Per-endpoint keys:
  K_phone  — phone/laptop supervisory session channel
  K_cane   — cane (ESP32) base and secure channels
  Phone packets cannot be accepted by the cane context and vice-versa.

Usage:
    python3 ble_server.py
    BENCHMARK_PROVISIONING=1 python3 ble_server.py   # experiments only
    PHONE_GATE_PIN=17 CANE_GATE_PIN=27 python3 ble_server.py
    EXPERIMENT_SERVER_CSV_PATH=/data/server.csv python3 ble_server.py
"""

import asyncio
import csv
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import uuid as _uuid_mod

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from cipher import CipherChannel, ChannelException
from provisioning_gate import ProvisioningGate, BenchmarkProvisioningGate

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

# Pre-shared transport key (same on ESP32 firmware and all clients).
# Used only for the base channel that delivers per-endpoint operational keys.
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

# Persistent state for cane channel (survives server restart)
_STATE_DIR        = pathlib.Path(os.environ.get('AWAKE_STATE_DIR', '/tmp/awake_exp_state'))
_CANE_BASE_PATH   = str(_STATE_DIR / 'cc_cane_base')
_CANE_SECURE_PATH = str(_STATE_DIR / 'cc_cane_secure')

# Delay before clearing key material from GATT characteristic (seconds).
# The client must be given time to read the characteristic before we clear it.
_KEY_CLEAR_DELAY = 3.0


# ── Provisioning gates ────────────────────────────────────────────────────────

_benchmark_mode = os.environ.get('BENCHMARK_PROVISIONING') == '1'
if _benchmark_mode:
    print('[WARN] Benchmark provisioning gate enabled — NOT for production use')
    _phone_gate: ProvisioningGate = BenchmarkProvisioningGate()
    _cane_gate:  ProvisioningGate = BenchmarkProvisioningGate()
else:
    _phone_gate = ProvisioningGate()
    _cane_gate  = ProvisioningGate()


# ── GPIO button setup (production provisioning) ───────────────────────────────
# Wire normally-open pushbuttons to BCM 17 (phone) and BCM 27 (cane).
# Other terminal to GND; internal pull-up is enabled.
# Override via PHONE_GATE_PIN / CANE_GATE_PIN environment variables.

PHONE_GATE_PIN      = int(os.environ.get('PHONE_GATE_PIN', '17'))
CANE_GATE_PIN       = int(os.environ.get('CANE_GATE_PIN',  '27'))
_BUTTON_DEBOUNCE_MS = 300
_gpio_cleanup       = lambda: None    # replaced on successful GPIO init


def _setup_gpio() -> None:
    """
    Configure GPIO buttons for production provisioning.

    Skipped in benchmark mode.  If RPi.GPIO is not installed or setup fails,
    a warning is printed and provisioning gates must be opened programmatically
    via open_phone_gate() / open_cane_gate().  Production deployments MUST have
    GPIO working — the warning should be treated as an error in that context.
    """
    global _gpio_cleanup
    if _benchmark_mode:
        return
    try:
        import RPi.GPIO as GPIO
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(PHONE_GATE_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.setup(CANE_GATE_PIN,  GPIO.IN, pull_up_down=GPIO.PUD_UP)

        def _phone_cb(_ch: int) -> None:
            print(f"[{_ts()}] GPIO BCM{PHONE_GATE_PIN}: phone provisioning button pressed")
            _phone_gate.open('phone')

        def _cane_cb(_ch: int) -> None:
            print(f"[{_ts()}] GPIO BCM{CANE_GATE_PIN}: cane provisioning button pressed")
            _cane_gate.open('cane')

        GPIO.add_event_detect(PHONE_GATE_PIN, GPIO.FALLING,
                              callback=_phone_cb, bouncetime=_BUTTON_DEBOUNCE_MS)
        GPIO.add_event_detect(CANE_GATE_PIN,  GPIO.FALLING,
                              callback=_cane_cb,  bouncetime=_BUTTON_DEBOUNCE_MS)
        _gpio_cleanup = GPIO.cleanup
        print(f"[{_ts()}] GPIO ready: phone=BCM{PHONE_GATE_PIN}  cane=BCM{CANE_GATE_PIN}  "
              f"debounce={_BUTTON_DEBOUNCE_MS} ms")
    except ImportError:
        print("[WARN] RPi.GPIO not installed — GPIO button provisioning unavailable.")
        print("[WARN] Install with: pip install RPi.GPIO")
        print("[WARN] Provisioning gates must be opened via open_phone_gate() / open_cane_gate()")
    except Exception as e:
        print(f"[WARN] GPIO setup failed: {e}")
        print("[WARN] Provisioning gates must be opened programmatically")


# ── Global state ──────────────────────────────────────────────────────────────

_server: BlessServer = None   # type: ignore
_loop:   asyncio.AbstractEventLoop = None  # type: ignore

# Phone/laptop session — endpoint-specific operational key K_phone
_phone_key:     bytes | None          = None
_phone_channel: CipherChannel | None = None

# Cane (ESP32) session — endpoint-specific operational keys K_cane_base / K_cane_secure
_cane_key:            bytes | None          = None
_cane_base_channel:   CipherChannel | None = None
_cane_secure_channel: CipherChannel | None = None


# ── CSV ───────────────────────────────────────────────────────────────────────

_CSV_COLUMNS = ['endpoint', 'trial_id', 'action', 't_received_ns', 't_ack_set_ns']


def _init_csv() -> None:
    with open(SERVER_CSV, 'w', newline='') as f:
        csv.writer(f).writerow(_CSV_COLUMNS)
    print(f"Server CSV: {SERVER_CSV}")


def _append_row(endpoint: str, trial_id: str, action: str,
                t_received_ns: int, t_ack_set_ns: int = 0) -> None:
    with open(SERVER_CSV, 'a', newline='') as f:
        csv.writer(f).writerow([endpoint, trial_id, action, t_received_ns, t_ack_set_ns])


# ── Cane channel helpers ───────────────────────────────────────────────────────

def _load_or_create_cane_base() -> CipherChannel:
    """Load or create the cane base channel. Server is always responder."""
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        ch = CipherChannel.load(_CANE_BASE_PATH, endpoint_id='cane_base')
        print(f"[{_ts()}] Cane base channel loaded from {_CANE_BASE_PATH}")
        return ch
    except ChannelException:
        pass
    ch = CipherChannel.create(KEY, False, _CANE_BASE_PATH, endpoint_id='cane_base')
    print(f"[{_ts()}] Cane base channel created (fresh) at {_CANE_BASE_PATH}")
    return ch


def _put_encrypted_to_cane(char_uuid: str, plaintext: bytes,
                            channel: CipherChannel) -> bool:
    if _server is None:
        return False
    try:
        enc  = channel.send(plaintext)
        char = _server.get_characteristic(char_uuid)
        char.value = bytearray(enc)
        return True
    except Exception as e:
        print(f"[{_ts()}] Failed to encrypt for cane char {char_uuid}: {e}")
        return False


def _schedule_clear_char(char_uuid: str) -> None:
    """Schedule clearing key material from a GATT characteristic after a delay."""
    if _loop is None:
        return

    def _do_clear():
        if _server is not None:
            char = _server.get_characteristic(char_uuid)
            if char is not None:
                char.value = bytearray(b'')

    _loop.call_later(_KEY_CLEAR_DELAY, _do_clear)


def _close_phone_session() -> None:
    """Invalidate the phone session and close the provisioning gate."""
    global _phone_key, _phone_channel
    _phone_key     = None
    _phone_channel = None
    _phone_gate.close()


# ── GATT request handlers ─────────────────────────────────────────────────────

def read_request(characteristic: BlessGATTCharacteristic, **kwargs) -> bytearray:
    return characteristic.value or bytearray()


def write_request(characteristic: BlessGATTCharacteristic, value: any,
                  **kwargs) -> None:
    global _phone_key, _phone_channel
    global _cane_key, _cane_base_channel, _cane_secure_channel

    uuid = str(characteristic.uuid).lower()
    data = bytes(value)

    # ═══════════════════════════════════════════════════════════════════════════
    # Phone / laptop supervisory channel
    # ═══════════════════════════════════════════════════════════════════════════

    if uuid == SECURITY_UUID:
        if data == b"REQUEST_KEY":
            if not _phone_gate.try_provision('phone'):
                print(f"[{_ts()}] [phone] REQUEST_KEY rejected — provisioning gate closed")
                return

            # Generate endpoint-specific operational key K_phone
            _phone_key  = os.urandom(32)
            session_id  = _uuid_mod.uuid4().hex[:12]

            # Deliver K_phone via the pre-shared transport channel (initiator side)
            transport_path = f'/tmp/cc_transport_server_{session_id}'
            transport_ch   = CipherChannel.create(KEY, True, transport_path,
                                                  endpoint_id='phone_transport')

            # Create phone session channel — server is responder (K_phone)
            session_path   = f'/tmp/cc_session_server_{session_id}'
            _phone_channel = CipherChannel.create(_phone_key, False, session_path,
                                                  endpoint_id='phone')

            encrypted = transport_ch.send(_phone_key)
            characteristic.value = bytearray(encrypted)
            print(f"[{_ts()}] [phone] Key issued: session={session_id} ({len(encrypted)} B)")

            # Clear key material from characteristic after client reads it
            _schedule_clear_char(SECURITY_UUID)

        elif data == b"STOP_SHARING":
            print(f"[{_ts()}] [phone] STOP_SHARING (plaintext) — phone session invalidated")
            _close_phone_session()
            characteristic.value = bytearray(b'')
            _append_row('phone', 'key_exchange', 'STOP_SHARING', time.perf_counter_ns())

        return

    if uuid == COMMAND_UUID:
        t_received = time.perf_counter_ns()
        if _phone_channel is None:
            print(f"[{_ts()}] [phone] COMMAND but no session channel — do key exchange first")
            return
        payload_bytes = _phone_channel.receive(data)
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

        if action == 'STOP_SHARING':
            print(f"[{_ts()}] [phone] STOP_SHARING (encrypted) — phone session invalidated")
            _close_phone_session()
            _append_row('phone', trial_id, action, t_received)
            return

        print(f"[{_ts()}] [phone] Received  trial={trial_id}  action={action}")
        ack_char       = _server.get_characteristic(ACK_UUID)
        ack_char.value = bytearray(f"OK:{trial_id}".encode())
        t_ack_set      = time.perf_counter_ns()
        _append_row('phone', trial_id, action, t_received, t_ack_set)
        print(f"[{_ts()}] [phone] ACK set   trial={trial_id}  "
              f"rx→ack={(t_ack_set - t_received) / 1e6:.2f} ms")
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # Cane (ESP32) channel
    # ═══════════════════════════════════════════════════════════════════════════

    if uuid == CANE_SECURITY_UUID:
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
            msg    = json.loads(payload_bytes)
            action = msg.get('action', '')
        except (json.JSONDecodeError, UnicodeDecodeError):
            action = payload_bytes.decode('utf-8', errors='replace')

        if action == 'REQUEST_KEY':
            if not _cane_gate.try_provision('cane'):
                print(f"[{_ts()}] [cane] REQUEST_KEY rejected — provisioning gate closed")
                return

            # Generate endpoint-specific operational key K_cane
            _STATE_DIR.mkdir(parents=True, exist_ok=True)
            _cane_key            = os.urandom(32)
            _cane_secure_channel = CipherChannel.create(
                _cane_key, False, _CANE_SECURE_PATH, endpoint_id='cane_secure')

            ok = _put_encrypted_to_cane(
                CANE_SECURITY_UUID, _cane_key, _cane_base_channel)
            if ok:
                print(f"[{_ts()}] [cane] Key issued: new K_cane in CANE_SECURITY_UUID")
                _schedule_clear_char(CANE_SECURITY_UUID)
            else:
                print(f"[{_ts()}] [cane] Key exchange: failed to write to characteristic")
                _cane_key            = None
                _cane_secure_channel = None
                _cane_gate.close()    # provisioning error — close gate
            _append_row('cane', 'key_exchange', 'REQUEST_KEY', time.perf_counter_ns())

        elif action == 'STOP_SHARING':
            # STOP_SHARING means "I received K_cane, clear it from the characteristic."
            # The secure channel remains alive — RESET and CANE2PHONE follow immediately.
            print(f"[{_ts()}] [cane] STOP_SHARING received — gate closed, secure channel active")
            _cane_gate.close()
            characteristic.value = bytearray(b'')
            _append_row('cane', 'key_exchange', 'STOP_SHARING', time.perf_counter_ns())

        else:
            print(f"[{_ts()}] [cane] CANE_SECURITY: unknown action={action!r}")
        return

    if uuid == CANE2PHONE_UUID:
        t_received = time.perf_counter_ns()
        if _cane_secure_channel is None:
            print(f"[{_ts()}] [cane] CANE2PHONE but no secure channel")
            return
        payload_bytes = _cane_secure_channel.receive(data)
        if payload_bytes is None:
            print(f"[{_ts()}] [cane] CANE2PHONE: decrypt/replay failed — rejected")
            return
        payload_str = payload_bytes.decode('utf-8', errors='replace')
        print(f"[{_ts()}] [cane] CANE2PHONE: {payload_str}")
        _append_row('cane', 'cane2phone', payload_str, t_received)
        return

    if uuid == CANE_RESET_UUID:
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

        if action == 'RESET' and _cane_base_channel is not None:
            _put_encrypted_to_cane(
                CANE_RESET_UUID, b'{"action":"RESET_ACK"}', _cane_base_channel)
            print(f"[{_ts()}] [cane] RESET_ACK written to CANE_RESET_UUID")
        return


def _ts() -> str:
    return time.strftime('%H:%M:%S')


# ── Public helpers ────────────────────────────────────────────────────────────

def open_phone_gate(duration_s: int = ProvisioningGate.WINDOW_SECONDS) -> None:
    """Open the phone provisioning window. In production, call from GPIO handler."""
    _phone_gate.open('phone', duration_s)


def open_cane_gate(duration_s: int = ProvisioningGate.WINDOW_SECONDS) -> None:
    """Open the cane provisioning window. In production, call from GPIO handler."""
    _cane_gate.open('cane', duration_s)


def send_command_to_cane(plaintext: bytes) -> bool:
    if _cane_base_channel is None:
        print("No cane base channel — cane key exchange not complete")
        return False
    return _put_encrypted_to_cane(CANE2PHONE_UUID, plaintext, _cane_base_channel)


def send_reset_to_cane() -> bool:
    if _cane_secure_channel is None:
        print("No cane secure channel — cane key exchange not complete")
        return False
    ok = _put_encrypted_to_cane(
        CANE_RESET_UUID, b'{"action":"RESET"}', _cane_secure_channel)
    if ok:
        print(f"[{_ts()}] Reset command written to CANE_RESET_UUID")
    return ok


# ── Main ──────────────────────────────────────────────────────────────────────

def _disable_br_edr_scan() -> None:
    try:
        subprocess.run(['sudo', 'hciconfig', 'hci0', 'noscan'],
                       check=True, capture_output=True)
        print(f"[{_ts()}] Classic BT scan disabled (hci0 noscan)")
    except Exception as e:
        print(f"[{_ts()}] Warning: could not disable classic BT scan: {e}")


async def main() -> None:
    global _server, _cane_base_channel, _loop

    _disable_br_edr_scan()
    _init_csv()
    _setup_gpio()
    _loop = asyncio.get_event_loop()

    _cane_base_channel = _load_or_create_cane_base()

    _server = BlessServer(name=DEVICE_NAME, loop=_loop)
    _server.read_request_func  = read_request
    _server.write_request_func = write_request

    RW  = GATTCharacteristicProperties.read  | GATTCharacteristicProperties.write
    W   = GATTCharacteristicProperties.write | GATTCharacteristicProperties.write_without_response
    RWN = RW | GATTCharacteristicProperties.notify
    RP  = GATTAttributePermissions.readable | GATTAttributePermissions.writeable

    gatt = {
        SERVICE_UUID: {
            SECURITY_UUID: {"Properties": RW,  "Permissions": RP,  "Value": bytearray(b'')},
            COMMAND_UUID:  {"Properties": W,   "Permissions": GATTAttributePermissions.writeable, "Value": None},
            ACK_UUID:      {"Properties": GATTCharacteristicProperties.read, "Permissions": GATTAttributePermissions.readable, "Value": bytearray(b'READY')},
            CANE_SECURITY_UUID: {"Properties": RWN, "Permissions": RP, "Value": bytearray(b'')},
            CANE2PHONE_UUID:    {"Properties": RWN, "Permissions": RP, "Value": bytearray(b'')},
            CANE_RESET_UUID:    {"Properties": RW,  "Permissions": RP, "Value": bytearray(b'')},
        }
    }

    await _server.add_gatt(gatt)
    await _server.start()
    print(f"[{_ts()}] {DEVICE_NAME!r} advertising — {len(gatt[SERVICE_UUID])} characteristics.")
    print(f"[{_ts()}] Phone channel : SECURITY / COMMAND / ACK")
    print(f"[{_ts()}] Cane channel  : CANE_SECURITY / CANE2PHONE / CANE_RESET")
    print(f"[{_ts()}] Cane state    : {_STATE_DIR}")
    if _benchmark_mode:
        print(f"[{_ts()}] Provisioning  : BENCHMARK MODE (gate always open)")
    else:
        print(f"[{_ts()}] Provisioning  : gate CLOSED — "
              f"press BCM{PHONE_GATE_PIN}/BCM{CANE_GATE_PIN} buttons to open")
    print(f"[{_ts()}] Waiting for connections…\n")

    stop = asyncio.Event()
    try:
        await stop.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        print(f"\n[{_ts()}] Shutting down.")
        # Close both gates to prevent any in-flight provisioning from completing
        _phone_gate.close()
        _cane_gate.close()
        _gpio_cleanup()
        await _server.stop()
        print(f"[{_ts()}] Server CSV → {SERVER_CSV}")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
