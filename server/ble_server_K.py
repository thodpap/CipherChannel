#!/usr/bin/env python3
"""
BLE GATT server for Experiment K — Concurrent phone and cane traffic.

Identical to ble_server.py except:
  - Extended CSV columns: counter, runtime_forward_ns, ack_set_ns, action, success, scenario
  - Counter is extracted from the raw packet nonce BEFORE receive() so it is
    logged even if decryption fails.
  - runtime_forward_ns is recorded after JSON parse + action dispatch (the
    point at which the server has identified what to do) but before setting ACK.
  - scenario label is set via EXPERIMENT_K_SCENARIO env var (default 'unset').

Usage (RPi):
  BENCHMARK_PROVISIONING=1 \\
  EXPERIMENT_K_SCENARIO=concurrent \\
  EXPERIMENT_SERVER_CSV_PATH=/tmp/exp_K_concurrent.csv \\
  server/.venv/bin/python server/ble_server_K.py
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

KEY: bytes = b'*\xc3,6s\xa4\xa2\xeeI\x08S>\xd0\xff%\x84\xba\xe9\x95\xcaNL\xffzL%h\x04)\x04%\xf8'

DEVICE_NAME  = "AWAKE-EXP"
SERVICE_UUID = "12345678-0000-1000-8000-00805f9b34fb"

SECURITY_UUID      = "fec26ec4-6d71-4442-9f81-55bc21d658d6"
COMMAND_UUID       = "51ff12bb-3ed8-46e5-b4f9-d64e2fec021b"
ACK_UUID           = "51ff12bc-3ed8-46e5-b4f9-d64e2fec021b"
CANE2PHONE_UUID    = "74278bda-b644-4520-8f0c-720eaf059935"
CANE_SECURITY_UUID = "fa87c0d0-afac-11de-8a39-0800200c9a66"
CANE_RESET_UUID    = "d2b9a3d4-1a3d-0a6d-d7c8-b4d4d0a4b1e2"

SERVER_CSV = os.environ.get('EXPERIMENT_SERVER_CSV_PATH', '/tmp/exp_K_server.csv')
_SCENARIO  = os.environ.get('EXPERIMENT_K_SCENARIO', 'unset')

_STATE_DIR        = pathlib.Path(os.environ.get('AWAKE_STATE_DIR', '/tmp/awake_exp_state'))
_CANE_BASE_PATH   = str(_STATE_DIR / 'cc_cane_base')
_CANE_SECURE_PATH = str(_STATE_DIR / 'cc_cane_secure')

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

PHONE_GATE_PIN      = int(os.environ.get('PHONE_GATE_PIN', '17'))
CANE_GATE_PIN       = int(os.environ.get('CANE_GATE_PIN',  '27'))
_BUTTON_DEBOUNCE_MS = 300
_gpio_cleanup       = lambda: None

def _setup_gpio() -> None:
    global _gpio_cleanup
    if _benchmark_mode:
        return
    try:
        import RPi.GPIO as GPIO
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(PHONE_GATE_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.setup(CANE_GATE_PIN,  GPIO.IN, pull_up_down=GPIO.PUD_UP)
        def _phone_cb(_ch): _phone_gate.open('phone')
        def _cane_cb(_ch):  _cane_gate.open('cane')
        GPIO.add_event_detect(PHONE_GATE_PIN, GPIO.FALLING,
                              callback=_phone_cb, bouncetime=_BUTTON_DEBOUNCE_MS)
        GPIO.add_event_detect(CANE_GATE_PIN,  GPIO.FALLING,
                              callback=_cane_cb,  bouncetime=_BUTTON_DEBOUNCE_MS)
        _gpio_cleanup = GPIO.cleanup
    except Exception as e:
        print(f"[WARN] GPIO setup failed: {e}")

# ── Global state ──────────────────────────────────────────────────────────────

_server: BlessServer = None  # type: ignore
_loop:   asyncio.AbstractEventLoop = None  # type: ignore

_phone_key:     bytes | None          = None
_phone_channel: CipherChannel | None = None

_cane_key:            bytes | None          = None
_cane_base_channel:   CipherChannel | None = None
_cane_secure_channel: CipherChannel | None = None

# ── CSV ───────────────────────────────────────────────────────────────────────

_CSV_COLUMNS = [
    'scenario', 'endpoint', 'message_id', 'action',
    'counter',
    'gateway_receive_ns', 'runtime_forward_ns', 'ack_set_ns',
    'success',
]


def _init_csv() -> None:
    with open(SERVER_CSV, 'w', newline='') as f:
        csv.writer(f).writerow(_CSV_COLUMNS)
    print(f"Server CSV: {SERVER_CSV}  (scenario={_SCENARIO})")


def _append_row(endpoint: str, message_id: str, action: str,
                counter: int,
                gateway_receive_ns: int,
                runtime_forward_ns: int,
                ack_set_ns: int,
                success: bool) -> None:
    with open(SERVER_CSV, 'a', newline='') as f:
        csv.writer(f).writerow([
            _SCENARIO, endpoint, message_id, action,
            counter,
            gateway_receive_ns, runtime_forward_ns, ack_set_ns,
            success,
        ])


def _extract_counter(data: bytes) -> int:
    """Read the 12-byte little-endian nonce from the packet header as an integer."""
    if len(data) < 12:
        return -1
    return int.from_bytes(data[:12], 'little')

# ── Cane channel helpers ───────────────────────────────────────────────────────

def _load_or_create_cane_base() -> CipherChannel:
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
    if _loop is None:
        return
    def _do_clear():
        if _server is not None:
            char = _server.get_characteristic(char_uuid)
            if char is not None:
                char.value = bytearray(b'')
    _loop.call_later(_KEY_CLEAR_DELAY, _do_clear)


def _close_phone_session() -> None:
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
                print(f"[{_ts()}] [phone] REQUEST_KEY rejected — gate closed")
                return
            _phone_key  = os.urandom(32)
            session_id  = _uuid_mod.uuid4().hex[:12]
            transport_path = f'/tmp/cc_K_transport_{session_id}'
            transport_ch   = CipherChannel.create(KEY, True, transport_path,
                                                  endpoint_id='phone_transport')
            session_path   = f'/tmp/cc_K_session_{session_id}'
            _phone_channel = CipherChannel.create(_phone_key, False, session_path,
                                                  endpoint_id='phone')
            encrypted = transport_ch.send(_phone_key)
            characteristic.value = bytearray(encrypted)
            print(f"[{_ts()}] [phone] Key issued: session={session_id}")
            _schedule_clear_char(SECURITY_UUID)

        elif data == b"STOP_SHARING":
            print(f"[{_ts()}] [phone] STOP_SHARING — session invalidated")
            _close_phone_session()
            characteristic.value = bytearray(b'')
        return

    if uuid == COMMAND_UUID:
        gateway_receive_ns = time.perf_counter_ns()
        counter = _extract_counter(data)

        if _phone_channel is None:
            print(f"[{_ts()}] [phone] COMMAND but no session — do key exchange first")
            _append_row('phone', 'unknown', 'NO_SESSION', counter,
                        gateway_receive_ns, gateway_receive_ns, 0, False)
            return

        payload_bytes = _phone_channel.receive(data)
        if payload_bytes is None:
            print(f"[{_ts()}] [phone] Decrypt/replay failed — rejected")
            _append_row('phone', 'unknown', 'DECRYPT_FAIL', counter,
                        gateway_receive_ns, gateway_receive_ns, 0, False)
            return

        try:
            payload  = json.loads(payload_bytes)
            trial_id = str(payload.get('trial_id', 'unknown'))
            action   = str(payload.get('action',   'unknown'))
        except Exception as e:
            print(f"[{_ts()}] [phone] JSON parse error: {e}")
            _append_row('phone', 'unknown', 'JSON_ERROR', counter,
                        gateway_receive_ns, time.perf_counter_ns(), 0, False)
            return

        runtime_forward_ns = time.perf_counter_ns()

        if action == 'STOP_SHARING':
            _close_phone_session()
            _append_row('phone', trial_id, action, counter,
                        gateway_receive_ns, runtime_forward_ns, 0, True)
            return

        ack_char = _server.get_characteristic(ACK_UUID)
        ack_char.value = bytearray(f"OK:{trial_id}".encode())
        ack_set_ns = time.perf_counter_ns()

        _append_row('phone', trial_id, action, counter,
                    gateway_receive_ns, runtime_forward_ns, ack_set_ns, True)
        print(f"[{_ts()}] [phone] {trial_id}  ctr={counter}  "
              f"rx→fwd={(runtime_forward_ns - gateway_receive_ns)/1e6:.2f}  "
              f"fwd→ack={(ack_set_ns - runtime_forward_ns)/1e6:.2f} ms")
        return

    # ═══════════════════════════════════════════════════════════════════════════
    # Cane (ESP32 or Python simulator) channel
    # ═══════════════════════════════════════════════════════════════════════════

    if uuid == CANE_SECURITY_UUID:
        if _cane_base_channel is None:
            _cane_base_channel = _load_or_create_cane_base()

        payload_bytes = _cane_base_channel.receive(data)
        if payload_bytes is None and data == b"REQUEST_CANE_KEY":
            payload_bytes = b'{"action":"REQUEST_KEY"}'

        if payload_bytes is None:
            print(f"[{_ts()}] [cane] CANE_SECURITY: decrypt failed")
            return

        try:
            msg    = json.loads(payload_bytes)
            action = msg.get('action', '')
        except (json.JSONDecodeError, UnicodeDecodeError):
            action = payload_bytes.decode('utf-8', errors='replace')

        if action == 'REQUEST_KEY':
            if not _cane_gate.try_provision('cane'):
                print(f"[{_ts()}] [cane] REQUEST_KEY rejected — gate closed")
                return
            _STATE_DIR.mkdir(parents=True, exist_ok=True)
            _cane_key            = os.urandom(32)
            _cane_secure_channel = CipherChannel.create(
                _cane_key, False, _CANE_SECURE_PATH, endpoint_id='cane_secure')
            ok = _put_encrypted_to_cane(CANE_SECURITY_UUID, _cane_key, _cane_base_channel)
            if ok:
                print(f"[{_ts()}] [cane] Key issued")
                _schedule_clear_char(CANE_SECURITY_UUID)
            else:
                _cane_key = None
                _cane_secure_channel = None
                _cane_gate.close()

        elif action == 'STOP_SHARING':
            print(f"[{_ts()}] [cane] STOP_SHARING — gate closed, secure channel active")
            _cane_gate.close()
            characteristic.value = bytearray(b'')
        return

    if uuid == CANE2PHONE_UUID:
        gateway_receive_ns = time.perf_counter_ns()
        counter = _extract_counter(data)

        if _cane_secure_channel is None:
            print(f"[{_ts()}] [cane] CANE2PHONE but no secure channel")
            _append_row('cane', 'unknown', 'NO_SESSION', counter,
                        gateway_receive_ns, gateway_receive_ns, 0, False)
            return

        payload_bytes = _cane_secure_channel.receive(data)
        if payload_bytes is None:
            print(f"[{_ts()}] [cane] CANE2PHONE: decrypt/replay failed")
            _append_row('cane', 'unknown', 'DECRYPT_FAIL', counter,
                        gateway_receive_ns, gateway_receive_ns, 0, False)
            return

        try:
            parsed  = json.loads(payload_bytes)
            msg_id  = str(parsed.get('msg_id',  'cane'))
            action  = str(parsed.get('action',  'STOP'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            msg_id = 'cane'
            action = payload_bytes.decode('utf-8', errors='replace')

        runtime_forward_ns = time.perf_counter_ns()

        _append_row('cane', msg_id, action, counter,
                    gateway_receive_ns, runtime_forward_ns, 0, True)
        print(f"[{_ts()}] [cane] {msg_id}  ctr={counter}  "
              f"rx→fwd={(runtime_forward_ns - gateway_receive_ns)/1e6:.2f} ms")
        return

    if uuid == CANE_RESET_UUID:
        t_received = time.perf_counter_ns()
        if _cane_secure_channel is None:
            return
        payload_bytes = _cane_secure_channel.receive(data)
        if payload_bytes is None:
            return
        try:
            msg    = json.loads(payload_bytes)
            action = msg.get('action', 'unknown')
        except Exception:
            action = payload_bytes.decode('utf-8', errors='replace')
        print(f"[{_ts()}] [cane] CANE_RESET: action={action}")
        if action == 'RESET' and _cane_base_channel is not None:
            _put_encrypted_to_cane(CANE_RESET_UUID, b'{"action":"RESET_ACK"}',
                                   _cane_base_channel)


def _ts() -> str:
    return time.strftime('%H:%M:%S')


# ── Main ──────────────────────────────────────────────────────────────────────

def _disable_br_edr_scan() -> None:
    try:
        subprocess.run(['sudo', 'hciconfig', 'hci0', 'noscan'],
                       check=True, capture_output=True)
    except Exception:
        pass


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
            SECURITY_UUID:      {"Properties": RW,  "Permissions": RP,  "Value": bytearray(b'')},
            COMMAND_UUID:       {"Properties": W,   "Permissions": GATTAttributePermissions.writeable, "Value": None},
            ACK_UUID:           {"Properties": GATTCharacteristicProperties.read, "Permissions": GATTAttributePermissions.readable, "Value": bytearray(b'READY')},
            CANE_SECURITY_UUID: {"Properties": RWN, "Permissions": RP, "Value": bytearray(b'')},
            CANE2PHONE_UUID:    {"Properties": RWN, "Permissions": RP, "Value": bytearray(b'')},
            CANE_RESET_UUID:    {"Properties": RW,  "Permissions": RP, "Value": bytearray(b'')},
        }
    }

    await _server.add_gatt(gatt)
    await _server.start()
    print(f"[{_ts()}] {DEVICE_NAME!r} advertising — Experiment K server")
    print(f"[{_ts()}] Scenario : {_SCENARIO}")
    print(f"[{_ts()}] CSV      : {SERVER_CSV}")
    if _benchmark_mode:
        print(f"[{_ts()}] Provisioning: BENCHMARK MODE")
    print(f"[{_ts()}] Waiting for connections…\n")

    stop = asyncio.Event()
    try:
        await stop.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        print(f"\n[{_ts()}] Shutting down.")
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
