#!/usr/bin/env python3
"""
BLE GATT server — instrumented for Experiment H (gateway internal stage timing).
=================================================================================
Identical to ble_server.py except for the COMMAND_UUID write handler, which records
nanosecond timestamps at every internal processing stage and writes them to a
per-command CSV row.

Gateway timing stages (all times: time.perf_counter_ns()):
  T0  GATT write_request callback entered
  T1  packet parse complete (nonce extracted, sequence number computed)
  T3  freshness + direction-parity validation complete  [NOTE: precedes T2 in cipher.py]
  T2  AES-256-GCM authentication + decryption complete
  T4  receive counter durably persisted (fsync → state file replaced)
  T5  command forwarded ("runtime path" — JSON parsed, action identified)
  T6  = T5  (ACK is plaintext; no ACK encryption in this protocol)
  T7  BLE characteristic value set (ack_char.value = ...)

Derived metrics:
  parse_ms            = (T1 - T0) / 1e6
  freshness_valid_ms  = (T3 - T1) / 1e6
  crypto_ms           = (T2 - T3) / 1e6
  persistence_ms      = (T4 - T2) / 1e6
  json_parse_ms       = (T5 - T4) / 1e6
  ack_set_ms          = (T7 - T5) / 1e6   (ACK plaintext — ack_encrypt_ms = 0)
  gateway_total_ms    = (T7 - T0) / 1e6

NOTE on stage ordering: cipher.py's receive() checks freshness/direction BEFORE
calling AES.decrypt_and_verify().  Hence T3 (validation) < T2 (crypto) — contrary
to the user-facing label order from the experiment specification.  The CSV records
all four timestamps individually so the reader can verify the actual order.

InstrumentedCipherChannel replicates CipherChannel.receive() with inserted
timestamp captures.  The logic is byte-for-byte identical; a divergence would
invalidate the measurement.  If cipher.py is updated, keep this in sync.

Run on RPi:
  BENCHMARK_PROVISIONING=1 \
  EXPERIMENT_GATEWAY_CSV_PATH=/tmp/gateway_internal.csv \
  server/.venv/bin/python server/ble_server_instrumented.py

Client (laptop) — use the gateway_internal experiment client or any steady-state client:
  client/.venv/bin/python results/canonical/latency/gateway_internal/run_gateway_internal.py \
    --address B8:27:EB:07:01:22 --trials 1000

After the run, copy the gateway CSV:
  ssh rpi 'cat /tmp/gateway_internal.csv' > \
    results/canonical/latency/gateway_internal/gateway_internal_server_raw.csv
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
from cipher import (
    CipherChannel, ChannelException,
    NONCE_LEN, MAC_LEN, MAX_PACKET_SIZE,
)
from provisioning_gate import ProvisioningGate, BenchmarkProvisioningGate

from Crypto.Cipher import AES

try:
    from bless import (
        BlessServer,
        BlessGATTCharacteristic,
        GATTCharacteristicProperties,
        GATTAttributePermissions,
    )
except ImportError:
    sys.exit("bless not installed.  Run: pip install bless")

# ── Configuration (identical to ble_server.py) ────────────────────────────────

KEY: bytes = b'*\xc3,6s\xa4\xa2\xeeI\x08S>\xd0\xff%\x84\xba\xe9\x95\xcaNL\xffzL%h\x04)\x04%\xf8'

DEVICE_NAME  = "AWAKE-EXP"
SERVICE_UUID = "12345678-0000-1000-8000-00805f9b34fb"

SECURITY_UUID      = "fec26ec4-6d71-4442-9f81-55bc21d658d6"
COMMAND_UUID       = "51ff12bb-3ed8-46e5-b4f9-d64e2fec021b"
ACK_UUID           = "51ff12bc-3ed8-46e5-b4f9-d64e2fec021b"
CANE2PHONE_UUID    = "74278bda-b644-4520-8f0c-720eaf059935"
CANE_SECURITY_UUID = "fa87c0d0-afac-11de-8a39-0800200c9a66"
CANE_RESET_UUID    = "d2b9a3d4-1a3d-0a6d-d7c8-b4d4d0a4b1e2"

SERVER_CSV     = os.environ.get('EXPERIMENT_SERVER_CSV_PATH', '/tmp/experiment_server.csv')
GATEWAY_CSV    = os.environ.get('EXPERIMENT_GATEWAY_CSV_PATH', '/tmp/gateway_internal.csv')
_STATE_DIR     = pathlib.Path(os.environ.get('AWAKE_STATE_DIR', '/tmp/awake_exp_state'))
_CANE_BASE_PATH   = str(_STATE_DIR / 'cc_cane_base')
_CANE_SECURE_PATH = str(_STATE_DIR / 'cc_cane_secure')
_KEY_CLEAR_DELAY  = 3.0


# ── Instrumented CipherChannel ────────────────────────────────────────────────
# Replicates CipherChannel.receive() with nanosecond timing inserted at each stage.
# Logic must stay in sync with cipher.py.  Do not modify cipher.py for this experiment.

class InstrumentedCipherChannel(CipherChannel):
    """
    CipherChannel subclass with per-stage timing in receive().

    After a successful receive(), self._last_timing contains:
      t_callback    : time.perf_counter_ns() at entry to receive()
      t_parse       : after nonce extraction + sequence int decode
      t_validate    : after freshness + direction-parity checks
      t_crypto      : after AES-GCM decrypt_and_verify
      t_persist     : after _write_state() (counter durably fsynced)
    All values are None on init or if the last receive() returned None (reject).
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._last_timing: dict | None = None

    def receive(self, data: bytes):
        # Stage T0: callback entry (set by caller before calling receive();
        # we record t_callback here to capture the receive() entry point)
        t_callback = time.perf_counter_ns()
        self._last_timing = None

        if len(data) < NONCE_LEN + MAC_LEN:
            return None
        if len(data) > MAX_PACKET_SIZE:
            return None

        with self._lock:
            # ── Parse: extract nonce and decode sequence number ────────────────
            nonce    = data[:NONCE_LEN]
            sequence = int.from_bytes(nonce, 'little')
            t_parse  = time.perf_counter_ns()  # T1

            # ── Validate: freshness check ─────────────────────────────────────
            if sequence <= self._seq_receive:
                return None
            # ── Validate: direction-parity check ─────────────────────────────
            if (sequence & 1) != (self._seq_receive & 1):
                return None
            t_validate = time.perf_counter_ns()  # T3

            # ── Crypto: AES-256-GCM authentication + decryption ───────────────
            ciphertext = data[NONCE_LEN:-MAC_LEN]
            tag        = data[-MAC_LEN:]
            try:
                cipher    = AES.new(self._key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                return None
            t_crypto = time.perf_counter_ns()  # T2

            # ── Persist: increment receive counter, fsync state file ──────────
            self._seq_receive = sequence
            self._write_state()
            t_persist = time.perf_counter_ns()  # T4

            self._last_timing = {
                't_callback': t_callback,
                't_parse':    t_parse,
                't_validate': t_validate,
                't_crypto':   t_crypto,
                't_persist':  t_persist,
            }
            return plaintext


# ── Provisioning gates ────────────────────────────────────────────────────────

_benchmark_mode = os.environ.get('BENCHMARK_PROVISIONING') == '1'
if _benchmark_mode:
    print('[WARN] Benchmark provisioning gate — NOT for production')
    _phone_gate: ProvisioningGate = BenchmarkProvisioningGate()
    _cane_gate:  ProvisioningGate = BenchmarkProvisioningGate()
else:
    _phone_gate = ProvisioningGate()
    _cane_gate  = ProvisioningGate()

# ── Global state ──────────────────────────────────────────────────────────────

_server: BlessServer            = None  # type: ignore
_loop:   asyncio.AbstractEventLoop = None  # type: ignore

_phone_key:     bytes | None                    = None
_phone_channel: InstrumentedCipherChannel | None = None

_cane_key:            bytes | None          = None
_cane_base_channel:   CipherChannel | None = None
_cane_secure_channel: CipherChannel | None = None


# ── CSV helpers ───────────────────────────────────────────────────────────────

_SERVER_COLUMNS  = ['endpoint', 'trial_id', 'action', 't_received_ns', 't_ack_set_ns']
_GATEWAY_COLUMNS = [
    'trial_id', 'action',
    'T0_ns', 'T1_parse_ns', 'T3_validate_ns', 'T2_crypto_ns', 'T4_persist_ns',
    'T5_forward_ns', 'T7_ack_set_ns',
    'parse_ms', 'freshness_valid_ms', 'crypto_ms', 'persistence_ms',
    'json_parse_ms', 'ack_set_ms', 'gateway_total_ms',
]


def _init_csvs() -> None:
    with open(SERVER_CSV, 'w', newline='') as f:
        csv.writer(f).writerow(_SERVER_COLUMNS)
    with open(GATEWAY_CSV, 'w', newline='') as f:
        csv.writer(f).writerow(_GATEWAY_COLUMNS)
    print(f"Server CSV  : {SERVER_CSV}")
    print(f"Gateway CSV : {GATEWAY_CSV}")


def _append_server_row(endpoint: str, trial_id: str, action: str,
                        t_recv: int, t_ack: int = 0) -> None:
    with open(SERVER_CSV, 'a', newline='') as f:
        csv.writer(f).writerow([endpoint, trial_id, action, t_recv, t_ack])


def _append_gateway_row(trial_id: str, action: str, timing: dict, T5: int, T7: int) -> None:
    T0 = timing['t_callback']
    T1 = timing['t_parse']
    T3 = timing['t_validate']
    T2 = timing['t_crypto']
    T4 = timing['t_persist']

    def _ms(a: int, b: int) -> float:
        return round((b - a) / 1e6, 4)

    with open(GATEWAY_CSV, 'a', newline='') as f:
        csv.writer(f).writerow([
            trial_id, action,
            T0, T1, T3, T2, T4, T5, T7,
            _ms(T0, T1),   # parse_ms
            _ms(T1, T3),   # freshness_valid_ms
            _ms(T3, T2),   # crypto_ms
            _ms(T2, T4),   # persistence_ms
            _ms(T4, T5),   # json_parse_ms
            _ms(T5, T7),   # ack_set_ms
            _ms(T0, T7),   # gateway_total_ms
        ])


# ── Cane channel helpers (unchanged from ble_server.py) ──────────────────────

def _load_or_create_cane_base() -> CipherChannel:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        ch = CipherChannel.load(_CANE_BASE_PATH, endpoint_id='cane_base')
        print(f"[{_ts()}] Cane base channel loaded from {_CANE_BASE_PATH}")
        return ch
    except ChannelException:
        pass
    ch = CipherChannel.create(KEY, False, _CANE_BASE_PATH, endpoint_id='cane_base')
    print(f"[{_ts()}] Cane base channel created at {_CANE_BASE_PATH}")
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
        print(f"[{_ts()}] Failed to encrypt for cane: {e}")
        return False


def _schedule_clear_char(char_uuid: str) -> None:
    if _loop is None:
        return

    def _do():
        if _server is not None:
            ch = _server.get_characteristic(char_uuid)
            if ch is not None:
                ch.value = bytearray(b'')

    _loop.call_later(_KEY_CLEAR_DELAY, _do)


def _close_phone_session() -> None:
    global _phone_key, _phone_channel
    _phone_key     = None
    _phone_channel = None
    _phone_gate.close()


# ── GATT handlers ─────────────────────────────────────────────────────────────

def read_request(characteristic: BlessGATTCharacteristic, **kwargs) -> bytearray:
    return characteristic.value or bytearray()


def write_request(characteristic: BlessGATTCharacteristic, value: any, **kwargs) -> None:
    global _phone_key, _phone_channel
    global _cane_key, _cane_base_channel, _cane_secure_channel

    uuid = str(characteristic.uuid).lower()
    data = bytes(value)

    # ── SECURITY_UUID (identical to ble_server.py) ────────────────────────────
    if uuid == SECURITY_UUID:
        if data == b"REQUEST_KEY":
            if not _phone_gate.try_provision('phone'):
                print(f"[{_ts()}] [phone] REQUEST_KEY rejected — gate closed")
                return
            _phone_key = os.urandom(32)
            session_id = _uuid_mod.uuid4().hex[:12]
            transport_path = f'/tmp/cc_transport_server_{session_id}'
            transport_ch   = CipherChannel.create(KEY, True, transport_path,
                                                  endpoint_id='phone_transport')
            session_path   = f'/tmp/cc_session_server_{session_id}'

            # Use InstrumentedCipherChannel for the phone session
            _phone_channel = InstrumentedCipherChannel(
                _phone_key, session_path, 1, 0, 'phone', False
            )
            _phone_channel._write_state()

            encrypted = transport_ch.send(_phone_key)
            characteristic.value = bytearray(encrypted)
            print(f"[{_ts()}] [phone] Key issued: session={session_id}")
            _schedule_clear_char(SECURITY_UUID)

        elif data == b"STOP_SHARING":
            print(f"[{_ts()}] [phone] STOP_SHARING — session invalidated")
            _close_phone_session()
            characteristic.value = bytearray(b'')
            _append_server_row('phone', 'key_exchange', 'STOP_SHARING',
                               time.perf_counter_ns())
        return

    # ── COMMAND_UUID — instrumented ───────────────────────────────────────────
    if uuid == COMMAND_UUID:
        T0 = time.perf_counter_ns()   # T0: GATT callback entered

        if _phone_channel is None:
            print(f"[{_ts()}] [phone] COMMAND but no session — do key exchange first")
            return

        payload_bytes = _phone_channel.receive(data)

        if payload_bytes is None:
            print(f"[{_ts()}] [phone] Decrypt/replay failed — packet rejected")
            return

        timing = _phone_channel._last_timing
        if timing is None:
            print(f"[{_ts()}] [phone] COMMAND: timing not available (internal error)")
            return

        try:
            payload  = json.loads(payload_bytes)
            trial_id = str(payload.get('trial_id', 'unknown'))
            action   = str(payload.get('action',   'unknown'))
        except Exception as e:
            print(f"[{_ts()}] [phone] JSON parse error: {e}")
            return
        T5 = time.perf_counter_ns()   # T5: JSON parse done / command "forwarded"

        if action == 'STOP_SHARING':
            print(f"[{_ts()}] [phone] STOP_SHARING — session invalidated")
            _close_phone_session()
            _append_server_row('phone', trial_id, action, T0)
            return

        print(f"[{_ts()}] [phone] Received trial={trial_id} action={action}")
        ack_char       = _server.get_characteristic(ACK_UUID)
        ack_char.value = bytearray(f"OK:{trial_id}".encode())
        T7 = time.perf_counter_ns()   # T7: BLE char value set (T6=T5, ACK is plaintext)

        _append_server_row('phone', trial_id, action, T0, T7)
        _append_gateway_row(trial_id, action, timing, T5, T7)
        print(f"[{_ts()}] [phone] ACK set trial={trial_id}  "
              f"gateway={round((T7 - T0) / 1e6, 3)} ms")
        return

    # ── CANE channels (unchanged from ble_server.py) ──────────────────────────

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
                _cane_key = None; _cane_secure_channel = None; _cane_gate.close()
            _append_server_row('cane', 'key_exchange', 'REQUEST_KEY', time.perf_counter_ns())
        elif action == 'STOP_SHARING':
            _cane_gate.close()
            characteristic.value = bytearray(b'')
            _append_server_row('cane', 'key_exchange', 'STOP_SHARING', time.perf_counter_ns())
        return

    if uuid == CANE2PHONE_UUID:
        t = time.perf_counter_ns()
        if _cane_secure_channel is None:
            print(f"[{_ts()}] [cane] CANE2PHONE but no secure channel"); return
        pb = _cane_secure_channel.receive(data)
        if pb is None:
            print(f"[{_ts()}] [cane] CANE2PHONE: decrypt/replay failed — rejected"); return
        print(f"[{_ts()}] [cane] CANE2PHONE: {pb.decode('utf-8', errors='replace')}")
        _append_server_row('cane', 'cane2phone', pb.decode(errors='replace'), t)
        return

    if uuid == CANE_RESET_UUID:
        t = time.perf_counter_ns()
        if _cane_secure_channel is None:
            print(f"[{_ts()}] [cane] CANE_RESET but no secure channel"); return
        pb = _cane_secure_channel.receive(data)
        if pb is None:
            print(f"[{_ts()}] [cane] CANE_RESET: decrypt/replay failed"); return
        try:
            action = json.loads(pb).get('action', 'unknown')
        except Exception:
            action = pb.decode(errors='replace')
        print(f"[{_ts()}] [cane] CANE_RESET: action={action}")
        _append_server_row('cane', 'cane_reset', action, t)
        if action == 'RESET' and _cane_base_channel:
            _put_encrypted_to_cane(CANE_RESET_UUID, b'{"action":"RESET_ACK"}', _cane_base_channel)
        return


def _ts() -> str:
    return time.strftime('%H:%M:%S')


# ── Main ──────────────────────────────────────────────────────────────────────

def _disable_br_edr_scan() -> None:
    try:
        subprocess.run(['sudo', 'hciconfig', 'hci0', 'noscan'],
                       check=True, capture_output=True)
        print(f"[{_ts()}] Classic BT scan disabled")
    except Exception as e:
        print(f"[{_ts()}] Warning: could not disable classic BT scan: {e}")


async def main() -> None:
    global _server, _cane_base_channel, _loop

    _disable_br_edr_scan()
    _init_csvs()
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
            SECURITY_UUID:      {"Properties": RW,  "Permissions": RP, "Value": bytearray(b'')},
            COMMAND_UUID:       {"Properties": W,   "Permissions": GATTAttributePermissions.writeable, "Value": None},
            ACK_UUID:           {"Properties": GATTCharacteristicProperties.read, "Permissions": GATTAttributePermissions.readable, "Value": bytearray(b'READY')},
            CANE_SECURITY_UUID: {"Properties": RWN, "Permissions": RP, "Value": bytearray(b'')},
            CANE2PHONE_UUID:    {"Properties": RWN, "Permissions": RP, "Value": bytearray(b'')},
            CANE_RESET_UUID:    {"Properties": RW,  "Permissions": RP, "Value": bytearray(b'')},
        }
    }

    await _server.add_gatt(gatt)
    await _server.start()
    print(f"[{_ts()}] {DEVICE_NAME!r} advertising (INSTRUMENTED — Experiment H)")
    print(f"[{_ts()}] Gateway CSV  : {GATEWAY_CSV}")
    print(f"[{_ts()}] Server CSV   : {SERVER_CSV}")
    if _benchmark_mode:
        print(f"[{_ts()}] Provisioning : BENCHMARK (gate always open)")
    print(f"[{_ts()}] Waiting for connections…\n")

    stop = asyncio.Event()
    try:
        await stop.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        print(f"\n[{_ts()}] Shutting down.")
        _phone_gate.close(); _cane_gate.close()
        await _server.stop()
        print(f"[{_ts()}] Gateway CSV → {GATEWAY_CSV}")
        print(f"[{_ts()}] Server CSV  → {SERVER_CSV}")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
