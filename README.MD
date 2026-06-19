# Secure BLE Communication — Experiment Suite

Experimental implementation of an authenticated, replay-protected BLE communication
layer for an exoskeleton assistive device system. This codebase accompanies a journal
paper and provides the full protocol implementation, GATT server/client, and the
experiment scripts used to produce the paper's results.

> **Note — reimplementation.**  
> The `CipherChannel` cryptographic protocol (`shared/cipher.py`,
> `esp32/CipherChannel.*`) is a Python and C++ reimplementation of an
> original protocol designed by Björn Bergman Turkiewicz. The counter-nonce scheme,
> direction-parity rules, and persistence guarantees are faithful reproductions of his
> design. All surrounding BLE infrastructure (GATT server, client, key exchange,
> experiment scripts) was built on top of that protocol.

See [PROTOCOL.md](PROTOCOL.md) for the full normative specification (MUST/SHOULD/MAY).

---

## Overview

The system connects three nodes over Bluetooth Low Energy:

```
┌─────────────┐   BLE   ┌───────────────────┐   BLE   ┌───────────────┐
│  ESP32 cane │ ──────► │  Raspberry Pi      │ ◄────── │  Laptop /     │
│  controller │ ◄────── │  GATT server       │ ──────► │  Android app  │
└─────────────┘         └───────────────────┘         └───────────────┘
```

- **Raspberry Pi** — acts as the BLE GATT peripheral/gateway. Maintains separate
  encrypted `CipherChannel` contexts for the cane and for the supervisory client.
- **ESP32** — BLE central (client). Controls the cane actuator and sends status
  messages. Requests a session key from the RPi on first connect.
- **Laptop** — substitutes for the Android phone in all experiments. The encrypted
  packet format is byte-identical to the mobile app.

---

## Cryptographic Protocol

All traffic is encrypted with **AES-256-GCM** using a monotonically-increasing
96-bit counter encoded directly in the GCM nonce (Björn's counter-nonce protocol).

**Wire format:**

```
nonce(12 B) || ciphertext(N B) || GCM-tag(16 B)
```

- Raw binary, no length prefix, no base64.
- **Fixed overhead = 28 bytes per packet.**
- Ciphertext length equals plaintext length — no padding is applied.
- Maximum plaintext: **400 bytes**; maximum packet: **428 bytes**.

**Counter / nonce:**

- The nonce is a 96-bit unsigned integer in **little-endian** byte order.
- The send counter increments by 2 and is persisted _before_ producing each packet,
  so the nonce is never reused even if the device crashes between encrypt and transmit.
- A received counter must be **strictly greater** than the last accepted counter and
  must have the **same parity** (direction-coded to prevent reflection attacks).
- Counters never reset under the same key; exhaustion (≥ 2^96 − 2) is detected
  and causes a hard failure before the counter wraps.

**Direction parity:**

| Role                          | Sends             | Receives |
| ----------------------------- | ----------------- | -------- |
| Initiator (`initiator=True`)  | even (2, 4, 6, …) | odd      |
| Responder (`initiator=False`) | odd (3, 5, 7, …)  | even     |

The ESP32 is always the initiator; the RPi is always the responder for each channel.

**Per-endpoint key isolation:**

Two independent operational keys are maintained per session:

- `K_phone` — phone/laptop supervisory channel (RPi ↔ laptop)
- `K_cane` — cane (ESP32) base and secure channels (RPi ↔ ESP32)

A packet encrypted under `K_phone` cannot be accepted by the cane context and
vice-versa: AES-256-GCM authentication fails with probability ≥ 1 − 2^−128.
Both channels share the same GATT service but use separate CipherChannel instances
with separate state files/NVS namespaces and separate threading locks.

**Provisioning gate:**

Key material is only issued while a physical-presence gate is active.
In production a normally-open pushbutton wired to a Raspberry Pi GPIO pin opens
a 60-second provisioning window for a specific endpoint. The window accepts exactly
one `REQUEST_KEY` and closes immediately after success. It also closes on timeout,
`STOP_SHARING`, client disconnect, error, or server shutdown.

For automated experiments, set `BENCHMARK_PROVISIONING=1` — this replaces the
production gate with a bypass that always returns True. **Never use in production.**

**Thread safety:**

Each `CipherChannel` context carries its own lock (Python: `threading.Lock`;
ESP32: FreeRTOS `SemaphoreHandle_t` mutex). The complete send and receive critical
sections — counter check, increment, persist, and crypto — are executed under a
single lock acquisition. Concurrent sends on the same context serialize; concurrent
sends and receives on the same context are safe.

**Persistence:**

- **Python (RPi):** atomic temp-file rename with double-fsync (write → fsync fd →
  os.replace → fsync parent dir). This provides durability on ext4 with ordered-data
  mode when the state directory is on persistent storage. Some automated experiments
  use temporary paths under `/tmp`; those runs validate simulated process restart,
  not power-loss or reboot durability.
- **ESP32:** Arduino `Preferences` (NVS flash). `Preferences::end()` calls
  `nvs_commit()` internally. Each channel uses its own NVS namespace (`ble_chan`,
  `ble_sec`). State format version 2 (12-byte counters).

**Key exchange:**

A pre-shared 256-bit transport key bootstraps the channel. The ESP32 then requests
an endpoint-specific session key via `REQUEST_KEY`. The RPi delivers it encrypted
over the transport channel and clears it from the GATT characteristic after 3 seconds.

---

## Repository Structure

```
CipherChannel/
├── shared/
│   ├── cipher.py              # Python CipherChannel (AES-256-GCM, 96-bit counter)
│   └── provisioning_gate.py   # ProvisioningGate + BenchmarkProvisioningGate
│
├── server/
│   └── ble_server.py          # RPi GATT server (bless) — includes GPIO button setup
│
├── client/
│   └── experiment_client.py   # Laptop BLE client (bleak)
│
├── esp32/
│   ├── esp32.ino              # Arduino sketch entry point
│   ├── BLEProtocol.h/.cpp     # BLE central logic (scan, connect, key exchange)
│   └── CipherChannel.h/.cpp   # C++ CipherChannel (AES-256-GCM, mbedTLS, FreeRTOS mutex)
│
├── cipher_tests/
│   ├── test_cipher.py         # 49 unit tests for Python CipherChannel
│   ├── test_provisioning.py   # 24 unit tests for ProvisioningGate
│   └── bench_cipher.py        # Overhead benchmark (N=10 000 trials)
│
├── PROTOCOL.md                # Normative protocol specification (MUST/SHOULD/MAY)
│
├── final_restart_adversarial.py  # Experiment A: 13 adversarial security tests
├── final_mtu_check.py            # Experiment B: MTU / long-write confirmation
├── final_concurrent_endpoints.py # Experiment C: automated endpoint-isolation / replay validation
├── final_summarize.py            # Aggregates all results into Markdown tables
├── esp32_footprint.sh            # ESP32 flash/RAM footprint via arduino-cli
│
├── config.sh                  # Auto-detects RPi / laptop and creates venv
├── FINAL_EXPERIMENTS.md       # Step-by-step experiment instructions
└── results/
    └── final/
        ├── raw/               # Per-experiment CSV files
        └── summary/           # JSON summaries + final_experiment_tables.md
```

---

## Hardware Requirements

| Component             | Role                          | Notes                                        |
| --------------------- | ----------------------------- | -------------------------------------------- |
| Raspberry Pi 3A+ / 4  | GATT server                   | BlueZ ≥ 5.50, Python ≥ 3.11                  |
| ESP32 (any variant)   | BLE central / cane controller | Arduino IDE ≥ 2.x, esp32:esp32 board package |
| Linux laptop (x86_64) | Experiment client             | BlueZ, Python ≥ 3.11                         |

Experiments A (adversarial) and D (footprint) do not require all three nodes.

---

## Setup

### Raspberry Pi (GATT server)

```bash
# Ensure BlueZ is running and user has bluetooth group access
sudo usermod -aG bluetooth $USER   # log out and back in after

cd CipherChannel
bash config.sh --server
# Creates server/.venv with bless + pycryptodome + RPi.GPIO
```

**Provisioning buttons (production):**

Wire two normally-open pushbuttons between GND and BCM 17 (phone gate) and BCM 27
(cane gate). The server uses the internal pull-up resistor with 300 ms debounce.
Override pins via environment variables:

```bash
PHONE_GATE_PIN=17 CANE_GATE_PIN=27 python3 server/ble_server.py
```

If `RPi.GPIO` is not installed, the server starts but prints a warning; gates must
then be opened programmatically via `open_phone_gate()` / `open_cane_gate()` in a REPL.

### Laptop (experiment client)

```bash
cd CipherChannel
bash config.sh --client
# Creates client/.venv with bleak + pycryptodome
```

`config.sh` auto-detects architecture (aarch64 → server, x86_64 → client) so you
can omit the flag on most machines.

### ESP32

Open `esp32/esp32.ino` in Arduino IDE. Install the **esp32 by Espressif** board
package via Boards Manager. Flash to your ESP32. No external libraries needed —
`CipherChannel` uses mbedTLS and Preferences bundled with the ESP32 Arduino core.

**Important:** the pre-shared transport key in `BLEProtocol.cpp` must match `KEY`
in `server/ble_server.py`. Both are set to the same 32-byte value in this repository.

After any change to the CipherChannel wire format or state format (e.g. this
upgrade from state format v1 → v2), reflash the ESP32. Old NVS state is rejected on
load and the firmware falls back to `create()` automatically.

---

## Running the Experiments

Full step-by-step instructions are in [FINAL_EXPERIMENTS.md](FINAL_EXPERIMENTS.md).
Quick reference:

### Unit tests (no hardware)

```bash
# Python CipherChannel: 49 tests
python3 cipher_tests/test_cipher.py

# ProvisioningGate: 24 tests
python3 cipher_tests/test_provisioning.py
```

### A — Adversarial / Restart Validation (no hardware)

```bash
python3 final_restart_adversarial.py
```

Runs 13 deterministic security tests against the Python `CipherChannel`:
replay, tamper, wrong key, reflection, counter-reset, state-file corruption,
and counter persistence across simulated restarts.

Expected output: **13/13 PASS**.

### B — MTU / Long-Write Confirmation (laptop + RPi)

```bash
# RPi:
BENCHMARK_PROVISIONING=1 python3 server/ble_server.py

# Laptop (find MAC with: bluetoothctl scan on):
python3 final_mtu_check.py --address <RPi-MAC>
```

Sends encrypted frames of increasing plaintext size (up to 400 B) and confirms
that 428-byte packets are within the evaluated BLE long-write limit.

### C — Automated Endpoint-Isolation Validation (laptop + RPi)

````bash
# RPi: server already running (BENCHMARK_PROVISIONING=1)

# Laptop:
python3 final_concurrent_endpoints.py --address <RPi-MAC> --trials 30

### D — ESP32 Resource Footprint

```bash
bash esp32_footprint.sh
````

Reports flash and static RAM usage from the compiler. See
[FINAL_EXPERIMENTS.md](FINAL_EXPERIMENTS.md) for peak stack measurement.

### Aggregate Results

```bash
python3 final_summarize.py
# Writes results/final/summary/final_experiment_tables.md
```

---

## Key Exchange — Sequence Diagram

```
ESP32 (initiator)                          RPi (responder)
─────────────────                          ───────────────
  encrypt(REQUEST_KEY, base_channel)
         ──────── write CANE_SECURITY ────────►
                                             decrypt(base_channel)
                                             [gate must be open: BCM27 button]
                                             generate cane_key (32 B random)
                                             create secure_channel(cane_key, responder)
                                             encrypt(cane_key, base_channel)
                                             → nonce(12)+ciphertext(32)+tag(16) = 60 B
                                             set CANE_SECURITY value
                                             schedule: clear characteristic in 3 s
  poll-read CANE_SECURITY (60 B)
         ◄───────────────────────────────────
  decrypt(base_channel) → cane_key
  secureChannel.updateKey(cane_key, initiator)
         ──────── write CANE2PHONE (encrypted with secure_channel) ────────►
                                             decrypt(secure_channel)  ✓
```

---

## Known Limitations

- **bless 0.3.0 notification bug** — bless does not reliably deliver GATT notify
  packets when `char.value` is set. The ESP32 firmware works around this by
  poll-reading the security characteristic after each write (rather than using
  `registerForNotify`). The poll-read loop can be removed if a fixed bless version
  is available.

- **Single BLE connection** — the RPi handles one phone/laptop session and one ESP32
  session concurrently, but bless itself is single-threaded. High-frequency concurrent
  writes from both endpoints may queue.

- **Pre-shared transport key** — the 256-bit bootstrap key is embedded in source.
  For a production deployment this should be provisioned via a secure out-of-band
  channel (QR code, NFC, manufacturing process).

- **GPIO provisioning** — the production path requires a physical button and
  `RPi.GPIO`. If `RPi.GPIO` is absent, provisioning falls back to the programmatic
  API. An automated SSH session or REST endpoint opening the gate without hardware
  defeats the physical-presence guarantee.

---

## Dependencies

| Component            | Library               | Version tested         |
| -------------------- | --------------------- | ---------------------- |
| Python CipherChannel | `pycryptodome`        | 3.23.0                 |
| RPi GATT server      | `bless`               | 0.3.0                  |
| RPi GPIO buttons     | `RPi.GPIO`            | 0.7.x                  |
| Laptop BLE client    | `bleak`               | 3.0.2                  |
| BLE transport (both) | BlueZ                 | 5.86                   |
| ESP32 crypto         | mbedTLS (bundled)     | ESP32 Arduino core 2.x |
| ESP32 persistence    | Preferences (bundled) | ESP32 Arduino core 2.x |
| ESP32 threading      | FreeRTOS (bundled)    | ESP32 Arduino core 2.x |

---

## Protocol Changes from Previous Version

| #   | Change                                       | Impact                          |
| --- | -------------------------------------------- | ------------------------------- |
| 1   | Nonce 16 B → 12 B (96-bit IETF standard)     | Wire-format incompatible        |
| 2   | PKCS7 padding removed                        | Wire-format incompatible        |
| 3   | Fixed overhead 32 B → 28 B                   | Packet sizes change             |
| 4   | MAX_PLAINTEXT_SIZE = 400 enforced            | Rejects 401–512 B               |
| 5   | Per-endpoint keys (K_phone, K_cane)          | Separate provisioning           |
| 6   | Provisioning gate (physical presence)        | New deployment step             |
| 7   | State file / NVS versioned                   | Old state rejected; reprovision |
| 8   | ESP32 counter 64-bit → 96-bit (cc_counter_t) | NVS sfv 1 → 2                   |
| 9   | Per-context FreeRTOS mutex on ESP32          | No observable wire change       |
| 10  | Key exchange response 80 B → 60 B            | Client/firmware must match      |

---

## License

This project is released for research and educational purposes.  
The `CipherChannel` protocol is attributed to Björn Bergman Turkiewicz.
