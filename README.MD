# Secure BLE Communication — Experiment Suite

Experimental implementation of an authenticated, replay-protected BLE communication
layer for an exoskeleton assistive device system. This codebase accompanies a journal
paper and provides the full protocol implementation, GATT server/client, and the
experiment scripts used to produce the paper's results.

> **Note — reimplementation.**  
> The `CipherChannel` cryptographic protocol (`shared/cipher.py`,
> `awake-esp32/esp32/CipherChannel.*`) is a Python and C++ reimplementation of an
> original protocol designed by Björn Bergman Turkiewicz. The counter-nonce scheme,
> direction-parity rules, and persistence guarantees are faithful reproductions of his
> design. All surrounding BLE infrastructure (GATT server, client, key exchange,
> experiment scripts) was built on top of that protocol.

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
counter encoded in the GCM nonce (Björn's counter-nonce protocol).

**Wire format:** `nonce(16 B) || PKCS7-ciphertext || GCM-tag(16 B)` — raw binary, no
length prefix.

**Counter rules:**

- The send counter increments by 2 and is persisted _before_ producing each packet,
  so the counter is never reused even if the device crashes between encrypt and
  transmit.
- A received counter must be **strictly greater** than the last accepted counter and
  must have the **same parity** (direction-coded to prevent reflection attacks).
- Counters never reset under the same key.

**Direction parity:**
| Role | Sends | Receives |
|------|-------|---------|
| Initiator (`initiator=True`) | even (2, 4, 6, …) | odd |
| Responder (`initiator=False`) | odd (3, 5, 7, …) | even |

The ESP32 is always the initiator; the RPi is always the responder.

**Key exchange** uses a pre-shared 256-bit transport key embedded in both firmware
and server. On first connect the ESP32 encrypts a `REQUEST_KEY` message on the
security characteristic; the RPi generates a fresh random session key, encrypts it
with the transport channel, and writes it to the characteristic value. The ESP32
poll-reads the response (rather than relying on GATT notify, which is unreliable in
bless 0.3.0) and installs the session key.

**Persistence:**

- ESP32: Arduino `Preferences` library (NVS flash partition). Each channel stores
  key + counters in its own namespace (`ble_chan`, `ble_sec`).
- Python: atomic temp-file replacement. Each channel is a single binary file under
  `~/.awake_exp_state/` (server) or `/tmp/` (client, per-session).

---

## Repository Structure

```
experiment_ble/
├── shared/
│   └── cipher.py                  # Python CipherChannel (AES-256-GCM)
│
├── server/
│   ├── ble_server.py              # RPi GATT server (bless)
│   └── requirements.txt           # bless, pycryptodome
│
├── client/
│   ├── experiment_client.py       # Laptop BLE client (bleak)
│   └── requirements.txt           # bleak, pycryptodome
│
├── awake-esp32/esp32/
│   ├── esp32.ino                  # Arduino sketch entry point
│   ├── BLEProtocol.h/.cpp         # BLE central logic (scan, connect, key exchange)
│   ├── CipherChannel.h/.cpp       # C++ CipherChannel (AES-256-GCM via mbedTLS)
│   └── ...
│
├── cipher_tests/
│   ├── test_cipher.py             # Unit tests for Python CipherChannel
│   ├── bench_cipher.py            # Throughput benchmark
│   └── run_all.sh                 # Run all tests
│
├── config.sh                      # Auto-detects RPi / laptop and sets up venv
│
├── final_restart_adversarial.py   # Experiment A: 13 adversarial security tests
├── final_mtu_check.py             # Experiment B: MTU / long-write confirmation
├── final_concurrent_endpoints.py  # Experiment C: concurrent endpoint isolation
├── final_summarize.py             # Aggregates all results into Markdown tables
├── esp32_footprint.sh             # ESP32 flash/RAM footprint via arduino-cli
│
├── FINAL_EXPERIMENTS.md           # Detailed step-by-step experiment instructions
└── results/
    └── final/
        ├── raw/                   # Per-experiment CSV files
        └── summary/               # JSON summaries + final_experiment_tables.md
```

---

## Hardware Requirements

| Component             | Role                          | Notes                                        |
| --------------------- | ----------------------------- | -------------------------------------------- |
| Raspberry Pi 3B+ / 4  | GATT server                   | BlueZ ≥ 5.50, Python ≥ 3.11                  |
| ESP32 (any variant)   | BLE central / cane controller | Arduino IDE ≥ 2.x, esp32:esp32 board package |
| Linux laptop (x86_64) | Experiment client             | BlueZ, Python ≥ 3.11                         |

Experiments A (adversarial) and D (footprint) do not require all three nodes.

---

## Setup

### Raspberry Pi (GATT server)

```bash
# Ensure BlueZ is running and user has bluetooth group access
sudo usermod -aG bluetooth $USER   # log out and back in after

cd experiment_ble
bash config.sh --server
# Creates server/.venv with bless + pycryptodome
```

### Laptop (experiment client)

```bash
cd experiment_ble
bash config.sh --client
# Creates client/.venv with bleak + pycryptodome
```

`config.sh` auto-detects architecture (aarch64 → server, x86_64 → client) so you
can omit the flag on most machines.

### ESP32

Open `awake-esp32/esp32/esp32.ino` in Arduino IDE. Install the **esp32 by Espressif**
board package via Boards Manager. Flash to your ESP32. No external libraries are
needed — `CipherChannel` uses the mbedTLS and Preferences libraries bundled with the
ESP32 Arduino core.

**Important:** the pre-shared transport key in `BLEProtocol.cpp` must match the `KEY`
constant in `server/ble_server.py`. Both are set to the same value in this repository.

---

## Running the Experiments

Full step-by-step instructions are in [FINAL_EXPERIMENTS.md](FINAL_EXPERIMENTS.md).
Quick reference:

### A — Adversarial / Restart Validation (no hardware)

```bash
cd experiment_ble
python3 final_restart_adversarial.py
```

Runs 13 deterministic security tests against the Python `CipherChannel`:
replay, tamper, wrong key, reflection, counter-reset, state-file corruption, and
counter persistence across simulated restarts.

Expected output: **13/13 PASS**.

### B — MTU / Long-Write Confirmation (laptop + RPi)

```bash
# RPi:
cd experiment_ble/server && .venv/bin/python ble_server.py

# Laptop (find MAC with: bluetoothctl scan on):
cd experiment_ble
python3 final_mtu_check.py --address <RPi-MAC>
```

Sends encrypted frames of increasing plaintext size (up to 512 B) and confirms
BlueZ/Bleak handles long ATT writes transparently.

### C — Concurrent Endpoint Validation (laptop + RPi + ESP32)

```bash
# RPi: server already running

# Laptop:
python3 final_concurrent_endpoints.py --address <RPi-MAC> --trials 20
```

Validates that the RPi maintains separate `CipherChannel` contexts for the laptop
supervisory client and the ESP32 cane controller simultaneously.

### D — ESP32 Resource Footprint

```bash
# Requires arduino-cli with esp32:esp32 installed:
bash esp32_footprint.sh
```

Reports flash and static RAM usage from the compiler. Peak stack and current draw
must be measured manually — see [FINAL_EXPERIMENTS.md](FINAL_EXPERIMENTS.md#e-esp32-resource-footprint).

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
                                             generate cane_key (32 B random)
                                             create secure_channel(cane_key, responder)
                                             encrypt(cane_key, base_channel)
                                             set CANE_SECURITY value
  poll-read CANE_SECURITY (80 B)
         ◄───────────────────────────────────
  decrypt(base_channel) → cane_key
  secureChannel.updateKey(cane_key, initiator)
         ──────── write CANE2PHONE (encrypted with secure_channel) ────────►
                                             decrypt(secure_channel)  ✓
```

---

## Known Limitations

- **bless 0.3.0 notification bug** — bless does not reliably deliver GATT notify
  packets to connected centrals when `char.value` is set. The ESP32 firmware works
  around this by poll-reading the security characteristic after each write, rather
  than relying on `registerForNotify`. If a newer bless version fixes this, the
  poll loop in `BLEProtocol::requestSecureKey()` can be removed.

- **Single BLE connection** — the RPi GATT server handles one phone/laptop session
  and one ESP32 session concurrently, but the bless server itself is single-threaded.
  High-frequency concurrent writes from both endpoints may queue.

- **Pre-shared transport key** — the 256-bit bootstrap key is embedded in source.
  For a production deployment this should be provisioned via a secure out-of-band
  channel (QR code, NFC, manufacturing process).

---

## Dependencies

| Component            | Library               | Version tested         |
| -------------------- | --------------------- | ---------------------- |
| Python CipherChannel | `pycryptodome`        | 3.20                   |
| RPi GATT server      | `bless`               | 0.3.0                  |
| Laptop BLE client    | `bleak`               | 0.21                   |
| ESP32 crypto         | mbedTLS (bundled)     | ESP32 Arduino core 2.x |
| ESP32 persistence    | Preferences (bundled) | ESP32 Arduino core 2.x |

---

## License

This project is released for research and educational purposes.  
The `CipherChannel` protocol is attributed to Björn Bergman Turkiewicz.
