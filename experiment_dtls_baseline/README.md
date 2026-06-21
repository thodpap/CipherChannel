# DTLS Baseline Experiment

This experiment measures the **cold-start command latency** of a standard
DTLS 1.2 PSK secure channel between the laptop client and the Raspberry Pi
gateway — the same hardware pair used in the CipherChannel experiments.

It answers the reviewer question: *"Why not just use DTLS?"*

---

## What the experiment measures

Each **trial** is one complete cold-start round trip:

```
t0 ─── socket create & UDP connect ─────── t1
t1 ─── DTLS 1.2 handshake (PSK) ─────────── t2
t2 ─── send command JSON datagram ────────── t3
t3 ─── receive ACK JSON datagram ─────────── t4
```

Recorded per trial:

| Column | Description |
|--------|-------------|
| `trial_id` | Trial identifier `t0001`–`tNNNN` |
| `success` | `true` / `false` |
| `error` | Error message if failed, empty otherwise |
| `t0_start_ns` | Monotonic ns — trial start |
| `t1_socket_ready_ns` | After UDP `connect()` |
| `t2_handshake_done_ns` | After DTLS handshake completes |
| `t3_command_sent_ns` | After command datagram sent |
| `t4_ack_received_ns` | After ACK datagram received |
| `socket_setup_ms` | `t1 − t0` in ms |
| `handshake_ms` | `t2 − t1` in ms (includes PSK key derivation) |
| `command_ack_ms` | `t4 − t3` in ms |
| `total_ms` | `t4 − t0` in ms (end-to-end cold-start latency) |
| `payload_len` | Command payload bytes |
| `ack_len` | ACK payload bytes |

> **Cold start** means each trial creates a fresh DTLS session from scratch:
> new UDP socket, new SSL context, full handshake, one command, one ACK,
> close.  No session resumption or connection reuse.

---

## Transport

**UDP/IP — not BLE/GATT.**

This is a *standard secure-channel baseline on the same client/RPi hardware*,
not a DTLS-over-BLE integration.  The choice is intentional: DTLS is designed
for IP networks, so we measure it on UDP/IP at its best.  CipherChannel runs
on top of BLE/GATT.  The comparison isolates protocol overhead, not radio
effects.

---

## Which DTLS version is used, and why

**DTLS 1.2** (via mbedTLS 3.6).

mbedTLS 3.6 supports TLS 1.3 over TCP but does **not** implement DTLS 1.3.
The DTLS 1.3 specification (RFC 9147) was standardised in 2022 and no
production-grade open-source C library with stable DTLS 1.3 support is
currently available for Raspberry Pi.  DTLS 1.2 (RFC 6347) is the de-facto
standard for constrained-device secure channels and is what all existing
DTLS-on-RPi deployments use.

---

## Protocol and authentication

- **Transport:** UDP/IP
- **Protocol:** DTLS 1.2
- **Ciphersuite:** `TLS_PSK_WITH_AES_128_GCM_SHA256`
- **Auth:** Pre-shared key (PSK) — lightweight, no certificate infrastructure,
  fair comparison against CipherChannel's pre-provisioned AES-256-GCM key
- **PSK identity:** `exo-dtls-client` (configurable)
- **Cookie:** `HelloVerifyRequest` cookie enabled (mbedTLS default for servers;
  prevents UDP reflection attacks)

---

## Directory layout

```
experiment_dtls_baseline/
├── README.md                  this file
├── config/
│   └── psk_config.cfg         PSK identity, hex key, port, trial count
├── server/
│   ├── dtls_server.c          DTLS 1.2 PSK server (runs on RPi)
│   └── Makefile
├── client/
│   ├── dtls_client.c          DTLS 1.2 PSK benchmark client (runs on laptop)
│   └── Makefile
├── scripts/
│   ├── run_trials.sh          build + run + analyse
│   └── analyze_results.py     statistics, JSON, Markdown
└── results/
    ├── .gitkeep
    ├── dtls_trials_<ts>.csv   raw per-trial data (generated)
    ├── dtls_summary_<ts>.json statistics summary (generated)
    └── dtls_summary_<ts>.md   Markdown table (generated)
```

---

## Installing dependencies

### Fedora laptop (client)

```bash
sudo dnf install gcc make mbedtls-devel
```

Verify:
```bash
pkg-config --modversion mbedtls   # should print 3.x.x
```

### Raspberry Pi (server)

**Raspberry Pi OS (Bookworm / Bullseye):**
```bash
sudo apt-get update
sudo apt-get install gcc make libmbedtls-dev
```

If `libmbedtls-dev` is not available (older Pi OS), build from source:
```bash
sudo apt-get install gcc make cmake
git clone --depth 1 --branch v3.6.2 https://github.com/Mbed-TLS/mbedtls.git
cd mbedtls
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

---

## Building

### On the laptop (client)

```bash
cd experiment_dtls_baseline/client
make
# → produces ./dtls_client
```

### On the RPi (server)

Copy the server directory to the RPi and build there:

```bash
# On laptop — copy source
rsync -av experiment_dtls_baseline/server/ pi@<RPI_IP>:~/dtls_server/

# On RPi
cd ~/dtls_server
make
# → produces ./dtls_server
```

---

## Running experiments

### Step 1 — Start the server on the RPi

```bash
# On RPi — default port 4433, default PSK
./dtls_server

# Custom port and PSK
./dtls_server --port 4433 \
              --psk-id exo-dtls-client \
              --psk-hex deadbeef0102030405060708090a0b0c
```

The server loops indefinitely, serving one trial (handshake + command + ACK)
per client connection.  Stop with `Ctrl-C`.

### Step 2 — Smoke test (10 trials) on the laptop

```bash
cd experiment_dtls_baseline
DRY_RUN=1 SERVER_HOST=<RPI_IP> ./scripts/run_trials.sh
```

Verify that all 10 trials print `OK` and that `handshake_ms` is plausible
(typically 5–50 ms over Wi-Fi/Ethernet).

### Step 3 — Full cold-start run (500 trials)

```bash
SERVER_HOST=<RPI_IP> ./scripts/run_trials.sh
```

The script:
1. Builds `client/dtls_client` if not already built.
2. Runs the client for 500 trials with 250 ms inter-trial pause.
3. Writes `results/dtls_trials_<timestamp>.csv`.
4. Runs `analyze_results.py` and writes JSON + Markdown summaries.

### Step 4 — 300-trial run

```bash
SERVER_HOST=<RPI_IP> TRIALS=300 ./scripts/run_trials.sh
```

### Running the client manually

```bash
./client/dtls_client \
    --host 192.168.1.50 \
    --port 4433 \
    --trials 500 \
    --inter-ms 250 \
    --timeout-ms 5000 \
    --psk-id exo-dtls-client \
    --psk-hex deadbeef0102030405060708090a0b0c \
    --output results/dtls_trials.csv
```

### Running the analysis manually

```bash
python3 scripts/analyze_results.py \
    --input   results/dtls_trials_<timestamp>.csv \
    --json    results/dtls_summary_<timestamp>.json \
    --markdown results/dtls_summary_<timestamp>.md
```

---

## Interpreting the CSV columns

| Column | Notes |
|--------|-------|
| `socket_setup_ms` | Usually < 1 ms (just a syscall).  Spikes indicate kernel/scheduling jitter. |
| `handshake_ms` | Dominant cost.  Includes two round trips for PSK DTLS 1.2 + cookie round trip = **3 UDP RTTs** total. |
| `command_ack_ms` | Application data RTT after the session is established. |
| `total_ms` | The number to compare against CipherChannel `t_total_ms`. |
| `success=false` | Timeout, connection refused, or PSK mismatch.  Check `error` column. |

**Expected ranges (Wi-Fi LAN, same room):**

| Metric | Typical |
|--------|---------|
| `socket_setup_ms` | 0.05–0.5 ms |
| `handshake_ms` | 8–40 ms |
| `command_ack_ms` | 2–10 ms |
| `total_ms` | 10–55 ms |

---

## Comparing against CipherChannel cold-start results

CipherChannel cold-start results are in:
```
client/results/client_cold_start.csv   (client-side timestamps)
client/results/server_cold_start.csv   (server-side timestamps)
```

The column to compare is `t_total_ms` (CipherChannel) vs `total_ms` (DTLS).

Key differences to document in the paper:

| | CipherChannel | DTLS baseline |
|---|---|---|
| Transport | BLE/GATT | UDP/IP (Wi-Fi) |
| Auth | AES-256-GCM + monotonic nonce | PSK-AES-128-GCM |
| Session setup | BLE scan + connect + key exchange | DTLS 1.2 handshake (3 RTTs) |
| Reconnect cost | BLE re-scan + re-connect | Full DTLS handshake |

Do **not** claim CipherChannel is faster without verifying the measured medians.
The analysis script reports median and CI-95 for both directions.

---

## Reproducibility notes

- Each trial is an independent DTLS session.  No session tickets or resumption.
- The shared entropy/RNG context is initialised once at client startup and
  reused across trials (same as how CipherChannel initialises AES once).
- `inter_ms=250` gives the RPi time to reset between trials and avoids
  back-to-back UDP port reuse collisions.
- All timestamps use `CLOCK_MONOTONIC` on the client.  Server timestamps use
  `CLOCK_REALTIME` for log correlation only; they are not in the CSV.
- Failed trials are included in the CSV with `success=false`; the analysis
  script excludes them from latency statistics.
- Do not run other network-intensive workloads on either machine during the
  experiment.

---

## Limitations

1. **DTLS 1.3 not available**: mbedTLS 3.6 does not implement DTLS 1.3.
   DTLS 1.2 is the current real-world standard for this class of device.
2. **UDP/IP, not BLE**: This baseline tests DTLS at its natural transport
   layer.  A DTLS-over-GATT integration would add BLE overhead on top.
3. **Single PSK**: The server accepts any client with the matching PSK.
   For a multi-device deployment, per-device PSKs or certificates would
   require additional handshake overhead.
4. **Client runs on laptop**: Timing reflects laptop CPU + Wi-Fi RTT to RPi,
   matching the CipherChannel client topology.
