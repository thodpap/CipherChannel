# Latency Experiments

Four latency sub-experiments were run against the RPi BLE server
(B8:27:EB:07:01:22, `bless` 0.3.0, BlueZ 5.86, `BENCHMARK_PROVISIONING=1`).
Client: laptop i7-12650H, Fedora, BlueZ 5.86, `bleak` 3.0.2.

---

## Experiment F — Cold Start (500 trials)

Each trial: scan → connect → key exchange → encrypt command → write → ACK.
Full connection setup repeated every trial.

```bash
client/.venv/bin/python results/canonical/latency/cold_start/run_cold_start.py \
    --address B8:27:EB:07:01:22 --trials 500
```

| Phase | Mean | Median | p95 | Max |
|-------|------|--------|-----|-----|
| Scan | 1018 ms | 808 ms | 2657 ms | 5215 ms |
| Connect | 3413 ms | 2689 ms | 5922 ms | 10679 ms |
| Key exchange | 438 ms | 400 ms | 578 ms | 1072 ms |
| Command encrypt | 0.09 ms | 0.07 ms | 0.16 ms | 0.33 ms |
| Write (BLE) | 90 ms | 89 ms | 91 ms | 136 ms |
| ACK wait | 91 ms | 90 ms | 91 ms | 180 ms |
| Command→ACK | 181 ms | 179 ms | 181 ms | 269 ms |
| **Total** | **5050 ms** | **4624 ms** | **7775 ms** | **12905 ms** |

**Result: 500/500 PASS** — 0 failures at any stage.

Key observation: Scan and connect together account for ~88% of total cold-start
latency; AES-256-GCM encryption is <0.1 ms and is negligible.

---

## Experiment G — Steady State (1000 trials)

One-time setup (scan 365 ms · connect 3449 ms · key exchange 766 ms), then
1000 write/ACK cycles on the persistent encrypted channel.

```bash
client/.venv/bin/python results/canonical/latency/steady_state/run_steady_state.py \
    --address B8:27:EB:07:01:22 --trials 1000
```

| Phase | Mean | Median | p95 | Max |
|-------|------|--------|-----|-----|
| Client encrypt | 0.23 ms | 0.22 ms | 0.35 ms | 0.61 ms |
| Write (BLE) | 80 ms | 79 ms | 80 ms | 126 ms |
| ACK wait | 90 ms | 90 ms | 91 ms | 136 ms |
| **Command→ACK** | **171 ms** | **170 ms** | **171 ms** | **215 ms** |

**Result: 1000/1000 PASS** — 0 failures.

Key observation: Per-command latency is almost entirely BLE transport
(~170 ms round-trip). AES-256-GCM encrypt is <0.25 ms mean; it contributes
<0.15% of round-trip time.

---

## Experiment H — Gateway Internal Breakdown (1000 trials)

Server-side timing instrumented inside the RPi gateway handler.  Same
steady-state connection (1000 commands), but each stage of the server's
receive-path is timestamped.

One-time setup: scan 298 ms · connect 5462 ms · key exchange 768 ms.

```bash
client/.venv/bin/python results/canonical/latency/gateway_internal/run_gateway_internal.py \
    --address B8:27:EB:07:01:22 --trials 1000
```

### Server-side stage breakdown

| Stage | Mean | Median | p95 | Max |
|-------|------|--------|-----|-----|
| Packet parse (nonce extract + seq decode) | 0.030 ms | 0.029 ms | 0.031 ms | 0.181 ms |
| Freshness + direction-parity validation | 0.003 ms | 0.003 ms | 0.003 ms | 0.102 ms |
| AES-256-GCM auth + decryption | 1.708 ms | 1.699 ms | 1.872 ms | 4.761 ms |
| **fsync receive counter to state file** | **20.0 ms** | **14.2 ms** | **30.5 ms** | **155.2 ms** |
| JSON parse + action identification | 0.296 ms | 0.296 ms | 0.336 ms | 0.416 ms |
| ACK char.value set (BLE write) | 0.492 ms | 0.491 ms | 0.563 ms | 1.027 ms |
| **Gateway total (callback → char set)** | **22.5 ms** | **16.8 ms** | **33.2 ms** | **156.6 ms** |

**Result: 1000/1000 client-side PASS.**

Key observations:
- **fsync dominates server processing** (20 ms mean, up to 155 ms at p99).
  All other server stages combined add <2.5 ms.
- AES-256-GCM decryption is 1.7 ms median — fast for a Python/PyCryptodome
  implementation.
- The ACK character set is plaintext by design (0.49 ms); BLE notification
  delivery to the client (~90 ms) is not included in gateway_total_ms.

---

## Experiment I — Key Exchange Latency (235 trials)

Each trial: scan → connect → write `REQUEST_KEY` → poll for 60-byte encrypted
K_phone response → decrypt (client side).  Measures full provisioning round-trip
time from the client's perspective.

```bash
client/.venv/bin/python results/canonical/latency/key_exchange/run_key_exchange.py \
    --address B8:27:EB:07:01:22 --trials 235
```

| Phase | Mean | Median | p95 | Max |
|-------|------|--------|-----|-----|
| Scan | 988 ms | 768 ms | 2503 ms | 3930 ms |
| Connect | 3442 ms | 2736 ms | 5922 ms | 8027 ms |
| REQUEST_KEY write | 366 ms | 353 ms | 488 ms | 984 ms |
| Server process (crypto + BLE write) | 92 ms | 91 ms | 92 ms | 136 ms |
| Client decrypt K_phone | 0.28 ms | 0.26 ms | 0.34 ms | 6.74 ms |
| Client channel state_init | 0.03 ms | 0.02 ms | 0.05 ms | 0.23 ms |
| **KEX total (write→K_phone decrypted)** | **458 ms** | **444 ms** | **579 ms** | **1075 ms** |

**Result: 235/235 PASS** — 0 failures.

Key observations:
- Key exchange itself (REQUEST_KEY → encrypted key received + decrypted) takes
  ~444 ms median, dominated by the BLE write + server response poll.
- Client-side AES decryption of K_phone is <0.3 ms.
- Connection setup (scan + connect) adds another ~3.5 s median before the
  key exchange begins.

---

## Summary across experiments

| Experiment | Trials | Success | Command→ACK median |
|------------|--------|---------|-------------------|
| F — Cold start (full per-trial setup) | 500 | 100% | 181 ms (excl. scan/connect) |
| G — Steady state (persistent connection) | 1000 | 100% | 170 ms |
| H — Gateway internal (server breakdown) | 1000 | 100% | 170 ms client-side |
| I — Key exchange (provisioning RTT) | 235 | 100% | 444 ms KEX only |

## Output files

| File | Contents |
|------|----------|
| `cold_start/cold_start_raw.csv` | Per-trial cold-start rows |
| `cold_start/cold_start_raw_summary.json` | Aggregated cold-start statistics |
| `cold_start/cold_start_server_raw.csv` | Server-side timing for cold-start trials |
| `steady_state/steady_state_raw.csv` | Per-trial steady-state rows |
| `steady_state/steady_state_raw_summary.json` | Aggregated steady-state statistics |
| `steady_state/steady_state_server_raw.csv` | Server-side timing for steady-state trials |
| `gateway_internal/gateway_client_raw.csv` | Client timing (same as steady-state) |
| `gateway_internal/gateway_internal_server_raw.csv` | Per-trial server-side stage timestamps |
| `gateway_internal/gateway_internal_summary.json` | Server-side stage statistics |
| `key_exchange/key_exchange_raw.csv` | Per-trial key exchange rows |
| `key_exchange/key_exchange_raw_summary.json` | Aggregated key exchange statistics |
| `latency_summary.json` | Legacy combined summary (Exp A/B/C from earlier run) |
