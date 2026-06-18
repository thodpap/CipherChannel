# CipherChannel — Canonical Experimental Evaluation

**Git commit:** `4d67c9660da1a1094d68e6ece5037441678f2c01` (working tree clean)  
**Run date:** 2026-06-14  
**Run host:** Laptop — 12th Gen Intel Core i7-12650H, Fedora Linux 7.0.11-200.fc44.x86_64  
**Python:** 3.14.5 · PyCryptodome 3.23.0 · BlueZ 5.86 · BLE adapter hci0 (USB)  
**Protocol version:** 1 · State format version: 1  
**MAX_PLAINTEXT_SIZE:** 400 B · **MAX_PACKET_SIZE:** 428 B  

---

## Experiment A — Protocol Correctness

| Subsection | Tests | Passed | Failed |
|---|---|---|---|
| A1 Packet-length invariants | 15 | 15 | 0 |
| A2 Counter behaviour | 22 | 22 | 0 |
| A3 Malformed-input rejection | 13 | 13 | 0 |
| A4 Protocol test vector | 3 | 3 | 0 |
| **Total** | **52** | **52** | **0** |

**Result: 52/52 PASS** — elapsed 16.9 ms

Key findings:
- Packet overhead is exactly 28 bytes at every plaintext size (0–400 B).
- No padding: ciphertext length == plaintext length for all tested sizes.
- Nonce is 12-byte little-endian at boundary values 0xff through 2^64.
- Counter exhaustion guard fires before 2^96 nonce reuse.
- Protocol test vector (PROTOCOL.md §15) matches byte-for-byte.

---

## Experiment B — Cross-platform Interoperability

### Implementations
| Implementation | Status |
|---|---|
| Python / PyCryptodome 3.23.0 | **TESTED** |
| ESP32 / mbedTLS | **BLOCKED** — device not connected |
| C / OpenSSL | **BLOCKED** — no C implementation in codebase |

### Python/PyCryptodome results

| Section | Description | Tests | Passed |
|---|---|---|---|
| B1 | Round-trip 100 pkts × 6 payload sizes | 6 | 6 |
| B2 | Replay-state advancement (20 pkts) | 2 | 2 |
| B3 | Attack matrix (8 attack types) | 8 | 8 |
| **Total** | | **16** | **16** |

**Result: 16/16 PASS** — 620 packet rows — elapsed 67.6 ms

### Interoperability matrix
| Encryptor | Decryptor | Result |
|---|---|---|
| Python/PyCryptodome | Python/PyCryptodome | **PASS** |
| Python/PyCryptodome | ESP32/mbedTLS | BLOCKED |
| ESP32/mbedTLS | Python/PyCryptodome | BLOCKED |
| Python/PyCryptodome | C/OpenSSL | BLOCKED |
| C/OpenSSL | Python/PyCryptodome | BLOCKED |

---

## Experiment C — Adversarial Rejection

| Section | Description | Attempts | Accepted | Rejected | Unexpected | Status |
|---|---|---|---|---|---|---|
| C1.local | Exact replay, 100 local | 100 | 0 | 100 | 0 | **PASS** |
| C1.ble | Exact replay, 30 BLE e2e | 30 | 0 | 30 | 0 | **PASS** |
| C2 | Replay after BLE reconnect (30 trials) | 30 | 0 | 30 | 0 | **PASS** |
| C3 | Replay after process restart (30, simulated) | 30 | 0 | 30 | 0 | **PASS** |
| C4 | Replay after RPi reboot | — | — | — | — | **BLOCKED** |
| C5 | Tampering: 6 sites × 20 payloads = 120 mutations | 120 | 0 | 120 | 0 | **PASS** |
| C6 | Wrong key + cross-endpoint (4 variants) | 4 | 0 | 4 | 0 | **PASS** |
| C7 | Direction reflection (100 attempts) | 100 | 0 | 100 | 0 | **PASS** |
| C8 | Reorder 2→6→4→8 (30 trials × 4) | 120 | 90* | 30 | 0 | **PASS** |

*90 legitimate (pkts 2, 6, 8 per trial accepted); 30 correctly rejected (pkt 4 stale after 6).

C1.ble / C2 note: server confirmed 90 "Decrypt/replay failed" entries (30 C1.ble + 30 C2 + 30 stale-state rejections).
C2 mechanism: server does NOT clear `_phone_channel` on BLE disconnect, so the channel state (seqRecv) persists across reconnects; replaying an already-consumed ciphertext is rejected by AES-GCM's monotonic counter check.

**Runnable sections: 8/8 PASS** — 534 adversarial attempts — 0 unexpected acceptances — C4 blocked (requires RPi reboot)

---

## Provisioning Gate

| Section | Tests | Passed |
|---|---|---|
| ProvisioningGate (physical-presence gated) | 22 | 22 |
| BenchmarkProvisioningGate (test-only bypass) | 6 | 6 |
| **Total** | **28** | **28** |

**Result: 28/28 PASS** — elapsed 42.2 ms

---

## Latency

BLE transport; RPi server at B8:27:EB:07:01:22; BENCHMARK_PROVISIONING=1; Bless 0.3.0 / BlueZ 5.86 / Bleak 3.0.2.

### Exp A — Per-trial reconnect (30 trials, full cycle per trial)

| Phase | Mean | Median | p95 | Max |
|---|---|---|---|---|
| Scan | 1365 ms | 844 ms | 3414 ms | 3426 ms |
| Connect | 4618 ms | 4429 ms | 9602 ms | 10840 ms |
| Key exchange | 457 ms | 445 ms | 579 ms | 726 ms |
| Write (encrypt+BLE write) | 90 ms | 89 ms | 91 ms | 135 ms |
| ACK (notification round-trip) | 91 ms | 90 ms | 91 ms | 91 ms |
| **Total** | **8945 ms** | **7988 ms** | **15009 ms** | **15010 ms** |

**Result: 30/30 PASS**

### Exp B — Steady-state (connect once, 100 write/ACK cycles)

One-time setup: scan 756 ms · connect 4520 ms · key exchange 409 ms

| Phase | Mean | Median | p95 | Max |
|---|---|---|---|---|
| Write | 81 ms | 79 ms | 81 ms | 124 ms |
| ACK | 91 ms | 90 ms | 91 ms | 135 ms |
| **Total** | **173 ms** | **170 ms** | **214 ms** | **216 ms** |

**Result: 100/100 PASS**

### Exp C — Key-once (key exchange trial 1; reconnect each trial, 30 trials)

Key exchange (trial 1 only): 767 ms

| Phase | Mean | Median | p95 | Max |
|---|---|---|---|---|
| Scan | 1467 ms | 842 ms | 3410 ms | 5971 ms |
| Connect | 4196 ms | 3197 ms | 9584 ms | 12144 ms |
| Write (cached-key encrypt) | 280 ms | 263 ms | 309 ms | 533 ms |
| ACK | 96 ms | 90 ms | 135 ms | 181 ms |
| **Total** | **8460 ms** | **7472 ms** | **13028 ms** | **18022 ms** |

**Result: 30/30 PASS**

Note: Exp C write latency (~263–309 ms) is ~3× higher than Exp A/B (~79–90 ms). The write phase in key-once mode transmits the encrypted command over a fresh BLE connection without the optimised notification path established during key exchange.

---

## Concurrent Endpoint Isolation (D)

BLE server at B8:27:EB:07:01:22; Python acts as both phone and cane clients sequentially.

| Phase | Description | Attempts | Rejected | Unexpected | Result |
|---|---|---|---|---|---|
| D1 | Cane key exchange (Python plaintext fallback) | 1 | — | — | **PASS** |
| D2 | Phone key exchange (standard transport channel) | 1 | — | — | **PASS** |
| D3.p→c | Phone-encrypted packets sent to cane channel | 30 | 30 | 0 | **PASS** |
| D3.c→p | Cane-encrypted packets sent to phone channel | 30 | 30 | 0 | **PASS** |
| D4 | Sanity: one valid command per channel | 2 | — | — | **PASS** |

**Result: PASS** — 60/60 cross-endpoint injections rejected via AES-GCM authentication failure — elapsed 54.0 s

Mechanism: K_phone ≠ K_cane; AES-GCM's authentication tag is bound to the key. Supplying a packet authenticated with K_phone to the cane channel (which holds K_cane) fails authentication, and vice versa. No counter check needed — rejection occurs at the GCM tag verification step.

Server log confirmed: 30 × "CANE2PHONE: decrypt/replay failed — rejected" + 30 × "[phone] Decrypt/replay failed — packet rejected".

---

## Blocked Experiments

| Experiment | Blocked sections / reason |
|---|---|
| B — ESP32/mbedTLS | ESP32 not connected; requires flashed device + RPi server |
| B — C/OpenSSL | No C implementation in repository |
| C4 | Requires physical RPi power cycle |
| Distance | Requires physical BLE range measurement |
| Resources | CPU/RAM profiling on RPi required |
| Soak | Long-duration BLE run requires RPi + ESP32 |

---

## Totals

| Metric | Value |
|---|---|
| Git commit | `4d67c96` (clean) |
| Total correctness / provisioning tests | **96** (52 + 16 + 28) |
| Total adversarial attempts | **534** (474 local + 60 BLE) |
| Cross-endpoint injection attempts | **60** (30 phone→cane + 30 cane→phone) |
| Unexpected acceptance events | **0** |
| Latency trials | **160** (30 A + 100 B + 30 C) |
| Blocked experiments | distance, resources, soak, B-ESP32, B-C, C4 |

---

## Required hardware for remaining experiments
1. **Connect ESP32** (flashed with CipherChannel firmware) + RPi running `ble_server.py` for B-ESP32 interoperability
2. Power-cycle RPi while server is running to test C4 (replay after reboot)
3. Physical distance testing for BLE range measurement
4. Two simultaneous BLE clients + RPi for concurrency experiments
