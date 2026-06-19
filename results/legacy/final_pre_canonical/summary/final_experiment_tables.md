# CipherChannel — Final Experiment Tables

Generated from: `/home/thodpap/repos/CT-Engineering/exoskeleton/awake-bt-controller-rpi/experiment_ble/results/final/summary`

## Table: Adversarial / Restart Validation

Total: **13/13 passed** in 11 ms

| # | Test | Result | Duration (ms) |
|---|------|--------|---------------|
| ✓ | TC01 normal send/receive after fresh provisioning | PASS | 8.48 |
| ✓ | TC02 replay of accepted packet rejected | PASS | 0.25 |
| ✓ | TC03 tampered ciphertext rejected | PASS | 0.13 |
| ✓ | TC04 tampered GCM tag rejected | PASS | 0.12 |
| ✓ | TC05 tampered nonce rejected | PASS | 0.12 |
| ✓ | TC06 wrong key rejected | PASS | 0.14 |
| ✓ | TC07 reflection: initiator rejects own packet | PASS | 0.12 |
| ✓ | TC08 stale counter rejected after newer accepted | PASS | 0.21 |
| ✓ | TC09 send counter survives restart | PASS | 0.35 |
| ✓ | TC10 recv counter survives restart | PASS | 0.65 |
| ✓ | TC11 replay rejected after receiver restart | PASS | 0.18 |
| ✓ | TC12 corrupted state file fails closed | PASS | 0.02 |
| ✓ | TC13 counter reset under same key detected as stale | PASS | 0.27 |

## Table: MTU / Long-Write Confirmation

- Negotiated ATT MTU: **23**
- All packets above 20-byte default ATT payload accepted: **No**
- Max successful plaintext: **400 B**  →  encrypted: **448 B**

| Plaintext (B) | Encrypted (B) | Above 20B ATT? | Result |
|--------------|--------------|----------------|--------|
| 1 | 48 | Yes | ✓ OK |
| 8 | 48 | Yes | ✓ OK |
| 16 | 64 | Yes | ✓ OK |
| 20 | 64 | Yes | ✓ OK |
| 32 | 80 | Yes | ✓ OK |
| 50 | 96 | Yes | ✓ OK |
| 64 | 112 | Yes | ✓ OK |
| 100 | 144 | Yes | ✓ OK |
| 128 | 176 | Yes | ✓ OK |
| 200 | 240 | Yes | ✓ OK |
| 256 | 304 | Yes | ✓ OK |
| 400 | 448 | Yes | ✓ OK |
| 512 | 560 | Yes | ✗ FAIL |

> Some large packets failed — see failures_bytes.

## Table: Concurrent Endpoint Validation

Experiment window: 119.0 s

| Endpoint | Sent | Accepted | Failed | Notes |
|----------|------|----------|--------|-------|
| Laptop (supervisory) | 100 | 100 | 0 | Fedora/Bleak, substitutes for Android app |

**Replay rejection**: 2/2 replayed packets rejected by server counter check

**Counter isolation**: pass

**Notes:**
- Laptop used as supervisory client (substitutes for Android app) — identical CipherChannel packet format and BLE/GATT path.
- Cane counter isolation is verified at the ESP32 firmware level via separate NVS namespaces; server-side isolation confirmed by independent session channels.
- operator_reported_57_presses_in_119.0s
