# Experiment A — Protocol Correctness

## Purpose
Deterministic unit-level verification of the CipherChannel protocol implementation
(Python / PyCryptodome).  No BLE, RPi, or ESP32 hardware required.

## Run command
```
python3.14 results/canonical/correctness/run_correctness.py
```

## Subsections
| ID | Coverage |
|----|----------|
| A1 | Packet-length invariants for plaintext sizes 0–400 B; oversized send raises; oversized receive returns None |
| A2 | Counter serialisation (12B LE), first-nonce values, increment-by-2, direction parity, boundary counters (255–2^64), exhaustion at 2^96, missed-packet acceptance |
| A3 | Malformed input: empty, short, oversized, tampered ciphertext/tag/nonce, bad protocol version, corrupt state, endpoint-id mismatch |
| A4 | Protocol test vector from PROTOCOL.md §15 (zero key, pt=b"test") |

## Result (canonical run, commit 4d67c96)
**52/52 PASS** — elapsed 16.9 ms

## Output files
| File | Contents |
|------|----------|
| `raw.csv` | One row per test case: test_id, description, expected, actual, pass, note |
| `summary.json` | Aggregated counts + full result list |
| `metadata.json` | Run context |

## Analysis
All 52 test cases pass.  Key observations:
- Packet overhead is exactly 28 bytes at every plaintext size (0–400 B).
- No PKCS7 or other padding detected: ciphertext length == plaintext length for all sizes.
- Counter serialisation is correct 12-byte little-endian at boundary values through 2^64.
- Counter exhaustion guard fires correctly before 2^96 nonce reuse.
- Replay, direction reflection, tampering, and malformed inputs are all rejected without exception propagation.
- Protocol test vector matches the normative values in PROTOCOL.md §15.
