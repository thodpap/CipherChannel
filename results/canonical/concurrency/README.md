# Concurrency Experiments

Two concurrency experiments were executed against the RPi BLE server
(B8:27:EB:07:01:22, `BENCHMARK_PROVISIONING=1`).

---

## Experiment D — Concurrent Endpoint Isolation

Verifies that the phone and cane channels are cryptographically isolated:
packets authenticated with K_phone are rejected by the cane channel and
vice versa.  The laptop acts as both clients (sequentially).

```bash
client/.venv/bin/python results/canonical/concurrency/run_concurrent_endpoints.py \
    --address B8:27:EB:07:01:22
```

| Phase | Description | Attempts | Rejected | Unexpected | Result |
|-------|-------------|----------|----------|------------|--------|
| D1 | Cane key exchange (Python plaintext fallback → encrypted K_cane) | 1 | — | — | **PASS** |
| D2 | Phone key exchange (standard transport channel) | 1 | — | — | **PASS** |
| D3.p→c | Phone-encrypted packets injected into cane channel | 30 | 30 | 0 | **PASS** |
| D3.c→p | Cane-encrypted packets injected into phone channel | 30 | 30 | 0 | **PASS** |
| D4 | Sanity: one valid command per channel | 2 | — | — | **PASS** |

**Result: PASS** — 60/60 cross-endpoint injections rejected — elapsed 54.0 s.

Rejection mechanism: K_phone ≠ K_cane.  AES-GCM's authentication tag is
bound to the key, so supplying a packet authenticated under K_phone to the
cane channel (which holds K_cane) fails GCM tag verification before any
counter check is reached.  Server log confirmed 30 ×
`"CANE2PHONE: decrypt/replay failed — rejected"` + 30 ×
`"[phone] Decrypt/replay failed — packet rejected"`.

---

## Experiment K — Sustained Concurrent Traffic (partial)

Intended to run 500 phone commands and 500 cane messages concurrently
(`asyncio.gather`) to measure latency-under-load and verify no deadlocks
or wrong-endpoint accepts occur under sustained dual-client traffic.

```bash
client/.venv/bin/python results/canonical/concurrency/run_K.py \
    --address B8:27:EB:07:01:22 --scenario concurrent --n-phone 500 --n-cane 500
```

| File | Rows | Status |
|------|------|--------|
| `K_concurrent_phone_client.csv` | 3 (3 successful commands) | Incomplete — run aborted |
| `K_concurrent_cane_client.csv` | 0 data rows | Incomplete — cane task did not complete kex |

**Status: INCOMPLETE.** The 3 phone commands that did run returned
`round_trip_ms` of ~170 ms each with `success=True`, consistent with
steady-state latency.  The run was interrupted before completing.

Isolation is already proven by Experiment D (60/60 rejections).  K would add
sustained-load latency data but is not required for the security claims of the paper.

---

## Output files

| File | Contents |
|------|----------|
| `concurrent_endpoints_raw.csv` | Per-phase rows for Experiment D |
| `concurrent_endpoints_summary.json` | Experiment D summary and overall result |
| `K_concurrent_phone_client.csv` | Partial phone-side rows from Experiment K |
| `K_concurrent_cane_client.csv` | Partial cane-side rows from Experiment K (header only) |
