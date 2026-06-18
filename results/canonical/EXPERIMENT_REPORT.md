# CipherChannel — Experiment Report

**Git commit:** `4d67c9660da1a1094d68e6ece5037441678f2c01`  

**Run date:** 2026-06-14  

**Host:** Laptop — fedora.home, 12th Gen Intel i7-12650H, Fedora Linux 7.0.11-200.fc44.x86_64  

**Python:** 3.14.5 · PyCryptodome 3.23.0  

**BlueZ:** 5.86 · bless 0.3.0 (server/.venv on RPi) (RPi) · bleak 3.0.2 (client/.venv) (client)  

**Protocol version:** 1 · **State format version:** 1  

**MAX_PLAINTEXT_SIZE:** 400 B · **MAX_PACKET_SIZE:** 428 B  


---


## Statistical Methodology

**Percentile method:** linear interpolation (Hyndman & Fan 1996, Type 7).  

For a sorted array *x* of length *N*, the value at percentile *p* is:  



```

i      = p / 100 × (N − 1)          # fractional index

result = x[⌊i⌋] + frac(i) × (x[⌈i⌉] − x[⌊i⌋])

```



Equivalent to `numpy.percentile(x, p, method="linear")` and R `quantile(x, type=7)`.  



**95% confidence interval for success proportion:** Wilson score interval (Wilson 1927).  

Preferred over the Wald interval because it is valid when p̂ is near 0 or 1 and for small N.  



```

z  = 1.96  (two-tailed α = 0.05)

n  = attempts,  p̂ = successes / n

centre = (p̂ + z²/(2n)) / (1 + z²/n)

margin = z × √(p̂(1−p̂)/n + z²/(4n²)) / (1 + z²/n)

CI     = [max(0, centre − margin),  min(1, centre + margin)]

```


---


## Experiment A — Protocol Correctness

Unit test suite exercising CipherChannel in pure Python (no BLE).  

**Git commit:** `4d67c9660da1a1094d68e6ece5037441678f2c01`  



| Group | Tests | Passed | Failed |
|-------|-------|--------|--------|
| A1 — Packet-length invariants | 15 | 15 | 0 |
| A2 — Counter behaviour | 21 | 21 | 0 |
| A3 — Malformed-input rejection | 13 | 13 | 0 |
| A4 — Protocol test vector | 3 | 3 | 0 |
| **Total** | **52** | **52** | **0** |

**Result: 52/52 PASS**  

Success rate: 100.00%  

95% Wilson CI: [93.12%, 100.00%]  

Elapsed: 15.0 ms  


---


## Experiment P — Provisioning Gate

Unit test suite for the ProvisioningGate state machine (time-windowed, one-shot provisioning).  

**Git commit:** `4d67c9660da1a1094d68e6ece5037441678f2c01`  



| Group | Tests | Passed | Failed |
|-------|-------|--------|--------|
| P01–P19 — Gate behaviour (timeout, one-shot, isolation, concurrent) | 22 | 22 | 0 |
| B01–B06 — BenchmarkGate (always-open mode) | 6 | 6 | 0 |
| **Total** | **28** | **28** | **0** |

**Result: 28/28 PASS**  

Success rate: 100.00%  

95% Wilson CI: [87.94%, 100.00%]  

Elapsed: 41.8 ms  


---


## Experiment D — Concurrent Endpoint Isolation (Adversarial)

Cross-endpoint injection test: packets authenticated with K_phone are submitted to the cane channel and vice versa.  Server must reject all — a single unexpected acceptance is a critical security failure.  



**RPI address:** `B8:27:EB:07:01:22`  

**Injections per direction:** 30  



| Direction | Attack attempts | Rejections | Unexpected accepted | Rejection rate |
|-----------|-----------------|------------|---------------------|----------------|
| phone→cane (K_phone on cane channel) | 30 | 30 | 0 | 100.00% |
| cane→phone (K_cane on phone channel) | 30 | 30 | 0 | 100.00% |
| **Total** | **60** | **60** | **0** | **100.00%** |

Unexpected forwards: 0  

Counter changes after rejection: not applicable (server-side stateless reject — GCM auth failure before counter update).  



**Result: PASS** — rejection mechanism is AES-GCM tag verification: K_phone ≠ K_cane, so GCM authentication fails before any replay counter is consulted.  

D4 sanity: 2/2 valid commands accepted post-injection.  

Elapsed: 54022.2 ms  


---


## Experiment F — Cold Start Latency

Each trial: scan → connect → key exchange → encrypt command → BLE write → ACK.  

Full connection setup on every trial (no connection reuse).  



**Trials:** 500  

**Successes:** 500  

**Failures:** 0  

**Success rate:** 100.00%  

**95% Wilson CI:** [99.24%, 100.00%]  



| Phase | N | Mean (ms) | Median (ms) | Std (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) |
|-------|---|-----------|-------------|----------|----------|----------|----------|----------|
| Scan | 500 | 1018.1 | 807.8 | 788.0 | 2607.2 | 4117.0 | 18.1 | 5215.3 |
| Connect | 500 | 3412.9 | 2688.5 | 1218.2 | 5920.8 | 7376.1 | 1914.3 | 10679.2 |
| Key exchange | 500 | 437.7 | 399.6 | 83.9 | 577.7 | 804.8 | 351.8 | 1072.2 |
| Command encrypt | 500 | 0.091 | 0.069 | 0.047 | 0.154 | 0.306 | 0.056 | 0.326 |
| Write (BLE) | 500 | 90.3 | 89.0 | 7.5 | 90.8 | 134.4 | 82.6 | 136.4 |
| ACK wait | 500 | 90.9 | 90.1 | 6.3 | 91.2 | 135.1 | 87.3 | 179.8 |
| Command→ACK | 500 | 181.3 | 179.5 | 9.7 | 181.3 | 224.9 | 173.7 | 268.7 |
| Total | 500 | 5050.1 | 4624.1 | 1502.0 | 7773.8 | 10384.2 | 3095.1 | 12904.6 |


---


## Experiment G — Steady-State Latency

One-time setup (scan · connect · key exchange), then repeated write/ACK cycles on the persistent encrypted channel.  



Setup: scan 365 ms · connect 3449 ms · key exchange 766 ms  



**Trials:** 999  

**Successes:** 999  

**Failures:** 0  

**Success rate:** 100.00%  

**95% Wilson CI:** [99.62%, 100.00%]  



| Phase | N | Mean (ms) | Median (ms) | Std (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) |
|-------|---|-----------|-------------|----------|----------|----------|----------|----------|
| Client encrypt | 999 | 0.232 | 0.215 | 0.058 | 0.354 | 0.405 | 0.161 | 0.606 |
| Write (BLE) | 999 | 80.2 | 79.2 | 6.6 | 80.4 | 124.2 | 76.0 | 125.5 |
| ACK wait | 999 | 90.2 | 90.1 | 2.5 | 91.1 | 91.4 | 88.0 | 136.2 |
| Command→ACK | 999 | 170.7 | 169.6 | 7.1 | 170.7 | 214.7 | 166.5 | 215.5 |


---


## Experiment H — Gateway Internal Breakdown

Server-side per-stage timing for 1 000 steady-state commands.  Timestamps injected inside the GATT characteristic-write callback.  



**Trials:** 1000 (all client-side PASS)  



| Phase | N | Mean (ms) | Median (ms) | Std (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) |
|-------|---|-----------|-------------|----------|----------|----------|----------|----------|
| Packet parse (nonce extract + seq decode) | 1000 | 0.029 | 0.029 | 0.011 | 0.031 | 0.042 | 0.016 | 0.181 |
| Freshness + direction-parity validation | 1000 | 0.003 | 0.003 | 0.003 | 0.003 | 0.004 | 0.001 | 0.102 |
| AES-256-GCM auth + decryption | 1000 | 1.708 | 1.699 | 0.209 | 1.871 | 1.973 | 0.838 | 4.761 |
| fsync receive counter to state file | 1000 | 20.012 | 14.212 | 16.583 | 30.537 | 101.822 | 12.834 | 155.194 |
| JSON parse + action identification | 1000 | 0.295 | 0.296 | 0.025 | 0.336 | 0.347 | 0.181 | 0.416 |
| ACK char.value set (BLE write) | 1000 | 0.492 | 0.491 | 0.049 | 0.563 | 0.590 | 0.279 | 1.027 |
| Gateway total (callback → char set) | 1000 | 22.540 | 16.811 | 16.572 | 32.939 | 104.457 | 14.209 | 156.560 |


---


## Experiment I — Key Exchange Latency

Each trial: scan → connect → write REQUEST_KEY → poll for 60-byte encrypted K_phone response → client decrypt.  



**Trials:** 500  

**Successes:** 500  

**Failures:** 0  

**Success rate:** 100.00%  

**95% Wilson CI:** [99.24%, 100.00%]  



| Phase | N | Mean (ms) | Median (ms) | Std (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) |
|-------|---|-----------|-------------|----------|----------|----------|----------|----------|
| Scan | 500 | 991.7 | 741.7 | 832.4 | 2581.5 | 3930.5 | 18.4 | 6961.3 |
| Connect | 500 | 3674.0 | 3323.7 | 1414.3 | 6639.7 | 8033.0 | 1919.4 | 10964.9 |
| REQUEST_KEY write | 500 | 363.3 | 352.6 | 92.6 | 488.3 | 847.4 | 258.3 | 984.2 |
| Server process (crypto + BLE write) | 500 | 92.2 | 90.9 | 8.7 | 92.4 | 136.3 | 87.3 | 180.0 |
| Client decrypt K_phone | 500 | 0.303 | 0.237 | 0.639 | 0.336 | 0.513 | 0.179 | 9.142 |
| Client channel state_init | 500 | 0.028 | 0.019 | 0.021 | 0.047 | 0.129 | 0.014 | 0.225 |
| KEX total (write→K decrypted) | 500 | 455.8 | 443.5 | 93.1 | 578.7 | 937.9 | 349.8 | 1075.4 |


---


## Experiment J — Distance / Reconnect

Full reconnect latency (scan → connect → key exchange → write → ACK) across five distance/obstruction conditions, 200 trials per condition.  



**Total trials:** 1000 (5 conditions × 200)  

**Successes:** 1000  

**Failures:** 0  

**Overall success rate:** 100.00%  

**95% Wilson CI:** [99.62%, 100.00%]  



### Per-condition total latency (ms)



| Condition | N | Mean | Median | Std | p95 | p99 | Min | Max | Successes |
|-----------|---|------|--------|-----|-----|-----|-----|-----|-----------|
| 0.5m_los | 200 | 4481.9 | 4303.7 | 1334.8 | 7051.8 | 8217.7 | 2324.0 | 8444.4 | 200/200 (100.0%) |
| 1m_los | 200 | 4468.4 | 4258.3 | 1316.0 | 6823.8 | 7999.6 | 2369.0 | 8804.1 | 200/200 (100.0%) |
| 2m_los | 200 | 4329.0 | 4124.2 | 1302.1 | 6646.8 | 8713.2 | 2324.5 | 9164.2 | 200/200 (100.0%) |
| 4m_los | 200 | 5002.7 | 4731.5 | 1557.6 | 7560.2 | 9666.9 | 2414.0 | 12988.4 | 200/200 (100.0%) |
| 7m_wall | 200 | 5561.2 | 4798.5 | 2359.1 | 10624.3 | 12686.4 | 2504.8 | 16138.9 | 200/200 (100.0%) |

### Per-condition write latency (ms)



| Condition | N | Mean | Median | Std | p95 | p99 | Min | Max |
|-----------|---|------|--------|-----|-----|-----|-----|-----|
| 0.5m_los | 200 | 276.5 | 258.5 | 44.9 | 304.7 | 526.8 | 254.7 | 573.5 |
| 1m_los | 200 | 289.3 | 301.3 | 42.9 | 348.0 | 525.3 | 255.8 | 572.0 |
| 2m_los | 200 | 291.0 | 302.1 | 40.9 | 308.1 | 526.8 | 252.3 | 527.5 |
| 4m_los | 200 | 284.6 | 286.1 | 41.8 | 330.3 | 482.5 | 218.8 | 620.9 |
| 7m_wall | 200 | 290.9 | 295.2 | 44.3 | 348.9 | 468.6 | 229.3 | 572.6 |


---


## Experiment J-Steady — Distance / Steady-State

Sustained write/ACK latency on an already-established connection across four distance/obstruction conditions, 500 trials per condition.  



**Total trials:** 2000 (4 conditions × 500)  

**Successes:** 2000  

**Failures:** 0  

**Overall success rate:** 100.00%  

**95% Wilson CI:** [99.81%, 100.00%]  



### Per-condition total latency (ms)



| Condition | N | Mean | Median | Std | p95 | p99 | Min | Max | Successes |
|-----------|---|------|--------|-----|-----|-----|-----|-----|-----------|
| 1m_los | 500 | 170.8 | 169.3 | 8.4 | 170.2 | 214.2 | 166.8 | 258.1 | 500/500 (100.0%) |
| 2m_los | 500 | 170.3 | 169.3 | 7.2 | 170.2 | 214.3 | 166.3 | 259.6 | 500/500 (100.0%) |
| 4m_los | 500 | 171.8 | 169.3 | 10.5 | 211.4 | 214.4 | 166.3 | 258.5 | 500/500 (100.0%) |
| 7m_wall | 500 | 182.0 | 169.4 | 25.9 | 215.1 | 259.6 | 166.3 | 350.5 | 500/500 (100.0%) |

### Per-condition write latency (ms)



| Condition | N | Mean | Median | Std | p95 | p99 | Min | Max |
|-----------|---|------|--------|-----|-----|-----|-----|-----|
| 1m_los | 500 | 80.1 | 79.2 | 6.9 | 80.1 | 124.1 | 76.4 | 168.1 |
| 2m_los | 500 | 80.0 | 79.2 | 6.6 | 80.1 | 123.9 | 76.2 | 169.6 |
| 4m_los | 500 | 80.4 | 79.1 | 8.1 | 80.3 | 124.1 | 75.5 | 124.6 |
| 7m_wall | 500 | 87.1 | 79.2 | 20.6 | 124.4 | 169.1 | 76.3 | 259.4 |


---


## Experiment J-Range — Distance-Sweep Range Limit

Single BLE session with key exchange performed once at ~7 m. Commands were issued continuously while the mobile device was moved to ~10 m through one interior wall. Trials are divided into four approximate distance bins (~11 trials each). Connection dropped at trial 44 with GATT UNLIKELY_ERROR (0x0E).  



| Phase (approx.) | N | Mean (ms) | Median (ms) | Max (ms) |
|-----------------|---|-----------|-------------|----------|
| ∼7 m (trials 1–11) | 11 | 214.3 | 214.2 | 349.2 |
| ∼8 m (trials 12–22) | 11 | 263.3 | 214.7 | 529.6 |
| ∼9 m (trials 23–33) | 11 | 353.3 | 259.4 | 620.6 |
| ∼10 m (trials 34–43) | 10 | 398.9 | 395.0 | 664.4 |
| Connection failure (trial 44) | 1 | — | — | 753.1 (GATT 0x0E + disconnect) |

Trial 44: write succeeded (349 ms), ACK returned GATT UNLIKELY_ERROR (0x0E) after 404 ms. Trial 45 confirmed connection lost.  



**Effective trials (up to failure):** 44  

**Successes:** 43  

**Success rate (effective):** 97.73%  

**95% Wilson CI:** [88.19%, 99.60%]  



**Key finding:** median latency nearly doubled from 214 ms near 7 m to 395 ms near 10 m, confirming that the tested hardware configuration (RPi 3B+, standard laptop BLE adapter) reaches its practical range limit between 8 m and 10 m through a single interior wall.  


---


## Summary

### Correctness & security experiments



| Experiment | N | Successes | Failures | Success rate | 95% Wilson CI |
|------------|---|-----------|----------|--------------|----------------|
| A — Protocol correctness | 52 | 52 | 0 | 100.00% | [93.12%, 100.00%] |
| P — Provisioning gate | 28 | 28 | 0 | 100.00% | [87.94%, 100.00%] |

### Adversarial experiments



| Experiment | Attack attempts | Rejections | Unexpected accepted | Rejection rate |
|------------|-----------------|------------|---------------------|----------------|
| D — Endpoint isolation | 60 | 60 | 0 | 100.00% |

### Latency experiments (median command→ACK)



| Experiment | N | Median (ms) | p95 (ms) | p99 (ms) | Success rate | 95% Wilson CI |
|------------|---|-------------|----------|----------|--------------|----------------|
| F — Cold start (command→ACK) | 500 | 179.5 | 181.3 | 224.9 | 100.00% | [99.24%, 100.00%] |
| G — Steady state (command→ACK) | 999 | 169.6 | 170.7 | 214.7 | 100.00% | [99.62%, 100.00%] |
| H — Gateway total (server-side) | 1000 | 16.8 | 32.9 | 104.5 | N/A (server only) | — |
| I — Key exchange (KEX total) | 500 | 443.5 | 578.7 | 937.9 | 100.00% | [99.24%, 100.00%] |

### Distance experiments (all conditions combined)



| Experiment | Conditions | Total trials | Successes | Success rate | Median total (ms) |
|------------|------------|--------------|-----------|--------------|-------------------|
| J — Reconnect | 5 | 1000 | 1000 | 100.00% | 4394.7 |
| J-Steady — Steady state | 4 | 2000 | 2000 | 100.00% | 169.3 |


---

*Report generated by `results/canonical/generate_report.py`.*  

