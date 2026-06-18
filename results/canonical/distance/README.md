# Experiment J — Distance & Reliability

## Purpose
Measure BLE connection reliability and command-round-trip latency across five
distance / obstacle conditions.  Two modes are tested:

- **J (reconnect)** — key exchange once at session start; scan → connect → write →
  ACK → disconnect per trial.  Models a device that reconnects for every command.
- **J (steady)** — scan, connect, and key exchange once; stay connected for all N
  trials.  Models a persistent real-world BLE session.

## Run commands

```bash
# Server (RPi) — same instance for all conditions:
BENCHMARK_PROVISIONING=1 \
EXPERIMENT_SERVER_CSV_PATH=/tmp/exp_J_server.csv \
server/.venv/bin/python server/ble_server.py

# J (reconnect) — one condition at a time:
client/.venv/bin/python results/canonical/distance/run_J.py \
    --address B8:27:EB:07:01:22 \
    --condition <condition> \
    --description "<description>" \
    --trials 200

# J (steady) — one condition at a time:
client/.venv/bin/python results/canonical/distance/run_J_steady.py \
    --address B8:27:EB:07:01:22 \
    --condition <condition> \
    --description "<description>" \
    --trials 500

# Aggregate cross-condition table:
client/.venv/bin/python results/canonical/distance/summarize_J.py
```

---

## Results — J (reconnect): 200 trials per condition, reconnect per trial

Key exchange done **once** at the start of each condition; subsequent trials
scan → connect → write encrypted command → poll ACK → disconnect.

| Condition | N | Success | Scan med | Conn med | Write med | ACK med | **Total med** | Total p95 |
|-----------|---|---------|----------|----------|-----------|---------|---------------|-----------|
| 0.5m_los  | 200 | **100%** | 749 ms | 2708 ms | 258 ms | 90 ms | **4304 ms** | 7094 ms |
| 1m_los    | 200 | **100%** | 745 ms | 2823 ms | 301 ms | 90 ms | **4258 ms** | 6825 ms |
| 2m_los    | 200 | **100%** | 719 ms | 2644 ms | 302 ms | 90 ms | **4124 ms** | 6689 ms |
| 4m_los    | 200 | **100%** | 790 ms | 3377 ms | 286 ms | 90 ms | **4731 ms** | 7859 ms |
| 7m_wall   | 200 | **100%** | 753 ms | 3392 ms | 295 ms | 90 ms | **4799 ms** | 11008 ms |

**Total: 1000/1000 PASS across all conditions.**

Failure count: 0 at any stage (scan / connect / write / ACK).

Key observations:
- Write latency (~258–302 ms median) is the encrypted BLE write on a fresh
  connection; substantially higher than steady-state (~79 ms) because no BlueZ
  MTU optimisation has been established yet.
- Connection latency is the dominant variable and increases noticeably at 7 m
  through a wall (median 3392 ms vs 2644–2823 ms for LOS conditions).
- ACK latency is stable at ~90 ms across all distances.

---

## Results — J (steady): 500 trials per condition, persistent connection

Scan, connect, and key exchange once; all 500 commands sent on the same
connection without reconnecting.

| Condition | N | Success | One-time scan | One-time conn | One-time KEX | Write med | ACK med | **Total med** | Total p95 |
|-----------|---|---------|---------------|---------------|--------------|-----------|---------|---------------|-----------|
| 1m_los    | 500 | **100%** | 657 ms | 3419 ms | 812 ms | 79 ms | 90 ms | **169 ms** | 170 ms |
| 2m_los    | 500 | **100%** | 743 ms | 3887 ms | 500 ms | 79 ms | 90 ms | **169 ms** | 170 ms |
| 4m_los    | 500 | **100%** | 813 ms | 3439 ms | 769 ms | 79 ms | 90 ms | **169 ms** | 213 ms |
| 7m_wall   | 500 | **100%** | 242 ms | 2593 ms | 539 ms | 79 ms | 90 ms | **169 ms** | 215 ms |

**Total: 2000/2000 PASS. Zero connection drops across all conditions.**

Key observations:
- Per-command round-trip is ~169 ms median at every distance once connected —
  distance has no measurable effect on in-session latency.
- Write latency drops to ~79 ms in steady-state vs ~258–302 ms in reconnect
  mode; the overhead in reconnect mode is BLE renegotiation on a fresh
  connection.
- ACK latency is ~90 ms in both modes — BLE notification path dominates.
- No disconnections occurred at 7 m through a wall across 500 consecutive
  commands, demonstrating excellent BLE connection stability for the application.

---

## Conditions tested

| Condition | Description |
|-----------|-------------|
| `0.5m_los` | RPi on desk. Laptop 0.5 m away, direct line of sight, no obstacles. |
| `1m_los`   | RPi on desk. Laptop 1 m away, direct line of sight, no obstacles. |
| `2m_los`   | RPi on desk. Laptop 2 m away, direct line of sight, no obstacles. |
| `4m_los`   | RPi on desk. Laptop 4 m away, direct line of sight, no obstacles. |
| `7m_wall`  | RPi in one room. Laptop 7 m away in adjacent room, one standard interior wall between devices. |

## Output files

| File | Contents |
|------|----------|
| `<condition>/raw.csv` | Per-trial reconnect rows: trial_id, scan/connect/write/ack/total ms, success, failure_reason |
| `<condition>/summary.json` | Per-stage statistics and success rates (reconnect mode) |
| `<condition>/condition.json` | Condition metadata |
| `<condition>/steady_raw.csv` | Per-trial persistent-connection rows: write/ack/total ms, success, failure_reason |
| `<condition>/steady_summary.json` | Persistent-session statistics including one-time setup latencies |
| `all_conditions_summary.json` | Cross-condition aggregate (reconnect mode) |
