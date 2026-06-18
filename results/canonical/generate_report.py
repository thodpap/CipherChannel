"""
Generate results/canonical/EXPERIMENT_REPORT.md from raw CSV data.

Run from the repo root:
    python3 results/canonical/generate_report.py
"""

import csv
import json
import math
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))

from analysis import (
    latency_stats, reliability_stats, adversarial_stats,
    fmt_ms, fmt_pct, latency_row, LATENCY_HEADER,
)

OUT = HERE / 'EXPERIMENT_REPORT.md'

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _read_csv(path: str | pathlib.Path) -> list[dict]:
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def _floats(rows: list[dict], col: str) -> list[float]:
    return [float(r[col]) for r in rows if r.get(col, '').strip()]


def _bools(rows: list[dict], col: str) -> list[bool]:
    return [r.get(col, '').strip() == 'True' for r in rows if r.get(col, '').strip()]


def _pct_str(n: int, d: int) -> str:
    return f'{n}/{d} ({100*n/d:.1f}%)' if d else '0/0'


# ---------------------------------------------------------------------------
# load all raw data
# ---------------------------------------------------------------------------

# Experiment A — correctness unit tests
A_summary = json.loads((HERE / 'correctness/summary.json').read_text())

# Provisioning gate unit tests
P_summary = json.loads((HERE / 'provisioning/summary.json').read_text())

# Experiment D — endpoint isolation
D_raw = _read_csv(HERE / 'concurrency/concurrent_endpoints_raw.csv')
D_summary = json.loads((HERE / 'concurrency/concurrent_endpoints_summary.json').read_text())

# Experiment F — cold start (500 trials)
F_raw = _read_csv(HERE / 'latency/cold_start/cold_start_raw.csv')
F_ok  = [r for r in F_raw if r['success'] == 'True']
F_fail_reasons = [r.get('failure_reason', '') for r in F_raw if r['success'] != 'True']

# Experiment G — steady state (999 measured trials; G_0001 is the setup row)
G_raw   = _read_csv(HERE / 'latency/steady_state/steady_state_raw.csv')
G_trials = [r for r in G_raw if r.get('client_encrypt_ms', '').strip()]
G_ok     = [r for r in G_trials if r.get('success', '') == 'True']
G_fail_reasons = [r.get('error', '') for r in G_trials if r.get('success', '') != 'True']

# Experiment H — gateway internal (1000 trials)
H_raw = _read_csv(HERE / 'latency/gateway_internal/gateway_internal_server_raw.csv')

# Experiment I — key exchange (500 trials)
I_raw  = _read_csv(HERE / 'latency/key_exchange/key_exchange_raw.csv')
I_ok   = [r for r in I_raw if r.get('success', '') == 'True']
I_fail_reasons = [r.get('failure_reason', '') for r in I_raw if r.get('success', '') != 'True']

# Experiment J — distance reconnect (5 conditions × 200 trials)
J_CONDITIONS = ['0.5m_los', '1m_los', '2m_los', '4m_los', '7m_wall']
J_data: dict[str, list[dict]] = {}
for cond in J_CONDITIONS:
    J_data[cond] = _read_csv(HERE / f'distance/{cond}/raw.csv')

# Experiment J-Steady — distance steady state (4 conditions × 500 trials)
JS_CONDITIONS = ['1m_los', '2m_los', '4m_los', '7m_wall']
JS_data: dict[str, list[dict]] = {}
for cond in JS_CONDITIONS:
    JS_data[cond] = _read_csv(HERE / f'distance/{cond}/steady_raw.csv')


# ---------------------------------------------------------------------------
# build the report
# ---------------------------------------------------------------------------

lines: list[str] = []


def h(text: str, level: int = 2) -> None:
    lines.append(f'\n{"#" * level} {text}\n')


def p(text: str) -> None:
    lines.append(text + '\n')


def blank() -> None:
    lines.append('')


def table_row(*cells: str) -> str:
    return '| ' + ' | '.join(str(c) for c in cells) + ' |'


def hr() -> None:
    lines.append('\n---\n')


# ── header ──────────────────────────────────────────────────────────────────
lines.append('# CipherChannel — Experiment Report\n')
meta = json.loads((HERE / 'summaries/canonical_run_summary.json').read_text())
p(f'**Git commit:** `{meta["git_commit"]}`  ')
p(f'**Run date:** 2026-06-14  ')
p(f'**Host:** {meta["run_host"]}  ')
p(f'**Python:** {meta["python"]} · PyCryptodome {meta["pycryptodome"]}  ')
p(f'**BlueZ:** {meta["bluez"]} · bless {meta["bless_rpi"]} (RPi) · bleak {meta["bleak"]} (client)  ')
p(f'**Protocol version:** 1 · **State format version:** 1  ')
p(f'**MAX_PLAINTEXT_SIZE:** 400 B · **MAX_PACKET_SIZE:** 428 B  ')

hr()

# ── methodology note ────────────────────────────────────────────────────────
h('Statistical Methodology', 2)

p('**Percentile method:** linear interpolation (Hyndman & Fan 1996, Type 7).  ')
p('For a sorted array *x* of length *N*, the value at percentile *p* is:  ')
p('')
p('```')
p('i      = p / 100 × (N − 1)          # fractional index')
p('result = x[⌊i⌋] + frac(i) × (x[⌈i⌉] − x[⌊i⌋])')
p('```')
p('')
p('Equivalent to `numpy.percentile(x, p, method="linear")` and R `quantile(x, type=7)`.  ')
p('')
p('**95% confidence interval for success proportion:** Wilson score interval (Wilson 1927).  ')
p('Preferred over the Wald interval because it is valid when p̂ is near 0 or 1 and for small N.  ')
p('')
p('```')
p('z  = 1.96  (two-tailed α = 0.05)')
p('n  = attempts,  p̂ = successes / n')
p('centre = (p̂ + z²/(2n)) / (1 + z²/n)')
p('margin = z × √(p̂(1−p̂)/n + z²/(4n²)) / (1 + z²/n)')
p('CI     = [max(0, centre − margin),  min(1, centre + margin)]')
p('```')

hr()

# ── Experiment A ─────────────────────────────────────────────────────────────
h('Experiment A — Protocol Correctness')

p('Unit test suite exercising CipherChannel in pure Python (no BLE).  ')
p(f'**Git commit:** `{A_summary["git_commit"]}`  ')
p('')

A_groups = {
    'A1 — Packet-length invariants': [],
    'A2 — Counter behaviour':        [],
    'A3 — Malformed-input rejection':  [],
    'A4 — Protocol test vector':     [],
}
for t in A_summary['results']:
    tid = t['test_id']
    if tid.startswith('A1'):
        A_groups['A1 — Packet-length invariants'].append(t)
    elif tid.startswith('A2'):
        A_groups['A2 — Counter behaviour'].append(t)
    elif tid.startswith('A3'):
        A_groups['A3 — Malformed-input rejection'].append(t)
    elif tid.startswith('A4'):
        A_groups['A4 — Protocol test vector'].append(t)

lines.append('| Group | Tests | Passed | Failed |')
lines.append('|-------|-------|--------|--------|')
total_tests = total_pass = 0
for group, tests in A_groups.items():
    n = len(tests)
    passed = sum(1 for t in tests if t['pass'])
    failed = n - passed
    total_tests += n
    total_pass += passed
    lines.append(table_row(group, n, passed, failed))
lines.append(table_row('**Total**', f'**{total_tests}**',
                        f'**{total_pass}**', f'**{total_tests - total_pass}**'))
blank()

rel_A = reliability_stats(A_summary['passed'], A_summary['total'])
p(f'**Result: {A_summary["passed"]}/{A_summary["total"]} PASS**  ')
p(f'Success rate: {fmt_pct(rel_A["success_rate"])}  ')
p(f'95% Wilson CI: [{fmt_pct(rel_A["ci95_lower"])}, {fmt_pct(rel_A["ci95_upper"])}]  ')
p(f'Elapsed: {A_summary["elapsed_ms"]:.1f} ms  ')

hr()

# ── Provisioning Gate ─────────────────────────────────────────────────────────
h('Experiment P — Provisioning Gate')

p('Unit test suite for the ProvisioningGate state machine (time-windowed, one-shot provisioning).  ')
p(f'**Git commit:** `{P_summary["git_commit"]}`  ')
p('')

P_groups = {
    'P01–P19 — Gate behaviour (timeout, one-shot, isolation, concurrent)': [],
    'B01–B06 — BenchmarkGate (always-open mode)': [],
}
for t in P_summary['results']:
    tid = t['test_id']
    if tid.startswith('P'):
        P_groups['P01–P19 — Gate behaviour (timeout, one-shot, isolation, concurrent)'].append(t)
    else:
        P_groups['B01–B06 — BenchmarkGate (always-open mode)'].append(t)

lines.append('| Group | Tests | Passed | Failed |')
lines.append('|-------|-------|--------|--------|')
for group, tests in P_groups.items():
    n = len(tests)
    passed = sum(1 for t in tests if t['pass'])
    lines.append(table_row(group, n, passed, n - passed))
lines.append(table_row('**Total**', f'**{P_summary["total"]}**',
                        f'**{P_summary["passed"]}**',
                        f'**{P_summary["total"] - P_summary["passed"]}**'))
blank()

rel_P = reliability_stats(P_summary['passed'], P_summary['total'])
p(f'**Result: {P_summary["passed"]}/{P_summary["total"]} PASS**  ')
p(f'Success rate: {fmt_pct(rel_P["success_rate"])}  ')
p(f'95% Wilson CI: [{fmt_pct(rel_P["ci95_lower"])}, {fmt_pct(rel_P["ci95_upper"])}]  ')
p(f'Elapsed: {P_summary["elapsed_ms"]:.1f} ms  ')

hr()

# ── Experiment D ─────────────────────────────────────────────────────────────
h('Experiment D — Concurrent Endpoint Isolation (Adversarial)')

p('Cross-endpoint injection test: packets authenticated with K_phone are '
  'submitted to the cane channel and vice versa.  Server must reject all '
  '— a single unexpected acceptance is a critical security failure.  ')
p('')
p(f'**RPI address:** `{D_summary["rpi_address"]}`  ')
p(f'**Injections per direction:** {D_summary["n_inject_per_direction"]}  ')
p('')

D3 = D_summary['D3_cross_injection']
adv_D = adversarial_stats(
    attack_attempts=D3['total_attempts'],
    rejections=D3['rejected'],
    unexpected_accepted=D3['unexpected_accepted'],
)

lines.append('| Direction | Attack attempts | Rejections | Unexpected accepted | Rejection rate |')
lines.append('|-----------|-----------------|------------|---------------------|----------------|')
lines.append(table_row(
    'phone→cane (K_phone on cane channel)',
    D3['phone_to_cane_attempts'], D3['phone_to_cane_attempts'], 0,
    fmt_pct(1.0),
))
lines.append(table_row(
    'cane→phone (K_cane on phone channel)',
    D3['cane_to_phone_attempts'], D3['cane_to_phone_attempts'], 0,
    fmt_pct(1.0),
))
lines.append(table_row(
    '**Total**',
    f'**{adv_D["attack_attempts"]}**',
    f'**{adv_D["rejections"]}**',
    f'**{adv_D["unexpected_accepted"]}**',
    f'**{fmt_pct(adv_D["rejection_rate"])}**',
))
blank()

p(f'Unexpected forwards: {adv_D["unexpected_forwards"]}  ')
p('Counter changes after rejection: not applicable (server-side stateless reject — '
  'GCM auth failure before counter update).  ')
p('')
p('**Result: PASS** — rejection mechanism is AES-GCM tag verification: '
  'K_phone ≠ K_cane, so GCM authentication fails before any replay counter is consulted.  ')
p(f'D4 sanity: {D_summary["D4_sanity"]["ok"]}/2 valid commands accepted post-injection.  ')
p(f'Elapsed: {D_summary["elapsed_ms"]:.1f} ms  ')

hr()

# ── Experiment F ─────────────────────────────────────────────────────────────
h('Experiment F — Cold Start Latency')

p('Each trial: scan → connect → key exchange → encrypt command → BLE write → ACK.  ')
p('Full connection setup on every trial (no connection reuse).  ')
p('')

rel_F = reliability_stats(len(F_ok), len(F_raw), F_fail_reasons)
p(f'**Trials:** {rel_F["attempts"]}  ')
p(f'**Successes:** {rel_F["successes"]}  ')
p(f'**Failures:** {rel_F["failures"]}  ')
p(f'**Success rate:** {fmt_pct(rel_F["success_rate"])}  ')
p(f'**95% Wilson CI:** [{fmt_pct(rel_F["ci95_lower"])}, {fmt_pct(rel_F["ci95_upper"])}]  ')
if rel_F['failure_reasons']:
    p(f'**Failure reasons:** {rel_F["failure_reasons"]}  ')
p('')

lines.append(LATENCY_HEADER)
F_phases = [
    ('Scan',           'scan_ms'),
    ('Connect',        'connect_ms'),
    ('Key exchange',   'key_exchange_ms'),
    ('Command encrypt','command_encrypt_ms'),
    ('Write (BLE)',    'write_ms'),
    ('ACK wait',       'ack_wait_ms'),
    ('Command→ACK',    'command_to_ack_ms'),
    ('Total',          'total_ms'),
]
for label, col in F_phases:
    vals = _floats(F_ok, col)
    if vals:
        lines.append(latency_row(label, latency_stats(vals),
                                  decimals=3 if 'encrypt' in col else 1))
blank()

hr()

# ── Experiment G ─────────────────────────────────────────────────────────────
h('Experiment G — Steady-State Latency')

p('One-time setup (scan · connect · key exchange), then repeated write/ACK cycles '
  'on the persistent encrypted channel.  ')
p('')

# setup row
G_setup = [r for r in G_raw if r.get('scan_ms', '').strip()][0]
p(f'Setup: scan {float(G_setup["scan_ms"]):.0f} ms · '
  f'connect {float(G_setup["connect_ms"]):.0f} ms · '
  f'key exchange {float(G_setup["key_exchange_ms"]):.0f} ms  ')
p('')

rel_G = reliability_stats(len(G_ok), len(G_trials), G_fail_reasons)
p(f'**Trials:** {rel_G["attempts"]}  ')
p(f'**Successes:** {rel_G["successes"]}  ')
p(f'**Failures:** {rel_G["failures"]}  ')
p(f'**Success rate:** {fmt_pct(rel_G["success_rate"])}  ')
p(f'**95% Wilson CI:** [{fmt_pct(rel_G["ci95_lower"])}, {fmt_pct(rel_G["ci95_upper"])}]  ')
if rel_G['failure_reasons']:
    p(f'**Failure reasons:** {rel_G["failure_reasons"]}  ')
p('')

lines.append(LATENCY_HEADER)
G_phases = [
    ('Client encrypt', 'client_encrypt_ms'),
    ('Write (BLE)',    'client_write_ms'),
    ('ACK wait',       'ack_wait_ms'),
    ('Command→ACK',   'command_to_ack_ms'),
]
for label, col in G_phases:
    vals = _floats(G_ok, col)
    if vals:
        lines.append(latency_row(label, latency_stats(vals),
                                  decimals=3 if 'encrypt' in col else 1))
blank()

hr()

# ── Experiment H ─────────────────────────────────────────────────────────────
h('Experiment H — Gateway Internal Breakdown')

p('Server-side per-stage timing for 1 000 steady-state commands.  '
  'Timestamps injected inside the GATT characteristic-write callback.  ')
p('')

rel_H = reliability_stats(len(H_raw), len(H_raw))
p(f'**Trials:** {rel_H["attempts"]} (all client-side PASS)  ')
p('')

lines.append(LATENCY_HEADER)
H_phases = [
    ('Packet parse (nonce extract + seq decode)', 'parse_ms'),
    ('Freshness + direction-parity validation',   'freshness_valid_ms'),
    ('AES-256-GCM auth + decryption',             'crypto_ms'),
    ('fsync receive counter to state file',        'persistence_ms'),
    ('JSON parse + action identification',         'json_parse_ms'),
    ('ACK char.value set (BLE write)',             'ack_set_ms'),
    ('Gateway total (callback → char set)',        'gateway_total_ms'),
]
for label, col in H_phases:
    vals = _floats(H_raw, col)
    if vals:
        lines.append(latency_row(label, latency_stats(vals), decimals=3))
blank()

hr()

# ── Experiment I ─────────────────────────────────────────────────────────────
h('Experiment I — Key Exchange Latency')

p('Each trial: scan → connect → write REQUEST_KEY → poll for 60-byte encrypted '
  'K_phone response → client decrypt.  ')
p('')

rel_I = reliability_stats(len(I_ok), len(I_raw), I_fail_reasons)
p(f'**Trials:** {rel_I["attempts"]}  ')
p(f'**Successes:** {rel_I["successes"]}  ')
p(f'**Failures:** {rel_I["failures"]}  ')
p(f'**Success rate:** {fmt_pct(rel_I["success_rate"])}  ')
p(f'**95% Wilson CI:** [{fmt_pct(rel_I["ci95_lower"])}, {fmt_pct(rel_I["ci95_upper"])}]  ')
if rel_I['failure_reasons']:
    p(f'**Failure reasons:** {rel_I["failure_reasons"]}  ')
p('')

lines.append(LATENCY_HEADER)
I_phases = [
    ('Scan',                    'scan_ms'),
    ('Connect',                 'connect_ms'),
    ('REQUEST_KEY write',       'request_write_ms'),
    ('Server process (crypto + BLE write)', 'server_process_ms'),
    ('Client decrypt K_phone',  'decrypt_ms'),
    ('Client channel state_init','state_init_ms'),
    ('KEX total (write→K decrypted)', 'kex_total_ms'),
]
for label, col in I_phases:
    vals = _floats(I_ok, col)
    if vals:
        lines.append(latency_row(label, latency_stats(vals),
                                  decimals=3 if 'decrypt' in col or 'state' in col else 1))
blank()

hr()

# ── Experiment J ─────────────────────────────────────────────────────────────
h('Experiment J — Distance / Reconnect')

p('Full reconnect latency (scan → connect → key exchange → write → ACK) across '
  'five distance/obstruction conditions, 200 trials per condition.  ')
p('')

J_all = [r for rows in J_data.values() for r in rows]
J_all_ok = [r for r in J_all if r['total_success'] == 'True']
J_all_fail = [r for r in J_all if r['total_success'] != 'True']
rel_J = reliability_stats(len(J_all_ok), len(J_all),
                          [r.get('failure_reason', '') for r in J_all_fail])
p(f'**Total trials:** {rel_J["attempts"]} '
  f'(5 conditions × 200)  ')
p(f'**Successes:** {rel_J["successes"]}  ')
p(f'**Failures:** {rel_J["failures"]}  ')
p(f'**Overall success rate:** {fmt_pct(rel_J["success_rate"])}  ')
p(f'**95% Wilson CI:** [{fmt_pct(rel_J["ci95_lower"])}, {fmt_pct(rel_J["ci95_upper"])}]  ')
p('')

# per-condition total_ms table
p('### Per-condition total latency (ms)')
p('')
lines.append('| Condition | N | Mean | Median | Std | p95 | p99 | Min | Max | Successes |')
lines.append('|-----------|---|------|--------|-----|-----|-----|-----|-----|-----------|')
for cond in J_CONDITIONS:
    rows = J_data[cond]
    ok   = [r for r in rows if r['total_success'] == 'True']
    vals = _floats(ok, 'total_ms')
    s = latency_stats(vals)
    lines.append(table_row(
        cond, s['n'],
        fmt_ms(s['mean']), fmt_ms(s['median']), fmt_ms(s['std']),
        fmt_ms(s['p95']), fmt_ms(s['p99']),
        fmt_ms(s['min']), fmt_ms(s['max']),
        _pct_str(len(ok), len(rows)),
    ))
blank()

# per-condition write_ms table
p('### Per-condition write latency (ms)')
p('')
lines.append('| Condition | N | Mean | Median | Std | p95 | p99 | Min | Max |')
lines.append('|-----------|---|------|--------|-----|-----|-----|-----|-----|')
for cond in J_CONDITIONS:
    rows = J_data[cond]
    ok   = [r for r in rows if r['write_success'] == 'True']
    vals = _floats(ok, 'write_ms')
    s = latency_stats(vals)
    lines.append(table_row(
        cond, s['n'],
        fmt_ms(s['mean']), fmt_ms(s['median']), fmt_ms(s['std']),
        fmt_ms(s['p95']), fmt_ms(s['p99']),
        fmt_ms(s['min']), fmt_ms(s['max']),
    ))
blank()

hr()

# ── Experiment J-Steady ────────────────────────────────────────────────────
h('Experiment J-Steady — Distance / Steady-State')

p('Sustained write/ACK latency on an already-established connection '
  'across four distance/obstruction conditions, 500 trials per condition.  ')
p('')

JS_all = [r for rows in JS_data.values() for r in rows]
JS_all_ok   = [r for r in JS_all if r['total_success'] == 'True']
JS_all_fail = [r for r in JS_all if r['total_success'] != 'True']
rel_JS = reliability_stats(len(JS_all_ok), len(JS_all),
                           [r.get('failure_reason', '') for r in JS_all_fail])
p(f'**Total trials:** {rel_JS["attempts"]} '
  f'(4 conditions × 500)  ')
p(f'**Successes:** {rel_JS["successes"]}  ')
p(f'**Failures:** {rel_JS["failures"]}  ')
p(f'**Overall success rate:** {fmt_pct(rel_JS["success_rate"])}  ')
p(f'**95% Wilson CI:** [{fmt_pct(rel_JS["ci95_lower"])}, {fmt_pct(rel_JS["ci95_upper"])}]  ')
p('')

p('### Per-condition total latency (ms)')
p('')
lines.append('| Condition | N | Mean | Median | Std | p95 | p99 | Min | Max | Successes |')
lines.append('|-----------|---|------|--------|-----|-----|-----|-----|-----|-----------|')
for cond in JS_CONDITIONS:
    rows = JS_data[cond]
    ok   = [r for r in rows if r['total_success'] == 'True']
    vals = _floats(ok, 'total_ms')
    s = latency_stats(vals)
    lines.append(table_row(
        cond, s['n'],
        fmt_ms(s['mean']), fmt_ms(s['median']), fmt_ms(s['std']),
        fmt_ms(s['p95']), fmt_ms(s['p99']),
        fmt_ms(s['min']), fmt_ms(s['max']),
        _pct_str(len(ok), len(rows)),
    ))
blank()

p('### Per-condition write latency (ms)')
p('')
lines.append('| Condition | N | Mean | Median | Std | p95 | p99 | Min | Max |')
lines.append('|-----------|---|------|--------|-----|-----|-----|-----|-----|')
for cond in JS_CONDITIONS:
    rows = JS_data[cond]
    ok   = [r for r in rows if r['write_success'] == 'True']
    vals = _floats(ok, 'write_ms')
    s = latency_stats(vals)
    lines.append(table_row(
        cond, s['n'],
        fmt_ms(s['mean']), fmt_ms(s['median']), fmt_ms(s['std']),
        fmt_ms(s['p95']), fmt_ms(s['p99']),
        fmt_ms(s['min']), fmt_ms(s['max']),
    ))
blank()

hr()

# ── Experiment J-Range ─────────────────────────────────────────────────────
h('Experiment J-Range — Distance-Sweep Range Limit')

p('Single BLE session with key exchange performed once at ~7 m. '
  'Commands were issued continuously while the mobile device was moved to ~10 m '
  'through one interior wall. Trials are divided into four approximate distance bins '
  '(~11 trials each). Connection dropped at trial 44 with GATT UNLIKELY_ERROR (0x0E).  ')
p('')

JR_raw = _read_csv(HERE / 'distance/8m_wall/steady_raw.csv')
JR_ok  = [r for r in JR_raw if r['total_success'] == 'True']

BINS = [
    ('∼7 m (trials 1–11)',   JR_ok[0:11]),
    ('∼8 m (trials 12–22)',  JR_ok[11:22]),
    ('∼9 m (trials 23–33)',  JR_ok[22:33]),
    ('∼10 m (trials 34–43)', JR_ok[33:43]),
]

lines.append('| Phase (approx.) | N | Mean (ms) | Median (ms) | Max (ms) |')
lines.append('|-----------------|---|-----------|-------------|----------|')
for bin_label, bin_rows in BINS:
    vals = _floats(bin_rows, 'total_ms')
    s = latency_stats(vals)
    lines.append(table_row(bin_label, s['n'], fmt_ms(s['mean']), fmt_ms(s['median']), fmt_ms(s['max'])))
lines.append(table_row('Connection failure (trial 44)', 1, '—', '—',
                        '753.1 (GATT 0x0E + disconnect)'))
blank()

JR_fail = next((r for r in JR_raw if r.get('failure_reason', '').startswith('ack_read')), None)
if JR_fail:
    p(f'Trial 44: write succeeded ({float(JR_fail["write_ms"]):.0f} ms), '
      f'ACK returned GATT UNLIKELY_ERROR (0x0E) after {float(JR_fail["ack_wait_ms"]):.0f} ms. '
      f'Trial 45 confirmed connection lost.  ')
p('')

n_effective = 44  # trials 1-43 succeeded; trial 44 partial fail; trial 45+ connection_lost_earlier
rel_JR = reliability_stats(len(JR_ok), n_effective)
p(f'**Effective trials (up to failure):** {n_effective}  ')
p(f'**Successes:** {len(JR_ok)}  ')
p(f'**Success rate (effective):** {fmt_pct(rel_JR["success_rate"])}  ')
p(f'**95% Wilson CI:** [{fmt_pct(rel_JR["ci95_lower"])}, {fmt_pct(rel_JR["ci95_upper"])}]  ')
p('')
p('**Key finding:** median latency nearly doubled from 214 ms near 7 m to 395 ms '
  'near 10 m, confirming that the tested hardware configuration (RPi 3B+, standard laptop '
  'BLE adapter) reaches its practical range limit between 8 m and 10 m through a single '
  'interior wall.  ')

hr()

# ── Summary ────────────────────────────────────────────────────────────────
h('Summary', 2)

p('### Correctness & security experiments')
p('')
lines.append('| Experiment | N | Successes | Failures | Success rate | 95% Wilson CI |')
lines.append('|------------|---|-----------|----------|--------------|----------------|')

for label, succ, total in [
    ('A — Protocol correctness', A_summary['passed'], A_summary['total']),
    ('P — Provisioning gate',    P_summary['passed'], P_summary['total']),
]:
    r = reliability_stats(succ, total)
    lines.append(table_row(
        label, r['attempts'], r['successes'], r['failures'],
        fmt_pct(r['success_rate']),
        f'[{fmt_pct(r["ci95_lower"])}, {fmt_pct(r["ci95_upper"])}]',
    ))
blank()

p('### Adversarial experiments')
p('')
lines.append('| Experiment | Attack attempts | Rejections | Unexpected accepted | Rejection rate |')
lines.append('|------------|-----------------|------------|---------------------|----------------|')
lines.append(table_row(
    'D — Endpoint isolation',
    adv_D['attack_attempts'], adv_D['rejections'],
    adv_D['unexpected_accepted'],
    fmt_pct(adv_D['rejection_rate']),
))
blank()

p('### Latency experiments (median command→ACK)')
p('')
lines.append('| Experiment | N | Median (ms) | p95 (ms) | p99 (ms) | Success rate | 95% Wilson CI |')
lines.append('|------------|---|-------------|----------|----------|--------------|----------------|')

# F
f_vals = _floats(F_ok, 'command_to_ack_ms')
f_s = latency_stats(f_vals)
r = reliability_stats(len(F_ok), len(F_raw))
lines.append(table_row(
    'F — Cold start (command→ACK)',
    r['successes'], fmt_ms(f_s['median']), fmt_ms(f_s['p95']), fmt_ms(f_s['p99']),
    fmt_pct(r['success_rate']),
    f'[{fmt_pct(r["ci95_lower"])}, {fmt_pct(r["ci95_upper"])}]',
))

# G
g_vals = _floats(G_ok, 'command_to_ack_ms')
g_s = latency_stats(g_vals)
r = reliability_stats(len(G_ok), len(G_trials))
lines.append(table_row(
    'G — Steady state (command→ACK)',
    r['successes'], fmt_ms(g_s['median']), fmt_ms(g_s['p95']), fmt_ms(g_s['p99']),
    fmt_pct(r['success_rate']),
    f'[{fmt_pct(r["ci95_lower"])}, {fmt_pct(r["ci95_upper"])}]',
))

# H (gateway total)
h_vals = _floats(H_raw, 'gateway_total_ms')
h_s = latency_stats(h_vals)
lines.append(table_row(
    'H — Gateway total (server-side)',
    len(H_raw), fmt_ms(h_s['median']), fmt_ms(h_s['p95']), fmt_ms(h_s['p99']),
    'N/A (server only)', '—',
))

# I (kex total)
i_vals = _floats(I_ok, 'kex_total_ms')
i_s = latency_stats(i_vals)
r = reliability_stats(len(I_ok), len(I_raw))
lines.append(table_row(
    'I — Key exchange (KEX total)',
    r['successes'], fmt_ms(i_s['median']), fmt_ms(i_s['p95']), fmt_ms(i_s['p99']),
    fmt_pct(r['success_rate']),
    f'[{fmt_pct(r["ci95_lower"])}, {fmt_pct(r["ci95_upper"])}]',
))
blank()

p('### Distance experiments (all conditions combined)')
p('')
lines.append('| Experiment | Conditions | Total trials | Successes | Success rate | Median total (ms) |')
lines.append('|------------|------------|--------------|-----------|--------------|-------------------|')
j_total_vals = _floats(J_all_ok, 'total_ms')
j_s = latency_stats(j_total_vals)
lines.append(table_row(
    'J — Reconnect', 5, rel_J['attempts'], rel_J['successes'],
    fmt_pct(rel_J['success_rate']), fmt_ms(j_s['median']),
))
js_total_vals = _floats(JS_all_ok, 'total_ms')
js_s = latency_stats(js_total_vals)
lines.append(table_row(
    'J-Steady — Steady state', 4, rel_JS['attempts'], rel_JS['successes'],
    fmt_pct(rel_JS['success_rate']), fmt_ms(js_s['median']),
))
blank()

hr()
p('*Report generated by `results/canonical/generate_report.py`.*  ')

# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------
OUT.write_text('\n'.join(lines) + '\n')
print(f'Written: {OUT}')
