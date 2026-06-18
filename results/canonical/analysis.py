"""
Shared statistical analysis for CipherChannel canonical experiments.

Percentile method
-----------------
Linear interpolation (equivalent to numpy.percentile with method='linear').
For a sorted array x of length N, the value at percentile p is computed as:

    i = p / 100 * (N - 1)          # fractional index into sorted array
    result = x[floor(i)] + frac(i) * (x[ceil(i)] - x[floor(i)])

This is the "C = 1, alpha = 1" definition (Hyndman & Fan 1996, Type 7),
which is the default in numpy, R (type 7), and scipy.stats.

95% confidence interval for success proportion
-----------------------------------------------
Wilson score interval (Wilson 1927).  Preferred over Wald ("normal
approximation") because it remains valid when p̂ is near 0 or 1 and
for small N.

    z  = 1.96  (two-tailed α = 0.05)
    n  = attempts
    p̂  = successes / n
    centre = (p̂ + z²/(2n)) / (1 + z²/n)
    margin = z * sqrt(p̂(1−p̂)/n + z²/(4n²)) / (1 + z²/n)
    CI = [max(0, centre − margin), min(1, centre + margin)]
"""

import math
import statistics
from typing import Sequence


def _percentile(data: list, p: float) -> float:
    """Linear-interpolation percentile of a pre-sorted list."""
    n = len(data)
    if n == 0:
        return float('nan')
    if n == 1:
        return float(data[0])
    i = p / 100.0 * (n - 1)
    lo = int(math.floor(i))
    hi = int(math.ceil(i))
    if lo == hi:
        return float(data[lo])
    return float(data[lo]) + (i - lo) * (float(data[hi]) - float(data[lo]))


def latency_stats(values: Sequence) -> dict:
    """
    Descriptive statistics for a latency distribution.

    Parameters
    ----------
    values : sequence of numeric (ms or same unit throughout)

    Returns
    -------
    dict with keys: n, mean, median, std, p95, p99, min, max
    All values in the same unit as input.
    """
    v = sorted(float(x) for x in values)
    n = len(v)
    if n == 0:
        return {k: float('nan') for k in
                ('n', 'mean', 'median', 'std', 'p95', 'p99', 'min', 'max')}
    return {
        'n':      n,
        'mean':   statistics.mean(v),
        'median': statistics.median(v),
        'std':    statistics.stdev(v) if n > 1 else 0.0,
        'p95':    _percentile(v, 95),
        'p99':    _percentile(v, 99),
        'min':    v[0],
        'max':    v[-1],
    }


def reliability_stats(successes: int, attempts: int,
                      failure_reasons: list | None = None) -> dict:
    """
    Reliability statistics with Wilson 95% CI for success proportion.

    Parameters
    ----------
    successes       : int
    attempts        : int
    failure_reasons : list of str (may contain empty strings)

    Returns
    -------
    dict with keys:
        attempts, successes, failures,
        success_rate, failure_rate,
        failure_reasons (dict reason -> count),
        ci95_lower, ci95_upper
    """
    failures = attempts - successes
    p_hat = successes / attempts if attempts > 0 else float('nan')

    z = 1.96
    n = attempts
    if n > 0 and not math.isnan(p_hat):
        centre = (p_hat + z * z / (2 * n)) / (1 + z * z / n)
        margin = (z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n))
                  / (1 + z * z / n))
        ci_lo = max(0.0, centre - margin)
        ci_hi = min(1.0, centre + margin)
    else:
        ci_lo = ci_hi = float('nan')

    reason_counts: dict = {}
    for r in (failure_reasons or []):
        if r:
            reason_counts[r] = reason_counts.get(r, 0) + 1

    return {
        'attempts':        attempts,
        'successes':       successes,
        'failures':        failures,
        'success_rate':    p_hat,
        'failure_rate':    (1.0 - p_hat) if not math.isnan(p_hat) else float('nan'),
        'failure_reasons': reason_counts,
        'ci95_lower':      ci_lo,
        'ci95_upper':      ci_hi,
    }


def adversarial_stats(attack_attempts: int,
                      rejections: int,
                      unexpected_accepted: int = 0,
                      unexpected_forwards: int = 0,
                      counter_changes_after_reject: int = 0) -> dict:
    """
    Statistics for adversarial / injection experiments.

    Returns
    -------
    dict with keys:
        attack_attempts, rejections, unexpected_accepted,
        unexpected_forwards, counter_changes_after_reject,
        rejection_rate
    """
    return {
        'attack_attempts':              attack_attempts,
        'rejections':                   rejections,
        'unexpected_accepted':          unexpected_accepted,
        'unexpected_forwards':          unexpected_forwards,
        'counter_changes_after_reject': counter_changes_after_reject,
        'rejection_rate': (rejections / attack_attempts
                           if attack_attempts > 0 else float('nan')),
    }


def fmt_ms(v: float, decimals: int = 1) -> str:
    """Format a millisecond value for table display."""
    if math.isnan(v):
        return 'N/A'
    return f'{v:.{decimals}f}'


def fmt_pct(v: float, decimals: int = 2) -> str:
    """Format a proportion [0,1] as a percentage string."""
    if math.isnan(v):
        return 'N/A'
    return f'{v * 100:.{decimals}f}%'


def latency_row(label: str, stats: dict, decimals: int = 1) -> str:
    """Return a Markdown table row for a latency stats dict."""
    f = fmt_ms
    d = decimals
    return (f'| {label} '
            f'| {stats["n"]} '
            f'| {f(stats["mean"], d)} '
            f'| {f(stats["median"], d)} '
            f'| {f(stats["std"], d)} '
            f'| {f(stats["p95"], d)} '
            f'| {f(stats["p99"], d)} '
            f'| {f(stats["min"], d)} '
            f'| {f(stats["max"], d)} |')


LATENCY_HEADER = (
    '| Phase | N | Mean (ms) | Median (ms) | Std (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) |\n'
    '|-------|---|-----------|-------------|----------|----------|----------|----------|----------|'
)
