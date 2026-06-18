#!/usr/bin/env python3
"""
Summarize all completed Experiment J conditions into a single cross-condition table.

Run after completing all conditions:
  client/.venv/bin/python results/canonical/distance/summarize_J.py

Reads:  results/canonical/distance/<condition>/summary.json  (all conditions)
Writes: results/canonical/distance/all_conditions_summary.json
"""

import json
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

# Canonical order for the cross-condition table
_CONDITION_ORDER = [
    '0.5m_los', '1m_los', '2m_los', '3m_los',
    '4m_wall', '6m_2wall', '7m_wall',
]


def main() -> None:
    conditions: list[dict] = []

    # Collect all conditions that have a summary.json
    found_dirs = []
    for name in os.listdir(_THIS_DIR):
        d = os.path.join(_THIS_DIR, name)
        if os.path.isdir(d) and os.path.exists(os.path.join(d, 'summary.json')):
            found_dirs.append(name)

    # Sort by canonical order first, then alphabetically for any extras
    def _sort_key(name):
        try:
            return (_CONDITION_ORDER.index(name), name)
        except ValueError:
            return (len(_CONDITION_ORDER), name)
    found_dirs.sort(key=_sort_key)

    if not found_dirs:
        sys.exit("No condition summaries found. Run run_J.py for at least one condition first.")

    print(f"\nExperiment J — Cross-condition summary")
    print(f"{'─' * 100}")
    hdr = (f"  {'Condition':<12} {'N':>5} {'Total%':>8}"
           f" {'Scan%':>7} {'Conn%':>7} {'KEX%':>7} {'Write%':>7} {'ACK%':>7}"
           f"  {'med_tot':>8}  {'p95_tot':>8}  (ms)")
    print(hdr)
    print(f"  {'─' * 96}")

    for name in found_dirs:
        path = os.path.join(_THIS_DIR, name, 'summary.json')
        with open(path) as f:
            s = json.load(f)

        stages   = s.get('stages', {})
        n        = s.get('n_trials', 0)
        tot_rate = s.get('success_rate', '?')

        def _rate(stage):
            st = stages.get(stage, {})
            att = st.get('attempted', 0)
            ok  = st.get('success', 0)
            return f'{100*ok/att:.0f}%' if att else 'N/A'

        def _ms(stage, key):
            lat = stages.get(stage, {}).get('latency_ms')
            if not lat:
                return 'N/A'
            v = lat.get(key)
            return f'{v:.0f}' if v is not None else 'N/A'

        row = (f"  {name:<12} {n:>5} {tot_rate:>8}"
               f" {_rate('scan'):>7} {_rate('connect'):>7}"
               f" {_rate('kex'):>7} {_rate('write'):>7} {_rate('ack'):>7}"
               f"  {_ms('total','median'):>8}  {_ms('total','p95'):>8}")
        print(row)
        conditions.append(s)

    # Write combined JSON
    out_path = os.path.join(_THIS_DIR, 'all_conditions_summary.json')
    with open(out_path, 'w') as f:
        json.dump({
            'n_conditions': len(conditions),
            'conditions':   conditions,
        }, f, indent=2)

    print(f"\nSummary → {out_path}")


if __name__ == '__main__':
    main()
