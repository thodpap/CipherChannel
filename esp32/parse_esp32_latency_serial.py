#!/usr/bin/env python3
"""Parse ESP32 latency serial logs and print summary statistics.

Usage:
    python3 parse_esp32_latency_serial.py serial.log
"""
import csv
import statistics
import sys
from pathlib import Path


def pct(values, q):
    if not values:
        return None
    values = sorted(values)
    idx = round((len(values) - 1) * q)
    return values[idx]


def ms(us):
    return us / 1000.0


def main(path: str) -> None:
    trials = []
    conns = []
    kex = []

    for raw in Path(path).read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line.startswith("CSV_"):
            continue
        row = next(csv.reader([line]))
        kind = row[0]
        if kind == "CSV_TRIAL" and row[1] != "trial_id":
            trials.append({
                "trial_id": int(row[1]),
                "payload_len": int(row[2]),
                "ciphertext_len": int(row[3]),
                "cc_send_us": int(row[4]),
                "ble_write_us": int(row[5]),
                "rtt_us": int(row[6]),
                "ack_received": int(row[7]),
            })
        elif kind == "CSV_CONN" and row[1] != "client_create_us":
            conns.append([int(x) for x in row[1:]])
        elif kind == "CSV_KEX" and row[1] != "cc_send_us":
            kex.append([int(x) for x in row[1:]])

    ok = [t for t in trials if t["ack_received"] == 1]
    rtt_ms = [ms(t["rtt_us"]) for t in ok]
    cc_ms = [ms(t["cc_send_us"]) for t in ok]
    wr_ms = [ms(t["ble_write_us"]) for t in ok]

    print(f"trials_total={len(trials)}")
    print(f"trials_ack={len(ok)}")
    print(f"trials_timeout={len(trials) - len(ok)}")

    if rtt_ms:
        print(f"rtt_ms_median={statistics.median(rtt_ms):.3f}")
        print(f"rtt_ms_p95={pct(rtt_ms, 0.95):.3f}")
        print(f"rtt_ms_p99={pct(rtt_ms, 0.99):.3f}")
        print(f"rtt_ms_max={max(rtt_ms):.3f}")
        print(f"cc_send_ms_median={statistics.median(cc_ms):.3f}")
        print(f"ble_write_ms_median={statistics.median(wr_ms):.3f}")

    if conns:
        successful = [c for c in conns if c[-1] == 1]
        print(f"conn_attempts={len(conns)}")
        print(f"conn_success={len(successful)}")
        if successful:
            total_ms = [ms(c[-2]) for c in successful]
            print(f"conn_total_ms_median={statistics.median(total_ms):.3f}")
            print(f"conn_total_ms_max={max(total_ms):.3f}")

    if kex:
        successful = [x for x in kex if x[-2] == 1]
        print(f"kex_attempts={len(kex)}")
        print(f"kex_success={len(successful)}")
        if successful:
            total_ms = [ms(x[3]) for x in successful]
            print(f"kex_total_ms_median={statistics.median(total_ms):.3f}")
            print(f"kex_total_ms_max={max(total_ms):.3f}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 parse_esp32_latency_serial.py serial.log")
    main(sys.argv[1])
