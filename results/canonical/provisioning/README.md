# Provisioning Gate Tests

## Purpose
Verify the ProvisioningGate (physical-presence gated, PROTOCOL.md §10) and
BenchmarkProvisioningGate state machines.

## Run command
```
python3.14 results/canonical/provisioning/run_provisioning.py
```

## Coverage
| ID | Description |
|----|-------------|
| P01-P02 | Closed gate rejects both endpoints |
| P03-P06 | Active window: correct endpoint allowed, wrong rejected, one-shot, auto-close |
| P07 | Expired window (duration_s=0) rejects provision |
| P08-P11 | is_open property: default, after open, after close, after timeout |
| P12-P15 | close() simulates disconnect / STOP_SHARING / shutdown / no-op on closed |
| P16-P17 | Re-open after provision; separate phone/cane gates are independent |
| P18 | Thread safety: exactly one win under 20 concurrent try_provision calls |
| P19 | REQUEST_KEY while CLOSED → False (no key material returned) |
| B01-B06 | BenchmarkProvisioningGate: always-allow, multi-call, open/close no-ops |

## Result (canonical run, commit 4d67c96)
**28/28 PASS** — elapsed 42.2 ms

## Hardware limitation
GPIO-triggered provisioning (actual physical button press on RPi) is not testable
on this host. The ProvisioningGate state machine is fully tested in isolation;
the GPIO integration is verified separately on the Raspberry Pi.
