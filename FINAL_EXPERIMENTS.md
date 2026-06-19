# CipherChannel — Final Experiment Instructions

These experiments close the reviewer gaps for the paper.
Run them in order. Only the adversarial test requires no hardware.

---

## Prerequisites

### Laptop (Fedora / x86_64)

```bash
cd experiment_ble
bash config.sh --client          # creates client/.venv with bleak + pycryptodome
```

### RPi (aarch64)

```bash
cd experiment_ble
bash config.sh --server          # creates server/.venv with bless + pycryptodome
```

### ESP32

Flash the sketch from `experiment_ble/awake-esp32/esp32/` using Arduino IDE or
Arduino CLI (see [E. ESP32 footprint](#e-esp32-resource-footprint) below).

---

## A. Adversarial / Restart Validation (no hardware needed)

Runs 13 deterministic security tests against the local Python CipherChannel.
Produces CSV and JSON for the paper's adversarial-validation table.

```bash
# From experiment_ble/ on any machine:
cd experiment_ble
python3 final_restart_adversarial.py
# or with explicit output dir:
python3 final_restart_adversarial.py --output-dir results/final
```

Expected: **13/13 PASS**.

Output:

- `results/final/raw/final_restart_adversarial.csv`
- `results/final/summary/final_restart_adversarial_summary.json`

---

## B. MTU / Long-Write Confirmation (laptop + RPi)

Confirms that BlueZ/Bleak handles encrypted frames larger than the 20-byte
default ATT MTU payload transparently.

### 1. Start the server on the RPi

```bash
# On RPi:
cd experiment_ble/server
.venv/bin/python ble_server.py
```

### 2. Run the MTU check from the laptop

```bash
# On laptop:
cd experiment_ble
python3 final_mtu_check.py --address <RPi-BLE-MAC>
# e.g.:
python3 final_mtu_check.py --address B8:27:EB:07:01:22
```

Output:

- `results/final/raw/final_mtu_check.csv`
- `results/final/summary/final_mtu_check_summary.json`

---

## C. Concurrent Endpoint Validation (laptop + RPi + ESP32 cane)

Validates that the gateway maintains separate CipherChannel contexts for the
supervisory laptop client and the ESP32 cane controller.

The **laptop is used in place of the Android phone** because it gives
deterministic timing and logging; the CipherChannel packet format is identical.

### 1. Start the server on the RPi

```bash
# On RPi:
cd experiment_ble/server
.venv/bin/python ble_server.py
```

### 2. Run the concurrent test from the laptop

```bash
# On laptop:
cd experiment_ble

# With manual cane trigger (default):
python3 final_concurrent_endpoints.py --address <RPi-BLE-MAC> --trials 20

# Without cane (laptop-only, counter isolation only):
python3 final_concurrent_endpoints.py --address <RPi-BLE-MAC> --trials 20 --cane-mode skip
```

The script will pause and ask you to press the ESP32 cane button during the
experiment window. After the window, enter the number of cane presses when
prompted.

Manual steps for cane counter isolation:

1. Check the RPi server log for `trial_id` entries from the cane.
2. Verify that cane trial_ids and laptop trial_ids interleave without error.
3. Note that the server's `_channel` object is the laptop session channel;
   the cane operates on a separate NVS-persisted channel in the ESP32 firmware.

Output:

- `results/final/raw/final_concurrent_endpoints.csv`
- `results/final/summary/final_concurrent_endpoints_summary.json`

---

## D. Existing Steady-State Experiment (already run)

The 500/500 steady-state command results are already in:

- `client/results/server_cold_start.csv`
- `client/results/client_cold_start.csv`

No re-run needed unless the protocol changed.

---

## E. Generate Paper Tables

After running the experiments, aggregate all summaries into markdown tables:

```bash
cd experiment_ble
python3 final_summarize.py
```

Output: `results/final/summary/final_experiment_tables.md`

Copy the relevant table sections into the LaTeX paper.

---

## Notes

- All scripts are idempotent — re-running overwrites previous output files.
- The Fedora laptop substitutes for the Android phone throughout all BLE
  experiments. The CipherChannel packet format is byte-identical.
- BLE MAC addresses can be found with: `bluetoothctl scan on` then look for `AWAKE-EXP`.
- If BlueZ complains about BR/EDR: `bluetoothctl remove <address>` before each run.
