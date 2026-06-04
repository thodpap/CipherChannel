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
experiment window.  After the window, enter the number of cane presses when
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

## E. ESP32 Resource Footprint

### Automated (flash + RAM from Arduino CLI)

```bash
# Requires arduino-cli with esp32:esp32 core installed.
cd experiment_ble
bash esp32_footprint.sh
```

To use a different board variant or CLI path:

```bash
BOARD=esp32:esp32:esp32dev ARDUINO_CLI=~/.local/bin/arduino-cli bash esp32_footprint.sh
```

Output:
- `results/final/raw/esp32_build_output.txt`
- `results/final/summary/esp32_footprint_summary.json`

### Manual (stack high-water mark + current)

1. Add `#define CIPHERCHANNEL_FOOTPRINT_EXPERIMENT` to `BLEProtocol.cpp`
   (guard already prepared — uncomment or add to top of file).

2. Flash the sketch and open Serial Monitor at 115200 baud.

3. The firmware will print during setup and after each send/receive:
   ```
   [FOOTPRINT] Stack HWM: XXXX bytes
   [FOOTPRINT] Free heap before encrypt: XXXX
   [FOOTPRINT] Free heap after encrypt:  XXXX
   ```

4. Record the values and fill into `esp32_footprint_summary.json` manually.

5. For current measurement, use a bench power supply with current readout or a
   µCurrent Gold / INA219 module:
   - Idle current: read when ESP32 is connected but not transmitting.
   - TX current: read during BLE write (peak, ~2–10 ms window).

---

## F. Generate Paper Tables

After running the experiments, aggregate all summaries into markdown tables:

```bash
cd experiment_ble
python3 final_summarize.py
```

Output: `results/final/summary/final_experiment_tables.md`

Copy the relevant table sections into the LaTeX paper.

---

## Output Files Summary

| File | Script | Needs hardware? |
|------|--------|-----------------|
| `results/final/raw/final_restart_adversarial.csv` | `final_restart_adversarial.py` | No |
| `results/final/summary/final_restart_adversarial_summary.json` | same | No |
| `results/final/raw/final_mtu_check.csv` | `final_mtu_check.py` | Laptop + RPi |
| `results/final/summary/final_mtu_check_summary.json` | same | Laptop + RPi |
| `results/final/raw/final_concurrent_endpoints.csv` | `final_concurrent_endpoints.py` | Laptop + RPi (+ ESP32) |
| `results/final/summary/final_concurrent_endpoints_summary.json` | same | Laptop + RPi (+ ESP32) |
| `results/final/raw/esp32_build_output.txt` | `esp32_footprint.sh` | arduino-cli |
| `results/final/summary/esp32_footprint_summary.json` | same | arduino-cli |
| `results/final/summary/final_experiment_tables.md` | `final_summarize.py` | No (reads above) |

---

## Notes

- All scripts are idempotent — re-running overwrites previous output files.
- The Fedora laptop substitutes for the Android phone throughout all BLE
  experiments.  The CipherChannel packet format is byte-identical.
- BLE MAC addresses can be found with: `bluetoothctl scan on` then look for `AWAKE-EXP`.
- If BlueZ complains about BR/EDR: `bluetoothctl remove <address>` before each run.
