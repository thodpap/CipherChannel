# ESP32 cane latency experiment patch

This folder is the uploaded ESP32 sketch with firmware-side instrumentation added.

## What it measures

Serial output now includes three CSV-prefixed record types:

- `CSV_CONN`: connection setup stages in microseconds.
- `CSV_KEX`: REQUEST_KEY encryption/write/key-wait timing in microseconds.
- `CSV_TRIAL`: steady-state sequential cane command trial timing in microseconds.

`CSV_TRIAL.rtt_us` is only a valid end-to-end round trip if the RPi gateway sends an encrypted ACK/notify back to the ESP32 after receiving and accepting the cane command.

## Required gateway behavior

After the gateway accepts a `CANE2PHONE_UUID` encrypted cane command, it must send an encrypted ACK payload back on a characteristic that the ESP32 is subscribed to. The current ESP32 patch expects that ACK to arrive as a notification on `CANE2PHONE_UUID` and decrypt under the secure cane channel.

Recommended ACK plaintext:

```json
{"action":"ACK","trial_id":123}
```

The `trial_id` must match the inbound command's `trial_id`. The ESP32 also accepts a generic ACK without a trial ID, but matching trial IDs is safer.

## Experiment modes

In `esp32.ino`:

- `EXP_LATENCY_MODE 1`: sequential latency trials.
- `EXP_TRIALS 1000`: number of steady-state trials.
- `EXP_ACK_TIMEOUT_MS 2000`: timeout per ACK.
- `EXP_INTER_TRIAL_DELAY_MS 100`: quiet gap between trials.
- `CLEAR_SECURE_KEY_ON_BOOT 1`: cold-start/provisioning mode.
- `CLEAR_SECURE_KEY_ON_BOOT 0`: steady-state mode, assuming the secure key is already provisioned in NVS.

## Comparison with laptop -> RPi

Use the same statistical columns as the laptop experiment:

- accepted/success count: `ack_received == 1`
- median/p95/p99/max of `rtt_us / 1000.0`
- optionally report `cc_send_us / 1000.0` and `ble_write_us / 1000.0` separately

Do not subtract ESP32 timestamps from RPi timestamps. The valid RTT is measured entirely on the ESP32 clock.
