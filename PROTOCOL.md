# CipherChannel Protocol — Normative Specification

**Protocol version:** 1  
**State format version:** 1  
**Status:** Research reference implementation

---

## 1. Purpose and scope

CipherChannel provides authenticated, replay-protected, forward-sequential encrypted
communication between a central controller (Raspberry Pi 3A+) and two peripherals
(phone/laptop supervisory client, ESP32-based cane device) over BLE GATT.

This document uses the keywords MUST, MUST NOT, SHOULD, and MAY as defined in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Wire format

```
CtrNonce  :  12 bytes   (96-bit little-endian monotonic counter)
Ciphertext:   N bytes   (N == plaintext length, no padding)
GCM Tag   :  16 bytes   (AES-256-GCM authentication tag)
```

- The fixed overhead MUST be exactly **28 bytes** per packet.
- Ciphertext length MUST equal plaintext length.
- Implementations MUST NOT apply any padding before encryption.
- Implementations MUST NOT apply any padding removal after decryption.

---

## 3. Cryptographic algorithm

- **Cipher:** AES-256-GCM (AEAD)
- **Key length:** 32 bytes
- **Nonce length:** 12 bytes (IETF standard, per [RFC 5116])
- **Tag length:** 16 bytes
- **Additional data:** none (empty AAD)

---

## 4. Nonce construction

The nonce is a 96-bit unsigned integer encoded in **little-endian** byte order, derived
from a monotonic per-direction counter.

```
nonce_bytes = counter.to_bytes(12, byteorder='little')
```

- The counter MUST be strictly monotonically increasing within each direction.
- The counter MUST increment by exactly 2 on each send.
- The counter MUST be persisted durably BEFORE the packet is returned to the caller.
- Implementations MUST detect counter exhaustion before the counter reaches 2^96
  and MUST fail the send with an error rather than reusing a nonce.

---

## 5. Direction parity

Each CipherChannel context is configured as either **initiator** or **responder**.

| Role      | Sends counters | Receives counters | Initial seqSend | Initial seqRecv |
| --------- | -------------- | ----------------- | --------------- | --------------- |
| Initiator | Even: 2, 4, 6… | Odd: 3, 5, 7…     | 0               | 1               |
| Responder | Odd: 3, 5, 7…  | Even: 2, 4, 6…    | 1               | 0               |

Reflection rejection rule: a received counter MUST have the **same parity** as the
current receive counter (`seqRecv`). A counter with the wrong parity MUST be silently
rejected before decryption.

---

## 6. Receive validation sequence

Implementations MUST process an incoming packet in the following order:

1. Validate packet length: `28 ≤ len ≤ MAX_PACKET_SIZE`. Reject otherwise.
2. Extract the nonce (bytes 0–11) and parse the counter.
3. Check counter freshness: `counter > seqRecv`. Reject if not.
4. Check counter parity: `(counter & 1) == (seqRecv & 1)`. Reject if not.
5. Authenticate and decrypt using AES-256-GCM.
6. On authentication failure, return None / false. Do not expose partial output.
7. Persist the accepted counter durably.
8. Return plaintext to caller only after persistence succeeds.

Steps 3–4 MUST occur BEFORE step 5 to avoid wasted cryptographic work on replays.

---

## 7. Send sequence

1. Check `len(plaintext) ≤ MAX_PLAINTEXT_SIZE`. Raise error if not.
2. Check exhaustion: `seqSend + 2 ≤ 2^96 - 1`. Raise error if not.
3. Increment `seqSend += 2`.
4. Persist `seqSend` durably.
5. Construct 12-byte nonce from `seqSend`.
6. Encrypt with AES-256-GCM.
7. Return `nonce || ciphertext || tag`.

An outgoing packet MUST NOT be returned unless step 4 has completed successfully.

---

## 8. Payload size limits

Protocol version 1 uses **bounded messages** without application-level fragmentation.

```
MAX_PLAINTEXT_SIZE = 400   (bytes)
MAX_PACKET_SIZE    = 428   (bytes) = 12 + 400 + 16
```

These values are derived from empirical GATT long-write testing on the evaluated
BLE configuration (BlueZ/bless on Raspberry Pi 3A+ ↔ Arduino ESP32-BLE-Arduino).
A 400-byte plaintext → 428-byte encrypted packet was the largest that succeeded
reliably. The protocol makes no claim of universal BLE portability.

Implementations MUST reject plaintext longer than MAX_PLAINTEXT_SIZE before
encryption. Implementations MUST reject received packets longer than MAX_PACKET_SIZE
before any parsing or decryption.

Explicit authenticated fragmentation for larger payloads is future work.

---

## 9. Endpoint isolation

Deployments MUST maintain **separate** operational keys, CipherChannel contexts,
persistent state files/namespaces, and locks for each logical endpoint:

- `K_phone` — phone/laptop supervisory channel
- `K_cane` — cane (ESP32) base and secure channels

Packets encrypted under `K_phone` MUST NOT be accepted by the cane context, and
vice-versa. This is enforced cryptographically: GCM authentication will fail for
packets encrypted under a different key.

Direction parity within each endpoint channel provides reflection rejection.
Parity MUST NOT be used as a substitute for endpoint key separation.

---

## 10. Provisioning

Provisioning MUST only succeed while a **physical-presence gate** is active.

Required state machine:

1. Default state: **CLOSED** (no provisioning allowed).
2. A physical hardware action (e.g. button press) opens a provisioning window for
   a specific endpoint.
3. The window remains open for a configurable duration (default: 60 seconds).
4. A `REQUEST_KEY` during the active window receives exactly one endpoint-specific
   operational key.
5. After successful provisioning, the window closes immediately.
6. `STOP_SHARING`, timeout, error, or disconnect MUST close and clear the window.
7. `REQUEST_KEY` while the window is closed MUST fail without returning key material.
8. A second `REQUEST_KEY` in the same window MUST fail.
9. Key material MUST NOT remain readable in a GATT characteristic after provisioning.

### Test-only bypass

A `BenchmarkProvisioningGate` MAY be used for automated experiments. It MUST:

- Be disabled by default.
- Require explicit opt-in (e.g. `BENCHMARK_PROVISIONING=1` environment variable).
- Log clearly when active.
- Implement the same state-machine interface as the production gate.
- NEVER be enabled in production.

---

## 11. Durable persistence

Implementations MUST use a two-phase write that is durable against both process
crash and power loss.

### Python (Linux / ext4)

```
1. Create temp file in the same directory as the target.
2. Write full state payload.
3. fsync(fd)  — flush to storage device.
4. os.replace(tmp, target)  — atomic rename.
5. fsync(parent_dir_fd)  — make directory entry durable.
6. Clean up temp file on any failure.
```

This sequence is durable on ext4 with ordered-data mode (default) and equivalent
journalling filesystems. On FAT/exFAT, rename is not atomic; use ext4 or tmpfs.

### ESP32 (NVS via Preferences)

The `Preferences::end()` call invokes `nvs_commit()` internally, flushing NVS pages
to flash. NVS writes are therefore power-loss durable on the ESP32. The counter is
written before the key to ensure nonce non-reuse even on crash during initial setup.

### Guarantees

- An outgoing packet MUST NOT be returned if send-counter persistence fails.
- Plaintext MUST NOT be released if receive-counter persistence fails.
- Counters MUST NOT be silently reset if a state file is missing, truncated,
  corrupted, or belongs to a different key or endpoint.
- Counter reinitialization is permitted only with a fresh operational key.

---

## 12. Thread safety

Each CipherChannel context MUST have its own lock. The complete critical section
for `send()` and the complete critical section for `receive()` MUST each be
executed under a single lock acquisition. The validation and persistence sequence
MUST NOT be split across separate lock scopes.

Concurrent `send()` and `receive()` on the same context are safe.
Multiple concurrent `send()` callers on the same context will serialize.

---

## 13. State file format (Python)

```
Offset  Length  Field
------  ------  -----
0       1       STATE_FORMAT_VERSION  (= 1)
1       1       PROTOCOL_VERSION      (= 1)
2       1       endpoint_id_length N
3       N       endpoint_id (UTF-8)
3+N     1       role flags (bit 0: 1 = initiator)
4+N     2       key_length K (little-endian)
6+N     K       key bytes
6+N+K   12      seqSend (96-bit little-endian unsigned integer)
18+N+K  12      seqRecv (96-bit little-endian unsigned integer)
```

Implementations MUST fail closed (raise ChannelException) if:

- STATE_FORMAT_VERSION ≠ 1
- PROTOCOL_VERSION ≠ 1
- File is truncated at any field
- endpoint_id conflicts with the expected value (if supplied)
- key_length is not in {16, 24, 32}

The raw key MUST NOT appear in logs or debug output.

---

## 14. NVS state layout (ESP32)

| NVS key   | Type       | Content                    |
| --------- | ---------- | -------------------------- |
| `sfv`     | bytes (1)  | STATE_FORMAT_VERSION = 2   |
| `pv`      | bytes (1)  | PROTOCOL_VERSION = 1       |
| `seqSend` | bytes (12) | send counter (uint64_t LE) |
| `seqRecv` | bytes (12) | recv counter (uint64_t LE) |
| `key`     | bytes (32) | AES-256 key                |

Load MUST fail if `sfv` or `pv` are absent or do not match expected values.

---

## 15. Test vectors

All implementations MUST produce and accept the following deterministic packet.

| Field       | Value (hex)                                          |
| ----------- | ---------------------------------------------------- |
| key         | `00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00` |
|             | `00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00` |
| role        | initiator                                            |
| seqSend     | 0 (first send → 2)                                   |
| plaintext   | `74 65 73 74` (`"test"`, 4 bytes)                    |
| nonce       | `02 00 00 00  00 00 00 00  00 00 00 00` (12 B)       |
| ciphertext  | `bb 3a f9 b4` (4 bytes)                              |
| tag         | `d8 1a 74 11  3b 0c 7c 23  2a fe 5b 00  ca c5 09 5a` |
| full packet | nonce + ciphertext + tag = 32 bytes                  |

Acceptance criteria:

1. Python, C/OpenSSL, and ESP32/mbedTLS produce identical packets for this vector.
2. Nonce field is always 12 bytes.
3. Ciphertext length equals plaintext length (4 bytes here).
4. Fixed overhead is always 28 bytes.
5. Replayed packets are rejected.
6. Modified ciphertext or tag is rejected.
7. Wrong-direction packets (parity mismatch) are rejected.
8. Packets from another endpoint key are rejected.
9. Counters remain monotonic across restart.
10. Concurrent sends never reuse a nonce.
11. Plaintext is not released if receive-state persistence fails.
12. An outgoing packet is not returned if send-state persistence fails.
13. Provisioning without an active physical gate fails.
14. Oversized messages (> MAX_PLAINTEXT_SIZE) fail closed.

---

## 16. Protocol-breaking changes from the previous implementation

| #   | Change                                   | Impact                               |
| --- | ---------------------------------------- | ------------------------------------ |
| 1   | Nonce: 16 bytes → 12 bytes               | Wire-format incompatible             |
| 2   | PKCS7 padding removed                    | Wire-format incompatible             |
| 3   | State file format versioned (new header) | Old state files unreadable (correct) |
| 4   | MAX_PLAINTEXT_SIZE = 400 enforced        | Rejects previously-allowed 401–512B  |
| 5   | Counter checked before decryption        | No observable wire change            |
| 6   | send() raises on oversized plaintext     | API change (was silent)              |
| 7   | Provisioning gate required               | Deployment procedure change          |
| 8   | Endpoint-specific keys enforced          | Separate key provisioning required   |
