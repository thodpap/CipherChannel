# CipherChannel — ProVerif formal model

Symbolic (Dolev-Yao) verification of the CipherChannel protocol specified in
Section IV of the paper, using [ProVerif](https://proverif.inria.fr/) 2.05.

## Files

| File | Contents |
|------|----------|
| `cipherchannel.pv` | Baseline model: CipherChannel exactly as specified (Algorithms 1–2) and implemented in `server/ble_server.py` / `shared/cipher.py`. |
| `cipherchannel_hardened.pv` | Same model with one fix applied (endpoint identity bound into the provisioning ciphertext). |

## How to run

```bash
proverif formal/proverif/cipherchannel.pv
proverif formal/proverif/cipherchannel_hardened.pv
```

Requires a `proverif` binary on `PATH`. ProVerif's opam package pulls in
`lablgtk` (GTK GUI) as a hard dependency; if you don't want to install
`gtk2-devel`, build the CLI-only binary directly from source instead:

```bash
curl -LO https://proverif.inria.fr/proverif2.05.tar.gz
tar xzf proverif2.05.tar.gz && cd proverif2.05
./build -nointeract native   # produces ./proverif, no GTK needed
```

## What is modelled

- The dual-key architecture (Sec. IV-G): a static transport key `K_T` and
  per-endpoint operational keys `K_Sphone` / `K_Scane`.
- The physically gated key exchange (Sec. IV-H, Algorithm 2): provisioning
  is gated behind a private "button press" channel the network attacker
  cannot access, matching the paper's physical-presence argument.
- The persistent counter-nonce send/receive procedure with direction parity
  (Sec. IV-E, Algorithm 1): modelled as a "used at most once" table per
  (endpoint, direction) rather than literal integer counters — see the
  in-file comments for why this preserves the security property under test.
- Two independent endpoints (phone, cane), each on its own GATT
  characteristics for both key exchange and operational traffic, matching
  `server/ble_server.py`'s `SECURITY_UUID` / `CANE_SECURITY_UUID` /
  `COMMAND_UUID` / `CANE2PHONE_UUID` layout — giving a symbolic counterpart
  to Section VI's empirical cross-endpoint-injection test.

Not modelled: the 60-second provisioning timeout (no clock in ProVerif),
BLE MTU/fragmentation, and the reconnection/state-recovery procedure
(Sec. IV-J) — these are liveness/availability concerns already stated as
out of scope for CipherChannel's cryptographic guarantee (Sec. IV-A), not
confidentiality/integrity properties.

## Queries and results

| Query | `cipherchannel.pv` | `cipherchannel_hardened.pv` |
|---|---|---|
| `attacker(new K_Sphone)` — phone operational key stays secret | **true** | **true** |
| `attacker(new K_Scane)` — cane operational key stays secret | **true** | **true** |
| `inj-event(GatewayAccept) ==> inj-event(ClientSend)` — every accepted command was actually sent, by the claimed endpoint, exactly once | **false** (attack found) | cannot be proved automatically (see below) |
| non-injective version of the same correspondence | — | **true** |

## Finding: cross-endpoint provisioning confusion

`cipherchannel.pv` — modelling the protocol exactly as specified — finds a
genuine attack, not a modelling artefact:

**The provisioning response `aenc(K_S, provNonce, K_T)` carries no endpoint
identity inside the ciphertext.** Endpoint separation during key exchange
relies entirely on phone and cane using distinct GATT characteristics
(`SECURITY_UUID` vs `CANE_SECURITY_UUID`). Checking `shared/cipher.py`
confirms `endpoint_id` is part of the *local persistent state file* format
only (used to catch accidentally loading the wrong state file on disk) —
it is never transmitted or authenticated on the wire; the wire format is
strictly `nonce(12) || ciphertext(N) || tag(16)`.

An attacker able to relay bytes between the two provisioning
characteristics — a stronger, dual-session form of the "session hijacking /
MITM" threat already listed as in-scope in Sec. IV-A — can take the
gateway's genuine response to a cane `REQUEST_KEY` and deliver it to the
phone's provisioning listener instead, causing the phone to adopt
`K_cane` as its own operational key (or the symmetric case). Both keys
remain individually secret throughout (the attacker never learns the raw
key value — this is *not* a confidentiality break), but the binding between
"which key" and "which endpoint holds it" is not authenticated, so a
command sent under a confused key can be accepted as if it came from the
other endpoint.

**Scope / severity.** This does not let an unauthorised party inject a
command: it requires an attacker capable of bridging both endpoints'
already-open, physically-gated provisioning windows. Because CipherChannel
still checks AEAD authentication on the *operational* channel, a
confused-key client mostly bricks its own session (its commands fail to
decrypt at the gateway) unless the attacker can also relay the resulting
operational ciphertext to the other endpoint's command channel — at which
point the practical effect is misattributing a legitimate operator's
command to the wrong (already-authorised) endpoint, not admitting a forged
command from an unauthorised one.

**Fix (verified in `cipherchannel_hardened.pv`, and applied to the real
implementation).** Authenticate the endpoint identity together with the
key. The model does this by encrypting the pair, `aenc((ep, K_S),
provNonce, K_T)`, and having the client reject the response if the
decrypted tag does not match the endpoint it requested. The real
implementation uses the equivalent, wire-format-preserving construction:
the endpoint identity is passed as AES-GCM *associated data* (authenticated
by the tag, not transmitted, not part of the ciphertext) rather than
concatenated into the plaintext, so `MAX_PACKET_SIZE` and the documented
wire format (`nonce(12) || ciphertext(N) || tag(16)`) are unchanged. With
the fix, the non-injective correspondence (no forgery, no cross-endpoint
confusion) is proved automatically.

This has been applied to:
- `shared/cipher.py` — `CipherChannel.send()` / `.receive()` gained an
  optional `associated_data` parameter (default `b''`, preserving existing
  behaviour for every other call site); `PROVISION_TAG_PHONE` /
  `PROVISION_TAG_CANE` constants added.
- `server/ble_server.py` — the phone (`SECURITY_UUID`) and cane
  (`CANE_SECURITY_UUID`) key-issuance responses now pass the matching tag.
- `client/experiment_client.py` — the phone client's `_key_exchange()` now
  passes `PROVISION_TAG_PHONE` on receive.
- `esp32/CipherChannel.h` / `.cpp` — `send()` / `receive()` gained optional
  `aad`/`aadLen` parameters (default `nullptr`/`0`, threaded straight into
  mbedTLS's existing GCM AAD parameters, which were previously always
  `nullptr, 0`); every other call site is source-unchanged.
- `esp32/BLEProtocol.cpp` — the cane firmware's `CANE_SECURITY_UUID`
  receive call now passes `CC_PROVISION_TAG_CANE`.

Verified end-to-end with a standalone script exercising
`shared/cipher.py` directly (legitimate phone and cane round trips still
succeed; relaying a genuine cane provisioning response to the phone's
listener is now rejected; the same relay is confirmed to succeed against
the pre-fix, no-AAD code path, as a sanity check that the test actually
exercises the vulnerability). **The ESP32 firmware change is source-level
only** — edited for the same fix by direct analogy with the verified
Python/mbedTLS-equivalent construction, but not compiled, flashed, or
hardware-tested in this environment; it should be built and tested on real
hardware before being relied on.

Other server/client variants in this repository
(`server/ble_server_K.py`, `server/ble_server_instrumented.py`, and the
one-off scripts under `results/canonical/*/`) were **not** patched and
still use the pre-fix, unbound provisioning exchange; they were left alone
to avoid touching the already-executed canonical experiment scripts and
their instrumentation forks.

## A known ProVerif limitation (not a second finding)

Even in `cipherchannel_hardened.pv`, ProVerif reports the *injective*
correspondence (`inj-event(...) ==> inj-event(...)`, which additionally
claims replay-freedom) as "cannot be proved," while explicitly stating **no
attack trace exists** ("Could not find a trace corresponding to this
derivation"). This is a documented characteristic of ProVerif's
resolution/Horn-clause proof technique: it is sound (it never misses a
real attack) but incomplete for injective properties that interact with
mutable state (here, the `usedCtr` table) and replication — the
clause-based abstraction can lose track of how many times a fact was
consumed, which injectivity depends on but plain correspondence does not.
This is precisely the kind of property Tamarin's constraint-solving
approach is generally better suited to discharge automatically, since it
reasons about mutable state more precisely; it is noted here rather than
pursued further given time constraints. Replay-freedom itself still
follows directly from the model *by construction*: `GatewayAccept` only
fires immediately after `insert usedCtr(ep, dir, ctr)`, and `get
usedCtr(=ep, =dir, =ctr)` only takes the "already used" branch once that
exact row exists — so a given `(ep, dir, ctr)` triple can drive at most one
`GatewayAccept`, which is exactly injectivity, inspectable directly from
`GatewayCmdRecvOnce` without relying on the automated heuristic.

## Reproducing

Both files were run with `proverif <file>.pv`. Rebuilding the ProVerif
binary took roughly 10 minutes on a laptop (opam bootstrap + OCaml compiler
build + ProVerif build from source); each verification run completes in a
few seconds.
