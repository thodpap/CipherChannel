#ifndef CIPHER_CHANNEL_H
#define CIPHER_CHANNEL_H

/*
 * CipherChannel — AES-256-GCM with persistent counter nonces.
 *
 * Wire format:  nonce(12) || ciphertext(N) || tag(16)
 *   nonce       = _seqSend as a 12-byte little-endian 96-bit unsigned integer
 *   ciphertext  = AES-256-GCM(plaintext, nonce)  — no padding, len == plaintext len
 *   tag         = 16-byte GCM authentication tag
 *   Fixed overhead = 28 bytes
 *
 * Direction parity:
 *   initiator  sends even counters (2, 4, 6, …)   expects odd  from the other side
 *   responder  sends odd  counters (3, 5, 7, …)   expects even from the other side
 *
 * Counter rules:
 *   - Counter is a 96-bit unsigned integer (cc_counter_t) stored and transmitted
 *     as 12 little-endian bytes.  The in-memory layout IS the wire nonce field.
 *   - _seqSend is incremented by 2 and persisted to NVS BEFORE producing the packet.
 *   - Counter freshness and parity are checked BEFORE decryption.
 *   - _seqRecv is persisted to NVS BEFORE the plaintext is exposed to the caller.
 *   - Counters never reset under the same key.
 *   - Counter exhaustion is detected when counter + 2 would exceed 2^96 − 1.
 *
 * Thread safety:
 *   Each CipherChannel holds a FreeRTOS mutex (_mutex).  The complete critical
 *   section of send() (exhaustion check → increment → persist → encrypt) and the
 *   complete critical section of receive() (freshness/parity check → decrypt →
 *   persist) and updateKey() are each executed under a single mutex acquisition.
 *
 * Persistence:
 *   Preferences (NVS) is used.  Preferences::end() calls nvs_commit() internally,
 *   making writes power-loss durable.  Pass a short namespace string (≤ 15 chars)
 *   to create() / load().  Use different namespaces for different channels.
 *
 * Endpoint isolation:
 *   Maintain separate namespaces and CipherChannel instances per endpoint.
 *   Phone packets encrypted under K_phone will fail GCM auth on the cane
 *   context keyed with K_cane, and vice-versa.
 *
 * BLE transport constraint (protocol version 1):
 *   MAX_PLAINTEXT_SIZE is derived from empirical GATT long-write testing.
 *   400 B plaintext → 428 B packet fits within the evaluated BLE configuration.
 *
 * State format version 2 / Protocol version 1.
 *   State format version was bumped from 1→2 when counter storage changed from
 *   8-byte uint64_t to 12-byte cc_counter_t.  Old NVS state (sfv=1) is rejected
 *   on load and the channel must be reprovisioned.
 *
 * Usage:
 *   // First boot / provisioning:
 *   CipherChannel* ch = CipherChannel::create(key, true, "cc_phone");
 *   if (!ch) { /* handle NVS / heap failure *\/ }
 *
 *   // Every subsequent boot:
 *   CipherChannel* ch = CipherChannel::load("cc_phone");
 *   if (!ch) { /* handle missing / incompatible state — reprovision *\/ }
 *
 *   // Encrypt:
 *   uint8_t pkt[CC_MAX_PACKET_LEN];
 *   size_t  pktLen;
 *   if (!ch->send(plaintext, len, pkt, pktLen)) { /* handle error *\/ }
 *
 *   // Decrypt:
 *   uint8_t plain[CC_MAX_PLAIN];
 *   size_t  plainLen;
 *   if (!ch->receive(packet, packetLen, plain, plainLen)) { /* reject *\/ }
 */

#include <Arduino.h>
#include <Preferences.h>
#include "mbedtls/gcm.h"
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

// ── Protocol / state versioning ───────────────────────────────────────────────
#define CC_PROTOCOL_VERSION     1u
#define CC_STATE_FORMAT_VERSION 2u  // v2: counter storage changed 8B→12B

// ── Packet geometry constants ──────────────────────────────────────────────────
#define CC_NONCE_LEN      12u   // 96-bit little-endian counter (IETF AES-GCM standard)
#define CC_TAG_LEN        16u   // GCM authentication tag
#define CC_KEY_LEN        32u   // AES-256
#define CC_MAX_PLAIN     400u   // max plaintext bytes: 400 B → 428 B packet fits BLE

// Fixed overhead = CC_NONCE_LEN + CC_TAG_LEN = 28 bytes; ciphertext len == plaintext len
#define CC_MAX_PACKET_LEN (CC_NONCE_LEN + CC_MAX_PLAIN + CC_TAG_LEN)  // 428 bytes

// Provisioning associated-data tag (must match PROVISION_TAG_CANE in
// shared/cipher.py). The gateway's cane key-issuance response is encrypted
// under the transport key K_T, which both endpoints hold; without a bound
// tag, a response meant for the other endpoint (phone) would authenticate
// just as well here. Passed as aad/aadLen to CipherChannel::receive() when
// decrypting the CANE_SECURITY_UUID key response only — not used for any
// other message type.
static const uint8_t CC_PROVISION_TAG_CANE[] = "cane_provisioning";
#define CC_PROVISION_TAG_CANE_LEN (sizeof(CC_PROVISION_TAG_CANE) - 1)


// ── 96-bit counter type ───────────────────────────────────────────────────────
//
// Stored and transmitted as a 12-byte little-endian unsigned integer.
// The in-memory layout is identical to the wire nonce field — no conversion needed
// between counter and nonce; a memcpy suffices.
//
// All arithmetic and comparisons treat the 12 bytes as a single 96-bit integer
// with b[0] as the least-significant byte.

struct cc_counter_t {
    uint8_t b[CC_NONCE_LEN];   // b[0] = LSB, b[11] = MSB

    // Zero and one sentinels used for initiator/responder initialisation.
    static cc_counter_t zero() { cc_counter_t c{}; return c; }
    static cc_counter_t one()  { cc_counter_t c{}; c.b[0] = 1u; return c; }

    // Bit 0 of the least-significant byte (same parity as the counter value).
    uint8_t parity() const { return b[0] & 1u; }

    // Returns true if this counter is strictly greater than other.
    bool gt(const cc_counter_t& o) const {
        for (int i = CC_NONCE_LEN - 1; i >= 0; --i) {
            if (b[i] > o.b[i]) return true;
            if (b[i] < o.b[i]) return false;
        }
        return false;   // equal → not strictly greater
    }

    // Returns true if counter + 2 would exceed 2^96 − 1.
    // Equivalently: counter >= 2^96 − 2  (b[0] >= 0xFE while b[1..11] are all 0xFF).
    // Caller MUST check this before calling increment2().
    bool near_max() const {
        for (int i = 1; i < CC_NONCE_LEN; ++i)
            if (b[i] != 0xFFu) return false;
        return b[0] >= 0xFEu;
    }

    // Add 2 to the 96-bit little-endian counter.  Undefined behaviour if near_max().
    void increment2() {
        uint16_t carry = 2u;
        for (int i = 0; i < CC_NONCE_LEN && carry; ++i) {
            carry += b[i];
            b[i]   = static_cast<uint8_t>(carry & 0xFFu);
            carry >>= 8;
        }
    }
};


class CipherChannel {
public:
    ~CipherChannel();

    // ── Factory: create a new channel and persist initial state to NVS ────────
    // key         : CC_KEY_LEN (32) bytes
    // initiator   : true  → send even counters, receive odd
    //               false → send odd  counters, receive even
    // nvsNamespace: NVS namespace, ≤ 15 chars (use different NS per endpoint)
    // Returns nullptr on NVS write failure or FreeRTOS heap exhaustion.
    static CipherChannel* create(const uint8_t* key,
                                 bool           initiator,
                                 const char*    nvsNamespace);

    // ── Factory: load existing channel state from NVS ──────────────────────────
    // Returns nullptr if the namespace is missing, the state is corrupted or
    // truncated, or the state/protocol format version does not match.
    static CipherChannel* load(const char* nvsNamespace);

    // ── Encrypt ────────────────────────────────────────────────────────────────
    // Acquires _mutex, checks exhaustion, increments and persists _seqSend,
    // then encrypts.  Plaintext longer than CC_MAX_PLAIN is rejected.
    // out must be at least CC_MAX_PACKET_LEN bytes.
    // aad/aadLen: optional associated data authenticated by the GCM tag but
    // not transmitted (not part of out/outLen) and not counted against
    // CC_MAX_PLAIN — both ends must already agree on it out of band (e.g. a
    // fixed per-endpoint context string). Defaults to none, reproducing the
    // original (unbound) wire behaviour for callers that omit it. Used to
    // bind a provisioning key response to the endpoint it was issued for.
    // Returns true on success, false on any error (mutex released on all paths).
    bool send(const uint8_t* plaintext, size_t len,
              uint8_t* out, size_t& outLen,
              const uint8_t* aad = nullptr, size_t aadLen = 0);

    // ── Decrypt & validate ────────────────────────────────────────────────────
    // Acquires _mutex.  Checks counter freshness and parity BEFORE decryption.
    // aad/aadLen must match the value the sender used in send() or
    // authentication fails (see send() for why this is not carried on the
    // wire). Defaults to none, matching send()'s default.
    // Silently returns false for: short/oversized packet, replay, parity
    // mismatch, GCM auth failure, or NVS write failure after successful auth.
    // out must be at least CC_MAX_PLAIN bytes.
    bool receive(const uint8_t* packet, size_t len,
                 uint8_t* out, size_t& outLen,
                 const uint8_t* aad = nullptr, size_t aadLen = 0);

    // ── Key rotation ──────────────────────────────────────────────────────────
    // Acquires _mutex.  Replaces the key, resets counters, and persists.
    bool updateKey(const uint8_t* newKey, bool initiator);

    // ── Packet size helper ────────────────────────────────────────────────────
    static size_t maxPacketSize(size_t plaintextLen) {
        return CC_NONCE_LEN + plaintextLen + CC_TAG_LEN;
    }

private:
    CipherChannel();   // use create() or load()

    bool _writeCounters();  // persist _seqSend + _seqRecv; called inside mutex
    bool _writeState();     // persist version + key + counters; called inside mutex

    uint8_t           _key[CC_KEY_LEN];
    char              _ns[16];          // NVS namespace (max 15 chars + '\0')
    cc_counter_t      _seqSend;         // 96-bit send counter
    cc_counter_t      _seqRecv;         // 96-bit last-accepted receive counter
    SemaphoreHandle_t _mutex;           // FreeRTOS mutex; protects all state
};

#endif // CIPHER_CHANNEL_H
