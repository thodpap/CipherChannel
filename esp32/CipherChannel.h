#ifndef CIPHER_CHANNEL_H
#define CIPHER_CHANNEL_H

/*
 * CipherChannel — AES-256-GCM with persistent counter nonces (Björn's protocol).
 *
 * Wire format:  nonce(16) || ciphertext || tag(16)
 *   nonce       = _seqSend as a 16-byte little-endian unsigned integer
 *   ciphertext  = AES-256-GCM( PKCS7(plaintext) )  using nonce as IV
 *   tag         = 16-byte GCM authentication tag
 *
 * Direction parity:
 *   initiator  sends even counters (2, 4, 6, …)   and expects odd  from the other side
 *   responder  sends odd  counters (3, 5, 7, …)   and expects even from the other side
 *
 * Counter rules:
 *   - _seqSend is incremented by 2 and persisted to NVS BEFORE producing the packet.
 *   - A received counter must be strictly greater than _seqRecv AND have the same parity.
 *   - _seqRecv is persisted to NVS BEFORE the plaintext is exposed to the caller.
 *   - Counters never reset under the same key.
 *
 * Persistence:
 *   The Arduino Preferences library (NVS) is used.  Pass a short namespace string
 *   (≤ 15 chars) to create() / load() — use different namespaces for different channels.
 *
 * Usage:
 *   // First boot / provisioning:
 *   CipherChannel* ch = CipherChannel::create(key, /*initiator=* /true, "cc_main");
 *
 *   // Every subsequent boot:
 *   CipherChannel* ch = CipherChannel::load("cc_main");
 *   if (!ch) { /* handle corrupted / missing state * / }
 *
 *   // Encrypt:
 *   uint8_t pkt[CipherChannel::maxPacketSize(plaintextLen)];
 *   size_t  pktLen;
 *   if (!ch->send(plaintext, len, pkt, pktLen)) { /* handle error * / }
 *
 *   // Decrypt:
 *   uint8_t plain[512];
 *   size_t  plainLen;
 *   if (!ch->receive(packet, packetLen, plain, plainLen)) { /* reject * / }
 */

#include <Arduino.h>
#include <Preferences.h>
#include "mbedtls/gcm.h"

// ── Packet geometry constants ──────────────────────────────────────────────────
#define CC_NONCE_LEN      16u   // 128-bit little-endian counter
#define CC_TAG_LEN        16u   // GCM authentication tag
#define CC_BLOCK          16u   // AES block size (for PKCS7)
#define CC_KEY_LEN        32u   // AES-256
#define CC_MAX_PLAIN     512u   // maximum plaintext bytes per packet

// Maximum output buffer size for send():
//   nonce(16) + padded(plain + up to 16) + tag(16)
#define CC_MAX_PACKET_LEN (CC_NONCE_LEN + CC_MAX_PLAIN + CC_BLOCK + CC_TAG_LEN)


class CipherChannel {
public:
    ~CipherChannel();

    // ── Factory: create a new channel and persist initial state to NVS ────────
    // key         : CC_KEY_LEN (32) bytes
    // initiator   : true  → send even counters, receive odd
    //               false → send odd  counters, receive even
    // nvsNamespace: NVS namespace, ≤ 15 chars
    // Returns nullptr on NVS failure.
    static CipherChannel* create(const uint8_t* key,
                                 bool           initiator,
                                 const char*    nvsNamespace);

    // ── Factory: load existing channel state from NVS ──────────────────────────
    // Returns nullptr if the namespace is missing or the stored state is corrupted.
    static CipherChannel* load(const char* nvsNamespace);

    // ── Encrypt ────────────────────────────────────────────────────────────────
    // Increments and persists _seqSend BEFORE producing the nonce, so the counter
    // can never be reused even on a crash between send() and the BLE write.
    // out must be at least CC_MAX_PACKET_LEN bytes.
    // Returns true on success, false on any error (NVS failure, GCM error, …).
    bool send(const uint8_t* plaintext, size_t len,
              uint8_t* out, size_t& outLen);

    // ── Decrypt & validate ────────────────────────────────────────────────────
    // Silently returns false (no error detail exposed to caller) for:
    //   - short / mis-aligned packet
    //   - counter ≤ last received  (replay)
    //   - counter parity mismatch  (reflection / wrong direction)
    //   - GCM authentication failure (tampered data, wrong key)
    //   - bad PKCS7 padding
    //   - NVS write failure after successful auth
    // out must be at least CC_MAX_PLAIN bytes.
    bool receive(const uint8_t* packet, size_t len,
                 uint8_t* out, size_t& outLen);

    // ── Key rotation ──────────────────────────────────────────────────────────
    // Replace the key and reset counters.  Persists new state immediately.
    // initiator flag determines which parity this endpoint sends.
    bool updateKey(const uint8_t* newKey, bool initiator);

    // ── Helpers ────────────────────────────────────────────────────────────────
    static size_t maxPacketSize(size_t plaintextLen) {
        size_t padded = plaintextLen + (CC_BLOCK - (plaintextLen % CC_BLOCK));
        return CC_NONCE_LEN + padded + CC_TAG_LEN;
    }

private:
    CipherChannel() {}  // use create() or load()

    bool _writeCounters();  // persist _seqSend + _seqRecv (called on every send/receive)
    bool _writeState();     // persist key + _seqSend + _seqRecv (called on create/updateKey)

    uint8_t  _key[CC_KEY_LEN];
    char     _ns[16];        // NVS namespace (Preferences limit: 15 chars + '\0')
    uint64_t _seqSend;       // send counter  (pre-incremented by 2 before each use)
    uint64_t _seqRecv;       // last accepted receive counter
};

#endif // CIPHER_CHANNEL_H
