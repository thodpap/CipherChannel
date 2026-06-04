#include "CipherChannel.h"

// NVS key names (each ≤ 15 chars)
#define NVS_K_KEY      "key"      // 32 bytes: AES-256 key
#define NVS_K_SEQSEND  "seqSend"  //  8 bytes: send counter  (uint64_t)
#define NVS_K_SEQRECV  "seqRecv"  //  8 bytes: receive counter (uint64_t)


// ── Internal helpers ──────────────────────────────────────────────────────────

// Encode a uint64_t counter into the 16-byte little-endian nonce.
// Upper 8 bytes are zero: counters fit in 64 bits in any realistic deployment
// (2^63 messages per direction ≈ 9 × 10^18 packets).
static void counter_to_nonce(uint64_t counter, uint8_t nonce[CC_NONCE_LEN]) {
    memset(nonce, 0, CC_NONCE_LEN);
    for (int i = 0; i < 8; i++) {
        nonce[i] = static_cast<uint8_t>((counter >> (i * 8)) & 0xFF);
    }
}

// Read the lower 64 bits of a 16-byte LE nonce back as a uint64_t.
static uint64_t nonce_to_counter(const uint8_t nonce[CC_NONCE_LEN]) {
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val |= static_cast<uint64_t>(nonce[i]) << (i * 8);
    }
    return val;
}

// PKCS7 pad `in` to the next AES block boundary.
static void pkcs7_pad(const uint8_t* in, size_t inLen,
                      uint8_t* out, size_t& outLen) {
    uint8_t pad = static_cast<uint8_t>(CC_BLOCK - (inLen % CC_BLOCK));
    memcpy(out, in, inLen);
    memset(out + inLen, pad, pad);
    outLen = inLen + pad;
}

// PKCS7 unpad.  Returns false and sets outLen=0 on invalid padding.
static bool pkcs7_unpad(const uint8_t* in, size_t inLen,
                        uint8_t* out, size_t& outLen) {
    outLen = 0;
    if (inLen == 0 || (inLen % CC_BLOCK) != 0) return false;
    uint8_t pad = in[inLen - 1];
    if (pad == 0 || pad > CC_BLOCK) return false;
    for (size_t i = 0; i < pad; i++) {
        if (in[inLen - 1 - i] != pad) return false;
    }
    outLen = inLen - pad;
    memcpy(out, in, outLen);
    return true;
}


// ── Persistence ───────────────────────────────────────────────────────────────

// Write send + receive counters only (called on every send/receive).
// _seqSend is written first so the nonce-reuse guarantee holds even on crash.
bool CipherChannel::_writeCounters() {
    Preferences prefs;
    if (!prefs.begin(_ns, /*readOnly=*/false)) {
        Serial.printf("[CC/%s] NVS open failed\n", _ns);
        return false;
    }
    bool ok = true;
    ok &= (prefs.putBytes(NVS_K_SEQSEND, &_seqSend, sizeof(_seqSend)) == sizeof(_seqSend));
    ok &= (prefs.putBytes(NVS_K_SEQRECV, &_seqRecv, sizeof(_seqRecv)) == sizeof(_seqRecv));
    prefs.end();
    if (!ok) Serial.printf("[CC/%s] NVS counter write failed\n", _ns);
    return ok;
}

// Write the full state: key + counters (called by create() and updateKey()).
bool CipherChannel::_writeState() {
    Preferences prefs;
    if (!prefs.begin(_ns, /*readOnly=*/false)) {
        Serial.printf("[CC/%s] NVS open failed\n", _ns);
        return false;
    }
    bool ok = true;
    // Write send counter first — most critical for nonce non-reuse
    ok &= (prefs.putBytes(NVS_K_SEQSEND, &_seqSend, sizeof(_seqSend)) == sizeof(_seqSend));
    ok &= (prefs.putBytes(NVS_K_SEQRECV, &_seqRecv, sizeof(_seqRecv)) == sizeof(_seqRecv));
    ok &= (prefs.putBytes(NVS_K_KEY,     _key,       CC_KEY_LEN)      == CC_KEY_LEN);
    prefs.end();
    if (!ok) Serial.printf("[CC/%s] NVS state write failed\n", _ns);
    return ok;
}


// ── Factory: create ───────────────────────────────────────────────────────────

CipherChannel* CipherChannel::create(const uint8_t* key,
                                     bool           initiator,
                                     const char*    nvsNamespace) {
    CipherChannel* c = new CipherChannel();
    strncpy(c->_ns, nvsNamespace, sizeof(c->_ns) - 1);
    c->_ns[sizeof(c->_ns) - 1] = '\0';
    memcpy(c->_key, key, CC_KEY_LEN);

    // Initiator sends even counters: 0 → 2 → 4 …   receives odd:  1, 3, 5 …
    // Responder sends odd  counters: 1 → 3 → 5 …   receives even: 0, 2, 4 …
    c->_seqSend = initiator ? 0u : 1u;
    c->_seqRecv = initiator ? 1u : 0u;

    if (!c->_writeState()) {
        delete c;
        return nullptr;
    }
    Serial.printf("[CC/%s] created (initiator=%d)\n", nvsNamespace, initiator);
    return c;
}


// ── Factory: load ─────────────────────────────────────────────────────────────

CipherChannel* CipherChannel::load(const char* nvsNamespace) {
    Preferences prefs;
    if (!prefs.begin(nvsNamespace, /*readOnly=*/true)) {
        Serial.printf("[CC/%s] NVS open failed — namespace not found?\n", nvsNamespace);
        return nullptr;
    }

    // Validate stored sizes before reading
    size_t keyLen  = prefs.getBytesLength(NVS_K_KEY);
    size_t sendLen = prefs.getBytesLength(NVS_K_SEQSEND);
    size_t recvLen = prefs.getBytesLength(NVS_K_SEQRECV);

    if (keyLen != CC_KEY_LEN || sendLen != sizeof(uint64_t) || recvLen != sizeof(uint64_t)) {
        Serial.printf("[CC/%s] NVS state corrupted or missing "
                      "(key=%u seqSend=%u seqRecv=%u)\n",
                      nvsNamespace, keyLen, sendLen, recvLen);
        prefs.end();
        return nullptr;
    }

    CipherChannel* c = new CipherChannel();
    strncpy(c->_ns, nvsNamespace, sizeof(c->_ns) - 1);
    c->_ns[sizeof(c->_ns) - 1] = '\0';

    prefs.getBytes(NVS_K_KEY,     c->_key,      CC_KEY_LEN);
    prefs.getBytes(NVS_K_SEQSEND, &c->_seqSend, sizeof(c->_seqSend));
    prefs.getBytes(NVS_K_SEQRECV, &c->_seqRecv, sizeof(c->_seqRecv));
    prefs.end();

    Serial.printf("[CC/%s] loaded (seqSend=%llu seqRecv=%llu)\n",
                  nvsNamespace, c->_seqSend, c->_seqRecv);
    return c;
}


// ── send ──────────────────────────────────────────────────────────────────────

bool CipherChannel::send(const uint8_t* plaintext, size_t len,
                         uint8_t* out, size_t& outLen) {
    if (len > CC_MAX_PLAIN) {
        Serial.printf("[CC/%s] send: plaintext too large (%u > %u)\n",
                      _ns, len, CC_MAX_PLAIN);
        return false;
    }

    // 1. Increment send counter by 2 and persist BEFORE producing the nonce.
    //    If the device crashes after this write but before the BLE write, the
    //    counter is already advanced — the nonce will never be reused.
    _seqSend += 2;
    if (!_writeCounters()) return false;

    // 2. Build 16-byte little-endian nonce from _seqSend.
    uint8_t nonce[CC_NONCE_LEN];
    counter_to_nonce(_seqSend, nonce);

    // 3. PKCS7 pad the plaintext.
    uint8_t padded[CC_MAX_PLAIN + CC_BLOCK];
    size_t  paddedLen;
    pkcs7_pad(plaintext, len, padded, paddedLen);

    // 4. AES-256-GCM encrypt.
    //    Output layout: nonce(16) || ciphertext(paddedLen) || tag(16)
    uint8_t* cipherOut = out + CC_NONCE_LEN;
    uint8_t* tagOut    = cipherOut + paddedLen;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, _key, 256);
    if (ret != 0) {
        Serial.printf("[CC/%s] GCM setkey failed: %d\n", _ns, ret);
        mbedtls_gcm_free(&gcm);
        return false;
    }

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                    paddedLen,
                                    nonce,  CC_NONCE_LEN,
                                    nullptr, 0,           // no additional data
                                    padded, cipherOut,
                                    CC_TAG_LEN, tagOut);
    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        Serial.printf("[CC/%s] GCM encrypt failed: %d\n", _ns, ret);
        return false;
    }

    memcpy(out, nonce, CC_NONCE_LEN);
    outLen = CC_NONCE_LEN + paddedLen + CC_TAG_LEN;
    return true;
}


// ── receive ───────────────────────────────────────────────────────────────────

bool CipherChannel::receive(const uint8_t* packet, size_t len,
                            uint8_t* out, size_t& outLen) {
    outLen = 0;

    // 1. Length checks: need at least nonce + tag; ciphertext must be block-aligned.
    if (len < CC_NONCE_LEN + CC_TAG_LEN) return false;
    size_t ciphertextLen = len - CC_NONCE_LEN - CC_TAG_LEN;
    if (ciphertextLen == 0 || (ciphertextLen % CC_BLOCK) != 0) return false;

    // 2. Extract counter from nonce and enforce freshness + parity.
    const uint8_t* nonce     = packet;
    uint64_t       sequence  = nonce_to_counter(nonce);

    // Replay check: counter must be strictly greater than last received.
    // Parity check: counter parity must match _seqRecv parity (direction coding).
    if (sequence <= _seqRecv || (sequence & 1u) != (_seqRecv & 1u)) return false;

    // 3. AES-256-GCM decrypt + authenticate.
    const uint8_t* ciphertext = packet + CC_NONCE_LEN;
    const uint8_t* tag        = packet + CC_NONCE_LEN + ciphertextLen;

    uint8_t padded[CC_MAX_PLAIN + CC_BLOCK];
    if (ciphertextLen > sizeof(padded)) return false;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, _key, 256);
    if (ret != 0) {
        Serial.printf("[CC/%s] GCM setkey failed: %d\n", _ns, ret);
        mbedtls_gcm_free(&gcm);
        return false;
    }

    ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertextLen,
                                   nonce,     CC_NONCE_LEN,
                                   nullptr,   0,
                                   tag,       CC_TAG_LEN,
                                   ciphertext, padded);
    mbedtls_gcm_free(&gcm);

    // GCM authentication failed: tampered ciphertext, tag, or wrong key.
    if (ret != 0) return false;

    // 4. PKCS7 unpad.
    if (!pkcs7_unpad(padded, ciphertextLen, out, outLen)) return false;

    // 5. Accept: persist new receive counter BEFORE returning plaintext.
    //    If this NVS write fails, we zero the output and reject to avoid
    //    exposing plaintext without the replay-protection counter being updated.
    _seqRecv = sequence;
    if (!_writeCounters()) {
        memset(out, 0, outLen);
        outLen = 0;
        return false;
    }

    return true;
}


// ── updateKey ─────────────────────────────────────────────────────────────────

bool CipherChannel::updateKey(const uint8_t* newKey, bool initiator) {
    memcpy(_key, newKey, CC_KEY_LEN);
    _seqSend = initiator ? 0u : 1u;
    _seqRecv = initiator ? 1u : 0u;
    bool ok = _writeState();
    if (ok) Serial.printf("[CC/%s] key updated (initiator=%d)\n", _ns, initiator);
    return ok;
}


// ── Destructor ────────────────────────────────────────────────────────────────

CipherChannel::~CipherChannel() {
    // Securely erase key material from RAM before freeing.
    memset(_key, 0, sizeof(_key));
    _seqSend = 0;
    _seqRecv = 0;
}
