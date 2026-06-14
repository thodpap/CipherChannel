#include "CipherChannel.h"

// NVS key names (each ≤ 15 chars per Preferences API limit)
#define NVS_K_SFV      "sfv"      //  1 byte:  state format version
#define NVS_K_PV       "pv"       //  1 byte:  protocol version
#define NVS_K_KEY      "key"      // 32 bytes: AES-256 key
#define NVS_K_SEQSEND  "seqSend"  // 12 bytes: 96-bit send counter  (cc_counter_t)
#define NVS_K_SEQRECV  "seqRecv"  // 12 bytes: 96-bit receive counter (cc_counter_t)


// ── Internal helpers ──────────────────────────────────────────────────────────

// Counter bytes ARE the nonce bytes (both 12-byte LE) — memcpy suffices.
static void counter_to_nonce(const cc_counter_t& c, uint8_t nonce[CC_NONCE_LEN]) {
    memcpy(nonce, c.b, CC_NONCE_LEN);
}

static cc_counter_t nonce_to_counter(const uint8_t nonce[CC_NONCE_LEN]) {
    cc_counter_t c;
    memcpy(c.b, nonce, CC_NONCE_LEN);
    return c;
}


// ── Constructor / Destructor ──────────────────────────────────────────────────

CipherChannel::CipherChannel()
    : _mutex(xSemaphoreCreateMutex())
{
    memset(_key, 0, sizeof(_key));
    memset(_ns,  0, sizeof(_ns));
    _seqSend = cc_counter_t::zero();
    _seqRecv = cc_counter_t::zero();
}

CipherChannel::~CipherChannel() {
    memset(_key, 0, sizeof(_key));
    if (_mutex) {
        vSemaphoreDelete(_mutex);
        _mutex = nullptr;
    }
}


// ── Persistence ───────────────────────────────────────────────────────────────

// Write send + receive counters only (called on every send/receive).
// _seqSend is written before _seqRecv to preserve nonce non-reuse on crash.
// Preferences::end() calls nvs_commit() — writes are power-loss durable.
// Must be called while _mutex is held.
bool CipherChannel::_writeCounters() {
    Preferences prefs;
    if (!prefs.begin(_ns, /*readOnly=*/false)) {
        Serial.printf("[CC/%s] NVS open failed\n", _ns);
        return false;
    }
    bool ok = true;
    ok &= (prefs.putBytes(NVS_K_SEQSEND, _seqSend.b, CC_NONCE_LEN) == CC_NONCE_LEN);
    ok &= (prefs.putBytes(NVS_K_SEQRECV, _seqRecv.b, CC_NONCE_LEN) == CC_NONCE_LEN);
    prefs.end();   // commits to NVS flash (power-loss durable)
    if (!ok) Serial.printf("[CC/%s] NVS counter write failed\n", _ns);
    return ok;
}

// Write the full state: versions + key + counters.
// Called by create() and updateKey(). Must be called while _mutex is held.
bool CipherChannel::_writeState() {
    Preferences prefs;
    if (!prefs.begin(_ns, /*readOnly=*/false)) {
        Serial.printf("[CC/%s] NVS open failed\n", _ns);
        return false;
    }
    bool ok = true;
    uint8_t sfv = CC_STATE_FORMAT_VERSION;
    uint8_t pv  = CC_PROTOCOL_VERSION;
    ok &= (prefs.putBytes(NVS_K_SFV,     &sfv,        1)          == 1);
    ok &= (prefs.putBytes(NVS_K_PV,      &pv,         1)          == 1);
    // Write send counter first — most critical for nonce non-reuse on crash
    ok &= (prefs.putBytes(NVS_K_SEQSEND, _seqSend.b, CC_NONCE_LEN) == CC_NONCE_LEN);
    ok &= (prefs.putBytes(NVS_K_SEQRECV, _seqRecv.b, CC_NONCE_LEN) == CC_NONCE_LEN);
    ok &= (prefs.putBytes(NVS_K_KEY,     _key,        CC_KEY_LEN)   == CC_KEY_LEN);
    prefs.end();   // commits to NVS flash
    if (!ok) Serial.printf("[CC/%s] NVS state write failed\n", _ns);
    return ok;
}


// ── Factory: create ───────────────────────────────────────────────────────────

CipherChannel* CipherChannel::create(const uint8_t* key,
                                     bool           initiator,
                                     const char*    nvsNamespace) {
    CipherChannel* c = new CipherChannel();
    if (!c->_mutex) {
        Serial.println("[CC] FATAL: failed to create mutex — heap exhausted");
        delete c;
        return nullptr;
    }

    strncpy(c->_ns, nvsNamespace, sizeof(c->_ns) - 1);
    c->_ns[sizeof(c->_ns) - 1] = '\0';
    memcpy(c->_key, key, CC_KEY_LEN);

    // Initiator sends even counters: 0 → 2 → 4 …   receives odd:  1, 3, 5 …
    // Responder sends odd  counters: 1 → 3 → 5 …   receives even: 0, 2, 4 …
    c->_seqSend = initiator ? cc_counter_t::zero() : cc_counter_t::one();
    c->_seqRecv = initiator ? cc_counter_t::one()  : cc_counter_t::zero();

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
        Serial.printf("[CC/%s] NVS namespace not found\n", nvsNamespace);
        return nullptr;
    }

    // Validate state format and protocol versions (fail closed on mismatch)
    uint8_t sfv = 0, pv = 0;
    if (prefs.getBytesLength(NVS_K_SFV) == 1) prefs.getBytes(NVS_K_SFV, &sfv, 1);
    if (prefs.getBytesLength(NVS_K_PV)  == 1) prefs.getBytes(NVS_K_PV,  &pv,  1);

    if (sfv != CC_STATE_FORMAT_VERSION || pv != CC_PROTOCOL_VERSION) {
        Serial.printf("[CC/%s] Incompatible state: sfv=%u pv=%u (expected sfv=%u pv=%u)\n",
                      nvsNamespace, sfv, pv,
                      CC_STATE_FORMAT_VERSION, CC_PROTOCOL_VERSION);
        prefs.end();
        return nullptr;
    }

    // Validate stored field sizes before reading
    size_t keyLen  = prefs.getBytesLength(NVS_K_KEY);
    size_t sendLen = prefs.getBytesLength(NVS_K_SEQSEND);
    size_t recvLen = prefs.getBytesLength(NVS_K_SEQRECV);

    if (keyLen != CC_KEY_LEN || sendLen != CC_NONCE_LEN || recvLen != CC_NONCE_LEN) {
        Serial.printf("[CC/%s] NVS state corrupted or truncated "
                      "(key=%u seqSend=%u seqRecv=%u)\n",
                      nvsNamespace, keyLen, sendLen, recvLen);
        prefs.end();
        return nullptr;
    }

    CipherChannel* c = new CipherChannel();
    if (!c->_mutex) {
        Serial.println("[CC] FATAL: failed to create mutex — heap exhausted");
        prefs.end();
        delete c;
        return nullptr;
    }

    strncpy(c->_ns, nvsNamespace, sizeof(c->_ns) - 1);
    c->_ns[sizeof(c->_ns) - 1] = '\0';

    prefs.getBytes(NVS_K_KEY,     c->_key,       CC_KEY_LEN);
    prefs.getBytes(NVS_K_SEQSEND, c->_seqSend.b, CC_NONCE_LEN);
    prefs.getBytes(NVS_K_SEQRECV, c->_seqRecv.b, CC_NONCE_LEN);
    prefs.end();

    // Log the lower 8 bytes as uint64_t for diagnostics (upper 4 are zero in practice)
    uint64_t sendLo = 0, recvLo = 0;
    memcpy(&sendLo, c->_seqSend.b, sizeof(sendLo));
    memcpy(&recvLo, c->_seqRecv.b, sizeof(recvLo));
    Serial.printf("[CC/%s] loaded (seqSend=%llu seqRecv=%llu)\n",
                  nvsNamespace, sendLo, recvLo);
    return c;
}


// ── send ──────────────────────────────────────────────────────────────────────

bool CipherChannel::send(const uint8_t* plaintext, size_t len,
                         uint8_t* out, size_t& outLen) {
    if (!_mutex || xSemaphoreTake(_mutex, portMAX_DELAY) != pdTRUE) return false;

    bool ok = false;
    do {
        if (len > CC_MAX_PLAIN) {
            Serial.printf("[CC/%s] send: plaintext too large (%u > %u)\n",
                          _ns, (unsigned)len, CC_MAX_PLAIN);
            break;
        }

        // 1. Exhaustion check before incrementing.
        if (_seqSend.near_max()) {
            Serial.printf("[CC/%s] send: counter exhausted — provision a new key\n", _ns);
            break;
        }

        // 2. Increment send counter and persist BEFORE producing the nonce.
        //    If the device crashes after this write, the nonce will never be reused.
        _seqSend.increment2();
        if (!_writeCounters()) break;

        // 3. Build 12-byte nonce from _seqSend (direct copy — same layout).
        uint8_t nonce[CC_NONCE_LEN];
        counter_to_nonce(_seqSend, nonce);

        // 4. AES-256-GCM encrypt plaintext directly (no padding).
        //    Output layout: nonce(12) || ciphertext(len) || tag(16)
        uint8_t* cipherOut = out + CC_NONCE_LEN;
        uint8_t* tagOut    = cipherOut + len;

        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);

        int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, _key, 256);
        if (ret != 0) {
            Serial.printf("[CC/%s] GCM setkey failed: %d\n", _ns, ret);
            mbedtls_gcm_free(&gcm);
            break;
        }

        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                        len,
                                        nonce,   CC_NONCE_LEN,
                                        nullptr, 0,
                                        plaintext, cipherOut,
                                        CC_TAG_LEN, tagOut);
        mbedtls_gcm_free(&gcm);

        if (ret != 0) {
            Serial.printf("[CC/%s] GCM encrypt failed: %d\n", _ns, ret);
            break;
        }

        memcpy(out, nonce, CC_NONCE_LEN);
        outLen = CC_NONCE_LEN + len + CC_TAG_LEN;
        ok = true;
    } while (false);

    xSemaphoreGive(_mutex);
    return ok;
}


// ── receive ───────────────────────────────────────────────────────────────────

bool CipherChannel::receive(const uint8_t* packet, size_t len,
                            uint8_t* out, size_t& outLen) {
    outLen = 0;

    if (!_mutex || xSemaphoreTake(_mutex, portMAX_DELAY) != pdTRUE) return false;

    bool ok = false;
    do {
        // 1. Length checks: minimum 28 bytes (nonce + tag, empty ciphertext);
        //    maximum CC_MAX_PACKET_LEN.
        if (len < CC_NONCE_LEN + CC_TAG_LEN) break;
        if (len > CC_MAX_PACKET_LEN) break;
        size_t ciphertextLen = len - CC_NONCE_LEN - CC_TAG_LEN;

        // 2. Extract counter from nonce and enforce freshness + parity
        //    BEFORE decryption to avoid wasted crypto work on replays.
        const uint8_t* nonce    = packet;
        cc_counter_t   incoming = nonce_to_counter(nonce);

        if (!incoming.gt(_seqRecv)) break;                          // replay / not fresh
        if (incoming.parity() != _seqRecv.parity()) break;         // wrong direction

        // 3. AES-256-GCM decrypt + authenticate.
        const uint8_t* ciphertext = packet + CC_NONCE_LEN;
        const uint8_t* tag        = packet + CC_NONCE_LEN + ciphertextLen;

        if (ciphertextLen > CC_MAX_PLAIN) break;

        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);

        int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, _key, 256);
        if (ret != 0) {
            Serial.printf("[CC/%s] GCM setkey failed: %d\n", _ns, ret);
            mbedtls_gcm_free(&gcm);
            break;
        }

        ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertextLen,
                                       nonce,      CC_NONCE_LEN,
                                       nullptr,    0,
                                       tag,        CC_TAG_LEN,
                                       ciphertext, out);
        mbedtls_gcm_free(&gcm);

        if (ret != 0) break;   // tampered ciphertext, tag, or wrong key

        // 4. Accept: persist new receive counter BEFORE returning plaintext.
        //    If NVS write fails, zero the output to avoid exposing plaintext
        //    without the replay-protection counter being updated.
        _seqRecv = incoming;
        if (!_writeCounters()) {
            memset(out, 0, ciphertextLen);
            break;
        }

        outLen = ciphertextLen;
        ok = true;
    } while (false);

    xSemaphoreGive(_mutex);
    return ok;
}


// ── updateKey ─────────────────────────────────────────────────────────────────

bool CipherChannel::updateKey(const uint8_t* newKey, bool initiator) {
    if (!_mutex || xSemaphoreTake(_mutex, portMAX_DELAY) != pdTRUE) return false;

    memcpy(_key, newKey, CC_KEY_LEN);
    _seqSend = initiator ? cc_counter_t::zero() : cc_counter_t::one();
    _seqRecv = initiator ? cc_counter_t::one()  : cc_counter_t::zero();
    bool ok = _writeState();
    if (ok) Serial.printf("[CC/%s] key updated (initiator=%d)\n", _ns, initiator);

    xSemaphoreGive(_mutex);
    return ok;
}
