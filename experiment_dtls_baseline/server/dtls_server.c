/*
 * dtls_server.c — DTLS 1.2 PSK echo server for CipherChannel baseline experiment.
 *
 * Transport : UDP/IP (NOT BLE/GATT — this is a standard network baseline).
 * Protocol  : DTLS 1.2, ciphersuite TLS_PSK_WITH_AES_128_GCM_SHA256.
 * Library   : mbedTLS 2.x (Raspberry Pi / Debian) or 3.x (Fedora laptop).
 *             API differences are handled via MBEDTLS_VERSION_NUMBER.
 *
 * Note: DTLS 1.3 is not implemented in either mbedTLS 2.x or 3.x; DTLS 1.2
 * is the current real-world standard for constrained devices.
 *
 * Behaviour: listen on a UDP port, accept one DTLS session at a time,
 * receive one command datagram, reply with an ACK containing the trial_id,
 * close the session, repeat.
 *
 * Usage:
 *   ./dtls_server [--port PORT] [--psk-id ID] [--psk-hex HEX]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

/* mbedTLS version detection — version.h exists in both 2.x and 3.x */
#include "mbedtls/version.h"
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
#include "mbedtls/build_info.h"
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/timing.h"

/* ── defaults (must match client) ──────────────────────────────────────────── */
#define SERVER_PORT_DEFAULT  "4433"
#define READ_TIMEOUT_MS      5000
#define MAX_BUF              1024

static const char DEFAULT_PSK_ID[] = "exo-dtls-client";
/* 16-byte test PSK — change via --psk-hex or psk_config.cfg */
static const unsigned char DEFAULT_PSK[16] = {
    0xde, 0xad, 0xbe, 0xef,  0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,  0x09, 0x0a, 0x0b, 0x0c
};

/* Only PSK-AES-128-GCM for DTLS 1.2 */
static const int PSK_CIPHERSUITES[] = {
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    0
};

/* ── helpers ────────────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

static long long wall_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void log_event(const char *msg) {
    long long ns = wall_ns();
    printf("[%lld.%09lld] %s\n",
           (long long)(ns / 1000000000LL),
           (long long)(ns % 1000000000LL), msg);
    fflush(stdout);
}

static void print_err(const char *fn, int ret) {
    char buf[256];
    mbedtls_strerror(ret, buf, sizeof(buf));
    fprintf(stderr, "ERR %s returned -0x%04x: %s\n", fn, (unsigned int)(-ret), buf);
}

/* Minimal JSON trial_id extractor: finds "trial_id":"VALUE" */
static void extract_trial_id(const char *json, char *out, size_t outsz) {
    strncpy(out, "unknown", outsz - 1);
    out[outsz - 1] = '\0';

    const char *p = strstr(json, "\"trial_id\"");
    if (!p) return;
    p = strchr(p, ':');
    if (!p) return;
    p++;
    while (*p == ' ') p++;
    if (*p == '"') p++;
    const char *end = p;
    while (*end && *end != '"') end++;
    size_t len = (size_t)(end - p);
    if (len > 0 && len < outsz - 1) {
        memcpy(out, p, len);
        out[len] = '\0';
    }
}

static int hex_to_bytes(const char *hex, unsigned char *out,
                         size_t maxlen, size_t *outlen) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0 || hlen / 2 > maxlen) return -1;
    *outlen = hlen / 2;
    for (size_t i = 0; i < *outlen; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%02x", &b) != 1) return -1;
        out[i] = (unsigned char)b;
    }
    return 0;
}

/* ── main ───────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    /* Argument parsing */
    const char *port  = SERVER_PORT_DEFAULT;
    const char *psk_id = DEFAULT_PSK_ID;
    unsigned char psk_buf[64];
    const unsigned char *psk = DEFAULT_PSK;
    size_t psk_len = sizeof(DEFAULT_PSK);
    char psk_id_buf[128];

    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--port") == 0) {
            port = argv[++i];
        } else if (strcmp(argv[i], "--psk-id") == 0) {
            strncpy(psk_id_buf, argv[++i], sizeof(psk_id_buf) - 1);
            psk_id_buf[sizeof(psk_id_buf) - 1] = '\0';
            psk_id = psk_id_buf;
        } else if (strcmp(argv[i], "--psk-hex") == 0) {
            size_t l;
            if (hex_to_bytes(argv[++i], psk_buf, sizeof(psk_buf), &l) == 0) {
                psk = psk_buf;
                psk_len = l;
            } else {
                fprintf(stderr, "Invalid PSK hex string\n");
                return 1;
            }
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* mbedTLS contexts */
    mbedtls_net_context     listen_fd, client_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context     ssl;
    mbedtls_ssl_config      conf;
    mbedtls_ssl_cookie_ctx  cookie;
    mbedtls_timing_delay_context timer;

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_cookie_init(&cookie);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret;

    /* Seed RNG */
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                      (const unsigned char *)"dtls_srv", 8)) != 0) {
        print_err("ctr_drbg_seed", ret); return 1;
    }

    /* SSL configuration (shared across sessions — does not hold session state) */
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_err("ssl_config_defaults", ret); return 1;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_ciphersuites(&conf, PSK_CIPHERSUITES);
    /* Pin to DTLS 1.2 — API differs between mbedTLS 2.x and 3.x */
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
#else
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                         MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                         MBEDTLS_SSL_MINOR_VERSION_3);
#endif
    mbedtls_ssl_conf_read_timeout(&conf, READ_TIMEOUT_MS);

    if ((ret = mbedtls_ssl_conf_psk(&conf, psk, psk_len,
                                     (const unsigned char *)psk_id,
                                     strlen(psk_id))) != 0) {
        print_err("ssl_conf_psk", ret); return 1;
    }

    /* DTLS cookie (HelloVerifyRequest) prevents amplification attacks */
    if ((ret = mbedtls_ssl_cookie_setup(&cookie,
                                         mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        print_err("ssl_cookie_setup", ret); return 1;
    }
    mbedtls_ssl_conf_dtls_cookies(&conf, mbedtls_ssl_cookie_write,
                                   mbedtls_ssl_cookie_check, &cookie);

    /* Create the SSL context (reused across trials via session_reset) */
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        print_err("ssl_setup", ret); return 1;
    }

    /* Bind listening UDP socket */
    if ((ret = mbedtls_net_bind(&listen_fd, NULL, port, MBEDTLS_NET_PROTO_UDP)) != 0) {
        print_err("net_bind", ret); return 1;
    }

    printf("DTLS 1.2 PSK server listening on UDP port %s\n", port);
    printf("PSK identity : %s  |  PSK length: %zu bytes\n", psk_id, psk_len);
    printf("Ciphersuite  : TLS_PSK_WITH_AES_128_GCM_SHA256 (DTLS 1.2)\n");
    printf("mbedTLS      : %s\n", MBEDTLS_VERSION_STRING);
    fflush(stdout);

    unsigned long n_trials = 0;
    unsigned char buf[MAX_BUF];
    char logbuf[512];

    while (!g_stop) {
        /* ── Reset for new trial ────────────────────────────────────────────── */
        mbedtls_net_free(&client_fd);
        mbedtls_net_init(&client_fd);

        if ((ret = mbedtls_ssl_session_reset(&ssl)) != 0) {
            print_err("ssl_session_reset", ret);
            break;
        }

        /* Timer must be re-set after session_reset */
        mbedtls_ssl_set_timer_cb(&ssl, &timer,
                                  mbedtls_timing_set_delay,
                                  mbedtls_timing_get_delay);

        log_event("Waiting for client...");

        /* ── Accept new DTLS client ─────────────────────────────────────────── */
        unsigned char client_ip[16];
        size_t cilen = 0;

        ret = mbedtls_net_accept(&listen_fd, &client_fd,
                                  client_ip, sizeof(client_ip), &cilen);
        if (ret != 0) {
            if (g_stop) break;
            print_err("net_accept", ret);
            continue;
        }

        /* Cookie needs the client's network address as transport ID */
        if (cilen > 0) {
            ret = mbedtls_ssl_set_client_transport_id(&ssl, client_ip, cilen);
            if (ret != 0) {
                print_err("set_client_transport_id", ret);
                continue;
            }
        }

        mbedtls_ssl_set_bio(&ssl, &client_fd,
                             mbedtls_net_send,
                             mbedtls_net_recv,
                             mbedtls_net_recv_timeout);

        /* ── DTLS handshake ─────────────────────────────────────────────────── */
        log_event("Starting handshake...");
        do { ret = mbedtls_ssl_handshake(&ssl); }
        while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (ret != 0) {
            print_err("ssl_handshake", ret);
            continue;
        }
        log_event("Handshake OK. Waiting for command...");

        /* ── Receive command ────────────────────────────────────────────────── */
        int len;
        do { len = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1); }
        while (len == MBEDTLS_ERR_SSL_WANT_READ ||
               len == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (len <= 0) {
            if (len != 0) print_err("ssl_read", len);
            continue;
        }
        buf[len] = '\0';
        n_trials++;

        snprintf(logbuf, sizeof(logbuf),
                 "Trial %lu: recv %d bytes: %.120s", n_trials, len, (char *)buf);
        log_event(logbuf);

        /* ── Extract trial_id and build ACK ─────────────────────────────────── */
        char trial_id[64];
        extract_trial_id((const char *)buf, trial_id, sizeof(trial_id));

        char ack[256];
        int ack_len = snprintf(ack, sizeof(ack),
                               "{\"trial_id\":\"%s\",\"ack\":\"OK\"}", trial_id);

        /* ── Send ACK ───────────────────────────────────────────────────────── */
        do { ret = mbedtls_ssl_write(&ssl, (unsigned char *)ack, (size_t)ack_len); }
        while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (ret < 0) {
            print_err("ssl_write", ret);
            continue;
        }

        snprintf(logbuf, sizeof(logbuf),
                 "Trial %lu: sent ACK for trial_id=%s", n_trials, trial_id);
        log_event(logbuf);

        /* ── Graceful close ─────────────────────────────────────────────────── */
        do { ret = mbedtls_ssl_close_notify(&ssl); }
        while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE);
        /* Ignore close_notify errors — client may have already closed */
    }

    log_event("Server shutting down...");

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_cookie_free(&cookie);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    printf("Server stopped. Served %lu trials.\n", n_trials);
    return 0;
}
