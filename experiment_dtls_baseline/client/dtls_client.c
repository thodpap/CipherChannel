/*
 * dtls_client.c — DTLS 1.2 PSK benchmarking client for CipherChannel baseline.
 *
 * Transport : UDP/IP (NOT BLE/GATT).
 * Protocol  : DTLS 1.2, PSK-AES-128-GCM-SHA256.
 * Library   : mbedTLS 3.x.
 *
 * Cold-start definition: each trial creates a fresh UDP socket and DTLS
 * session, performs the full handshake, sends one command, receives one ACK,
 * then closes the session.  The shared entropy/RNG is initialised once at
 * program start (same as CipherChannel, which initialises AES once).
 *
 * Usage:
 *   ./dtls_client --host RPI_IP [--port PORT] [--trials N] [--dry-run]
 *                 [--inter-ms N] [--timeout-ms N]
 *                 [--psk-id ID] [--psk-hex HEX] [--output PATH]
 *
 * CSV columns (one row per trial):
 *   trial_id, success, error,
 *   t0_start_ns, t1_socket_ready_ns, t2_handshake_done_ns,
 *   t3_command_sent_ns, t4_ack_received_ns,
 *   socket_setup_ms, handshake_ms, command_ack_ms, total_ms,
 *   payload_len, ack_len
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "mbedtls/build_info.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/timing.h"

/* ── defaults ───────────────────────────────────────────────────────────────── */
#define DEFAULT_HOST        "192.168.1.100"   /* override with --host */
#define DEFAULT_PORT        "4433"
#define DEFAULT_TRIALS      500
#define DEFAULT_INTER_MS    250
#define DEFAULT_TIMEOUT_MS  5000
#define DEFAULT_PSK_ID      "exo-dtls-client"
#define DEFAULT_OUTPUT      "results/dtls_trials.csv"
#define MAX_BUF             1024

static const unsigned char DEFAULT_PSK[16] = {
    0xde, 0xad, 0xbe, 0xef,  0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,  0x09, 0x0a, 0x0b, 0x0c
};

static const int PSK_CIPHERSUITES[] = {
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    0
};

/* ── global shared RNG (initialised once) ───────────────────────────────────── */
static mbedtls_entropy_context  g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* ── timing helpers ─────────────────────────────────────────────────────────── */

static long long mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static double ns_to_ms(long long ns) {
    return (double)ns / 1.0e6;
}

static void sleep_ms(int ms) {
    if (ms <= 0) return;
    struct timespec ts = {
        .tv_sec  = (time_t)(ms / 1000),
        .tv_nsec = (long)((ms % 1000) * 1000000L)
    };
    nanosleep(&ts, NULL);
}

/* ── utility ────────────────────────────────────────────────────────────────── */

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

/* ── per-trial data structures ──────────────────────────────────────────────── */

typedef struct {
    const char          *host;
    const char          *port;
    const char          *psk_id;
    const unsigned char *psk;
    size_t               psk_len;
    int                  timeout_ms;
    int                  trial_num;
} trial_params_t;

typedef struct {
    int   trial_id;
    int   success;
    char  error[256];
    /* raw monotonic timestamps (nanoseconds) */
    long long t0_start_ns;
    long long t1_socket_ready_ns;
    long long t2_handshake_done_ns;
    long long t3_command_sent_ns;
    long long t4_ack_received_ns;
    /* derived latencies (milliseconds) */
    double socket_setup_ms;
    double handshake_ms;
    double command_ack_ms;
    double total_ms;
    int    payload_len;
    int    ack_len;
} trial_result_t;

/* ── core trial function ────────────────────────────────────────────────────── */

static void run_trial(const trial_params_t *p, trial_result_t *r) {
    r->success = 0;
    r->error[0] = '\0';
    r->payload_len = 0;
    r->ack_len = 0;
    r->t2_handshake_done_ns = 0;
    r->t3_command_sent_ns   = 0;
    r->t4_ack_received_ns   = 0;

    mbedtls_net_context  server_fd;
    mbedtls_ssl_context  ssl;
    mbedtls_ssl_config   conf;
    mbedtls_timing_delay_context timer;
    int ret;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    /* ── t0: trial start ────────────────────────────────────────────────────── */
    r->t0_start_ns = mono_ns();

    /* ── t0→t1: create UDP socket and connect to server ────────────────────── */
    ret = mbedtls_net_connect(&server_fd, p->host, p->port, MBEDTLS_NET_PROTO_UDP);
    r->t1_socket_ready_ns = mono_ns();

    if (ret != 0) {
        char eb[128]; mbedtls_strerror(ret, eb, sizeof(eb));
        snprintf(r->error, sizeof(r->error), "net_connect -0x%04x: %s",
                 (unsigned int)(-ret), eb);
        goto cleanup;
    }

    /* Configure DTLS 1.2 with PSK (fresh config per trial = cold-start) */
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        char eb[128]; mbedtls_strerror(ret, eb, sizeof(eb));
        snprintf(r->error, sizeof(r->error), "ssl_config_defaults -0x%04x: %s",
                 (unsigned int)(-ret), eb);
        goto cleanup;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);
    mbedtls_ssl_conf_ciphersuites(&conf, PSK_CIPHERSUITES);
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_read_timeout(&conf, (uint32_t)p->timeout_ms);

    if ((ret = mbedtls_ssl_conf_psk(&conf,
                                     p->psk, p->psk_len,
                                     (const unsigned char *)p->psk_id,
                                     strlen(p->psk_id))) != 0) {
        char eb[128]; mbedtls_strerror(ret, eb, sizeof(eb));
        snprintf(r->error, sizeof(r->error), "ssl_conf_psk -0x%04x: %s",
                 (unsigned int)(-ret), eb);
        goto cleanup;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        char eb[128]; mbedtls_strerror(ret, eb, sizeof(eb));
        snprintf(r->error, sizeof(r->error), "ssl_setup -0x%04x: %s",
                 (unsigned int)(-ret), eb);
        goto cleanup;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd,
                         mbedtls_net_send,
                         mbedtls_net_recv,
                         mbedtls_net_recv_timeout);

    /* Timer callback is required for DTLS retransmission */
    mbedtls_ssl_set_timer_cb(&ssl, &timer,
                              mbedtls_timing_set_delay,
                              mbedtls_timing_get_delay);

    /* ── t1→t2: DTLS handshake (includes PSK key exchange) ─────────────────── */
    do { ret = mbedtls_ssl_handshake(&ssl); }
    while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    r->t2_handshake_done_ns = mono_ns();

    if (ret != 0) {
        char eb[128]; mbedtls_strerror(ret, eb, sizeof(eb));
        snprintf(r->error, sizeof(r->error), "ssl_handshake -0x%04x: %s",
                 (unsigned int)(-ret), eb);
        goto cleanup;
    }

    /* ── t2→t3: send command payload ────────────────────────────────────────── */
    char payload[256];
    int plen = snprintf(payload, sizeof(payload),
                        "{\"trial_id\":\"t%04d\",\"action\":\"STAND_UP\"}",
                        p->trial_num);
    r->payload_len = plen;

    do { ret = mbedtls_ssl_write(&ssl, (unsigned char *)payload, (size_t)plen); }
    while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    r->t3_command_sent_ns = mono_ns();

    if (ret < 0) {
        char eb[128]; mbedtls_strerror(ret, eb, sizeof(eb));
        snprintf(r->error, sizeof(r->error), "ssl_write -0x%04x: %s",
                 (unsigned int)(-ret), eb);
        goto cleanup;
    }

    /* ── t3→t4: receive ACK ─────────────────────────────────────────────────── */
    unsigned char buf[MAX_BUF];
    int len;
    do { len = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1); }
    while (len == MBEDTLS_ERR_SSL_WANT_READ ||
           len == MBEDTLS_ERR_SSL_WANT_WRITE);

    r->t4_ack_received_ns = mono_ns();

    if (len <= 0) {
        char eb[128]; mbedtls_strerror(len, eb, sizeof(eb));
        snprintf(r->error, sizeof(r->error), "ssl_read -0x%04x: %s",
                 (unsigned int)(-len), eb);
        goto cleanup;
    }

    r->ack_len = len;
    r->success = 1;

    /* Graceful DTLS close — ignore errors (server may have already closed) */
    do { ret = mbedtls_ssl_close_notify(&ssl); }
    while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

cleanup:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_net_free(&server_fd);

    /* Fill any timestamps that weren't reached (failed early) */
    long long now = mono_ns();
    if (r->t2_handshake_done_ns == 0) r->t2_handshake_done_ns = now;
    if (r->t3_command_sent_ns   == 0) r->t3_command_sent_ns   = r->t2_handshake_done_ns;
    if (r->t4_ack_received_ns   == 0) r->t4_ack_received_ns   = r->t3_command_sent_ns;

    r->socket_setup_ms = ns_to_ms(r->t1_socket_ready_ns   - r->t0_start_ns);
    r->handshake_ms    = ns_to_ms(r->t2_handshake_done_ns - r->t1_socket_ready_ns);
    r->command_ack_ms  = ns_to_ms(r->t4_ack_received_ns   - r->t3_command_sent_ns);
    r->total_ms        = ns_to_ms(r->t4_ack_received_ns   - r->t0_start_ns);
}

/* ── CSV I/O ────────────────────────────────────────────────────────────────── */

static void write_csv_header(FILE *f) {
    fprintf(f,
            "trial_id,success,error,"
            "t0_start_ns,t1_socket_ready_ns,t2_handshake_done_ns,"
            "t3_command_sent_ns,t4_ack_received_ns,"
            "socket_setup_ms,handshake_ms,command_ack_ms,total_ms,"
            "payload_len,ack_len\n");
}

static void write_csv_row(FILE *f, const trial_result_t *r) {
    /* Escape any commas in the error string */
    char safe_error[256];
    strncpy(safe_error, r->error, sizeof(safe_error) - 1);
    safe_error[sizeof(safe_error) - 1] = '\0';
    for (char *c = safe_error; *c; c++) {
        if (*c == ',') *c = ';';
        if (*c == '\n') *c = ' ';
    }

    fprintf(f,
            "t%04d,%s,%s,"
            "%lld,%lld,%lld,%lld,%lld,"
            "%.4f,%.4f,%.4f,%.4f,"
            "%d,%d\n",
            r->trial_id,
            r->success ? "true" : "false",
            safe_error,
            r->t0_start_ns, r->t1_socket_ready_ns,
            r->t2_handshake_done_ns, r->t3_command_sent_ns,
            r->t4_ack_received_ns,
            r->socket_setup_ms, r->handshake_ms,
            r->command_ack_ms, r->total_ms,
            r->payload_len, r->ack_len);
}

/* ── usage ──────────────────────────────────────────────────────────────────── */

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "Options:\n"
            "  --host ADDR       Server IP/hostname (default: %s)\n"
            "  --port PORT       Server port (default: %s)\n"
            "  --trials N        Number of cold-start trials (default: %d)\n"
            "  --dry-run         Run 10 trials (smoke test)\n"
            "  --inter-ms N      Sleep between trials in ms (default: %d)\n"
            "  --timeout-ms N    Per-trial I/O timeout in ms (default: %d)\n"
            "  --psk-id ID       PSK identity string (default: %s)\n"
            "  --psk-hex HEX     PSK key as hex string (default: 16-byte test key)\n"
            "  --output PATH     CSV output file (default: %s)\n"
            "  --help            Show this help\n"
            "\n"
            "Example (dry-run):\n"
            "  ./dtls_client --host 192.168.1.50 --dry-run\n"
            "\n"
            "Example (full run):\n"
            "  ./dtls_client --host 192.168.1.50 --trials 500 --output results/dtls_trials.csv\n",
            prog,
            DEFAULT_HOST, DEFAULT_PORT, DEFAULT_TRIALS,
            DEFAULT_INTER_MS, DEFAULT_TIMEOUT_MS,
            DEFAULT_PSK_ID, DEFAULT_OUTPUT);
}

/* ── main ───────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const char *host       = DEFAULT_HOST;
    const char *port       = DEFAULT_PORT;
    int         num_trials = DEFAULT_TRIALS;
    int         inter_ms   = DEFAULT_INTER_MS;
    int         timeout_ms = DEFAULT_TIMEOUT_MS;
    const char *psk_id     = DEFAULT_PSK_ID;
    const char *output     = DEFAULT_OUTPUT;

    const unsigned char *psk = DEFAULT_PSK;
    size_t psk_len = sizeof(DEFAULT_PSK);
    unsigned char psk_buf[64];
    char psk_id_buf[128];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) { usage(argv[0]); return 0; }
        else if (strcmp(argv[i], "--dry-run") == 0) num_trials = 10;
        else if (i + 1 < argc) {
            if      (strcmp(argv[i], "--host")       == 0) host       = argv[++i];
            else if (strcmp(argv[i], "--port")       == 0) port       = argv[++i];
            else if (strcmp(argv[i], "--trials")     == 0) num_trials = atoi(argv[++i]);
            else if (strcmp(argv[i], "--inter-ms")   == 0) inter_ms   = atoi(argv[++i]);
            else if (strcmp(argv[i], "--timeout-ms") == 0) timeout_ms = atoi(argv[++i]);
            else if (strcmp(argv[i], "--output")     == 0) output     = argv[++i];
            else if (strcmp(argv[i], "--psk-id") == 0) {
                strncpy(psk_id_buf, argv[++i], sizeof(psk_id_buf) - 1);
                psk_id_buf[sizeof(psk_id_buf) - 1] = '\0';
                psk_id = psk_id_buf;
            } else if (strcmp(argv[i], "--psk-hex") == 0) {
                size_t l;
                if (hex_to_bytes(argv[++i], psk_buf, sizeof(psk_buf), &l) == 0) {
                    psk = psk_buf; psk_len = l;
                } else {
                    fprintf(stderr, "Invalid --psk-hex value\n");
                    return 1;
                }
            }
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* One-time RNG initialisation (shared across trials) */
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                                     (const unsigned char *)"dtls_cli", 8);
    if (ret != 0) {
        char eb[128]; mbedtls_strerror(ret, eb, sizeof(eb));
        fprintf(stderr, "ctr_drbg_seed failed: %s\n", eb);
        return 1;
    }

    /* Open output CSV */
    FILE *csv = fopen(output, "w");
    if (!csv) {
        fprintf(stderr, "Cannot open output file '%s': %s\n", output, strerror(errno));
        return 1;
    }
    write_csv_header(csv);

    printf("DTLS 1.2 PSK cold-start benchmark\n");
    printf("  Server      : %s:%s\n", host, port);
    printf("  PSK id      : %s  |  PSK len: %zu bytes\n", psk_id, psk_len);
    printf("  Trials      : %d  |  inter-trial: %d ms  |  timeout: %d ms\n",
           num_trials, inter_ms, timeout_ms);
    printf("  Output CSV  : %s\n\n", output);
    fflush(stdout);

    int n_ok = 0, n_fail = 0;

    trial_params_t params = {
        .host       = host,
        .port       = port,
        .psk_id     = psk_id,
        .psk        = psk,
        .psk_len    = psk_len,
        .timeout_ms = timeout_ms,
    };

    for (int i = 1; i <= num_trials && !g_stop; i++) {
        params.trial_num = i;

        trial_result_t result;
        memset(&result, 0, sizeof(result));
        result.trial_id = i;

        run_trial(&params, &result);

        write_csv_row(csv, &result);
        fflush(csv);

        if (result.success) {
            n_ok++;
            printf("Trial %4d/%d  OK   total=%7.2f ms  hs=%7.2f ms  cmd_ack=%6.2f ms\n",
                   i, num_trials,
                   result.total_ms, result.handshake_ms, result.command_ack_ms);
        } else {
            n_fail++;
            printf("Trial %4d/%d  FAIL %s\n", i, num_trials, result.error);
        }
        fflush(stdout);

        if (i < num_trials && !g_stop) {
            sleep_ms(inter_ms);
        }
    }

    fclose(csv);
    mbedtls_ctr_drbg_free(&g_ctr_drbg);
    mbedtls_entropy_free(&g_entropy);

    int total = n_ok + n_fail;
    printf("\n--- Done ---\n");
    printf("Trials: %d  OK: %d  Failed: %d  Success rate: %.1f%%\n",
           total, n_ok, n_fail,
           total > 0 ? 100.0 * n_ok / total : 0.0);
    printf("Results written to: %s\n", output);

    return (n_fail > 0) ? 1 : 0;
}
