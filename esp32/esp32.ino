#include "BLEProtocol.h"
#include "esp_system.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// ── Experiment M: ESP32 cane latency trials ──────────────────────────────────
// Sequential, one-command-at-a-time experiment. The gateway must send an
// encrypted ACK/notify payload on CANE2PHONE_UUID, e.g. {"action":"ACK","trial_id":N}.
#define EXP_LATENCY_MODE 1
#define EXP_TRIALS 1000
#define EXP_ACK_TIMEOUT_MS 2000
#define EXP_INTER_TRIAL_DELAY_MS 100

// Use 1 for cold-start / key-exchange experiments. Use 0 for steady-state
// latency after the secure key has already been provisioned and stored in NVS.
#define CLEAR_SECURE_KEY_ON_BOOT 1

BLEProtocol *bleProtocol = nullptr;
static uint32_t _msgId = 0;

void setup() {
    Serial.begin(115200);
    Serial.println("Starting Arduino BLE Client application...");

    bleProtocol = new BLEProtocol();
    bleProtocol->setup();

#if CLEAR_SECURE_KEY_ON_BOOT
    bleProtocol->clearSecureKey();
#endif

    Serial.println("CSV_TRIAL,trial_id,payload_len,ciphertext_len,cc_send_us,ble_write_us,rtt_us,ack_received");
    Serial.println("CSV_CONN,client_create_us,ble_connect_us,service_us,characteristics_us,notify_reg_us,total_us,success");
    Serial.println("CSV_KEX,cc_send_us,ble_write_us,key_wait_us,total_us,success,attempts");

    // ── Experiment L: resource stats at boot ──────────────────────────────────
    Serial.printf("[L] Build date/time   : %s %s\n", __DATE__, __TIME__);
    Serial.printf("[L] Free heap (post-init)  : %u bytes\n",
                  (unsigned)esp_get_free_heap_size());
    Serial.printf("[L] Min free heap so far   : %u bytes\n",
                  (unsigned)esp_get_minimum_free_heap_size());

    // NVS usage stats
    nvs_stats_t nvs_stats;
    if (nvs_get_stats(NULL, &nvs_stats) == ESP_OK) {
        Serial.printf("[L] NVS used_entries=%u  free_entries=%u  total_entries=%u\n",
                      nvs_stats.used_entries,
                      nvs_stats.free_entries,
                      nvs_stats.total_entries);
    }
}

void loop() {
    bleProtocol->checkConnect();

    if (digitalRead(BUTTON_PIN) == LOW) {
        bleProtocol->clearSecureKey();
        Serial.println("Secure key cleared from NVS");
        delay(200);
    }

#if EXP_LATENCY_MODE
    // Wait until the gateway is connected and the secure key is provisioned.
    if (!bleProtocol->isReady()) {
        delay(20);
        return;
    }

    if (_msgId >= EXP_TRIALS) {
        static bool printedDone = false;
        if (!printedDone) {
            Serial.printf("CSV_DONE,trials=%u\n", _msgId);
            printedDone = true;
        }
        delay(1000);
        return;
    }

    ++_msgId;

    // Trial payload. t_send_us is for debugging only; RTT must be computed on the ESP32 clock.
    char msgBuf[128];
    snprintf(msgBuf, sizeof(msgBuf),
             "{\"action\":\"STOP\",\"trial_id\":%u,\"msg_id\":\"C_%04u\",\"t_send_us\":%lu}",
             _msgId, _msgId, (unsigned long)micros());

    BLEProtocol::TransmitTiming timing;
    bleProtocol->transmitMessageTimed(
        msgBuf,
        _msgId,
        EXP_ACK_TIMEOUT_MS,
        timing
    );

    Serial.printf("CSV_TRIAL,%u,%u,%u,%lu,%lu,%lu,%u\n",
                  timing.trialId,
                  (unsigned)timing.payloadLen,
                  (unsigned)timing.ciphertextLen,
                  (unsigned long)timing.ccSendUs,
                  (unsigned long)timing.bleWriteUs,
                  (unsigned long)timing.rttUs,
                  timing.ackReceived ? 1 : 0);

    // ── Experiment L: periodic heap and stack reporting ────────────────────────
    if (_msgId % 50 == 0) {
        Serial.printf("[L] msg=%u  free_heap=%u  min_free_heap=%u  stack_hwm=%u bytes\n",
                      _msgId,
                      (unsigned)esp_get_free_heap_size(),
                      (unsigned)esp_get_minimum_free_heap_size(),
                      (unsigned)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)));
    }

    delay(EXP_INTER_TRIAL_DELAY_MS);
#else
    // Original background heartbeat path, retained only for Experiment K-style stress tests.
    char msgBuf[80];
    ++_msgId;
    snprintf(msgBuf, sizeof(msgBuf),
             "{\"action\":\"STOP\",\"msg_id\":\"C_%04u\",\"t_send_ms\":%lu}",
             _msgId, (unsigned long)millis());

    bleProtocol->transmitMessage(msgBuf);
    delay(1000);
#endif
}
