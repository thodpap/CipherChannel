#include "BLEProtocol.h"
#include "esp_system.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// ── Experiment K: auto-send interval ─────────────────────────────────────────
// Set to 1000 ms for Experiment K (concurrent traffic).
// Original value was 4000 ms.
#define AUTO_SEND_INTERVAL_MS 1000

BLEProtocol *bleProtocol = nullptr;
static uint32_t _msgId = 0;

void setup() {
    Serial.begin(115200);
    Serial.println("Starting Arduino BLE Client application...");

    bleProtocol = new BLEProtocol();
    bleProtocol->setup();
    bleProtocol->clearSecureKey();

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

    // Build payload with message counter and send timestamp for Experiment K tracking
    char msgBuf[80];
    ++_msgId;
    snprintf(msgBuf, sizeof(msgBuf),
             "{\"action\":\"STOP\",\"msg_id\":\"C_%04u\",\"t_send_ms\":%lu}",
             _msgId, (unsigned long)millis());

    bleProtocol->transmitMessage(msgBuf);

    if (digitalRead(BUTTON_PIN) == LOW) {
        bleProtocol->clearSecureKey();
        Serial.println("Secure key cleared from NVS");
        delay(200);
    }

    // ── Experiment L: periodic heap and stack reporting ────────────────────────
    if (_msgId % 50 == 0) {
        Serial.printf("[L] msg=%u  free_heap=%u  min_free_heap=%u  stack_hwm=%u bytes\n",
                      _msgId,
                      (unsigned)esp_get_free_heap_size(),
                      (unsigned)esp_get_minimum_free_heap_size(),
                      (unsigned)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)));
    }

    delay(AUTO_SEND_INTERVAL_MS);
}
