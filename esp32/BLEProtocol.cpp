#include "BLEProtocol.h"
#include <nvs.h>
#include <nvs_flash.h>
#include <Arduino.h>
#include <vector>

BLEProtocol *bleProtocolInstance = nullptr; // For static callback access

BLEProtocol::BLEProtocol()
    : serviceUUID("12345678-0000-1000-8000-00805f9b34fb"),
      cane2phoneUUID("74278BDA-B644-4520-8F0C-720EAF059935"),
      caneSecurityUUID("FA87C0D0-AFAC-11DE-8A39-0800200C9A66"),
      caneResetUUID("D2B9A3D4-1A3D-0A6D-D7C8-B4D4D0A4B1E2"),
      doConnect(false),
      connected(false),
      doScan(false),
      cane2phoneCharacteristic(nullptr),
      caneSecurityCharacteristic(nullptr),
      caneResetCharacteristic(nullptr),
      myDevice(nullptr),
      client(nullptr),
      channel(nullptr),
      secureChannel(nullptr),
      stopSharingFlag(false),
      needSecureKey(false),
      serverAddress(nullptr)
{
    // Pre-shared transport key (must match the RPi server)
    const unsigned char tempKey[32] = {
        0x2A, 0xC3, 0x2C, 0x36, 0x73, 0xA4, 0xA2, 0xEE,
        0x49, 0x08, 0x53, 0x3E, 0xD0, 0xFF, 0x25, 0x84,
        0xBA, 0xE9, 0x95, 0xCA, 0x4E, 0x4C, 0xFF, 0x7A,
        0x4C, 0x25, 0x68, 0x04, 0x29, 0x04, 0x25, 0xF8
    };
    memcpy(key, tempKey, 32);

    // Load the secure key from NVS
    if (!loadSecureKey(secureKey, sizeof(secureKey))) {
        Serial.println("Secure key not found, will request from server");
        memset(secureKey, 0, sizeof(secureKey));
    } else {
        Serial.println("Secure key loaded from NVS");
    }

    // Initialise CipherChannels — load persisted counters from NVS, or create fresh.
    channel = CipherChannel::load("ble_chan");
    if (!channel) {
        channel = CipherChannel::create(key, true, "ble_chan");
        Serial.println("Base channel: created fresh (ble_chan)");
    } else {
        Serial.println("Base channel: loaded from NVS (ble_chan)");
    }

    secureChannel = CipherChannel::load("ble_sec");
    if (!secureChannel) {
        secureChannel = CipherChannel::create(secureKey, true, "ble_sec");
        Serial.println("Secure channel: created fresh (ble_sec)");
    } else {
        Serial.println("Secure channel: loaded from NVS (ble_sec)");
    }

    bleProtocolInstance = this;
}

BLEProtocol::~BLEProtocol() {
    delete channel;
    delete secureChannel;
}

void BLEProtocol::setup() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        Serial.println("Erasing NVS partition...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    BLEDevice::init("");

    BLEScan *pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
    pBLEScan->setInterval(15000);
    pBLEScan->setWindow(10000);
    pBLEScan->setActiveScan(true);
    pBLEScan->start(5, false);

    pinMode(CLEAR_SECURE_KEY_BUTTON_PIN, INPUT_PULLUP);
}

void BLEProtocol::checkConnect() {
    if (doConnect) {
        if (connectToServer()) {
            Serial.println("We are now connected to the BLE Server.");
            if (secureKey[0] == 0) {
                Serial.println("Requesting secure key from server...");
                this->requestSecureKey();
            } else {
                Serial.println("Sending RESET command...");
                this->sendResetCommand();
            }
        } else {
            Serial.println("Failed to connect to the server.");
        }
        doConnect = false;
        Serial.println("Scanning for devices...");
    }
    if (stopSharingFlag) {
        stopSharingSecureKey();
        stopSharingFlag = false;
        sendResetCommand();
    }
}

void BLEProtocol::transmitMessage(const char* message) {
    if (needSecureKey) {
        Serial.println("[BLE] Skipping transmit: secure key not yet provisioned");
        return;
    }
    if (connected && message != nullptr) {
        uint8_t ciphertext[CC_MAX_PACKET_LEN];
        size_t ciphertextLen = sizeof(ciphertext);

        if (!secureChannel->send(
                reinterpret_cast<const uint8_t*>(message),
                strlen(message),
                ciphertext,
                ciphertextLen)
        ) {
            Serial.println("[BLE] Encryption failed");
            return;
        }

        cane2phoneCharacteristic->writeValue(
            ciphertext,
            ciphertextLen
        );

        Serial.print("[BLE] Message sent: ");
        Serial.println(message);
        return;
    }

    if (!connected && doScan) {
        Serial.println("[BLE] Not connected. Starting BLE scan...");

        BLEScan* scan = BLEDevice::getScan();

        if (scan == nullptr) {
            Serial.println("[BLE] Failed to obtain BLE scanner");
            return;
        }
        scan->start(0);
        Serial.println("[BLE] BLE scan started");
        return;
    }

    if (message == nullptr) {
        Serial.println("[BLE] Cannot transmit: message is null");
    } else {
        Serial.println("[BLE] Cannot transmit: disconnected and scanning is disabled");
    }
}

void BLEProtocol::notifyCallback(
    BLERemoteCharacteristic *pBLERemoteCharacteristic,
    uint8_t *pData,
    size_t length,
    bool isNotify
) {
    if (!bleProtocolInstance) return;

    Serial.println(pBLERemoteCharacteristic->getUUID().toString().c_str());

    uint8_t plain[CC_MAX_PLAIN];
    size_t plainLen = sizeof(plain);

    // ── Security channel: server sends a new 32-byte secure key ──────────────
    if (pBLERemoteCharacteristic->getUUID().equals(bleProtocolInstance->caneSecurityUUID)) {
        if (!bleProtocolInstance->channel->receive(pData, length, plain, plainLen)) {
            Serial.println("Failed to decrypt security channel message.");
            return;
        }
        if (plainLen == 32) {
            bleProtocolInstance->stopSharingFlag = true;
            bleProtocolInstance->setSecureKey(plain, plainLen);
            Serial.println("Secure key updated!");
        } else {
            plain[plainLen] = '\0';
            Serial.print("WARNING: Discarding non-key message of length ");
            Serial.print(plainLen);
            Serial.print(" on security channel: ");
            Serial.println((char*)plain);
        }
        return;
    }

    // ── Secure channel: server sends an encrypted command ────────────────────
    if (!bleProtocolInstance->secureChannel->receive(pData, length, plain, plainLen)) {
        Serial.println("Failed to decrypt the message.");
        return;
    }
    Serial.println("Decryption successful.");
    plain[plainLen] = '\0';
    Serial.println((char*)plain);
}

bool BLEProtocol::connectToServer() {
    Serial.print("Forming a connection to ");

    client = BLEDevice::createClient();
    Serial.println(" - Created client");

    client->setClientCallbacks(new MyClientCallback());
    client->connect(myDevice);
    Serial.println(" - Connected to server");

    BLERemoteService *pRemoteService = client->getService(serviceUUID);
    if (pRemoteService == nullptr) {
        Serial.print("Failed to find our service UUID: ");
        Serial.println(serviceUUID.toString().c_str());
        client->disconnect();
        return false;
    }
    Serial.println(" - Found our service");

    cane2phoneCharacteristic    = pRemoteService->getCharacteristic(cane2phoneUUID);
    caneSecurityCharacteristic  = pRemoteService->getCharacteristic(caneSecurityUUID);
    caneResetCharacteristic     = pRemoteService->getCharacteristic(caneResetUUID);

    if (cane2phoneCharacteristic   == nullptr ||
        caneSecurityCharacteristic == nullptr ||
        caneResetCharacteristic    == nullptr) {
        Serial.println("Failed to find our characteristics");
        client->disconnect();
        return false;
    }
    Serial.println(" - Found our characteristics");

    if (cane2phoneCharacteristic->canNotify()) {
        cane2phoneCharacteristic->registerForNotify(notifyCallback);
    } else {
        Serial.println("cane2phoneCharacteristic cannot notify");
        client->disconnect();
        return false;
    }

    if (caneSecurityCharacteristic->canNotify()) {
        caneSecurityCharacteristic->registerForNotify(notifyCallback);
    } else {
        Serial.println("caneSecurityCharacteristic cannot notify");
        client->disconnect();
        return false;
    }

    if (serverAddress) delete serverAddress;
    serverAddress = new BLEAddress(myDevice->getAddress().toString().c_str());
    connected = true;
    return true;
}

void BLEProtocol::MyClientCallback::onConnect(BLEClient *pclient) {
    Serial.println("Client connected");
}

void BLEProtocol::MyClientCallback::onDisconnect(BLEClient *pclient) {
    bleProtocolInstance->connected = false;
    Serial.println("Client disconnected");
}

void BLEProtocol::MyAdvertisedDeviceCallbacks::onResult(BLEAdvertisedDevice advertisedDevice) {
    Serial.print("BLE Advertised Device found: ");
    Serial.println(advertisedDevice.toString().c_str());
    if (bleProtocolInstance->serverAddress == nullptr) {
        bleProtocolInstance->serverAddress = new BLEAddress("");
    }
    if (bleProtocolInstance->serverAddress->equals(advertisedDevice.getAddress())) {
        BLEDevice::getScan()->stop();
        if (bleProtocolInstance->myDevice) delete bleProtocolInstance->myDevice;
        bleProtocolInstance->myDevice   = new BLEAdvertisedDevice(advertisedDevice);
        bleProtocolInstance->doConnect  = true;
        bleProtocolInstance->doScan     = true;
    } else if (advertisedDevice.haveServiceUUID() &&
               advertisedDevice.isAdvertisingService(bleProtocolInstance->serviceUUID)) {
        BLEDevice::getScan()->stop();
        if (bleProtocolInstance->myDevice) delete bleProtocolInstance->myDevice;
        bleProtocolInstance->myDevice   = new BLEAdvertisedDevice(advertisedDevice);
        bleProtocolInstance->doConnect  = true;
        bleProtocolInstance->doScan     = true;
    }
}

// ── NVS key storage ───────────────────────────────────────────────────────────

void BLEProtocol::storeSecureKey(const unsigned char *key, size_t keyLength) {
    nvs_handle_t nvsHandle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvsHandle);
    if (err != ESP_OK) {
        Serial.println("Error opening NVS handle");
        return;
    }
    err = nvs_set_blob(nvsHandle, "secure_key", key, keyLength);
    if (err != ESP_OK) Serial.println("Error writing secure key to NVS");

    if (serverAddress) {
        const char *addressStr = serverAddress->toString().c_str();
        err = nvs_set_str(nvsHandle, "server_address", addressStr);
        if (err != ESP_OK) Serial.println("Error writing server address to NVS");
    }

    err = nvs_commit(nvsHandle);
    if (err != ESP_OK) {
        Serial.println("Error committing data to NVS");
    } else {
        Serial.println("Secure key and server address stored in NVS");
    }
    nvs_close(nvsHandle);
}

bool BLEProtocol::loadSecureKey(unsigned char *key, size_t keyLength) {
    nvs_handle_t nvsHandle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &nvsHandle);
    if (err != ESP_OK) {
        Serial.println("Error opening NVS handle for reading");
        return false;
    }
    size_t requiredSize = keyLength;
    err = nvs_get_blob(nvsHandle, "secure_key", key, &requiredSize);
    if (err != ESP_OK || requiredSize != keyLength) {
        Serial.println("Secure key not found in NVS or size mismatch");
        nvs_close(nvsHandle);
        return false;
    }
    char addressStr[18];
    size_t addressLen = sizeof(addressStr);
    bool ret = true;
    err = nvs_get_str(nvsHandle, "server_address", addressStr, &addressLen);
    if (err != ESP_OK) {
        Serial.println("Server address not found in NVS");
        ret = false;
    } else {
        serverAddress = new BLEAddress(addressStr);
    }
    nvs_close(nvsHandle);
    return ret;
}

void BLEProtocol::setSecureKey(const unsigned char *_key, size_t keyLength) {
    memcpy(secureKey, _key, 32);
    storeSecureKey(_key, 32);
    secureChannel->updateKey(secureKey, true);  // initiator=true: send even, receive odd
    // Do NOT reset the base channel — its counter must keep increasing so the
    // next STOP_SHARING (counter N+2) is strictly greater than the REQUEST_KEY
    // counter (N) the server already accepted.  Resetting to zero causes the
    // STOP_SHARING to arrive with nonce=2, which the server treats as a replay.
    needSecureKey = false;  // provisioning complete — allow transmitMessage()
    Serial.println("Secure channel key updated.");
}

void BLEProtocol::clearSecureKey() {
    Serial.println("Clearing secure key from NVS...");

    nvs_handle_t nvsHandle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvsHandle);
    if (err != ESP_OK) {
        Serial.println("Error opening NVS handle for clearing");
        return;
    }

    err = nvs_erase_key(nvsHandle, "secure_key");
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        Serial.println("secure_key not found in NVS");
    } else if (err != ESP_OK) {
        Serial.println("Error erasing secure key from NVS");
    } else {
        Serial.println("secure_key erased from NVS");
    }

    err = nvs_erase_key(nvsHandle, "server_address");
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        Serial.println("server_address not found in NVS");
    } else if (err != ESP_OK) {
        Serial.println("Error erasing server_address from NVS");
    } else {
        Serial.println("server_address erased from NVS");
    }

    err = nvs_commit(nvsHandle);
    if (err != ESP_OK) {
        Serial.println("Error committing NVS changes");
    } else {
        Serial.println("NVS changes committed");
    }
    nvs_close(nvsHandle);

    memset(secureKey, 0, sizeof(secureKey));

    if (serverAddress) delete serverAddress;
    serverAddress = new BLEAddress("");

    needSecureKey = true;
    Serial.println("Secure key cleared.");
}

// ── Encrypted writes to server characteristics ────────────────────────────────

void BLEProtocol::requestSecureKey() {
    const char *msg = "{\"action\":\"REQUEST_KEY\"}";
    uint8_t ciphertext[CC_MAX_PACKET_LEN];
    size_t ciphertextLen = sizeof(ciphertext);
    if (!channel->send((const uint8_t*)msg, strlen(msg), ciphertext, ciphertextLen)) {
        Serial.println("Failed to encrypt REQUEST_KEY command");
        return;
    }
    caneSecurityCharacteristic->writeValue(ciphertext, ciphertextLen);

    // bless 0.3.0 does not send GATT notify packets even when char.value is set.
    // The server populates the characteristic synchronously inside its write
    // handler, so by the time writeValue() returns the ATT Write Response the
    // encrypted key is already there.  Poll-read until we see the 60-byte
    // response: nonce(12) + ciphertext(32) + GCM-tag(16) = 60 bytes.
    for (int attempt = 0; attempt < 10; ++attempt) {
      delay(200);
  
      String val = caneSecurityCharacteristic->readValue();
  
      Serial.printf(
          "requestSecureKey: attempt %d, received %u bytes\n",
          attempt + 1,
          static_cast<unsigned>(val.length())
      );
  
      if (val.length() == 60) {
          Serial.println("requestSecureKey: key received via poll");
  
          uint8_t buffer[60];
          memcpy(buffer, val.c_str(), sizeof(buffer));
  
          notifyCallback(
              caneSecurityCharacteristic,
              buffer,
              sizeof(buffer),
              false
          );
  
          return;
      }
    }
  
    Serial.println("requestSecureKey: key not received via polling");
}

void BLEProtocol::stopSharingSecureKey() {
    const char *msg = "{\"action\":\"STOP_SHARING\"}";
    uint8_t ciphertext[CC_MAX_PACKET_LEN];
    size_t ciphertextLen = sizeof(ciphertext);
    if (!channel->send((const uint8_t*)msg, strlen(msg), ciphertext, ciphertextLen)) {
        Serial.println("Failed to encrypt STOP_SHARING command");
        return;
    }
    caneSecurityCharacteristic->writeValue(ciphertext, ciphertextLen);
}

void BLEProtocol::sendResetCommand() {
    const char *msg = "{\"action\":\"RESET\"}";
    uint8_t ciphertext[CC_MAX_PACKET_LEN];
    size_t ciphertextLen = sizeof(ciphertext);
    if (!secureChannel->send((const uint8_t*)msg, strlen(msg), ciphertext, ciphertextLen)) {
        Serial.println("Failed to encrypt RESET command");
        return;
    }
    Serial.println("Sending RESET command");
    caneResetCharacteristic->writeValue(ciphertext, ciphertextLen);
    delay(1000);
}
