#ifndef BLE_PROTOCOL_H
#define BLE_PROTOCOL_H

#include <Arduino.h>
#include "BLEDevice.h"
#include "CipherChannel.h"

#define BUTTON_PIN                  0   // Use the appropriate GPIO pin number
#define CLEAR_SECURE_KEY_BUTTON_PIN BUTTON_PIN

class BLEProtocol {
public:
    BLEProtocol();
    ~BLEProtocol();

    void setup();
    void checkConnect();
    void transmitMessage(const char* message);

    struct TransmitTiming {
        uint32_t trialId = 0;
        size_t payloadLen = 0;
        size_t ciphertextLen = 0;
        uint32_t ccSendUs = 0;
        uint32_t bleWriteUs = 0;
        uint32_t rttUs = 0;
        bool ackReceived = false;
    };

    bool transmitMessageTimed(const char* message,
                              uint32_t trialId,
                              uint32_t ackTimeoutMs,
                              TransmitTiming& timing);

    bool isConnected() const { return connected; }
    bool isReady() const { return connected && !needSecureKey; }

    bool loadSecureKey(unsigned char*, size_t);
    void storeSecureKey(const unsigned char *key, size_t keyLength);
    
    void requestSecureKey();
    void stopSharingSecureKey();
    void sendResetCommand();

    void setSecureKey(const unsigned char *key, size_t keyLength);
    void clearSecureKey();

    volatile bool stopSharingFlag;
    volatile bool needSecureKey;
private:
    static void notifyCallback(
        BLERemoteCharacteristic *pBLERemoteCharacteristic,
        uint8_t *pData,
        size_t length,
        bool isNotify
    );

    static uint32_t extractTrialId(const char* plaintext);
    static bool isAckPayload(const char* plaintext);

    bool connectToServer();

    class MyClientCallback : public BLEClientCallbacks {
        void onConnect(BLEClient *pclient) override;
        void onDisconnect(BLEClient *pclient) override;
    };

    class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
        void onResult(BLEAdvertisedDevice advertisedDevice) override;
    };

    // Member variables
    BLEUUID serviceUUID;
    BLEUUID cane2phoneUUID;
    BLEUUID caneSecurityUUID;
    BLEUUID caneResetUUID;

    bool doConnect;
    bool connected;
    bool doScan;

    BLERemoteCharacteristic *cane2phoneCharacteristic;
    BLERemoteCharacteristic *caneSecurityCharacteristic;
    BLERemoteCharacteristic *caneResetCharacteristic;

    BLEAdvertisedDevice *myDevice;
    BLEClient *client;

    CipherChannel *channel;
    CipherChannel *secureChannel;

    // Key material (should be securely stored and managed)
    unsigned char key[32];
    unsigned char secureKey[32];

    BLEAddress *serverAddress;

    volatile bool waitingForAck;
    volatile bool ackReceived;
    volatile uint32_t pendingAckTrialId;
    volatile uint32_t ackReceiveUs;
};

#endif // BLE_PROTOCOL_H
