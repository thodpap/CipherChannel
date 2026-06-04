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
};

#endif // BLE_PROTOCOL_H
