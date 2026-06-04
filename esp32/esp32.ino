#include "BLEProtocol.h"

BLEProtocol *bleProtocol = nullptr;

void setup() {
    Serial.begin(115200);
    Serial.println("Starting Arduino BLE Client application...");
    bleProtocol = new BLEProtocol();
    bleProtocol->setup();
    bleProtocol->clearSecureKey();
}

void loop() {
    bleProtocol->checkConnect();
    bleProtocol->transmitMessage("STOP");

    if (digitalRead(BUTTON_PIN) == LOW) { // Adjust logic for your wiring
        bleProtocol->clearSecureKey();
        // Optional: Provide feedback to the user
        Serial.println("Secure key cleared from NVS");
        // Debounce delay
        delay(200); // Adjust as necessary
    }

    delay(4000);
}
