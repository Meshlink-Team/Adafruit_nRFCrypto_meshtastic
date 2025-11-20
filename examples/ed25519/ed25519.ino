#include "Adafruit_nRFCrypto.h"
#include <Adafruit_TinyUSB.h> // for Serial

#define ED25519_KEY_SIZE_BYTES 32
#define ED25519_SIGNATURE_SIZE_BYTES 64
#define DATA_SIZE  48
uint8_t pSecrKey[ED25519_KEY_SIZE_BYTES];
uint8_t pPublKey[ED25519_KEY_SIZE_BYTES];
uint8_t pSign[ED25519_SIGNATURE_SIZE_BYTES];


uint8_t random_data[DATA_SIZE] = {
    0xF4, 0x2C, 0x8E, 0x1B, 0xA7, 0x03, 0x9D, 0x5F, 
    0x6A, 0xC1, 0xE8, 0xB2, 0x77, 0xD0, 0x51, 0x3A,
    0x49, 0x22, 0xC5, 0x99, 0x0F, 0xB4, 0x33, 0xD1, 
    0x85, 0x76, 0xA2, 0x4E, 0xC0, 0x6B, 0x18, 0x93,
    0x71, 0xD6, 0x0A, 0xB0, 0x5C, 0x24, 0xE3, 0xF7, 
    0x8F, 0x14, 0xC9, 0xA6, 0x5D, 0x3B, 0x62, 0x98
};

void setup()
{
    Serial.begin(115200);
    while (!Serial && millis() < 10000);

    nRFCrypto_ed25519 ec;
    Serial.println("INIT nRFCrypto...");
    nRFCrypto.begin();
    ec.begin();

    ec.generateKeyPair(pSecrKey, pPublKey);
    ec.sign(pSign, random_data, DATA_SIZE, pSecrKey);
    ec.verify(pSign, pPublKey, random_data, DATA_SIZE);
    
    ec.end();
    nRFCrypto.end();
}

void loop()
{

}