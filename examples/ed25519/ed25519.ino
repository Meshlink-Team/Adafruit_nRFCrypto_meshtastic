#include "Adafruit_nRFCrypto.h"
#include <Adafruit_TinyUSB.h> // for Serial
//prova
/*
Execution times in hardware (time measuring using scilloscope)
ec.generateKeyPair(pSecrKey, pPublKey) 502 ns
ec.sign(pSign, random_data, DATA_SIZE, pSecrKey) 562 ns
ec.verify(pFakeSign, pPublKey, random_data, DATA_SIZE) 614 ns

Execution times in software (time measuring using scilloscope)
ec.sign() 170 ms
ec.verify() 
*/
#define ED25519_KEY_SIZE_BYTES 32
#define ED25519_SIGNATURE_SIZE_BYTES 64
#define DATA_SIZE  48
uint8_t pSecrKey[2 * ED25519_KEY_SIZE_BYTES];
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

uint8_t tampered_data[DATA_SIZE] = {
    0xF4, 0x04, 0x8E, 0x1B, 0xA7, 0x03, 0x9D, 0x5F, 
    0x6A, 0xC1, 0xE8, 0xB2, 0x77, 0xD0, 0x51, 0x3A,
    0x49, 0x22, 0xC5, 0x99, 0x0F, 0xB4, 0x33, 0xD1, 
    0x85, 0x76, 0xA2, 0x4E, 0xC0, 0x6B, 0x18, 0x93,
    0x71, 0xD6, 0x0A, 0xB0, 0x5C, 0x24, 0xD5, 0xF7, 
    0x8F, 0x14, 0xC9, 0xA6, 0x5D, 0x3B, 0x62, 0x98
};

uint8_t pFakeSign[ED25519_SIGNATURE_SIZE_BYTES] = {
    0x1C, 0x1D, 0x01, 0x8E, 0x08, 0x53, 0xD1, 0x0B, 0xCF, 0x77, 0xE7, 0x31, 0xCF, 0x16, 0x77, 0xA0, 
    0x39, 0xDE, 0x43, 0xC2, 0x0F, 0xF8, 0x6A, 0x9F, 0x7E, 0x22, 0x14, 0x07, 0xE2, 0xE9, 0x0D, 0x9C, 
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
    
    Serial.flush();
    Serial.println("Private Key:");
    Serial.printBuffer((uint8_t *)pSecrKey, 2 * ED25519_KEY_SIZE_BYTES, ' ', 16);
    Serial.println();
    Serial.println();
    Serial.println("Public Key:");
    Serial.printBuffer((uint8_t *)pPublKey, ED25519_KEY_SIZE_BYTES, ' ', 16);
    Serial.println();
    Serial.println();
    Serial.println("Sign:");
    Serial.printBuffer((uint8_t *)pSign, 2 * ED25519_KEY_SIZE_BYTES, ' ', 16);
    Serial.println();
    Serial.println();
    Serial.println("Verify with Fake pSign:");
    Serial.println(ec.verify(pFakeSign, pPublKey, random_data, DATA_SIZE));
    Serial.println();
    Serial.println();
    Serial.println("Verify with tampered data:");
    Serial.println(ec.verify(pSign, pPublKey, tampered_data, DATA_SIZE));
    Serial.println();
    Serial.println();
    Serial.println("Verify with Real pSign:");
    Serial.println(ec.verify(pSign, pPublKey, random_data, DATA_SIZE));

    ec.end();
    nRFCrypto.end();
}

void loop()
{

}