#include <Adafruit_nRFCrypto.h>
#include <Adafruit_TinyUSB.h> // for Serial
/*
Message Encryption: Each DM is encrypted using the recipient's public key,
ensuring that only the recipient can decrypt the message with their private key.

Digital Signatures: Messages are signed with the sender's private key,
allowing the recipient to verify the sender's identity and ensuring the integrity of the message.
*/
uint8_t recipientPublicKey[32];
uint8_t recipientPrivateKey[32];
uint8_t senderPublicKey[32];
uint8_t senderPrivateKey[32];

uint8_t meshPacket[237];

void setup()
{

}

void loop()
{

}