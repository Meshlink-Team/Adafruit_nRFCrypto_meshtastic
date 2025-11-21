/*
   The MIT License (MIT)
   Copyright (c) 2021 by Kongduino
   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:
   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
*/

#include "Adafruit_nRFCrypto.h"
#include "nRFCrypto_ed25519.h"

nRFCrypto_ed25519::nRFCrypto_ed25519(void) {
  _begun = false;
}

bool nRFCrypto_ed25519::begin(void) {
  _begun = true;
  rng.begin(); //we need to make sure RNG is initialized before generating keys
  return true;
}

void nRFCrypto_ed25519::end(void) {
  _begun = false;
  rng.end();
}

bool nRFCrypto_ed25519::generateKeyPair(uint8_t *pSecrKey, uint8_t *pPublKey) {
  if (!_begun) return false;

  size_t secrKeySize = 2 * ED25519_KEY_SIZE_BYTES; // as said in crys_ec_adw_api.h we need the keySize to be 2*algorithm signature size, in our case 2*256 bits
  size_t publKeySize = ED25519_KEY_SIZE_BYTES; // as before but public key must be at least the size of the signature
  CRYS_RND_State_t *rndState = rng.getContext(); // need the pointer to the rng context in order to use it later

  VERIFY_ERROR(CRYS_ECEDW_KeyPair(pSecrKey, &secrKeySize, pPublKey, &publKeySize, rndState, CRYS_RND_GenerateVector, &_tempBuff), false);
  // when fixing we discovered that you can get the specific error (if there is one) by checking the base addresses in the various *_error.h files and checking the value after the base adddress to get to the specific one
  return true;
}

bool nRFCrypto_ed25519::sign(uint8_t *pSign, const uint8_t *pMsg, size_t msgSize, const uint8_t *pSignSecrKey) {
  if (!_begun) return false;
  
  size_t signSize = 2 * ED25519_SIGNATURE_SIZE_BYTES;
  size_t secrKeySize = 2 * ED25519_KEY_SIZE_BYTES;

  VERIFY_ERROR(CRYS_ECEDW_Sign(pSign, &signSize, pMsg, msgSize, pSignSecrKey, secrKeySize, &_tempBuff), false);

  return true;
}

bool nRFCrypto_ed25519::verify(const uint8_t *pSign, const uint8_t *pSignPublKey, const uint8_t *pMsg, size_t msgSize) {
  if (!_begun) return false;

  size_t signSize = ED25519_SIGNATURE_SIZE_BYTES;
  size_t publKeySize = ED25519_KEY_SIZE_BYTES;

  CRYSError_t err;
  err = CRYS_ECEDW_Verify(pSign, signSize, pSignPublKey, publKeySize, (uint8_t*)pMsg, msgSize, &_tempBuff);
  if(err != 0)
    return false;
  return true;
}