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

static CRYS_RND_State_t rndState;
static CRYS_RND_WorkBuff_t rndWorkBuff;

nRFCrypto_ed25519::nRFCrypto_ed25519(void) {
  _begun = false;
}

bool nRFCrypto_ed25519::begin(void) {
  _begun = true;
  return true;
}

void nRFCrypto_ed25519::end(void) {
  _begun = false;
}

bool nRFCrypto_ed25519::generateKeyPair(uint8_t pSecrKey[], uint8_t pPublKey[]) {
  if (!_begun) return false;

  size_t secrKeySize = ED25519_KEY_SIZE_BYTES;
  size_t publKeySize = ED25519_KEY_SIZE_BYTES;

  CRYSError_t err = CRYS_ECEDW_KeyPair(pSecrKey, &secrKeySize, pPublKey, &publKeySize, &rndState, CRYS_RND_GenerateVector, &_tempBuff);

  VERIFY_ERROR(err, false);
  return true;
}

bool nRFCrypto_ed25519::sign(uint8_t pSign[], const uint8_t *pMsg, size_t msgSize, const uint8_t pSignSecrKey[]) {
  if (!_begun) return false;
  
  size_t signSize = ED25519_SIGNATURE_SIZE_BYTES;
  size_t secrKeySize = ED25519_KEY_SIZE_BYTES;

  CRYSError_t err = CRYS_ECEDW_Sign(pSign, &signSize, pMsg, msgSize, pSignSecrKey, secrKeySize, &_tempBuff);

  VERIFY_ERROR(err, false);
  return true;
}

bool nRFCrypto_ed25519::verify(const uint8_t pSign[ED25519_SIGNATURE_SIZE_BYTES], const uint8_t pSignPublKey[ED25519_KEY_SIZE_BYTES], const uint8_t *pMsg, size_t msgSize) {
  if (!_begun) return false;

  size_t signSize = ED25519_SIGNATURE_SIZE_BYTES;
  size_t publKeySize = ED25519_KEY_SIZE_BYTES;

  CRYSError_t err = CRYS_ECEDW_Verify(pSign, signSize, pSignPublKey, publKeySize, (uint8_t*)pMsg, msgSize, &_tempBuff);
 
  if (err != 0) return false; 
  return true;
}