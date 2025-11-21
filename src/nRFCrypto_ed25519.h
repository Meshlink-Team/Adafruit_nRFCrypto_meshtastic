/*
   The MIT License (MIT)
   Copyright (c) 2025 Meshtastic Team
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

#ifndef NRFCRYPTO_ED25519_H_
#define NRFCRYPTO_ED25519_H_

#include "nrf_cc310/include/crys_ec_edw_api.h"
#include "nrf_cc310/include/crys_ec_mont_edw_error.h"
#include "nrf_cc310/include/crys_rnd.h"

#define ED25519_KEY_SIZE_BYTES       32
#define ED25519_SIGNATURE_SIZE_BYTES 64

class nRFCrypto_ed25519 {
  public:
    nRFCrypto_ed25519(void);
    bool begin(void);
    void end(void);

    bool generateKeyPair(uint8_t *pSecrKey, uint8_t *PublKey);
    bool sign(uint8_t *pSign, const uint8_t *pMsg, size_t msgSize, const uint8_t *pSignSecrKey);
    bool verify(const uint8_t *pSign, const uint8_t *pSignPublKey, const uint8_t *pMsg, size_t msgSize);

  private:
    nRFCrypto_Random rng;
    bool _begun;
    CRYS_ECEDW_TempBuff_t _tempBuff; 
};

#endif /* NRFCRYPTO_ED25519_H_ */