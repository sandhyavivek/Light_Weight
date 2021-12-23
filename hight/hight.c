/**
  Copyright (C) 2018 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#include "hight.h"

// use lookup table for constants
#ifndef DYNAMIC
uint8_t rc[128]=
{ 0x5a, 0x6d, 0x36, 0x1b, 0x0d, 0x06, 0x03, 0x41,
  0x60, 0x30, 0x18, 0x4c, 0x66, 0x33, 0x59, 0x2c,
  0x56, 0x2b, 0x15, 0x4a, 0x65, 0x72, 0x39, 0x1c,
  0x4e, 0x67, 0x73, 0x79, 0x3c, 0x5e, 0x6f, 0x37,
  0x5b, 0x2d, 0x16, 0x0b, 0x05, 0x42, 0x21, 0x50,
  0x28, 0x54, 0x2a, 0x55, 0x6a, 0x75, 0x7a, 0x7d,
  0x3e, 0x5f, 0x2f, 0x17, 0x4b, 0x25, 0x52, 0x29,
  0x14, 0x0a, 0x45, 0x62, 0x31, 0x58, 0x6c, 0x76,
  0x3b, 0x1d, 0x0e, 0x47, 0x63, 0x71, 0x78, 0x7c,
  0x7e, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x43, 0x61,
  0x70, 0x38, 0x5c, 0x6e, 0x77, 0x7b, 0x3d, 0x1e,
  0x4f, 0x27, 0x53, 0x69, 0x34, 0x1a, 0x4d, 0x26,
  0x13, 0x49, 0x24, 0x12, 0x09, 0x04, 0x02, 0x01,
  0x40, 0x20, 0x10, 0x08, 0x44, 0x22, 0x11, 0x48,
  0x64, 0x32, 0x19, 0x0c, 0x46, 0x23, 0x51, 0x68,
  0x74, 0x3a, 0x5d, 0x2e, 0x57, 0x6b, 0x35, 0x5a };
#else

void gen_const(uint8_t *ci)
{
    int     i, j;
    uint8_t c;
    
    union {
      uint8_t  b[128+8];
      uint32_t w[(128+8)/4];
    } s;

    // zero initialize s
    memset(&s, 0, sizeof(s));

    // set initial bits
    s.w[1] = 65537;
    s.w[0] = s.w[1] << 8;

    // set first constant
    // calculated from bits of s array
    ci[0] = 0x5A;

    for(i=1; i<128; i++) {
      c = s.b[i + 2] ^
          s.b[i - 1];

      s.b[i + 6] = c;

      for(j=1; j<7; j++) {
        c += c;
        c ^= s.b[i + 6 - j];
      }
      ci[i] = c;
    }
}
#endif

void hight128_setkey(void *in, void *out)
{
    uint8_t i, j, idx;
    w128_t  *wk, *mk;
    uint8_t *sk;
    
    mk=(w128_t*)in;
    wk=(w128_t*)out;
    sk=(uint8_t*)out;
    

    wk->w[0] = mk->w[3];
    wk->w[1] = mk->w[0];

    #ifdef LUT
      memcpy(&sk[8], rc, sizeof(rc));
    #else  
      // generate constants
      gen_const(&sk[8]);
    #endif
 
    // generate subkeys
    for(i=0; i<8; i++) {
      sk += 8;
      for(j=0; j<8; j++) {
        idx = (j - i + 8) & 7;

        sk[0] += mk->b[idx  ];
        sk[8] += mk->b[idx+8];
        sk++;        
      }
    }
}

uint8_t F0(uint8_t x) {
    return ROTL8(x, 1) ^ ROTL8(x, 2) ^ ROTL8(x, 7);
}

uint8_t F1(uint8_t x) {
    return ROTL8(x, 3) ^ ROTL8(x, 4) ^ ROTL8(x, 6);
}

void hight128_encrypt(void *data, void *keys)
{
    int      i;
    w64_t    *x;
    uint8_t  *sk, *wk=(uint8_t*)keys;

    x  = (w64_t*)data;
    sk = &wk[8];

    // mix key with 1st 4 bytes
    x->b[0] += wk[0]; x->b[2] ^= wk[1];
    x->b[4] += wk[2]; x->b[6] ^= wk[3];

    for(i=0; i<32; i++) {
      // circular shift left by 8 bits
      x->q = ROTL64(x->q, 8);
      // apply linear/non-linear operations
      x->b[2] += (F1(x->b[1]) ^ *sk++);
      x->b[4] ^= (F0(x->b[3]) + *sk++);
      x->b[6] += (F1(x->b[5]) ^ *sk++);
      x->b[0] ^= (F0(x->b[7]) + *sk++);
    }
    // circular shift right by 8 bits
    x->q = ROTL64(x->q, 56);

    // mix key with 2nd 4 bytes
    x->b[0] += wk[4]; x->b[2] ^= wk[5];
    x->b[4] += wk[6]; x->b[6] ^= wk[7];
}