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
  
#define R(v,n)(((v)<<(n))|((v)>>(8-(n))))
#define X(x,y)t=x,x=y,y=t;

typedef unsigned char B;
typedef unsigned int W;

// S-Layer
void S(void *p) {
    B t, *x=(B*)p;
    
    t = x[3]; 
    x[3] &= x[2]; 
    x[3] ^= x[1];
    x[1] |= x[2];
     
    x[1] ^= x[0];
    x[0] &= x[3]; 
    x[0] ^=  t; 
    t    &= x[1];    
    x[2] ^=  t;
}

// encrypt 64-bits of data using 128-bit key  
void roadrunner(void *mk, void *data) {
    int i, j, r;
    W   t, *x=(W*)data, *k=(W*)mk;
    B   s, *p, k_idx=0;
    
    // apply K-Layer
    x[0] ^= ((W*)mk)[0];
    
    // apply 12 rounds of encryption
    for(r=12; r>0; r--) {
      // F round
      t = x[0];
      p = (B*)x;
      for(i=3; i>0; i--) {
        // add constant
        if(i==1) p[3] ^= r;
        // apply S-Layer
        S(p);
        k_idx = (k_idx+4) % 16;
        
        for (j=3; j>=0; j--) {      
          // apply L-Layer
          s = R(p[j], 1) ^ p[j];       
          s = R(s, 1) ^ p[j]; 
          // apply K-Layer
          p[j] = s ^ ((B*)k)[k_idx+j];
        }
      }
      // apply S-Layer
      S(p);
      // add upper 32-bits
      x[0]^= x[1]; 
      x[1] = t;
    }
    // permute
    X(x[0], x[1]);
    // apply K-Layer
    x[0] ^= ((W*)mk)[1];
}