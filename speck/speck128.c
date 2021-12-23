/**
  Copyright © 2017 Odzhan. All Rights Reserved.

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

#define R(v,n)(((v)>>(n))|((v)<<(64-(n))))
#define F(n)for(i=0;i<n;i++)
typedef unsigned long long W;

void speck128(void *mk, void *data) {
  W k[4],*x=data,i,t;

  // copy 256-bit master key to local memory
  F(4)k[i]=((W*)mk)[i];
  
  // apply 34 rounds
  F(34)
    // encrypt plaintext
    // linear/nonlinear layers, add key
    x[1]=(R(x[1],8)+x[0])^k[0],
    x[0]=R(x[0],61)^x[1],t=k[3],
    // create next subkey
    // linear/nonlinear layers, add round counter
    k[3]=(R(k[1],8)+k[0])^i,
    k[0]=R(k[0],61)^k[3],
    k[1]=k[2],k[2]=t;
}