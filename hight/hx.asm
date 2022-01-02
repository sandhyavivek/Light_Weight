;
;  Copyright © 2018 Odzhan. All Rights Reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions are
;  met:
;
;  1. Redistributions of source code must retain the above copyright
;  notice, this list of conditions and the following disclaimer.
;
;  2. Redistributions in binary form must reproduce the above copyright
;  notice, this list of conditions and the following disclaimer in the
;  documentation and/or other materials provided with the distribution.
;
;  3. The name of the author may not be used to endorse or promote products
;  derived from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
;  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
;  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
;  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;  POSSIBILITY OF SUCH DAMAGE.

; -----------------------------------------------
; HIGHT-64/128 block cipher in x86 assembly
;
; size: 283 bytes
;
; global calls use cdecl convention
;
; -----------------------------------------------


    bits 32

gen_constx:
    pushad
    mov    esi, edi ; esi = ci
    xor    eax, eax
    mov    cl, 80h + 8 ; allocate 136 bytes
    sub    esp, ecx
    mov    edi, esp
    ; memset(&s, 0, sizeof(s));
    rep    stosb
    ; s.w[1] = 65537;
    mov    dword[esp+4], 65537
    ; s.w[0] = s.w[1] << 8;
    mov    dword[esp+0], 65537 << 8
    ; ci[0] = 0x5A;
    mov    byte[esi], 0x5A
    ; i = 1;
    inc    eax
gen_l1:
    ; c = s.b[i+2] ^ s.b[i-1];
    mov    cl, [esp+eax+2]
    xor    cl, [esp+eax-1]
    ; s.b[i+6] = c
    mov    [esp+eax+6], cl
    ; j = 1
    cdq
    inc    edx
gen_l2:
    ; c += c
    add    cl, cl
    ; c ^= s.b[(i + 6) - j];
    lea    ebx, [eax+6]
    sub    ebx, edx  
    xor    cl, [esp+ebx]
    ; j++
    inc    edx
    cmp    dl, 7
    jnz    gen_l2
    ; ci[i] = c;
    mov    [esi+eax], cl
    ; i++
    inc    al
    ; i<128
    jns    gen_l1
    lea    esp, [esp+eax+8]   
    popad
    ret

    %ifndef BIN
      global hight128_setkeyx
      global _hight128_setkeyx
    %endif
    
hight128_setkeyx:    
_hight128_setkeyx:
    pushad
    mov    esi, [esp+32+4] ; esi = in
    mov    edi, [esp+32+8] ; edi = out
   
    mov    eax, [esi+3*4]
    stosd
    movsd
    ; i=0
    xor    ecx, ecx    
    call   gen_constx
sk_l1:
    ; j=0
    xor    edx, edx
sk_l2:
    ; idx = ((j + 8) - i) & 7;
    lea    ebx, [edx+8]
    sub    ebx, ecx
    and    ebx, 7
    ; sk[0] += mk->b[idx  ];
    mov    al, [esi+ebx-4]
    add    [edi+0], al
    ; sk[8] += mk->b[idx+8];
    mov    al, [esi+ebx+4]
    add    [edi+8], al
    ; sk++;
    inc    edi
    ; j++
    inc    edx
    ; j<8
    cmp    dl, 8
    jnz    sk_l2
    ; sk += 8
    add    edi, edx
    ; i++
    inc    ecx
    ; i<8
    cmp    cl, 8
    jnz    sk_l1    
    popad
    ret
   
    %ifndef BIN
      global hight128_encryptx
      global _hight128_encryptx       
    %endif
    
; rotate cipher text 64-bits    
rotl64: 
    pushad  
    mov    eax, [edi]
    mov    ebx, [edi+4]   
rt_l0:     
    add    eax, eax
    adc    ebx, ebx
    adc    al, 0
    loop   rt_l0    
    stosd
    xchg   eax, ebx
    stosd
    popad
    ret   
   
hight128_encryptx:
_hight128_encryptx:
    pushad
    mov    edi, [esp+32+4] ; data
    mov    esi, [esp+32+8] ; wk and sk
    push   2
    pop    ecx
    push   edi
hi_l0:    
    lodsw
    ; x->b[0] += wk[0];     
    add    [edi+0], al
    ; x->b[2] ^= wk[1];
    xor    [edi+2], ah
    scasd
    loop   hi_l0    
    pop    edi    
    lodsd    
    ; save wk[4]
    push   eax
    ; 32 rounds    
    mov    cl, 32
hi_enc:
    push   ecx
    ; x->q = ROTL64(x->q, 8);
    mov    cl, 8
    call   rotl64        
    mov    cl, 2
    movzx  edx, cl
hi_l1:
    ; c = x->b[j-1];
    mov    al, [edi+edx-1]
    ; c = ROTL8(c, 3) ^ ROTL8(c, 4) ^ ROTL8(c, 6);
    mov    ah, al
    rol    ah, 3
    rol    al, 4
    xor    ah, al
    rol    al, 6-4
    xor    ah, al
    ; x->b[j] += (c ^ *sk++);
    lodsb
    xor    al, ah
    add    [edi+edx], al    
    ; c = x->b[j+1];
    mov    al, [edi+edx+1]
    ; c = ROTL8(c, 1) ^ ROTL8(c, 2) ^ ROTL8(c, 7);
    mov    ah, al
    rol    ah, 1
    rol    al, 2
    xor    ah, al
    rol    al, 7-2
    xor    ah, al
    ; x->b[(j+2) & 7] ^= (c + *sk++);
    lodsb
    add    al, ah
    lea    ebx, [edx+2]
    and    bl, 7
    xor    [edi+ebx], al
    add    dl, 4    
    loop   hi_l1    
    pop    ecx
    loop   hi_enc    
    ; x->q = ROTL64(x->q, 56);   
    mov    cl, 56
    call   rotl64    
    ; restore wk[4]
    pop    eax
    ; x->b[0] += wk[0];     
    add    [edi+0], al
    ; x->b[2] ^= wk[1];
    xor    [edi+2], ah
    bswap  eax                ; instead of shr eax, 16
    ; x->b[4] += wk[6]; 
    add    [edi+4], ah    
    ; x->b[6] ^= wk[7];
    xor    [edi+6], al    
    popad
    ret
    