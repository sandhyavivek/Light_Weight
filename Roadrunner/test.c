

// test unit for RoadRunneR-64/128
// odzhan

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "roadrunner.c"

// 64-bit plaintext
uint8_t plain[8] = 
 { 0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10 };

// 128-bit master key
uint8_t key[16] = 
 { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF, 
   0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF };

// 64-bit ciphertext
uint8_t cipher[8] = 
 { 0xD9,0xDF,0x06,0x8F,0x59,0x93,0x88,0x82 };

void roadrunner(void *mk, void *data);

int main(void) {
    uint8_t data[8];
    int     equ;
    
    memcpy(data, plain, 8);
    roadrunner(key, data);
    equ = (memcmp(data, cipher, 8)==0);
    printf("RoadRunneR test : %s\n", equ ? "OK" : "FAILED");
    return 0;
}