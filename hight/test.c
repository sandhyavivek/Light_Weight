

// test unit for hight-64/128
#include<stdlib.h>
#include "hight.h"
#include<string.h>
#include<inttypes.h>


void print_bytes(char *s, void *p, int len) {
  int i;
  printf("%s : ", s);
  for (int i=0; i<len; i++)
  {  printf ("%02x ", ((uint8_t*)p)[i]);
  }
  printf("\n\n");
}

uint8_t plain[8];
//{ 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };

uint8_t key[16] = 
{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

uint8_t cipher[8] = 
{ 0xd8, 0xe6, 0x43, 0xe5, 0x72, 0x9f, 0xce, 0x23 };


int main(void)
{
  uint8_t buf[8];
  uint8_t subkeys[128+8];
  int     equ,k;
  printf("\nEnter the plaintext in 8subtext, each expressed in hexa eg:{ 0x77 0x66 0x55 0x44 0x33 0x22 0x11 0x00 }\n");
  for(k=0;k<8;k++){
  scanf("%0x", &plain[k]);}
  
  memcpy(buf, plain, 8);
  hight128_setkey(key, subkeys);
  hight128_encrypt(buf, subkeys);
  
  printf("\nCalculated Cipher Text would be as for above eg:{0xd8, 0xe6, 0x43, 0xe5, 0x72, 0x9f, 0xce, 0x23 } \n");
  for(k=0;k<8;k++){
  printf("%0x\n", buf[k]);} 

  //equ = memcmp(buf, cipher, 8)==0;
   // printf("\nHIGHT test : %s\n", equ ? "OK" : "FAILED");
  return 0;
}
