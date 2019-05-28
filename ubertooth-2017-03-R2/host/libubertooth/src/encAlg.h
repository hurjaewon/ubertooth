#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <string.h>
#include <stdint.h>


int aesEncrypt(unsigned char *key32, unsigned char *data, unsigned char *encData);
int aesDecrypt(unsigned char *key32, unsigned char *encData, unsigned char *data);
int createRsaKey(unsigned char *privateKey, unsigned char *publicKey);
RSA *createRSA(unsigned char *key, int public);
int public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted);
int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted);
