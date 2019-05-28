#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>

#include <string.h>
#include <stdint.h>

#include "encAlg.h"

#define BLOCK_SIZE 32
#define FREAD_COUNT 4096
#define KEY_BIT 256
#define IV_SIZE 32
#define RW_SIZE 1
#define SUCC 0
#define FAIL -1

AES_KEY aes_ks3;

int aesEncrypt(unsigned char *key32, unsigned char *data, unsigned char *encData) {
	int i =0, j = 0, len = 0, padding_len = 0;
	unsigned char iv[IV_SIZE];

	len = strlen(data) + 1;

//	printf("data: %s", data);
//	printf("\nkey16: ");
//	for(i=0; i<16; i++)
//		printf("%02x", key16[i]);
//	printf("\n");

	memset(iv, 0, sizeof(iv));
	AES_set_encrypt_key(key32, KEY_BIT, &aes_ks3);

	padding_len = BLOCK_SIZE - len % BLOCK_SIZE;
	memset(encData+len, padding_len, padding_len);
	AES_cbc_encrypt(data, encData, len+padding_len, &aes_ks3, iv, AES_ENCRYPT);

	return SUCC;
}

int aesDecrypt(unsigned char *key32, unsigned char *encData, unsigned char *data) {
	int i, j, len = 0, total_size = 0, save_len = 0, w_len = 0;
	unsigned char iv[IV_SIZE];

	len = strlen(encData) + 1;

//	printf("enc data: %s", encData);
//	printf("\ndec key16: ");
//	for(i=0; i<16; i++)
//		printf("%02x", key16[i]);
//	printf("\n");

	memset(iv, 0, sizeof(iv));
	AES_set_decrypt_key(key32, KEY_BIT, &aes_ks3);
	AES_cbc_encrypt(encData, data, len, &aes_ks3, iv, AES_DECRYPT);

//	printf("dec data: %s\n", data);

	return SUCC;
}

int createRsaKey(unsigned char *privateKey, unsigned char *publicKey) {
	FILE *rsaKey;
	int keyLen = 0, count;

	system("openssl genrsa -out private.pem 1024");
	system("openssl rsa -in private.pem -out public.pem -outform PEM -pubout");

	rsaKey = fopen("private.pem", "r");
	if (rsaKey == NULL) {
		printf("open failed\n");
		return 0;
	}

	fseek(rsaKey, 0, SEEK_END);
	keyLen = ftell(rsaKey);

	memset(privateKey, 0, sizeof(unsigned char) * keyLen + 1);
	fseek(rsaKey, 0, SEEK_SET);
	count = fread(privateKey, keyLen, 1, rsaKey);
	fclose(rsaKey);

	rsaKey = fopen("public.pem", "r");
	if (rsaKey == NULL) {
		printf("open failed\n");
		return 0;
	}

	fseek(rsaKey, 0, SEEK_END);
	keyLen = ftell(rsaKey);

	memset(publicKey, 0, sizeof(unsigned char) * keyLen + 1);
	fseek(rsaKey, 0, SEEK_SET);
	count = fread(publicKey, keyLen, 1, rsaKey);
	fclose(rsaKey);

	system("rm private.pem; rm public.pem");

	return keyLen;
}

RSA *createRSA(unsigned char *key, int public) {
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL) {
		printf("Failed to create key BIO");
		return 0;
	}
	if (public) {
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	} else {
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}

	return rsa;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted) {
	RSA *rsa = createRSA(key, 1);
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_PADDING);
	return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted) {
	RSA *rsa = createRSA(key, 0);
	int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, RSA_PKCS1_PADDING);
	return result;
}

EC_KEY *createECDH() {
	EC_KEY *privKey = NULL;
	if ((privKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		printf("Failed to generate ECDH key curve\n");
		return NULL;
	}

	if (EC_KEY_generate_key(privKey) != 1) {
		printf("Failed to generate ECDH key\n");
		return NULL;
	}

	return privKey;
}

int getECPubKey(EC_KEY *privKey, unsigned char *charPubKey) {
	int i =0;
	const EC_POINT *pubKey = EC_KEY_get0_public_key(privKey);

	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();

	if (!EC_POINT_get_affine_coordinates_GFp(ec_group, pubKey, x, y, NULL)) {
		printf("EC PubKey coordinate not generated!\n");
		return 0;
	}
	unsigned char charX[32], charY[32];
	BN_bn2bin(x, charX);
	BN_bn2bin(y, charY);

	for(i=0; i<32; i++) {
		charPubKey[i] = charX[i];
		charPubKey[i+32] = charY[i];
	}
	return 1;
}

unsigned char *getSharedSecret(EC_KEY *key, unsigned char *charPubKey, size_t *secret_len) {
	int field_size, i;
	unsigned char *secret; 
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	EC_POINT *peerPubKey = EC_POINT_new(ec_group);

	unsigned char charX[32], charY[32];
	for (i=0; i<32; i++) {
		charX[i] = charPubKey[i];
		charY[i] = charPubKey[i+32];
	}
	BIGNUM *x = BN_bin2bn(charX, 32, NULL);
	BIGNUM *y = BN_bin2bn(charY, 32, NULL);

	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
	*secret_len = (field_size + 7)/8;

	if ((secret = OPENSSL_malloc(*secret_len)) == NULL) {
		printf("Failed to allocate memory for secret\n");
		return 0;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(ec_group, peerPubKey, x, y, NULL)) {
		printf("EC peerPubKey coordinate not generated!\n");
		return 0;
	}

	*secret_len = ECDH_compute_key(secret, *secret_len, peerPubKey, key, NULL);

	return secret;
}


