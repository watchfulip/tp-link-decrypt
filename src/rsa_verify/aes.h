#ifndef _AES_H_
#define _AES_H_

struct AES_key {
	unsigned int key[60];
	int rounds;
};

int AES_set_encrypt_key(const unsigned char *key, const int bits, struct AES_key *aeskey);
int AES_set_decrypt_key(const unsigned char *key, const int bits, struct AES_key *aeskey);
int AES_encrypt(const unsigned char *in, unsigned char *out, const struct AES_key *key);
int AES_decrypt(const unsigned char *in, unsigned char *out, const struct AES_key *key);
int AES_cbc_encrypt(const unsigned char *in, unsigned char *out, unsigned int len, const struct AES_key *key, unsigned char *iv, int forward);
unsigned char* AES128FileBinary(char* szFilename, int offset, int totalLen);
#endif

