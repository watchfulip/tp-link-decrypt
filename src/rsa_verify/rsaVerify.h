#ifndef RSA_VERIFY_H_
#define RSA_VERIFY_H_

#include "bigNumber.h"

#pragma pack(push, 1) // Set alignment to 1-byte boundary
typedef struct _MY_PUBLICKEYSTRUC {
	char bType;
	char bVersion;
	short reserved;
	unsigned int aiKeyAlg;
}MY_BLOBHEADER, MY_PUBLICKEYSTRUC;
#pragma pack(pop) // Restore default alignment

#pragma pack(push, 1) // Set alignment to 1-byte boundary
typedef struct _MY_RSAPUBKEY {
	unsigned int magic;
	unsigned int bitlen;
	unsigned int pubexp;
} MY_RSAPUBKEY;
#pragma pack(pop) // Restore default alignment
#pragma pack(push, 1) // Set alignment to 1-byte boundary
typedef struct _MY_RSA_PUBLICK_BLOB{
	MY_PUBLICKEYSTRUC blob_header;
	MY_RSAPUBKEY      rsa_pub_key;
}MY_RSA_PUBLICK_BLOB;
#pragma pack(pop) // Restore default alignment
#pragma pack(push, 1) // Set alignment to 1-byte boundary
struct RSAKey {
	int bits;
	int bytes;
	Bignum modulus;
	Bignum exponent;
	Bignum private_exponent;
	Bignum p;
	Bignum q;
	Bignum iqmp;
	char *comment;
};
#pragma pack(pop) // Restore default alignment

#define CHAR64(c) (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])


/* 
 * fn		int rsaVerifySignByBase64EncodePublicKeyBlob(unsigned char *pPublicKeyBlob,
 *			 												 unsigned long PublicKeyBlobLen,
 *			 												 unsigned char *pInData,      
 *			 												 unsigned long inDataLen,		   
 *			 												 unsigned char *PInSignature,   
 *			 												 unsigned long inSignatureLen)
 * brief	Check signature with public key
 * details	
 *
 * param[in]	pPublicKeyBlob - public key	
 * param[in]	PublicKeyBlobLen - public key length
 * param[in]	pInData	- mod number
 * param[in]	inDataLen - mod number length
 * param[in]	PInSignature - signature	
 * param[in]	inSignatureLen - signature length
 *
 * return	1 is returned if signature is OK, otherwise the return value is 0 		
 */
int rsaVerifySignByBase64EncodePublicKeyBlob(unsigned char *pPublicKeyBlob,
 												 unsigned long PublicKeyBlobLen,
 												 unsigned char *pInData,      
 												 unsigned long inDataLen,		   
 												 unsigned char *PInSignature,   
 												 unsigned long inSignatureLen,
												 unsigned int data_dec_offset);

int rsaVerifyPSSSignByBase64EncodePublicKeyBlob(unsigned char *pPublicKeyBlob,
 						unsigned long PublicKeyBlobLen,
 						unsigned char *pInData,
 						unsigned long inDataLen,
 						unsigned char *PInSignature,
 						unsigned long inSignatureLen,
 						unsigned int bCheckOnly,
 						unsigned int header_align_size,
						unsigned int data_dec_offset);

#endif

