#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include "shaAndSha512.h"
#include "bigNumber.h"
#include "rsaVerify.h"
#include "aes.h"
#include "../md5/md5.h"

static const unsigned char asn1_weird_stuff[] = {
    0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B,
		0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
};

#define ASN1_LEN ( (int) sizeof(asn1_weird_stuff) )

//base 64 解密
static int app_base64decode(const unsigned char *in, unsigned inlen, unsigned char *out)
{
	
	//printf("app_base64decode\n");
	
    unsigned  len = 0, lup;
    int    c1,c2,c3,c4;
	static char     index_64[128] = {
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
			52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
			-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
			15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
			-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
			41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
	};
	
	/* xxx these necessary? */
    if (in[0] == '+' && in[1] == ' ')
        in += 2;
	
    if (*in == '\0')
        return 0;
	
    for (lup = 0; lup < inlen / 4; lup++)
    {
        c1 = in[0];
        if (CHAR64(c1) == -1)
            return 0;
        c2 = in[1];
        if (CHAR64(c2) == -1)
            return 0;
        c3 = in[2];
        if (c3 != '=' && CHAR64(c3) == -1)
            return 0;
        c4 = in[3];
        if (c4 != '=' && CHAR64(c4) == -1)
            return 0;
        in += 4;
        *out++ = (CHAR64(c1) << 2) | (CHAR64(c2) >> 4);
        ++len;
        if (c3 != '=')
        {
            *out++ = ((CHAR64(c2) << 4) & 0xf0) | (CHAR64(c3) >> 2);
            ++len;
            if (c4 != '=')
            {
                *out++ = ((CHAR64(c3) << 6) & 0xc0) | CHAR64(c4);
                ++len;
            }
        }
    }
	
    *out = 0; 
    
    	//printf("app_base64decode ret len %u\n",len);
    
	return len;
}


static unsigned long rsa_read_long_from_public_key(char *bit)
{
	unsigned long re =0;
	
	re = ((bit[0])&(0xFF)) |
		(((bit[1])&(0xFF))<<8) |
		(((bit[2])&(0xFF))<<16) |
		(((bit[3])&(0xFF))<<24);
	
	return re;
}

static void *rsa2_newkey_ex(char *data, int len, unsigned int pss_mode)
{
	

	unsigned long bit_len;
	struct RSAKey *rsa;
	char temp_buf[256];
	int i;
	MY_RSA_PUBLICK_BLOB *rsa_pub_blob;
	rsa_pub_blob = (MY_RSA_PUBLICK_BLOB *)data;
	
	rsa = snewn(1,struct RSAKey);
	if (!rsa)
		return NULL;

	
	//下面这段代码是专进MS PUBKEYBLOB 结构用的,请注意
  	char *p;  
	p = data + 8;           //RSAPUBKEY
//	p = data + sizeof(MY_PUBLICKEYSTRUC);           //RSAPUBKEY
	
	if(memcmp(p, "RSA1", 4))
	{
		printf("rsa2_newkey_ex() error\n");
		goto error_exit;
	}
	//else
		//printf("RSA1\n");

	bit_len = rsa_read_long_from_public_key((char*)&(rsa_pub_blob->rsa_pub_key.bitlen));
	
	
	rsa->exponent = RSA_bignum_from_long(rsa_read_long_from_public_key((char*)(&(rsa_pub_blob->rsa_pub_key.pubexp))));

    p=data + sizeof(MY_RSA_PUBLICK_BLOB);


	memset(temp_buf,0,sizeof(temp_buf));

	for(i=0; (i<(int)(bit_len/8))&&(i<sizeof(temp_buf)); i++)
	{
	//	printf("%d\n",i);
		temp_buf[i] = p[(bit_len/8)-1 -i];
	}

    rsa->modulus = RSA_bignum_from_bytes((unsigned char *)temp_buf, bit_len/8);

    rsa->private_exponent = NULL;

    rsa->comment = NULL;
	
				
	
    return rsa;
error_exit:
	sfree(rsa);
	printf("rsa2_newkey_ex error!\n");
	return NULL;
}


static int rsa2_verifysig(void *key, char *sig, int siglen, 
							char *data, int datalen)
{
	struct RSAKey *rsa = (struct RSAKey *) key;
	Bignum in, out;
	int slen;
	int bytes, i, j, ret;
	unsigned char hash[20];

	in = RSA_bignum_from_bytes((unsigned char *)sig, siglen);

	out = RSA_modpow(in, rsa->exponent, rsa->modulus);

	RSA_freebn(in);
	ret = 1;

	slen = (int)(out[0]);

#ifdef TEST_RSA
	printf("slen %d\n",slen);
	for(i = 1; i <=slen; i++)
	{
		printf("%02x",out[i]);
	}
	printf("\n");
#endif 

	bytes = (RSA_bignum_bitcount(rsa->modulus)+7) / 8;

	/* Top (partial) byte should be zero. */
	if (RSA_bignum_byte(out, bytes - 1) != 0)
		ret = 0;
	
	/* First whole byte should be 1. */
	if (RSA_bignum_byte(out, bytes - 2) != 1)
		ret = 0;
	
	/* Most of the rest should be FF. */
	for (i = bytes - 3; i >= 20 + ASN1_LEN; i--) {
		if (RSA_bignum_byte(out, i) != 0xFF)
		    ret = 0;
	}
	
	/* Then we expect to see the asn1_weird_stuff. */
	for (i = 20 + ASN1_LEN - 1, j = 0; i >= 20; i--, j++) {
		if (RSA_bignum_byte(out, i) != asn1_weird_stuff[j])
			ret = 0;
	}
	
    /* Finally, we expect to see the SHA-1 hash of the signed data. */
    //这里,我们要变一下,这里要用MD5算法解一下.
	//也可以用它来做HASH
    RSA_SHA_Simple(data, datalen, hash);
	
#ifdef TEST_RSA
	printf("\n");
	for(i = 0; i < 20; i++)
	{
		printf("%2x ",hash[i]);
	}
	printf("\n");
#endif

	for (i = 19, j = 0; i >= 0; i--, j++) {
		if (RSA_bignum_byte(out, i) != hash[j])
		    ret = 0;
	}
	
	RSA_freebn(out);

	return ret;
}

static int rsa2_pss_sha256_verifysig(void *key, char *sig, int siglen, char *data, int datalen, unsigned int bCheckOnly, unsigned int header_align_size, unsigned int data_dec_offset)
{
	
	//printf("rsa2_pss_sha256_verifysig()\n");
	
	struct RSAKey *rsa = (struct RSAKey *) key;
	Bignum in, out;
	int bytes = 0, hashLen = 32, saltpos = 0;
	int i, j, ret = 1, result = 0;
	unsigned char hash[32];
	unsigned char hash2[32];
	unsigned char em[256+8];
	unsigned char mask[256];
	unsigned char *salt = NULL;
	int slen = 0;

	bytes = (RSA_bignum_bitcount(rsa->modulus)+7) / 8;
	in = RSA_bignum_from_bytes((unsigned char *)sig, siglen);
	out = RSA_modpow(in, rsa->exponent, rsa->modulus);

	for (i = bytes - 1, j = 0; i >= 0; i--, j++) 
	{
		em[j] = RSA_bignum_byte(out, i);
	}
	
#ifdef TEST_RSA
	slen = (int)(out[0]);
	printf("slen %d\n",slen);
	for(i = 1; i <=slen; i++)
	{
		printf("%02x",out[i]);
	}
	printf("\n");
#endif 

	RSA_freebn(in);
	RSA_freebn(out);

	if (em[bytes - 1] != 0xbc) 
	{
		printf("RSA PSS Verify Error 1!\n");
		ret = 0;
	} 
	else 
	{
		RSA_SHA256_MGF1(mask, bytes - 1 - hashLen, em + bytes - 1 - hashLen, hashLen);
		for (i = 0; i < hashLen; i++) 
		{
			hash2[i] = em[bytes - 1 - hashLen + i];
		}
        
		for (i = 0; i < bytes - 1 - hashLen; i++) 
		{
			mask[i] ^= em[i];
			if (i == 0) 
			{
				mask[0] &= ~0x80;
			}
			if (saltpos <= 0) 
			{
				if (mask[i] == 0x01) 
				{
					saltpos = i + 1;
					salt = mask + saltpos;
					slen = bytes - 1 - hashLen - saltpos;
				} 
				else if (mask[i] != 0) 
				{
					ret = 0;
					printf("RSA PSS Verify Error 2!\n");
					break;
				}
			}
		}
        
		if (ret) 
		{
			memset(em, 0, 8);
			memcpy(em + 8 + hashLen, salt, slen);
			RSA_SHA256_Simple(data, datalen, em + 8);
			RSA_SHA256_Simple(em, slen + 8 + hashLen, hash);

#ifdef DEBUG
			printf("H1:\n");
			for(i = 0; i <hashLen; i++)
			{
				printf("%02x",em[i + 8]);
			}
			printf("\n");
			printf("H2:\n");
			for(i = 0; i <hashLen; i++)
			{
				printf("%02x",hash2[i]);
			}
			printf("\n");
			printf("H':\n");
			for(i = 0; i <hashLen; i++)
			{
				printf("%02x",hash[i]);
			}
			printf("\n");
#endif			

			printf("key/iv:\nKEY=");
			for(i = 0; i <16; i++)
			{
				printf("%02x",salt[i]);
			}
			printf("\n");			
			
			printf("IV=");
			for(i = 16; i <32; i++)
			{
				printf("%02x",salt[i]);
			}
			printf("\n");					

			if (memcmp(hash, hash2, hashLen)) 
			{
				printf("RSA PSS Verify Error 3!\n");
				ret = 0;
			} 
			else 
			{
				char magic[] = {0xaa,0x55,0x9d,0xd1,0xa8,0xc8,0x83,0x31,0xc9,0x69,0xfb,0xbf,0xbc,0xf0,0xd4,0x32,0x70,0xc7,0x55,0xaa};

				//Decryption
				if (bCheckOnly)
				{
					struct AES_key aes;
					AES_set_decrypt_key(salt, 128, &aes);
					AES_cbc_encrypt(data + 0x120, data + 0x120, (header_align_size - 0x120) & ~0xF, &aes, salt + 16, 0);
                    
				    result = 1;
				}
                else if (!bCheckOnly && slen > 32 && memcmp(data + 0x240, magic, 20)) 
				{
					struct AES_key aes;
					AES_set_decrypt_key(salt, 128, &aes);
					AES_cbc_encrypt(data + data_dec_offset, data + data_dec_offset, (datalen - data_dec_offset) & ~0xF, &aes, salt + 16, 0);
                    
				    result = 1;
				}
			}
		}
	}

	return result;
}

static int rsaVerifySign(
	unsigned char *public_key_blob,
	unsigned long        public_key_blob_len,
	unsigned char *in_data,      
	unsigned long        in_data_len,		   
	unsigned char *in_Signature,   
	unsigned long        in_Signature_len,
	unsigned int pss_mode,
	unsigned int bCheckOnly, 
	unsigned int header_align_size,
	unsigned int data_dec_offset)
{
	
		//printf("rsaVerifySign()\n");
	
	
	char signBuf[256];
	struct RSAKey *rsa = NULL;
	int re = 0;
	unsigned long i = 0;
	/*printf("rsaVerifySign()\n");*/
	
	if(sizeof(signBuf)<in_Signature_len)
	{
		re = 0;
		printf("error 1\n");
		goto err;		
	}
	/*printf("rsaVerifySign(1)\n");*/
	
	if(!public_key_blob || !in_data || !in_Signature)
	{
		re = 0;
		printf("error 2\n");
		goto err;
	}

	rsa = rsa2_newkey_ex((char *)public_key_blob, public_key_blob_len, pss_mode);
	/*printf("rsaVerifySign(2)\n");*/
	
	if(rsa==NULL)
	{   
		re = 0;
		printf("error 3\n");
		goto err;		
	}
	
	memset(signBuf, 0 ,sizeof(signBuf));
	//printf("rsaVerifySign(3)\n");
    
	for(i=0;i<in_Signature_len; i++)
	{
		signBuf[i] = in_Signature[in_Signature_len - 1 - i];
	}

	if (pss_mode) 
	{
		re = rsa2_pss_sha256_verifysig(rsa, signBuf, in_Signature_len, (char *)in_data, in_data_len, bCheckOnly, header_align_size, data_dec_offset);
		//printf("rsaVerifySign(4)\n");
	} 
	else 
	{
 		re = rsa2_verifysig(rsa,  signBuf, in_Signature_len, (char *)in_data, in_data_len);
		//printf("rsaVerifySign(5)\n");
	}
	
err:
	if(rsa)
		sfree(rsa);
	
	//printf("re is 0x%08X\n",re);
	return re;   
}

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
												 unsigned int data_dec_offset)
{
	

	
	unsigned char buf[512];                
	int len;
	
	if(PublicKeyBlobLen > sizeof(buf))
	{

		goto error_exit;
	}
	
	len = app_base64decode(pPublicKeyBlob, PublicKeyBlobLen, buf);

	if(len <= 0)
	{
		goto error_exit;
	}
	
	return  rsaVerifySign(buf,
						  len,
						  pInData,      
						  inDataLen,		   
						  PInSignature,   
						  inSignatureLen,
						  0,
						  0,
						  0,
						  data_dec_offset);

error_exit:
	return 0;	
}

int rsaVerifyPSSSignByBase64EncodePublicKeyBlob(unsigned char *pPublicKeyBlob,
 												 unsigned long PublicKeyBlobLen,
 												 unsigned char *pInData,      
 												 unsigned long inDataLen,		   
 												 unsigned char *PInSignature,   
 												 unsigned long inSignatureLen,
 												 unsigned int bCheckOnly,
 												 unsigned int header_align_size,
 												 unsigned int data_dec_offset)
{
	unsigned char buf[512];                
	int len;

	if(PublicKeyBlobLen > sizeof(buf))
	{
		goto error_exit;
	}

	len = app_base64decode(pPublicKeyBlob, PublicKeyBlobLen, buf);


	if(len <= 0)
	{
		goto error_exit;
	}
	
	return  rsaVerifySign(buf,
						  len,
						  pInData,      
						  inDataLen,		   
						  PInSignature,   
						  inSignatureLen,
						  1,
						  bCheckOnly, 
						  header_align_size,
						  data_dec_offset);

error_exit:
	return 0;	
}


