/***************************************************************
 *
 * Copyright(c) 2005-2007 Shenzhen TP-Link Technologies Co. Ltd.
 * All right reserved.
 *
 * Filename		:	md5_interface.c
 * Version		:	1.0
 * Abstract		:	md5 make and verify response interface
 * Author		:	LI SHAOZHANG (lishaozhang@tp-link.net)
 * Created Date	:	07/11/2007
 *
 * Modified History:
 * 04Feb09, lsz add functions: md5_des and file_md5_des
 ***************************************************************/
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include "md5.h"
#include "md5_interface.h"

/*
 * md5_make_digest:make md5 digest for 'input' and save in 'digest'
 */
void md5_make_digest(unsigned char* digest, unsigned char* input, int len)
{
	MD5_CTX ctx;
	
	MD5_Init(&ctx);
	MD5_Update(&ctx, input, len);
	MD5_Final(digest, &ctx);
}

/* verify the 'digest' for 'input'*/
int md5_verify_digest(unsigned char* digest, unsigned char* input, int len)
{
	unsigned char digst[MD5_DIGEST_LEN + 1];
	
	md5_make_digest(digst, input, len);
	
	if (memcmp(digst, digest, MD5_DIGEST_LEN) == 0)
		return 1;
	
	return -1;
}

void hmac_md5(
			unsigned char* text, /* pointer to data stream */
			int text_len, /* length of data stream */
			unsigned char* key, /* pointer to authentication key */
			int key_len, /* length of authentication key */
			unsigned char * digest) /* caller digest to be filled in */
{
	MD5_CTX context;
	unsigned char k_ipad[65]; /* inner padding -key XORd with ipad */
	unsigned char k_opad[65]; /* outer padding key XORd with opad*/

	unsigned char tk[16];
	int i;

	/* if key is longer than 64 bytes reset it to key=MD5(key) */

	if (key_len > 64) 
	{
		MD5_CTX tctx;
		MD5_Init(&tctx);
		MD5_Update(&tctx, key, key_len);
		MD5_Final(tk, &tctx);
		key = tk;
		key_len = 16;
	}


	/*
	the HMAC_MD5 transform looks like:
	MD5(K XOR opad, MD5(K XOR ipad, text))
	where K is an n byte key
	ipad is the byte 0x36 repeated 64 times
	opad is the byte 0x5c repeated 64 times
	and text is the data being protected
	*/

	/* start out by storing key in pads */
	bzero( k_ipad, sizeof k_ipad);
	bzero( k_opad, sizeof k_opad);
	bcopy( key, k_ipad, key_len);
	bcopy( key, k_opad, key_len);
	/* XOR key with ipad and opad values */
	for (i=0; i<64; i++) 
	{
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/*perform inner MD5	*/

	MD5_Init(&context); /* init context for 1st pass */
	MD5_Update(&context, k_ipad, 64); /* start with inner pad */
	MD5_Update(&context, text, text_len); /* then text of datagram */
	MD5_Final((unsigned char*)digest, &context); /* finish up 1st pass */

	/* perform outer MD5 */

	MD5_Init(&context); /* init context for 2nd pass */
	MD5_Update(&context, k_opad, 64); /* start with outer pad */
	MD5_Update(&context, digest, 16); /* then results of 1st hash */
	MD5_Final((unsigned char*)digest, &context); /* finish up 2nd pass */
}

/* md5 checksum and des encrypt */
int md5_des(const unsigned char *in,int in_len, unsigned char *out, int out_len, const unsigned char *key, int enc)
{
	unsigned char md5_digest[MD5_DIGEST_LEN+1];
	int len;
	int ret;

	if (enc)
	{
		if (out_len - 8 - MD5_DIGEST_LEN < in_len)
		{
			printf ("output buf too small.\r\n");
			return -1;
		}
		
		md5_make_digest(md5_digest, (unsigned char*)in, in_len);
		memcpy(out, md5_digest, MD5_DIGEST_LEN);
		len = des_min_do(in, in_len, out + MD5_DIGEST_LEN, out_len - MD5_DIGEST_LEN, key, DES_ENCRYPT);
		len += MD5_DIGEST_LEN;
	}
	else
	{
		if (out_len - 8 + MD5_DIGEST_LEN < in_len)
		{
			printf ("output buf too small.\r\n");
			return -1;
		}
		
		len = des_min_do(in + MD5_DIGEST_LEN, in_len - MD5_DIGEST_LEN, out, out_len, key, DES_DECRYPT);
		ret = md5_verify_digest((unsigned char*)in, out, len);
		if (ret < 0)
			return ret;
	}

	return len;
}

unsigned char cDesKey[8] = {0x47, 0x8D, 0xA5, 0x0B, 0xF9, 0xE3, 0xD2, 0xCF};

#define MAX_FILE_LENGTH	(16 * 1024)

int file_md5_des(char* infilename, char* outfilename, int bEncrypt)
{
	unsigned char readBuf[MAX_FILE_LENGTH];
	unsigned char outBuf[3*MAX_FILE_LENGTH];
	
	int infd = open(infilename, O_RDONLY);
	if (infd < 0)
	{
		perror("open input file");
		return -1;
	}
	
	int rt = read(infd, readBuf, MAX_FILE_LENGTH - 1);
	if (rt < 0)
	{
		perror("read");
		return -1;
	}
	else if (rt == MAX_FILE_LENGTH - 1)
	{
		printf("file too large!\n ");
		return -1;
	}
	
	int len = md5_des (readBuf, rt, outBuf, 3*MAX_FILE_LENGTH, cDesKey, bEncrypt);
	
	int outfd = open(outfilename, O_RDWR | O_CREAT | O_TRUNC);
	if (outfd < 0)
	{
		perror("open output file");
		return -1;
	}
	
	//printf("len:%d\n", len);
	if (write(outfd, outBuf, len) < 0)
	{
		perror("write");
	}
	
	close(infd);
	close(outfd);
	
	return 0;
}

