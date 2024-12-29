#ifndef SHA_AND_SHA512_H
#define SHA_AND_SHA512_H


typedef struct {
    unsigned long hi, lo;
} uint64;

typedef unsigned int uint32;
typedef unsigned int word32;


typedef struct {
    uint32 h[5];
    unsigned char block[64];
    int blkused;
    uint32 lenhi, lenlo;
} SHA_State;

typedef struct {
    uint64 h[8];
    unsigned char block[128];
    int blkused;
    uint32 len[4];
} SHA512_State;

typedef struct {
    uint32 h[8];
    unsigned char block[128];
    int blkused;
    uint32 len;
} SHA256_State;

#define rol(x,y) ( ((x) << (y)) | (((uint32)x) >> (32-y)) )


#define BLKSIZE 128

/*
 * Arithmetic implementations. Note that AND, XOR and NOT can
 * overlap destination with one source, but the others can't.
 */
#define add(r,x,y) ( r.lo = y.lo + x.lo, \
		     r.hi = y.hi + x.hi + (r.lo < y.lo) )
#define rorB(r,x,y) ( r.lo = (x.hi >> ((y)-32)) | (x.lo << (64-(y))), \
		      r.hi = (x.lo >> ((y)-32)) | (x.hi << (64-(y))) )
#define rorL(r,x,y) ( r.lo = (x.lo >> (y)) | (x.hi << (32-(y))), \
		      r.hi = (x.hi >> (y)) | (x.lo << (32-(y))) )
#define shrB(r,x,y) ( r.lo = x.hi >> ((y)-32), r.hi = 0 )
#define shrL(r,x,y) ( r.lo = (x.lo >> (y)) | (x.hi << (32-(y))), \
		      r.hi = x.hi >> (y) )
#define and(r,x,y) ( r.lo = x.lo & y.lo, r.hi = x.hi & y.hi )
#define xor(r,x,y) ( r.lo = x.lo ^ y.lo, r.hi = x.hi ^ y.hi )
#define not(r,x) ( r.lo = ~x.lo, r.hi = ~x.hi )
#define INIT(h,l) { h, l }
#define BUILD(r,h,l) ( r.hi = h, r.lo = l )
#define EXTRACT(h,l,r) ( h = r.hi, l = r.lo )

/* ----------------------------------------------------------------------
 * Core SHA512 algorithm: processes 16-doubleword blocks into a
 * message digest.
 */

#define Ch(r,t,x,y,z) ( not(t,x), and(r,t,z), and(t,x,y), xor(r,r,t) )
#define Maj(r,t,x,y,z) ( and(r,x,y), and(t,x,z), xor(r,r,t), \
			 and(t,y,z), xor(r,r,t) )
#define bigsigma0(r,t,x) ( rorL(r,x,28), rorB(t,x,34), xor(r,r,t), \
			   rorB(t,x,39), xor(r,r,t) )
#define bigsigma1(r,t,x) ( rorL(r,x,14), rorL(t,x,18), xor(r,r,t), \
			   rorB(t,x,41), xor(r,r,t) )
#define smallsigma0(r,t,x) ( rorL(r,x,1), rorL(t,x,8), xor(r,r,t), \
			     shrL(t,x,7), xor(r,r,t) )
#define smallsigma1(r,t,x) ( rorL(r,x,19), rorB(t,x,61), xor(r,r,t), \
			     shrL(t,x,6), xor(r,r,t) )

/*functions*/
void RSA_SHA_Simple(void *p, int len, unsigned char *output);
void RSA_SHA512_Init(SHA512_State *s);
void RSA_SHA512_Bytes(SHA512_State *s, const void *p, int len);
void RSA_SHA512_Final(SHA512_State *s, unsigned char *digest);


/*SHA256 functions*/
void RSA_SHA256_Simple(const unsigned char* message, unsigned int len, unsigned char* digest);
void RSA_SHA256_Init(SHA256_State *s);
void RSA_SHA256_Bytes(SHA256_State *s, const unsigned char *p, unsigned int len);
void RSA_SHA256_Final(SHA256_State *s, unsigned char *digest);
void RSA_SHA256_MGF1(unsigned char*mask, int mask_bytes, unsigned char*seed, int seed_len);
#endif
