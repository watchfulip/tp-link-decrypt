#ifndef BIG_NUMBER_H
#define BIG_NUMBER_H


typedef unsigned short BignumInt;
typedef unsigned long BignumDblInt;
#define BIGNUM_INT_MASK  0xFFFFU
#define BIGNUM_TOP_BIT   0x8000U
#define BIGNUM_INT_BITS  16
#define MUL_WORD(w1, w2) ((BignumDblInt)w1 * w2)
#define DIVMOD_WORD(q, r, hi, lo, w) do { \
    BignumDblInt n = (((BignumDblInt)hi) << BIGNUM_INT_BITS) | lo; \
    q = n / w; \
    r = n % w; \
} while (0)

typedef BignumInt *Bignum;


#define BIGNUM_INT_BYTES (BIGNUM_INT_BITS / 8)


#define snewn(n, type) ((type *)smalloc((n)*sizeof(type)))
#define smalloc RSA_safemalloc
#define sfree RSA_safefree

void *RSA_safemalloc(size_t);
void RSA_safefree(void *);


Bignum RSA_newbn(int length);
Bignum RSA_bignum_from_long(unsigned long nn);
Bignum RSA_bignum_from_bytes(const unsigned char *data, int nbytes);
Bignum RSA_bigmod(Bignum a, Bignum b);
void RSA_freebn(Bignum b);
Bignum RSA_modpow(Bignum base, Bignum exp, Bignum mod);
Bignum RSA_modmul(Bignum p, Bignum q, Bignum mod);
Bignum RSA_modinv(Bignum number, Bignum modulus);
Bignum RSA_bigmuladd(Bignum a, Bignum b, Bignum addend);
int RSA_bignum_bitcount(Bignum bn);
int RSA_bignum_byte(Bignum bn, int i);
int RSA_bignum_cmp(Bignum a, Bignum b);
int RSA_bignum_to_bytes(Bignum bn, char *out_buf, int buf_len);
void RSA_bignum_dump(Bignum bn);


#endif

