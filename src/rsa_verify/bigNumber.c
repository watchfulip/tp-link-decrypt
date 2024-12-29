#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "bigNumber.h"

void RSA_safefree(void *ptr)
{
    if (ptr) {
	free(ptr);
    }
	ptr = NULL;
}
void *RSA_safemalloc(size_t size)
{
    return malloc(size);
}


static BignumInt bnZero[1] = { 0 };
static BignumInt bnOne[2] = { 1, 1 };

/*
 * The Bignum format is an array of `BignumInt'. The first
 * element of the array counts the remaining elements. The
 * remaining elements express the actual number, base 2^BIGNUM_INT_BITS, 
_least_
 * significant digit first. (So it's trivial to extract the bit
 * with value 2^n for any n.)
 *
 * All Bignums in this module are positive. Negative numbers must
 * be dealt with outside it.
 *
 * INVARIANT: the most significant word of any Bignum must be
 * nonzero.
 */


static Bignum Zero = bnZero, One = bnOne;

Bignum RSA_newbn(int length)
{
    Bignum b = snewn(length + 1, BignumInt);
    if (!b)
	abort();		       /* FIXME */
    memset(b, 0, (length + 1) * sizeof(*b));
    b[0] = length;
    return b;
}

/*
 * Compute c = a * b.
 * Input is in the first len words of a and b.
 * Result is returned in the first 2*len words of c.
 */
static void internal_mul(BignumInt *a, BignumInt *b,
			 BignumInt *c, int len)
{
    int i, j;
    BignumDblInt t;

    for (j = 0; j < 2 * len; j++)
	c[j] = 0;

    for (i = len - 1; i >= 0; i--) {
	t = 0;
	for (j = len - 1; j >= 0; j--) {
	    t += MUL_WORD(a[i], (BignumDblInt) b[j]);
	    t += (BignumDblInt) c[i + j + 1];
	    c[i + j + 1] = (BignumInt) t;
	    t = t >> BIGNUM_INT_BITS;
	}
	c[i] = (BignumInt) t;
    }
}

static void internal_add_shifted(BignumInt *number,
				 unsigned n, int shift)
{
    int word = 1 + (shift / BIGNUM_INT_BITS);
    int bshift = shift % BIGNUM_INT_BITS;
    BignumDblInt addend;

    addend = (BignumDblInt)n << bshift;

    while (addend) {
	addend += number[word];
	number[word] = (BignumInt) addend & BIGNUM_INT_MASK;
	addend >>= BIGNUM_INT_BITS;
	word++;
    }
}

/*
 * Compute a = a % m.
 * Input in first alen words of a and first mlen words of m.
 * Output in first alen words of a
 * (of which first alen-mlen words will be zero).
 * The MSW of m MUST have its high bit set.
 * Quotient is accumulated in the `quotient' array, which is a Bignum
 * rather than the internal bigendian format. Quotient parts are shifted
 * left by `qshift' before adding into quot.
 */
static void internal_mod(BignumInt *a, int alen,
			 BignumInt *m, int mlen,
			 BignumInt *quot, int qshift)
{
    BignumInt m0, m1;
    unsigned int h;
    int i, k;

    m0 = m[0];
    if (mlen > 1)
	m1 = m[1];
    else
	m1 = 0;

    for (i = 0; i <= alen - mlen; i++) {
	BignumDblInt t;
	unsigned int q, r, c, ai1;

	if (i == 0) {
	    h = 0;
	} else {
	    h = a[i - 1];
	    a[i - 1] = 0;
	}

	if (i == alen - 1)
	    ai1 = 0;
	else
	    ai1 = a[i + 1];

	/* Find q = h:a[i] / m0 */
	DIVMOD_WORD(q, r, h, a[i], m0);

	/* Refine our estimate of q by looking at
	   h:a[i]:a[i+1] / m0:m1 */
	t = MUL_WORD(m1, q);
	if (t > ((BignumDblInt) r << BIGNUM_INT_BITS) + ai1) {
	    q--;
	    t -= m1;
	    r = (r + m0) & BIGNUM_INT_MASK;     /* overflow? */
	    if (r >= (BignumDblInt) m0 &&
		t > ((BignumDblInt) r << BIGNUM_INT_BITS) + ai1) q--;
	}

	/* Subtract q * m from a[i...] */
	c = 0;
	for (k = mlen - 1; k >= 0; k--) {
	    t = MUL_WORD(q, m[k]);
	    t += c;
	    c = t >> BIGNUM_INT_BITS;
	    if ((BignumInt) t > a[i + k])
		c++;
	    a[i + k] -= (BignumInt) t;
	}

	/* Add back m in case of borrow */
	if (c != h) {
	    t = 0;
	    for (k = mlen - 1; k >= 0; k--) {
		t += m[k];
		t += a[i + k];
		a[i + k] = (BignumInt) t;
		t = t >> BIGNUM_INT_BITS;
	    }
	    q--;
	}
	if (quot)
	    internal_add_shifted(quot, q, qshift + BIGNUM_INT_BITS * (alen - mlen - i
));
    }
}

/*
 * Compute p % mod.
 * The most significant word of mod MUST be non-zero.
 * We assume that the result array is the same size as the mod array.
 * We optionally write out a quotient if `quotient' is non-NULL.
 * We can avoid writing out the result if `result' is NULL.
 */
static void bigdivmod(Bignum p, Bignum mod, Bignum result, Bignum quotient)
{
    BignumInt *n, *m;
    int mshift;
    int plen, mlen, i, j;

    /* Allocate m of size mlen, copy mod to m */
    /* We use big endian internally */
    mlen = mod[0];
    m = snewn(mlen, BignumInt);
    for (j = 0; j < mlen; j++)
	m[j] = mod[mod[0] - j];

    /* Shift m left to make msb bit set */
    for (mshift = 0; mshift < BIGNUM_INT_BITS-1; mshift++)
	if ((m[0] << mshift) & BIGNUM_TOP_BIT)
	    break;
    if (mshift) {
	for (i = 0; i < mlen - 1; i++)
	    m[i] = (m[i] << mshift) | (m[i + 1] >> (BIGNUM_INT_BITS - mshift));
	m[mlen - 1] = m[mlen - 1] << mshift;
    }

    plen = p[0];
    /* Ensure plen > mlen */
    if (plen <= mlen)
	plen = mlen + 1;

    /* Allocate n of size plen, copy p to n */
    n = snewn(plen, BignumInt);
    for (j = 0; j < plen; j++)
	n[j] = 0;
    for (j = 1; j <= p[0]; j++)
	n[plen - j] = p[j];

    /* Main computation */
    internal_mod(n, plen, m, mlen, quotient, mshift);

    /* Fixup result in case the modulus was shifted */
    if (mshift) {
	for (i = plen - mlen - 1; i < plen - 1; i++)
	    n[i] = (n[i] << mshift) | (n[i + 1] >> (BIGNUM_INT_BITS - mshift));
	n[plen - 1] = n[plen - 1] << mshift;
	internal_mod(n, plen, m, mlen, quotient, 0);
	for (i = plen - 1; i >= plen - mlen; i--)
	    n[i] = (n[i] >> mshift) | (n[i - 1] << (BIGNUM_INT_BITS - mshift));
    }

    /* Copy result to buffer */
    if (result) {
	for (i = 1; i <= result[0]; i++) {
	    int j = plen - i;
	    result[i] = j >= 0 ? n[j] : 0;
	}
    }

    /* Free temporary arrays */
    for (i = 0; i < mlen; i++)
	m[i] = 0;
    sfree(m);
    for (i = 0; i < plen; i++)
	n[i] = 0;
    sfree(n);
}


/*
* Convert a (max 32-bit) long into a bignum.
*/
Bignum RSA_bignum_from_long(unsigned long nn)
{
    Bignum ret;
    BignumDblInt n = nn;
	
    ret = RSA_newbn(3);
    ret[1] = (BignumInt)(n & BIGNUM_INT_MASK);
    ret[2] = (BignumInt)((n >> BIGNUM_INT_BITS) & BIGNUM_INT_MASK);
    ret[3] = 0;
    ret[0] = (ret[2]  ? 2 : 1);
    return ret;
}

Bignum RSA_bignum_from_bytes(const unsigned char *data, int nbytes)
{
    Bignum result;
    int w, i;

    w = (nbytes + BIGNUM_INT_BYTES - 1) / BIGNUM_INT_BYTES; /* bytes->words */

    result = RSA_newbn(w);
    for (i = 1; i <= w; i++)
	result[i] = 0;
    for (i = nbytes; i--;) {
	unsigned char byte = *data++;
	result[1 + i / BIGNUM_INT_BYTES] |= byte << (8*i % BIGNUM_INT_BITS);
    }

    while (result[0] > 1 && result[result[0]] == 0)
	result[0]--;
    return result;
}

/*
 * Simple remainder.
 */
Bignum RSA_bigmod(Bignum a, Bignum b)
{
    Bignum r = RSA_newbn(b[0]);
    bigdivmod(a, b, r, NULL);
    return r;
}

void RSA_freebn(Bignum b)
{
    /*
     * Burn the evidence, just in case.
     */
    memset(b, 0, sizeof(b[0]) * (b[0] + 1));
    sfree(b);
}

/*
 * Compute (base ^ exp) % mod.
 * The base MUST be smaller than the modulus.
 * The most significant word of mod MUST be non-zero.
 * We assume that the result array is the same size as the mod array.
 */
Bignum RSA_modpow(Bignum base, Bignum exp, Bignum mod)
{
    BignumInt *a, *b, *n, *m;
    int mshift;
    int mlen, i, j;
    Bignum result;

    /* Allocate m of size mlen, copy mod to m */
    /* We use big endian internally */
    mlen = mod[0];
    m = snewn(mlen, BignumInt);
    for (j = 0; j < mlen; j++)
	m[j] = mod[mod[0] - j];

    /* Shift m left to make msb bit set */
    for (mshift = 0; mshift < BIGNUM_INT_BITS-1; mshift++)
	if ((m[0] << mshift) & BIGNUM_TOP_BIT)
	    break;
    if (mshift) {
	for (i = 0; i < mlen - 1; i++)
	    m[i] = (m[i] << mshift) | (m[i + 1] >> (BIGNUM_INT_BITS - mshift));
	m[mlen - 1] = m[mlen - 1] << mshift;
    }

    /* Allocate n of size mlen, copy base to n */
    n = snewn(mlen, BignumInt);
    i = mlen - base[0];
    for (j = 0; j < i; j++)
	n[j] = 0;
    for (j = 0; j < base[0]; j++)
	n[i + j] = base[base[0] - j];

    /* Allocate a and b of size 2*mlen. Set a = 1 */
    a = snewn(2 * mlen, BignumInt);
    b = snewn(2 * mlen, BignumInt);
    for (i = 0; i < 2 * mlen; i++)
	a[i] = 0;
    a[2 * mlen - 1] = 1;

    /* Skip leading zero bits of exp. */
    i = 0;
    j = BIGNUM_INT_BITS-1;
    while (i < exp[0] && (exp[exp[0] - i] & (1 << j)) == 0) {
	j--;
	if (j < 0) {
	    i++;
	    j = BIGNUM_INT_BITS-1;
	}
    }

    /* Main computation */
    while (i < exp[0]) {
	while (j >= 0) {
	    internal_mul(a + mlen, a + mlen, b, mlen);
	    internal_mod(b, mlen * 2, m, mlen, NULL, 0);
	    if ((exp[exp[0] - i] & (1 << j)) != 0) {
		internal_mul(b + mlen, n, a, mlen);
		internal_mod(a, mlen * 2, m, mlen, NULL, 0);
	    } else {
		BignumInt *t;
		t = a;
		a = b;
		b = t;
	    }
	    j--;
	}
	i++;
	j = BIGNUM_INT_BITS-1;
    }

    /* Fixup result in case the modulus was shifted */
    if (mshift) {
	for (i = mlen - 1; i < 2 * mlen - 1; i++)
	    a[i] = (a[i] << mshift) | (a[i + 1] >> (BIGNUM_INT_BITS - mshift));
	a[2 * mlen - 1] = a[2 * mlen - 1] << mshift;
	internal_mod(a, mlen * 2, m, mlen, NULL, 0);
	for (i = 2 * mlen - 1; i >= mlen; i--)
	    a[i] = (a[i] >> mshift) | (a[i - 1] << (BIGNUM_INT_BITS - mshift));
    }

    /* Copy result to buffer */
    result = RSA_newbn(mod[0]);
    for (i = 0; i < mlen; i++)
	result[result[0] - i] = a[i + mlen];
    while (result[0] > 1 && result[result[0]] == 0)
	result[0]--;

    /* Free temporary arrays */
    for (i = 0; i < 2 * mlen; i++)
	a[i] = 0;
    sfree(a);
    for (i = 0; i < 2 * mlen; i++)
	b[i] = 0;
    sfree(b);
    for (i = 0; i < mlen; i++)
	m[i] = 0;
    sfree(m);
    for (i = 0; i < mlen; i++)
	n[i] = 0;
    sfree(n);

    return result;
}

/*
 * Compute (p * q) % mod.
 * The most significant word of mod MUST be non-zero.
 * We assume that the result array is the same size as the mod array.
 */
Bignum RSA_modmul(Bignum p, Bignum q, Bignum mod)
{
    BignumInt *a, *n, *m, *o;
    int mshift;
    int pqlen, mlen, rlen, i, j;
    Bignum result;

    /* Allocate m of size mlen, copy mod to m */
    /* We use big endian internally */
    mlen = mod[0];
    m = snewn(mlen, BignumInt);
    for (j = 0; j < mlen; j++)
	m[j] = mod[mod[0] - j];

    /* Shift m left to make msb bit set */
    for (mshift = 0; mshift < BIGNUM_INT_BITS-1; mshift++)
	if ((m[0] << mshift) & BIGNUM_TOP_BIT)
	    break;
    if (mshift) {
	for (i = 0; i < mlen - 1; i++)
	    m[i] = (m[i] << mshift) | (m[i + 1] >> (BIGNUM_INT_BITS - mshift));
	m[mlen - 1] = m[mlen - 1] << mshift;
    }

    pqlen = (p[0] > q[0] ? p[0] : q[0]);

    /* Allocate n of size pqlen, copy p to n */
    n = snewn(pqlen, BignumInt);
    i = pqlen - p[0];
    for (j = 0; j < i; j++)
	n[j] = 0;
    for (j = 0; j < p[0]; j++)
	n[i + j] = p[p[0] - j];

    /* Allocate o of size pqlen, copy q to o */
    o = snewn(pqlen, BignumInt);
    i = pqlen - q[0];
    for (j = 0; j < i; j++)
	o[j] = 0;
    for (j = 0; j < q[0]; j++)
	o[i + j] = q[q[0] - j];

    /* Allocate a of size 2*pqlen for result */
    a = snewn(2 * pqlen, BignumInt);

    /* Main computation */
    internal_mul(n, o, a, pqlen);
    internal_mod(a, pqlen * 2, m, mlen, NULL, 0);

    /* Fixup result in case the modulus was shifted */
    if (mshift) {
	for (i = 2 * pqlen - mlen - 1; i < 2 * pqlen - 1; i++)
	    a[i] = (a[i] << mshift) | (a[i + 1] >> (BIGNUM_INT_BITS - mshift));
	a[2 * pqlen - 1] = a[2 * pqlen - 1] << mshift;
	internal_mod(a, pqlen * 2, m, mlen, NULL, 0);
	for (i = 2 * pqlen - 1; i >= 2 * pqlen - mlen; i--)
	    a[i] = (a[i] >> mshift) | (a[i - 1] << (BIGNUM_INT_BITS - mshift));
    }

    /* Copy result to buffer */
    rlen = (mlen < pqlen * 2 ? mlen : pqlen * 2);
    result = RSA_newbn(rlen);
    for (i = 0; i < rlen; i++)
	result[result[0] - i] = a[i + 2 * pqlen - rlen];
    while (result[0] > 1 && result[result[0]] == 0)
	result[0]--;

    /* Free temporary arrays */
    for (i = 0; i < 2 * pqlen; i++)
	a[i] = 0;
    sfree(a);
    for (i = 0; i < mlen; i++)
	m[i] = 0;
    sfree(m);
    for (i = 0; i < pqlen; i++)
	n[i] = 0;
    sfree(n);
    for (i = 0; i < pqlen; i++)
	o[i] = 0;
    sfree(o);

    return result;
}

static Bignum copybn(Bignum orig)
{
    Bignum b = snewn(orig[0] + 1, BignumInt);
    if (!b)
	abort();		       /* FIXME */
    memcpy(b, orig, (orig[0] + 1) * sizeof(*b));
    return b;
}
/*
 * Compare two bignums. Returns like strcmp.
 */
int RSA_bignum_cmp(Bignum a, Bignum b)
{
    int amax = a[0], bmax = b[0];
    int i = (amax > bmax ? amax : bmax);
    while (i) {
	BignumInt aval = (i > amax ? 0 : a[i]);
	BignumInt bval = (i > bmax ? 0 : b[i]);
	if (aval < bval)
	    return -1;
	if (aval > bval)
	    return +1;
	i--;
    }
    return 0;
}
/*
 * Modular inverse, using Euclid's extended algorithm.
 */
Bignum RSA_modinv(Bignum number, Bignum modulus)
{
    Bignum a = copybn(modulus);
    Bignum b = copybn(number);
    Bignum xp = copybn(Zero);
    Bignum x = copybn(One);
    int sign = +1;

    while (RSA_bignum_cmp(b, One) != 0) {
	Bignum t = RSA_newbn(b[0]);
	Bignum q = RSA_newbn(a[0]);
	bigdivmod(a, b, t, q);
	while (t[0] > 1 && t[t[0]] == 0)
	    t[0]--;
	RSA_freebn(a);
	a = b;
	b = t;
	t = xp;
	xp = x;
	x = RSA_bigmuladd(q, xp, t);
	sign = -sign;
	RSA_freebn(t);
	RSA_freebn(q);
    }

    RSA_freebn(b);
    RSA_freebn(a);
    RSA_freebn(xp);

    /* now we know that sign * x == 1, and that x < modulus */
    if (sign < 0) {
	/* set a new x to be modulus - x */
	Bignum newx = RSA_newbn(modulus[0]);
	BignumInt carry = 0;
	int maxspot = 1;
	int i;

	for (i = 1; i <= newx[0]; i++) {
	    BignumInt aword = (i <= modulus[0] ? modulus[i] : 0);
	    BignumInt bword = (i <= x[0] ? x[i] : 0);
	    newx[i] = aword - bword - carry;
	    bword = ~bword;
	    carry = carry ? (newx[i] >= bword) : (newx[i] > bword);
	    if (newx[i] != 0)
		maxspot = i;
	}
	newx[0] = maxspot;
	RSA_freebn(x);
	x = newx;
    }

    /* and return. */
    return x;
}

/*
 * Non-modular multiplication and addition.
 */
Bignum RSA_bigmuladd(Bignum a, Bignum b, Bignum addend)
{
    int alen = a[0], blen = b[0];
    int mlen = (alen > blen ? alen : blen);
    int rlen, i, maxspot;
    BignumInt *workspace;
    Bignum ret;

    /* mlen space for a, mlen space for b, 2*mlen for result */
    workspace = snewn(mlen * 4, BignumInt);
    for (i = 0; i < mlen; i++) {
	workspace[0 * mlen + i] = (mlen - i <= a[0] ? a[mlen - i] : 0);
	workspace[1 * mlen + i] = (mlen - i <= b[0] ? b[mlen - i] : 0);
    }

    internal_mul(workspace + 0 * mlen, workspace + 1 * mlen,
		 workspace + 2 * mlen, mlen);

    /* now just copy the result back */
    rlen = alen + blen + 1;
    if (addend && rlen <= addend[0])
	rlen = addend[0] + 1;
    ret = RSA_newbn(rlen);
    maxspot = 0;
    for (i = 1; i <= ret[0]; i++) {
	ret[i] = (i <= 2 * mlen ? workspace[4 * mlen - i] : 0);
	if (ret[i] != 0)
	    maxspot = i;
    }
    ret[0] = maxspot;

    /* now add in the addend, if any */
    if (addend) {
	BignumDblInt carry = 0;
	for (i = 1; i <= rlen; i++) {
	    carry += (i <= ret[0] ? ret[i] : 0);
	    carry += (i <= addend[0] ? addend[i] : 0);
	    ret[i] = (BignumInt) carry & BIGNUM_INT_MASK;
	    carry >>= BIGNUM_INT_BITS;
	    if (ret[i] != 0 && i > maxspot)
		maxspot = i;
	}
    }
    ret[0] = maxspot;

    sfree(workspace);
    return ret;
}
/*
 * Return the bit count of a bignum, for ssh1 encoding.
 */
int RSA_bignum_bitcount(Bignum bn)
{
	int bitcount = bn[0] * BIGNUM_INT_BITS - 1;
	while (bitcount >= 0
	   && (bn[bitcount / BIGNUM_INT_BITS + 1] >> (bitcount % BIGNUM_INT_BITS)) 
		== 0) bitcount--;
	return bitcount + 1;
}

int RSA_bignum_byte(Bignum bn, int i)
{
	if (i >= BIGNUM_INT_BYTES * bn[0])
	return 0;			   /* beyond the end */
	else
	return (bn[i / BIGNUM_INT_BYTES + 1] >>
		((i % BIGNUM_INT_BYTES)*8)) & 0xFF;
}


/* DBS: add for fileSign 28Apr13 */
void RSA_bignum_dump(Bignum bn)
{
	int slen = (int)(bn[0]);
	int i;
	printf("bigNum len %d", (BIGNUM_INT_BYTES * slen));
	for(i = 1; i <=slen; i++)
	{
		if ((i-1) % 8 == 0)
		{
			printf("\n");
			printf("%04X  ",bn[i]);
		}
		else
		{
			printf("%04X  ",bn[i]);
		}
	}
	printf("\n\n");
}

int RSA_bignum_to_bytes(Bignum bn, char *out_buf, int buf_len)
{
	int i = 0, j = 0;;
	int num_len = BIGNUM_INT_BYTES * bn[0];
	
	if (buf_len < num_len)
		return -1;			   /* exceed the buffer */

	for (i = 0; i <= num_len; i++)
	{
		j = num_len - 1 - i;
		out_buf[i] = (bn[j / BIGNUM_INT_BYTES + 1] >> ((j % BIGNUM_INT_BYTES)*8))  & 0xFF;
	}

	return 0;
}

/* DBS: add end 28Apr13 */
