/*	
 *	mpi.c
 *	Release $Name: MATRIXSSL_1_2_2_OPEN $
 *
 *	multiple-precision integer library
 */
/*
 *	Copyright (c) PeerSec Networks, 2002-2004. All Rights Reserved.
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software 
 *	into proprietary programs.  If you are unable to comply with the GPL, a 
 *	commercial license for this software may be purchased from PeerSec Networks
 *	at http://www.peersec.com
 *	
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	See the GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include "../cryptoLayer.h"
#include <stdarg.h>

/******************************************************************************/
/*
	FUTURE
	1. Convert the mp_init and mp_clear functions to not use malloc + free,
	but to use static storage within the bignum variable instead - but
	how to handle grow()?  Maybe use a simple memory allocator
	2. verify stack usage of all functions and use of MP_LOW_MEM:
		fast_mp_montgomery_reduce
		fast_s_mp_mul_digs
		fast_s_mp_sqr
		fast_s_mp_mul_high_digs
	3. HAC stands for Handbook of Applied Cryptography
		http://www.cacr.math.uwaterloo.ca/hac/
*/
/******************************************************************************/
/*
	Utility functions
*/
void psZeromem(void *dst, size_t len)
{
	unsigned char *mem = (unsigned char *)dst;
	
	if (dst == NULL) {
		return;
	}
	while (len-- > 0) {
		*mem++ = 0;
	}
}

void psBurnStack(unsigned long len)
{
	unsigned char buf[32];
	
	psZeromem(buf, sizeof(buf));
	if (len > (unsigned long)sizeof(buf)) {
		psBurnStack(len - sizeof(buf));
	}
}

/******************************************************************************/
/*
	Multiple precision integer functions
	Note: we don't use va_args here to prevent portability issues.
*/
int _mp_init_multi(mp_int *mp0, mp_int *mp1, mp_int *mp2, mp_int *mp3,
				  mp_int *mp4, mp_int *mp5, mp_int *mp6, mp_int *mp7)
{
	mp_err	res		= MP_OKAY;		/* Assume ok until proven otherwise */
	int		n		= 0;			/* Number of ok inits */
	mp_int	*tempArray[9] = {mp0, mp1, mp2, mp3, mp4, mp5, mp6, mp7, NULL};

	while (tempArray[n] != NULL) {
		if (mp_init(tempArray[n]) != MP_OKAY) {
			res = MP_MEM;
			break;
		}
		n++;
	}

	if (res == MP_MEM) {
		n = 0;
		while (tempArray[n] != NULL) {
			mp_clear(tempArray[n]);
			n++;
		}
	}
	return res;		/* Assumed ok, if error flagged above. */
}
/******************************************************************************/
/*
	Reads a unsigned char array, assumes the msb is stored first [big endian]
 */
int mp_read_unsigned_bin (mp_int * a, unsigned char *b, int c)
{
	int		res;

/*
	Make sure there are at least two digits.
 */
	if (a->alloc < 2) {
		if ((res = mp_grow(a, 2)) != MP_OKAY) {
			return res;
		}
	}

/*
	Zero the int.
 */
	mp_zero (a);

/*
	read the bytes in
 */
	while (c-- > 0) {
		if ((res = mp_mul_2d (a, 8, a)) != MP_OKAY) {
			return res;
		}

#ifndef MP_8BIT
		a->dp[0] |= *b++;
		a->used += 1;
#else
		a->dp[0] = (*b & MP_MASK);
		a->dp[1] |= ((*b++ >> 7U) & 1);
		a->used += 2;
#endif /* MP_8BIT */
	}
	mp_clamp (a);
	return MP_OKAY;
}

/******************************************************************************/
/* 
	Compare two ints (signed)
 */
int mp_cmp (mp_int * a, mp_int * b)
{
/*
	compare based on sign
 */
	if (a->sign != b->sign) {
		if (a->sign == MP_NEG) {
			return MP_LT;
		} else {
			return MP_GT;
		}
	}

/*
	compare digits
 */
	if (a->sign == MP_NEG) {
		/* if negative compare opposite direction */
		return mp_cmp_mag(b, a);
	} else {
		return mp_cmp_mag(a, b);
	}
}

/******************************************************************************/
/*
	Store in unsigned [big endian] format.
*/
int mp_to_unsigned_bin (mp_int * a, unsigned char *b)
{
	int			x, res;
	mp_int		t;

	if ((res = mp_init_copy (&t, a)) != MP_OKAY) {
		return res;
	}

	x = 0;
	while (mp_iszero (&t) == 0) {
#ifndef MP_8BIT
		b[x++] = (unsigned char) (t.dp[0] & 255);
#else
		b[x++] = (unsigned char) (t.dp[0] | ((t.dp[1] & 0x01) << 7));
#endif /* MP_8BIT */
		if ((res = mp_div_2d (&t, 8, &t, NULL)) != MP_OKAY) {
			mp_clear (&t);
			return res;
		}
	}
	bn_reverse (b, x);
	mp_clear (&t);
	return MP_OKAY;
}

void _mp_clear_multi(mp_int *mp0, mp_int *mp1, mp_int *mp2, mp_int *mp3,
				  mp_int *mp4, mp_int *mp5, mp_int *mp6, mp_int *mp7)
{
	int		n		= 0;		/* Number of ok inits */

	mp_int	*tempArray[9] = {mp0, mp1, mp2, mp3, mp4, mp5, mp6, mp7, NULL};

	for (n = 0; tempArray[n] != NULL; n++) {
		mp_clear(tempArray[n]);
	}
}

/******************************************************************************/
/*
	Init a new mp_int.
*/
int mp_init (mp_int * a)
{
	int		i;
/*
	allocate memory required and clear it
 */
	a->dp = OPT_CAST(mp_digit) psMalloc (sizeof (mp_digit) * MP_PREC);
	if (a->dp == NULL) {
		return MP_MEM;
	}

/*
	set the digits to zero
 */
	for (i = 0; i < MP_PREC; i++) {
		a->dp[i] = 0;
	}
/*
	set the used to zero, allocated digits to the default precision and sign
	to positive
 */
	a->used  = 0;
	a->alloc = MP_PREC;
	a->sign  = MP_ZPOS;

	return MP_OKAY;
}

/******************************************************************************/
/*
	clear one (frees).
 */
void mp_clear (mp_int * a)
{
	int		i;
/*
	only do anything if a hasn't been freed previously
 */
	if (a->dp != NULL) {
/*
		first zero the digits
 */
		for (i = 0; i < a->used; i++) {
			a->dp[i] = 0;
		}

		/* free ram */
		psFree (a->dp);

/*
		reset members to make debugging easier
 */
		a->dp		= NULL;
		a->alloc	= a->used = 0;
		a->sign		= MP_ZPOS;
	}
}

/******************************************************************************/
/*
	Get the size for an unsigned equivalent.
 */
int mp_unsigned_bin_size (mp_int * a)
{
	int		size = mp_count_bits (a);

	return	(size / 8 + ((size & 7) != 0 ? 1 : 0));
}

/******************************************************************************/
/*
	Trim unused digits 

	This is used to ensure that leading zero digits are trimed and the 
	leading "used" digit will be non-zero. Typically very fast.  Also fixes 
	the sign if there are no more leading digits
*/
void mp_clamp (mp_int * a)
{
/*
	decrease used while the most significant digit is zero.
 */
	while (a->used > 0 && a->dp[a->used - 1] == 0) {
		--(a->used);
	}

/*
	reset the sign flag if used == 0
 */
	if (a->used == 0) {
		a->sign = MP_ZPOS;
	}
}

/******************************************************************************/
/*
	Shift left by a certain bit count.
 */
int mp_mul_2d (mp_int * a, int b, mp_int * c)
{
	mp_digit	d;
	int			res;

/*
	Copy
 */
	if (a != c) {
		if ((res = mp_copy (a, c)) != MP_OKAY) {
			return res;
		}
	}

	if (c->alloc < (int)(c->used + b/DIGIT_BIT + 1)) {
		if ((res = mp_grow (c, c->used + b / DIGIT_BIT + 1)) != MP_OKAY) {
			return res;
		}
	}

/*
	Shift by as many digits in the bit count
 */
	if (b >= (int)DIGIT_BIT) {
		if ((res = mp_lshd (c, b / DIGIT_BIT)) != MP_OKAY) {
			return res;
		}
	}

/*
	shift any bit count < DIGIT_BIT
 */
	d = (mp_digit) (b % DIGIT_BIT);
	if (d != 0) {
		register mp_digit *tmpc, shift, mask, r, rr;
		register int x;

/*
		bitmask for carries
 */
		mask = (((mp_digit)1) << d) - 1;

/*
		shift for msbs
 */
		shift = DIGIT_BIT - d;

		/* alias */
		tmpc = c->dp;

		/* carry */
		r = 0;
		for (x = 0; x < c->used; x++) {
/*
			get the higher bits of the current word
 */
			rr = (*tmpc >> shift) & mask;

/*
			shift the current word and OR in the carry
 */
			*tmpc = ((*tmpc << d) | r) & MP_MASK;
			++tmpc;

/*
			set the carry to the carry bits of the current word
 */
			r = rr;
		}

/*
		set final carry
 */
		if (r != 0) {
			c->dp[(c->used)++] = r;
		}
	}
	mp_clamp (c);
	return MP_OKAY;
}

/******************************************************************************/
/* 
	Set to zero.
 */
void mp_zero (mp_int * a)
{
	a->sign = MP_ZPOS;
	a->used = 0;
	memset (a->dp, 0, sizeof (mp_digit) * a->alloc);
}

#ifdef MP_LOW_MEM
#define TAB_SIZE 32
#else
#define TAB_SIZE 256
#endif /* MP_LOW_MEM */

/******************************************************************************/
/*
	Compare maginitude of two ints (unsigned).
 */
int mp_cmp_mag (mp_int * a, mp_int * b)
{
	int			n;
	mp_digit	*tmpa, *tmpb;

/*
	compare based on # of non-zero digits
 */
	if (a->used > b->used) {
		return MP_GT;
	}

	if (a->used < b->used) {
		return MP_LT;
	}

	/* alias for a */
	tmpa = a->dp + (a->used - 1);

	/* alias for b */
	tmpb = b->dp + (a->used - 1);

/*
	compare based on digits
 */
	for (n = 0; n < a->used; ++n, --tmpa, --tmpb) {
		if (*tmpa > *tmpb) {
			return MP_GT;
		}

		if (*tmpa < *tmpb) {
			return MP_LT;
		}
	}
	return MP_EQ;
}

/******************************************************************************/
/*
	computes Y == G**X mod P, HAC pp.616, Algorithm 14.85

	Uses a left-to-right k-ary sliding window to compute the modular 
	exponentiation. The value of k changes based on the size of the exponent.

	Uses Montgomery or Diminished Radix reduction [whichever appropriate]
*/

#ifdef MP_LOW_MEM
#define TAB_SIZE 32
#else
#define TAB_SIZE 256
#endif /* MP_LOW_MEM */

int mp_exptmod (mp_int * G, mp_int * X, mp_int * P, mp_int * Y)
{
	mp_int		M[TAB_SIZE], res;
	mp_digit	buf, mp;
	int			err, bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;

/*
	Use a pointer to the reduction algorithm.  This allows us to use
	one of many reduction algorithms without modding the guts of
	the code with if statements everywhere.
*/
	int		(*redux)(mp_int*,mp_int*,mp_digit);

/*
	Find window size
 */
	x = mp_count_bits (X);
	if (x <= 7) {
		winsize = 2;
	} else if (x <= 36) {
		winsize = 3;
	} else if (x <= 140) {
		winsize = 4;
	} else if (x <= 450) {
		winsize = 5;
	} else if (x <= 1303) {
		winsize = 6;
	} else if (x <= 3529) {
		winsize = 7;
	} else {
		winsize = 8;
	}

#ifdef MP_LOW_MEM
	if (winsize > 5) {
		winsize = 5;
	}
#endif /* MP_LOW_MEM */

	/* init M array */
	/* init first cell */
	if ((err = mp_init(&M[1])) != MP_OKAY) {
		return err;
	}

/*
	Now init the second half of the array.
*/
	for (x = 1<<(winsize-1); x < (1 << winsize); x++) {
		if ((err = mp_init(&M[x])) != MP_OKAY) {
			for (y = 1<<(winsize-1); y < x; y++) {
				mp_clear (&M[y]);
			}
			mp_clear(&M[1]);
			return err;
		}
	}


/*
	Now setup montgomery
 */
	if ((err = mp_montgomery_setup (P, &mp)) != MP_OKAY) {
		goto __M;
	}

/*
	Automatically pick the comba one if available (saves quite a few calls/ifs)
 */
	if (((P->used * 2 + 1) < MP_WARRAY) &&
		P->used < (1 << ((CHAR_BIT * sizeof (mp_word)) - (2 * DIGIT_BIT)))) {
			redux = fast_mp_montgomery_reduce;
		} else {
			/* use slower baseline Montgomery method */
			redux = mp_montgomery_reduce;
		}


	/* setup result */
	if ((err = mp_init (&res)) != MP_OKAY) {
		goto __M;
	}

/* 
	Create M table
	The M table contains powers of the input base, e.g. M[x] = G^x mod P
	The first half of the table is not computed though accept for M[0] and M[1]
*/
/*
	now we need R mod m
 */
	if ((err = mp_montgomery_calc_normalization (&res, P)) != MP_OKAY) {
		goto __RES;
	}
/*
	now set M[1] to G * R mod m
 */
	if ((err = mp_mulmod (G, &res, P, &M[1])) != MP_OKAY) {
		goto __RES;
	}
	

/*
	compute the value at M[1<<(winsize-1)] by squaring M[1] (winsize-1) times
 */
	if ((err = mp_copy (&M[1], &M[1 << (winsize - 1)])) != MP_OKAY) {
		goto __RES;
	}

	for (x = 0; x < (winsize - 1); x++) {
		if ((err = mp_sqr (&M[1 << (winsize - 1)], &M[1 << (winsize - 1)])) != MP_OKAY) {
			goto __RES;
		}
		if ((err = redux (&M[1 << (winsize - 1)], P, mp)) != MP_OKAY) {
			goto __RES;
		}
	}

/*
	Create upper table
 */
	for (x = (1 << (winsize - 1)) + 1; x < (1 << winsize); x++) {
		if ((err = mp_mul (&M[x - 1], &M[1], &M[x])) != MP_OKAY) {
			goto __RES;
		}
		if ((err = redux (&M[x], P, mp)) != MP_OKAY) {
			goto __RES;
		}
	}

/*
	set initial mode and bit cnt
 */
	mode   = 0;
	bitcnt = 1;
	buf    = 0;
	digidx = X->used - 1;
	bitcpy = 0;
	bitbuf = 0;

	for (;;) {
/*
		grab next digit as required
 */
		if (--bitcnt == 0) {
/*
			if digidx == -1 we are out of digits so break
 */
			if (digidx == -1) {
				break;
			}
/*
			read next digit and reset bitcnt
 */
			buf    = X->dp[digidx--];
			bitcnt = (int)DIGIT_BIT;
		}

/*
		grab the next msb from the exponent
 */
		y     = (mp_digit)(buf >> (DIGIT_BIT - 1)) & 1;
		buf <<= (mp_digit)1;

/*
		If the bit is zero and mode == 0 then we ignore it
		These represent the leading zero bits before the first 1 bit
		in the exponent.  Technically this opt is not required but it
		does lower the # of trivial squaring/reductions used
 */
		if (mode == 0 && y == 0) {
			continue;
		}

/*
		if the bit is zero and mode == 1 then we square
 */
		if (mode == 1 && y == 0) {
			if ((err = mp_sqr (&res, &res)) != MP_OKAY) {
				goto __RES;
			}
			if ((err = redux (&res, P, mp)) != MP_OKAY) {
				goto __RES;
			}
			continue;
		}

/*
		else we add it to the window
 */
		bitbuf |= (y << (winsize - ++bitcpy));
		mode    = 2;

		if (bitcpy == winsize) {
/*
			ok window is filled so square as required and multiply square first
 */
			for (x = 0; x < winsize; x++) {
				if ((err = mp_sqr (&res, &res)) != MP_OKAY) {
					goto __RES;
				}
				if ((err = redux (&res, P, mp)) != MP_OKAY) {
					goto __RES;
				}
			}

/*
			then multiply
 */
			if ((err = mp_mul (&res, &M[bitbuf], &res)) != MP_OKAY) {
				goto __RES;
			}
			if ((err = redux (&res, P, mp)) != MP_OKAY) {
				goto __RES;
			}

/*
			empty window and reset
 */
			bitcpy = 0;
			bitbuf = 0;
			mode   = 1;
		}
	}

/*
	if bits remain then square/multiply
 */
	if (mode == 2 && bitcpy > 0) {
/*
		square then multiply if the bit is set
 */
		for (x = 0; x < bitcpy; x++) {
			if ((err = mp_sqr (&res, &res)) != MP_OKAY) {
				goto __RES;
			}
			if ((err = redux (&res, P, mp)) != MP_OKAY) {
				goto __RES;
			}

/*
			get next bit of the window
 */
			bitbuf <<= 1;
			if ((bitbuf & (1 << winsize)) != 0) {
				/* then multiply */
				if ((err = mp_mul (&res, &M[1], &res)) != MP_OKAY) {
					goto __RES;
				}
				if ((err = redux (&res, P, mp)) != MP_OKAY) {
					goto __RES;
				}
			}
		}
	}
/*
	Fixup result if Montgomery reduction is used recall that any value in
	a Montgomery system is actually multiplied by R mod n.  So we have
	to reduce one more time to cancel out the factor of R.
 */
	if ((err = mp_montgomery_reduce (&res, P, mp)) != MP_OKAY) {
		goto __RES;
	}

	/* swap res with Y */
	mp_exch (&res, Y);
	err = MP_OKAY;
	__RES:mp_clear (&res);
	__M:

	mp_clear(&M[1]);
	for (x = 1<<(winsize-1); x < (1 << winsize); x++) {
		mp_clear (&M[x]);
	}
	return err;
}

/******************************************************************************/
/*
	Grow as required
 */
int mp_grow (mp_int * a, int size)
{
	int			i;
	mp_digit	*tmp;

/* 
	If the alloc size is smaller alloc more ram.
 */
	if (a->alloc < size) {
/*
		ensure there are always at least MP_PREC digits extra on top
 */
		size += (MP_PREC * 2) - (size % MP_PREC);

/*
		Reallocate the array a->dp

		We store the return in a temporary variable in case the operation 
		failed we don't want to overwrite the dp member of a.
*/
		tmp = OPT_CAST(mp_digit) psRealloc (a->dp, sizeof (mp_digit) * size);
		if (tmp == NULL) {
/*
			reallocation failed but "a" is still valid [can be freed]
 */
			return MP_MEM;
		}

/*
		reallocation succeeded so set a->dp
 */
		a->dp = tmp;

/*
		zero excess digits
 */
		i			= a->alloc;
		a->alloc	= size;
		for (; i < a->alloc; i++) {
			a->dp[i] = 0;
		}
	}
	return MP_OKAY;
}

/******************************************************************************/
/*
	b = |a|

	Simple function copies the input and fixes the sign to positive
*/
int mp_abs (mp_int * a, mp_int * b)
{
	int		res;

/*
	copy a to b
 */
	if (a != b) {
		if ((res = mp_copy (a, b)) != MP_OKAY) {
			return res;
		}
	}

/*
	Force the sign of b to positive
 */
	b->sign = MP_ZPOS;

	return MP_OKAY;
}

/******************************************************************************/
/*
	Creates "a" then copies b into it
 */
int mp_init_copy (mp_int * a, mp_int * b)
{
	int		res;

	if ((res = mp_init (a)) != MP_OKAY) {
		return res;
	}
	return mp_copy (b, a);
}

/******************************************************************************/
/* 
	Reverse an array, used for radix code
 */
void bn_reverse (unsigned char *s, int len)
{
	int				ix, iy;
	unsigned char	t;

	ix = 0;
	iy = len - 1;
	while (ix < iy) {
		t		= s[ix];
		s[ix]	= s[iy];
		s[iy]	= t;
		++ix;
		--iy;
	}
}

/******************************************************************************/
/*
	Shift right by a certain bit count (store quotient in c, optional 
	remainder in d)
 */
int mp_div_2d (mp_int * a, int b, mp_int * c, mp_int * d)
{
	mp_digit	D, r, rr;
	int			x, res;
	mp_int		t;

/*
	If the shift count is <= 0 then we do no work
 */
	if (b <= 0) {
		res = mp_copy (a, c);
		if (d != NULL) {
			mp_zero (d);
		}
		return res;
	}

	if ((res = mp_init (&t)) != MP_OKAY) {
		return res;
	}

/*
	Get the remainder
 */
	if (d != NULL) {
		if ((res = mp_mod_2d (a, b, &t)) != MP_OKAY) {
			mp_clear (&t);
			return res;
		}
	}

	/* copy */
	if ((res = mp_copy (a, c)) != MP_OKAY) {
		mp_clear (&t);
		return res;
	}

/*
	Shift by as many digits in the bit count
 */
	if (b >= (int)DIGIT_BIT) {
		mp_rshd (c, b / DIGIT_BIT);
	}

	/* shift any bit count < DIGIT_BIT */
	D = (mp_digit) (b % DIGIT_BIT);
	if (D != 0) {
		register mp_digit *tmpc, mask, shift;

		/* mask */
		mask = (((mp_digit)1) << D) - 1;

		/* shift for lsb */
		shift = DIGIT_BIT - D;

		/* alias */
		tmpc = c->dp + (c->used - 1);

		/* carry */
		r = 0;
		for (x = c->used - 1; x >= 0; x--) {
/*	
			Get the lower  bits of this word in a temp.
 */
			rr = *tmpc & mask;

/*
			shift the current word and mix in the carry bits from the previous word
 */
			*tmpc = (*tmpc >> D) | (r << shift);
			--tmpc;

/*
			set the carry to the carry bits of the current word found above
 */
			r = rr;
		}
	}
	mp_clamp (c);
	if (d != NULL) {
		mp_exch (&t, d);
	}
	mp_clear (&t);
	return MP_OKAY;
}

/******************************************************************************/
/*
	copy, b = a
 */
int mp_copy (mp_int * a, mp_int * b)
{
	int		res, n;

/*
	If dst == src do nothing
 */
	if (a == b) {
		return MP_OKAY;
	}

/*
	Grow dest
 */
	if (b->alloc < a->used) {
		if ((res = mp_grow (b, a->used)) != MP_OKAY) {
			return res;
		}
	}

/*
	Zero b and copy the parameters over
 */
	{
		register mp_digit *tmpa, *tmpb;

		/* pointer aliases */
		/* source */
		tmpa = a->dp;

		/* destination */
		tmpb = b->dp;

		/* copy all the digits */
		for (n = 0; n < a->used; n++) {
			*tmpb++ = *tmpa++;
		}

		/* clear high digits */
		for (; n < b->used; n++) {
			*tmpb++ = 0;
		}
	}

/*
	copy used count and sign
 */
	b->used = a->used;
	b->sign = a->sign;
	return MP_OKAY;
}

/******************************************************************************/
/*
	Returns the number of bits in an int
 */
int mp_count_bits (mp_int * a)
{
	int			r;
	mp_digit	q;

/* 
	Shortcut
 */
	if (a->used == 0) {
		return 0;
	}

/*
	Get number of digits and add that.
 */
	r = (a->used - 1) * DIGIT_BIT;

/*
	Take the last digit and count the bits in it.
 */
	q = a->dp[a->used - 1];
	while (q > ((mp_digit) 0)) {
		++r;
		q >>= ((mp_digit) 1);
	}
	return r;
}

/******************************************************************************/
/*
	Shift left a certain amount of digits.
 */
int mp_lshd (mp_int * a, int b)
{
	int		x, res;

/*
	If its less than zero return.
 */
	if (b <= 0) {
		return MP_OKAY;
	}

/*
	Grow to fit the new digits.
 */
	if (a->alloc < a->used + b) {
		if ((res = mp_grow (a, a->used + b)) != MP_OKAY) {
			return res;
		}
	}

	{
		register mp_digit *top, *bottom;

/*
		Increment the used by the shift amount then copy upwards.
 */
		a->used += b;

		/* top */
		top = a->dp + a->used - 1;

		/* base */
		bottom = a->dp + a->used - 1 - b;

/*
		Much like mp_rshd this is implemented using a sliding window
		except the window goes the otherway around.  Copying from
		the bottom to the top.  see bn_mp_rshd.c for more info.
 */
		for (x = a->used - 1; x >= b; x--) {
			*top-- = *bottom--;
		}

		/* zero the lower digits */
		top = a->dp;
		for (x = 0; x < b; x++) {
			*top++ = 0;
		}
	}
	return MP_OKAY;
}

/******************************************************************************/
/*
	Set to a digit.
 */
void mp_set (mp_int * a, mp_digit b)
{
	mp_zero (a);
	a->dp[0] = b & MP_MASK;
	a->used  = (a->dp[0] != 0) ? 1 : 0;
}

/******************************************************************************/
/*
	Swap the elements of two integers, for cases where you can't simply swap 
	the 	mp_int pointers around 
*/
void mp_exch (mp_int * a, mp_int * b)
{
	mp_int		t;

	t	= *a;
	*a	= *b;
	*b	= t;
}

/******************************************************************************/
/*
	High level multiplication (handles sign)
 */
#ifdef USE_SLOW_MPI
int mp_mul (mp_int * a, mp_int * b, mp_int * c)
{
	int			res, neg;
	int			digs = a->used + b->used + 1;
	
	neg = (a->sign == b->sign) ? MP_ZPOS : MP_NEG;

/*	Can we use the fast multiplier?
	
	The fast multiplier can be used if the output will have less than 
	MP_WARRAY digits and the number of digits won't affect carry propagation
*/
	if ((digs < MP_WARRAY) &&
		MIN(a->used, b->used) <= 
		(1 << ((CHAR_BIT * sizeof (mp_word)) - (2 * DIGIT_BIT)))) {
			res = fast_s_mp_mul_digs (a, b, c, digs);
		} else {
			res = s_mp_mul (a, b, c);
		}
		c->sign = neg;
		return res;
}
#endif /* USE_SLOW_MPI */

/******************************************************************************/
/* 
	c = a mod b, 0 <= c < b
 */
int mp_mod (mp_int * a, mp_int * b, mp_int * c)
{
	mp_int		t;
	int			res;


	if ((res = mp_init (&t)) != MP_OKAY) {
		return res;
	}

	if ((res = mp_div (a, b, NULL, &t)) != MP_OKAY) {
		mp_clear (&t);
		return res;
	}

	if (t.sign != b->sign) {
		res = mp_add (b, &t, c);
	} else {
		res = MP_OKAY;
		mp_exch (&t, c);
	}

	mp_clear (&t);
	return res;
}

/******************************************************************************/
/*
	Calculates a = B^n mod b for Montgomery reduction. 	Where B is the 
	base [e.g. 2^DIGIT_BIT].B^n mod b is computed by first computing
	A = B^(n-1) which doesn't require a reduction but a simple OR.
	then C = A * B = B^n is computed by performing upto DIGIT_BIT
	shifts with subtractions when the result is greater than b.

	The method is slightly modified to shift B unconditionally upto just under
	the leading bit of b.  This saves alot of multiple precision shifting.
*/
int mp_montgomery_calc_normalization (mp_int * a, mp_int * b)
{
	int		x, bits, res;

/*
	How many bits of last digit does b use
 */
	bits = mp_count_bits (b) % DIGIT_BIT;

/*
	Compute A = B^(n-1) * 2^(bits-1)
 */
	if ((res = mp_2expt (a, (b->used - 1) * DIGIT_BIT + bits - 1)) != MP_OKAY) {
		return res;
	}

/*
	Now compute C = A * B mod b
 */
	for (x = bits - 1; x < (int)DIGIT_BIT; x++) {
		if ((res = mp_mul_2(a, a)) != MP_OKAY) {
			return res;
		}
		if (mp_cmp_mag (a, b) != MP_LT) {
			if ((res = s_mp_sub (a, b, a)) != MP_OKAY) {
				return res;
			}
		}
	}

	return MP_OKAY;
}

/******************************************************************************/
/*
	d = a * b (mod c)
 */
int mp_mulmod (mp_int * a, mp_int * b, mp_int * c, mp_int * d)
{
	int			res;
	mp_int		t;

	if ((res = mp_init (&t)) != MP_OKAY) {
		return res;
	}

	if ((res = mp_mul (a, b, &t)) != MP_OKAY) {
		mp_clear (&t);
		return res;
	}
	res = mp_mod (&t, c, d);
	mp_clear (&t);
	return res;
}

/******************************************************************************/
/*
	Computes b = a*a
 */
#ifdef USE_SLOW_MPI
int mp_sqr (mp_int * a, mp_int * b)
{
	int		res;

/*
	Can we use the fast comba multiplier?
 */
	if ((a->used * 2 + 1) < MP_WARRAY && 
		a->used < 
		(1 << (sizeof(mp_word) * CHAR_BIT - 2*DIGIT_BIT - 1))) {
			res = fast_s_mp_sqr (a, b);
		} else {
			res = s_mp_sqr (a, b);
		}
		b->sign = MP_ZPOS;
		return res;
}
#endif /* USE_SLOW_MPI */

/******************************************************************************/
/* 
	Computes xR**-1 == x (mod N) via Montgomery Reduction.

	This is an optimized implementation of mp_montgomery_reduce 
	which uses the comba method to quickly calculate the columns of the
	reduction.

	Based on Algorithm 14.32 on pp.601 of HAC.
*/
int fast_mp_montgomery_reduce (mp_int * x, mp_int * n, mp_digit rho)
{
	int			ix, res, olduse;
/*
	FUTURE - lower this stack usage, this is around 1K!.
 */
	mp_word W[MP_WARRAY];

/*
	Get old used count
 */
	olduse = x->used;

/*
	Grow a as required
 */
	if (x->alloc < n->used + 1) {
		if ((res = mp_grow (x, n->used + 1)) != MP_OKAY) {
			return res;
		}
	}

/*
	First we have to get the digits of the input into
	an array of double precision words W[...]
 */
	{
		register mp_word *_W;
		register mp_digit *tmpx;

/*
		Alias for the W[] array
 */
		_W   = W;

/*
		Alias for the digits of  x
 */
		tmpx = x->dp;

/*
		Copy the digits of a into W[0..a->used-1]
 */
		for (ix = 0; ix < x->used; ix++) {
			*_W++ = *tmpx++;
		}

/*
		Zero the high words of W[a->used..m->used*2]
 */
		for (; ix < n->used * 2 + 1; ix++) {
			*_W++ = 0;
		}
	}

/*
	Now we proceed to zero successive digits from the least
	significant upwards.
*/
#ifdef USE_SSE
/*
	compute globals we'd like to have in MMX registers
 */
	asm ("movl $268435455,%%eax		\n\t"		/* mm2 == MP_MASK */
		"movd %%eax,%%mm2			\n\t"
		"movd %0,%%mm3				\n\t"		/* mm3 = rho */
		"movq (%1),%%mm0			\n\t"		/* W[ix] for ix=0 */
		::"r"(rho),"r"(W):"%eax");
#endif

	for (ix = 0; ix < n->used; ix++) {
/*		
		mu = ai * m' mod b
		
		We avoid a double precision multiplication (which isn't required) by 
		casting the value down to a mp_digit.  Note this requires that
		W[ix-1] have  the carry cleared (see after the inner loop)
 */
#ifndef USE_SSE
	register mp_digit mu;
	mu = (mp_digit) (((W[ix] & MP_MASK) * rho) & MP_MASK);
#else
	asm("pmuludq		%mm3,%mm0	\n\t"		/* multiply against rho */
		"pand			%mm2,%mm0	\n\t");		/* mu == mm0 */
#endif
/*
		a = a + mu * m * b**i
		
		This is computed in place and on the fly.  The multiplication by b**i 
		is handled by offseting which columns the results are added to.
		
		Note the comba method normally doesn't handle carries in the inner loop
		In this case we fix the carry from the previous column since the
		Montgomery reduction requires digits of the result (so far) [see above]
		to work.  This is handled by fixing up one carry after the inner loop.
		The carry fixups are done in order so after these loops the first
		m->used words of W[] have the carries fixed
 */
		{
			register int iy;
			register mp_digit *tmpn;
			register mp_word *_W;

/*
			Alias for the digits of the modulus
 */
			tmpn = n->dp;

/*
			Alias for the columns set by an offset of ix
 */
			_W = W + ix;

/*			
			inner loop
 */
			for (iy = 0; iy < n->used; iy++) {
#ifndef USE_SSE
				*_W++ += ((mp_word)mu) * ((mp_word)*tmpn++);
#else
/*
				SSE version
*/
				asm ("movd		(%0), %%mm1 \n\t"	/* load right side */
					"pmuludq	%%mm0,%%mm1 \n\t"	/* multiply into left side */
					"paddq		(%1),%%mm1  \n\t"	/* add 64-bit result out */
					"movq		%%mm1,(%1)"			/* store result */
					:: "r"(tmpn), "r"(_W));
/*
				update pointers
 */
				++tmpn; 
				++_W;
#endif
			}
		}

/*
		Now fix carry for next digit, W[ix+1]
 */
#ifndef USE_SSE
		W[ix + 1] += W[ix] >> ((mp_word) DIGIT_BIT);
#else
		asm("movq  (%0),%%mm0			\n\t"		/* W[ix] */
			"psrlq $28,%%mm0			\n\t"		/* W[ix]>>28 */
			"paddq 8(%0),%%mm0			\n\t"		/* W[ix+1] + W[ix]>>28 */
			"movq  %%mm0,8(%0)				"		/* store */
			::"r"(&W[ix]));
#endif
	}

/*
		Now we have to propagate the carries and shift the words downward [all those 
		least significant digits we zeroed].
*/
	{
		register mp_digit *tmpx;
		register mp_word *_W, *_W1;

/*
		Now fix rest of carries 
 */

/*
		alias for current word
 */
		_W1 = W + ix;

/*
		alias for next word, where the carry goes
 */
		_W = W + ++ix;

/*
		alias for destination word
 */
		tmpx = x->dp;

		for (; ix <= n->used * 2 + 1; ix++) {
#ifndef USE_SSE
			*tmpx++ = (mp_digit)(*_W1 & ((mp_word) MP_MASK));
			*_W++  += *_W1++ >> ((mp_word) DIGIT_BIT);
#else
			asm("movq	%%mm0,%%mm1			\n\t"	/* copy of W[ix] */
				"psrlq	$28,%%mm0			\n\t"	/* >>28 */
				"pand	%%mm2,%%mm1			\n\t"	/* & with MP_MASK */
				"paddq	(%0),%%mm0			\n\t"	/* += _W */
				"movd	%%mm1,(%1)			\n\t"	/* store it */
				::"r"(_W),"r"(tmpx));
			++_W; ++tmpx;
#endif
		}

/* 
		Zero oldused digits, if the input a was larger than m->used+1 we'll 
		have to clear the digits.
 */
	for (ix = n->used + 1; ix < olduse; ix++) {
			*tmpx++ = 0;
		}
	}

#ifdef USE_SSE
	asm("emms");
#endif

/*
	Set the max used and clamp
 */
	x->used = n->used + 1;
	mp_clamp (x);

/*
	if A >= m then A = A - m
 */
	if (mp_cmp_mag (x, n) != MP_LT) {
		return s_mp_sub (x, n, x);
	}
	return MP_OKAY;
}

/******************************************************************************/
/*
	High level addition (handles signs)
 */
int mp_add (mp_int * a, mp_int * b, mp_int * c)
{
	int		sa, sb, res;

/*
	Get sign of both inputs
 */
	sa = a->sign;
	sb = b->sign;

/*
	Handle two cases, not four.
 */
	if (sa == sb) {
/*
		Both positive or both negative. Add their magnitudes, copy the sign.
 */
		c->sign = sa;
		res = s_mp_add (a, b, c);
	} else {
/*
		One positive, the other negative.  Subtract the one with the greater
		magnitude from the one of the lesser magnitude.  The result gets the sign of
		the one with the greater magnitude.
 */
		if (mp_cmp_mag (a, b) == MP_LT) {
			c->sign = sb;
			res = s_mp_sub (b, a, c);
		} else {
			c->sign = sa;
			res = s_mp_sub (a, b, c);
		}
	}
	return res;
}

/******************************************************************************/
/*
	Compare a digit.
 */
int mp_cmp_d (mp_int * a, mp_digit b)
{
/*
	Compare based on sign
 */
	if (a->sign == MP_NEG) {
		return MP_LT;
	}

/*
	Compare based on magnitude
 */
	if (a->used > 1) {
		return MP_GT;
	}

/*
	Compare the only digit of a to b
 */
	if (a->dp[0] > b) {
		return MP_GT;
	} else if (a->dp[0] < b) {
		return MP_LT;
	} else {
		return MP_EQ;
	}
}

/******************************************************************************/
/*
	b = a/2
 */
int mp_div_2 (mp_int * a, mp_int * b)
{
	int		x, res, oldused;

/*
	Copy
 */
	if (b->alloc < a->used) {
		if ((res = mp_grow (b, a->used)) != MP_OKAY) {
			return res;
		}
	}

	oldused = b->used;
	b->used = a->used;
	{
		register mp_digit r, rr, *tmpa, *tmpb;

/*
		Source alias
 */
		tmpa = a->dp + b->used - 1;

/*
		dest alias
 */
		tmpb = b->dp + b->used - 1;

/*
		carry
 */
		r = 0;
		for (x = b->used - 1; x >= 0; x--) {
/*
			Get the carry for the next iteration
 */
			rr = *tmpa & 1;

/*			
			Shift the current digit, add in carry and store
 */
			*tmpb-- = (*tmpa-- >> 1) | (r << (DIGIT_BIT - 1));
/*
			Forward carry to next iteration
 */
			r = rr;
		}

/* 
		Zero excess digits
 */
		tmpb = b->dp + b->used;
		for (x = b->used; x < oldused; x++) {
			*tmpb++ = 0;
		}
	}
	b->sign = a->sign;
	mp_clamp (b);
	return MP_OKAY;
}

/******************************************************************************/
/*
	Computes xR**-1 == x (mod N) via Montgomery Reduction
 */
#ifdef USE_SLOW_MPI
int mp_montgomery_reduce (mp_int * x, mp_int * n, mp_digit rho)
{
	int			ix, res, digs;
	mp_digit	mu;

/*	Can the fast reduction [comba] method be used?

	Note that unlike in mp_mul you're safely allowed *less* than the available
	columns [255 per default] since carries are fixed up in the inner loop.
 */
	digs = n->used * 2 + 1;
	if ((digs < MP_WARRAY) && 
		n->used < 
		(1 << ((CHAR_BIT * sizeof (mp_word)) - (2 * DIGIT_BIT)))) {
			return fast_mp_montgomery_reduce (x, n, rho);
		}

/*
		Grow the input as required.
 */
		if (x->alloc < digs) {
			if ((res = mp_grow (x, digs)) != MP_OKAY) {
				return res;
			}
		}
		x->used = digs;

		for (ix = 0; ix < n->used; ix++) {
/*
			mu = ai * rho mod b

			The value of rho must be precalculated via bn_mp_montgomery_setup()
			such that it equals -1/n0 mod b this allows the following inner
			loop to reduce the input one digit at a time
 */
			mu = (mp_digit)(((mp_word)x->dp[ix]) * ((mp_word)rho) & MP_MASK);

			/* a = a + mu * m * b**i */
			{
				register int iy;
				register mp_digit *tmpn, *tmpx, u;
				register mp_word r;

/*
				alias for digits of the modulus
 */
				tmpn = n->dp;

/*
				alias for the digits of x [the input]
 */
				tmpx = x->dp + ix;

/*
				set the carry to zero
 */
				u = 0;

/*
				Multiply and add in place
 */
				for (iy = 0; iy < n->used; iy++) {
					/* compute product and sum */
					r = ((mp_word)mu) * ((mp_word)*tmpn++) +
						((mp_word) u) + ((mp_word) * tmpx);

					/* get carry */
					u = (mp_digit)(r >> ((mp_word) DIGIT_BIT));

					/* fix digit */
					*tmpx++ = (mp_digit)(r & ((mp_word) MP_MASK));
				}
				/* At this point the ix'th digit of x should be zero */


/*
				propagate carries upwards as required
 */
				while (u) {
					*tmpx		+= u;
					u			= *tmpx >> DIGIT_BIT;
					*tmpx++ &= MP_MASK;
				}
			}
		}

/*
		At this point the n.used'th least significant digits of x are all zero
		which means we can shift x to the right by n.used digits and the 
		residue is unchanged.
*/
		/* x = x/b**n.used */
		mp_clamp(x);
		mp_rshd (x, n->used);

		/* if x >= n then x = x - n */
		if (mp_cmp_mag (x, n) != MP_LT) {
			return s_mp_sub (x, n, x);
		}

		return MP_OKAY;
}
#endif /* USE_SLOW_MPI */

/******************************************************************************/
/*
	Setups the montgomery reduction stuff.
 */
int mp_montgomery_setup (mp_int * n, mp_digit * rho)
{
	mp_digit x, b;

/*
	fast inversion mod 2**k
	
	Based on the fact that
	
	XA = 1 (mod 2**n)	=>  (X(2-XA)) A		= 1 (mod 2**2n)
						=>  2*X*A - X*X*A*A	= 1
						=>  2*(1) - (1)		= 1
*/
	b = n->dp[0];

	if ((b & 1) == 0) {
		return MP_VAL;
	}

	x = (((b + 2) & 4) << 1) + b;		/* here x*a==1 mod 2**4 */
	x = (x * (2 - b * x)) & MP_MASK;	/* here x*a==1 mod 2**8 */
#if !defined(MP_8BIT)
	x = (x * (2 - b * x)) & MP_MASK;	/* here x*a==1 mod 2**16 */
#endif /* MP_8BIT */
#if defined(MP_64BIT) || !(defined(MP_8BIT) || defined(MP_16BIT))
	x *= 2 - b * x;						/* here x*a==1 mod 2**32 */
#endif
#ifdef MP_64BIT
	x *= 2 - b * x;						/* here x*a==1 mod 2**64 */
#endif /* MP_64BIT */

	/* rho = -1/m mod b */
	*rho = (((mp_digit) 1 << ((mp_digit) DIGIT_BIT)) - x) & MP_MASK;

	return MP_OKAY;
}

/******************************************************************************/
/*
	High level subtraction (handles signs)
 */
int mp_sub (mp_int * a, mp_int * b, mp_int * c)
{
	int		sa, sb, res;

	sa = a->sign;
	sb = b->sign;

	if (sa != sb) {
/*
		Subtract a negative from a positive, OR subtract a positive from a
		negative.  In either case, ADD their magnitudes, and use the sign of
		the first number.
 */
		c->sign = sa;
		res = s_mp_add (a, b, c);
	} else {
/*
		Subtract a positive from a positive, OR subtract a negative 
		from a negative. First, take the difference between their
		magnitudes, then...
 */
		if (mp_cmp_mag (a, b) != MP_LT) {
/*
			Copy the sign from the first
 */
			c->sign = sa;
			/* The first has a larger or equal magnitude */
			res = s_mp_sub (a, b, c);
		} else {
/*
			The result has the *opposite* sign from the first number.
 */
			c->sign = (sa == MP_ZPOS) ? MP_NEG : MP_ZPOS;
/*
			The second has a larger magnitude 
 */
			res = s_mp_sub (b, a, c);
		}
	}
	return res;
}

/******************************************************************************/
/*
	calc a value mod 2**b
 */
int mp_mod_2d (mp_int * a, int b, mp_int * c)
{
	int		x, res;

/*
	if b is <= 0 then zero the int
 */
	if (b <= 0) {
		mp_zero (c);
		return MP_OKAY;
	}

/*
	If the modulus is larger than the value than return
 */
	if (b > (int) (a->used * DIGIT_BIT)) {
		res = mp_copy (a, c);
		return res;
	}

	/* copy */
	if ((res = mp_copy (a, c)) != MP_OKAY) {
		return res;
	}

/*
	Zero digits above the last digit of the modulus
 */
	for (x = (b / DIGIT_BIT) + ((b % DIGIT_BIT) == 0 ? 0 : 1); x < c->used; x++) {
		c->dp[x] = 0;
	}
/*
	Clear the digit that is not completely outside/inside the modulus
 */
	c->dp[b / DIGIT_BIT] &=
		(mp_digit) ((((mp_digit) 1) << (((mp_digit) b) % DIGIT_BIT)) - ((mp_digit) 1));
	mp_clamp (c);
	return MP_OKAY;
}

/******************************************************************************/
/*
	Shift right a certain amount of digits.
 */
void mp_rshd (mp_int * a, int b)
{
	int		x;

/*
	If b <= 0 then ignore it
 */
	if (b <= 0) {
		return;
	}

/*
	If b > used then simply zero it and return.
*/
	if (a->used <= b) {
		mp_zero (a);
		return;
	}

	{
		register mp_digit *bottom, *top;

/*
		Shift the digits down
 */
		/* bottom */
		bottom = a->dp;

		/* top [offset into digits] */
		top = a->dp + b;

/*
		This is implemented as a sliding window where the window is b-digits long
		and digits from the top of the window are copied to the bottom.
		
		 e.g.

		b-2 | b-1 | b0 | b1 | b2 | ... | bb |   ---->
		/\                   |      ---->
		\-------------------/      ---->
 */
		for (x = 0; x < (a->used - b); x++) {
			*bottom++ = *top++;
		}

/*
		Zero the top digits
 */
		for (; x < a->used; x++) {
			*bottom++ = 0;
		}
	}

/*
	Remove excess digits
 */
	a->used -= b;
}

/******************************************************************************/
/* 
	Low level subtraction (assumes |a| > |b|), HAC pp.595 Algorithm 14.9
 */
int s_mp_sub (mp_int * a, mp_int * b, mp_int * c)
{
	int		olduse, res, min, max;

/*
	Find sizes
 */
	min = b->used;
	max = a->used;

/*
	init result
 */
	if (c->alloc < max) {
		if ((res = mp_grow (c, max)) != MP_OKAY) {
			return res;
		}
	}
	olduse = c->used;
	c->used = max;

	{
		register mp_digit u, *tmpa, *tmpb, *tmpc;
		register int i;

/*
		alias for digit pointers
 */
		tmpa = a->dp;
		tmpb = b->dp;
		tmpc = c->dp;

/*
		set carry to zero
 */
		u = 0;
		for (i = 0; i < min; i++) {
			/* T[i] = A[i] - B[i] - U */
			*tmpc = *tmpa++ - *tmpb++ - u;

/*
			U = carry bit of T[i]
			Note this saves performing an AND operation since if a carry does occur it
			will propagate all the way to the MSB.  As a result a single shift
			is enough to get the carry
 */
			u = *tmpc >> ((mp_digit)(CHAR_BIT * sizeof (mp_digit) - 1));

			/* Clear carry from T[i] */
			*tmpc++ &= MP_MASK;
		}

/*
		Now copy higher words if any, e.g. if A has more digits than B
 */
		for (; i < max; i++) {
			/* T[i] = A[i] - U */
			*tmpc = *tmpa++ - u;

			/* U = carry bit of T[i] */
			u = *tmpc >> ((mp_digit)(CHAR_BIT * sizeof (mp_digit) - 1));

			/* Clear carry from T[i] */
			*tmpc++ &= MP_MASK;
		}

/*
		Clear digits above used (since we may not have grown result above)
 */
		for (i = c->used; i < olduse; i++) {
			*tmpc++ = 0;
		}
	}

	mp_clamp (c);
	return MP_OKAY;
}
/******************************************************************************/
/*
	integer signed division. 

	c*b + d == a [e.g. a/b, c=quotient, d=remainder]
	HAC pp.598 Algorithm 14.20

	Note that the description in HAC is horribly incomplete.  For example,
	it doesn't consider the case where digits are removed from 'x' in the inner
	loop.  It also doesn't consider the case that y has fewer than three
	digits, etc..

	The overall algorithm is as described as 14.20 from HAC but fixed to
	treat these cases.
 */
int mp_div (mp_int * a, mp_int * b, mp_int * c, mp_int * d)
{
	mp_int	ta, tb, tq, q;
	int		res, n, n2;

/*
	is divisor zero ?
 */
	if (mp_iszero (b) == 1) {
		return MP_VAL;
	}

/*
	if a < b then q=0, r = a
 */
	if (mp_cmp_mag (a, b) == MP_LT) {
		if (d != NULL) {
			res = mp_copy (a, d);
		} else {
			res = MP_OKAY;
		}
		if (c != NULL) {
			mp_zero (c);
		}
		return res;
	}
	
/*
	init our temps
 */
	if ((res = _mp_init_multi(&ta, &tb, &tq, &q, NULL, NULL, NULL, NULL) != MP_OKAY)) {
		return res;
	}

/*
	tq = 2^n,  tb == b*2^n
 */
	mp_set(&tq, 1);
	n = mp_count_bits(a) - mp_count_bits(b);
	if (((res = mp_copy(a, &ta)) != MP_OKAY) ||
		((res = mp_copy(b, &tb)) != MP_OKAY) || 
		((res = mp_mul_2d(&tb, n, &tb)) != MP_OKAY) ||
		((res = mp_mul_2d(&tq, n, &tq)) != MP_OKAY)) {
			goto __ERR;
	}

	while (n-- >= 0) {
		if (mp_cmp(&tb, &ta) != MP_GT) {
			if (((res = mp_sub(&ta, &tb, &ta)) != MP_OKAY) ||
				((res = mp_add(&q, &tq, &q)) != MP_OKAY)) {
					goto __ERR;
			}
		}
		if (((res = mp_div_2d(&tb, 1, &tb, NULL)) != MP_OKAY) ||
			((res = mp_div_2d(&tq, 1, &tq, NULL)) != MP_OKAY)) {
			goto __ERR;
		}
	}

/*
	now q == quotient and ta == remainder
 */
	n  = a->sign;
	n2 = (a->sign == b->sign ? MP_ZPOS : MP_NEG);
	if (c != NULL) {
		mp_exch(c, &q);
		c->sign  = n2;
	}
	if (d != NULL) {
		mp_exch(d, &ta);
		d->sign = n;
	}
__ERR:
	_mp_clear_multi(&ta, &tb, &tq, &q, NULL, NULL, NULL, NULL);
	return res;
}

/******************************************************************************/
/*
	multiplies |a| * |b| and only computes upto digs digits of result 
	HAC pp. 595, Algorithm 14.12  Modified so you can control how many digits
	of output are created.
 */
#ifdef USE_SLOW_MPI
int s_mp_mul_digs (mp_int * a, mp_int * b, mp_int * c, int digs)
{
	mp_int		t;
	int			res, pa, pb, ix, iy;
	mp_digit	u;
	mp_word		r;
	mp_digit	tmpx, *tmpt, *tmpy;

/*
	Can we use the fast multiplier?
 */
	if (((digs) < MP_WARRAY) &&
		MIN (a->used, b->used) < 
		(1 << ((CHAR_BIT * sizeof (mp_word)) - (2 * DIGIT_BIT)))) {
			return fast_s_mp_mul_digs (a, b, c, digs);
		}

		if ((res = mp_init_size (&t, digs)) != MP_OKAY) {
			return res;
		}
		t.used = digs;

/*
		Compute the digits of the product directly
 */
		pa = a->used;
		for (ix = 0; ix < pa; ix++) {
			/* set the carry to zero */
			u = 0;

/*
			Limit ourselves to making digs digits of output.
*/
			pb = MIN (b->used, digs - ix);

/*
			Setup some aliases. Copy of the digit from a used
			within the nested loop
 */
			tmpx = a->dp[ix];

/*
			An alias for the destination shifted ix places
 */
			tmpt = t.dp + ix;

/*
			An alias for the digits of b
 */
			tmpy = b->dp;

/*
			Compute the columns of the output and propagate the carry
 */
			for (iy = 0; iy < pb; iy++) {
				/* compute the column as a mp_word */
				r       = ((mp_word)*tmpt) +
					((mp_word)tmpx) * ((mp_word)*tmpy++) +
					((mp_word) u);

				/* the new column is the lower part of the result */
				*tmpt++ = (mp_digit) (r & ((mp_word) MP_MASK));

				/* get the carry word from the result */
				u       = (mp_digit) (r >> ((mp_word) DIGIT_BIT));
			}
/*
			Set carry if it is placed below digs
 */
			if (ix + iy < digs) {
				*tmpt = u;
			}
		}

		mp_clamp (&t);
		mp_exch (&t, c);

		mp_clear (&t);
		return MP_OKAY;
}
#endif /* USE_SLOW_MPI */

/******************************************************************************/
/*
	Fast (comba) multiplier

	This is the fast column-array [comba] multiplier.  It is designed to
	compute the columns of the product first then handle the carries afterwards.
	This has the effect of making the nested loops that compute the columns
	very simple and schedulable on super-scalar processors.

	This has been modified to produce a variable number of digits of output so
	if say only a half-product is required you don't have to compute the upper
	half (a feature required for fast Barrett reduction).

	Based on Algorithm 14.12 on pp.595 of HAC.

*/
int fast_s_mp_mul_digs (mp_int * a, mp_int * b, mp_int * c, int digs)
{
	int			olduse, res, pa, ix;
/*	FUTURE - lower this stack usage. */
	mp_word		W[MP_WARRAY];

/*
	grow the destination as required
 */
	if (c->alloc < digs) {
		if ((res = mp_grow (c, digs)) != MP_OKAY) {
			return res;
		}
	}

/*
	clear temp buf (the columns)
 */
	memset (W, 0, sizeof (mp_word) * digs);

/*
	calculate the columns
 */
	pa = a->used;
	for (ix = 0; ix < pa; ix++) {
/*
		This multiplier has been modified to allow you to control how many
		digits of output are produced.  So at most we want to make upto
		"digs" digits of output.
		
		This adds products to distinct columns (at ix+iy) of W note that each
		step through the loop is not dependent on the previous which means the
		compiler can easily unroll the loop without scheduling problems
 */
		{
#ifndef USE_SSE
			register mp_digit tmpx;
#endif
			register mp_digit *tmpy;
			register mp_word *_W;
			register int iy, pb;

/*
			alias for the the word on the left e.g. A[ix] * A[iy]
 */
#ifndef USE_SSE
			tmpx = a->dp[ix];
#else
/*
			SSE: now we load the left side in mm0
 */
			asm (" movd %0, %%mm0 " :: "r"(a->dp[ix]));
#endif

/*
			alias for the right side
 */
			tmpy = b->dp;

/*
			alias for the columns, each step through the loop adds a new
			term to each column
 */
			_W = W + ix;

/*
			the number of digits is limited by their placement.  E.g.we avoid
			multiplying digits that will end up above the # of digits of
			precision requested
 */
			pb = MIN (b->used, digs - ix);

			for (iy = 0; iy < pb; iy++) {
#ifndef USE_SSE
				*_W++ += ((mp_word)tmpx) * ((mp_word)*tmpy++);
#else
/*
				SSE version
*/
				asm ("movd		(%0), %%mm1 \n\t"		/* load right side */
					"pmuludq	%%mm0,%%mm1 \n\t"		/* multiply into left side */
					"paddq		(%1), %%mm1 \n\t"		/* add 64-bit result out */
					"movq		%%mm1,(%1)"				/* store result */
					:: "r"(tmpy), "r"(_W));
/*
				update pointers
*/
				++tmpy; 
				++_W;
#endif
			}
		}
	}

	/* setup dest */
	olduse = c->used;
	c->used = digs;

	{
		register mp_digit *tmpc;

/*
		At this point W[] contains the sums of each column.  To get the 
		correct result we must take the extra bits from each column and carry
		them down
		
		Note that while this adds extra code to the multiplier it saves time
		since the carry propagation is removed from the above nested loop.This
		has the effect of reducing the work 
		from N*(N+N*c)==N**2 + c*N**2 to N**2 + N*c where c is the cost of the
		shifting.  On very small numbers this is slower but on most 
		cryptographic size numbers it is faster.
		
		In this particular implementation we feed the carries from behind which
		means when the loop terminates we still have one last digit to copy
 */
		tmpc = c->dp;
#ifdef USE_SSE
/*
		mm2 has W[ix-1]
*/
		asm("movq (%0),%%mm2"::"r"(W));
#endif

		for (ix = 1; ix < digs; ix++) {
#ifndef USE_SSE
/*
			forward the carry from the previous temp
 */
			W[ix] += (W[ix - 1] >> ((mp_word) DIGIT_BIT));

/*
			now extract the previous digit [below the carry]
 */
			*tmpc++ = (mp_digit) (W[ix - 1] & ((mp_word) MP_MASK));

#else
			asm(
				"movq (%0),%%mm1			\n\t"		/* W[ix] */
				"movd  %%mm2,%%eax			\n\t"		/* get 32-bit version of it W[ix-1] */
				"psrlq $28,%%mm2			\n\t"		/* W[ix-1] >> DIGIT_BIT ... must be 28 */
				"andl  $268435455,%%eax		\n\t"		/* & with MP_MASK against W[ix-1] */
				"paddq %%mm1,%%mm2			\n\t"		/* add them */
				"movl  %%eax,(%1)			\n\t"		/* store it */
				:: "r"(&W[ix]), "r"(tmpc) : "%eax");
			++tmpc;
#endif
		}

#ifndef USE_SSE
/*
		fetch the last digit
 */
		*tmpc++ = (mp_digit) (W[digs - 1] & ((mp_word) MP_MASK));
#else
/*
		get last since we don't store into W[ix] anymore
 */
			asm("movd %%mm2,%%eax			\n\t"
				"andl  $268435455,%%eax		\n\t"	/* & with MP_MASK against W[ix-1] */
				"movl  %%eax,(%0)"					/* store it */
				::"r"(tmpc):"%eax");
			++tmpc;
#endif

/*
	clear unused digits [that existed in the old copy of c]
 */
		for (; ix < olduse; ix++) {
			*tmpc++ = 0;
		}
	}

#ifdef USE_SSE
	asm("emms");
#endif

	mp_clamp (c);
	return MP_OKAY;
}

/******************************************************************************/
/*
	b = a*2
 */
int mp_mul_2 (mp_int * a, mp_int * b)
{
	int		x, res, oldused;

/*
	grow to accomodate result
 */
	if (b->alloc < a->used + 1) {
		if ((res = mp_grow (b, a->used + 1)) != MP_OKAY) {
			return res;
		}
	}

	oldused = b->used;
	b->used = a->used;

	{
		register mp_digit r, rr, *tmpa, *tmpb;

		/* alias for source */
		tmpa = a->dp;

		/* alias for dest */
		tmpb = b->dp;

		/* carry */
		r = 0;
		for (x = 0; x < a->used; x++) {

/*
			get what will be the *next* carry bit from the MSB of the 
			current digit 
 */
			rr = *tmpa >> ((mp_digit)(DIGIT_BIT - 1));

/*
			now shift up this digit, add in the carry [from the previous]
 */
			*tmpb++ = ((*tmpa++ << ((mp_digit)1)) | r) & MP_MASK;

/*			copy the carry that would be from the source digit into the next
			iteration 
 */
			r = rr;
		}

/*
		new leading digit?
 */
		if (r != 0) {
/*
			add a MSB which is always 1 at this point
 */
			*tmpb = 1;
			++(b->used);
		}

/*
		now zero any excess digits on the destination that we didn't write to
 */
		tmpb = b->dp + b->used;
		for (x = b->used; x < oldused; x++) {
			*tmpb++ = 0;
		}
	}
	b->sign = a->sign;
	return MP_OKAY;
}

/******************************************************************************/
/*
	multiply by a digit
 */
int mp_mul_d (mp_int * a, mp_digit b, mp_int * c)
{
	mp_digit	u, *tmpa, *tmpc;
	mp_word		r;
	int			ix, res, olduse;

/*
	make sure c is big enough to hold a*b
 */
	if (c->alloc < a->used + 1) {
		if ((res = mp_grow (c, a->used + 1)) != MP_OKAY) {
			return res;
		}
	}

/*
	get the original destinations used count
 */
	olduse = c->used;

/*
	set the sign
 */
	c->sign = a->sign;

/*
	alias for a->dp [source]
 */
	tmpa = a->dp;

/*
	alias for c->dp [dest]
 */
	tmpc = c->dp;

	/* zero carry */
	u = 0;

	/* compute columns */
	for (ix = 0; ix < a->used; ix++) {
/*
		compute product and carry sum for this term
 */
		r       = ((mp_word) u) + ((mp_word)*tmpa++) * ((mp_word)b);

/*
		mask off higher bits to get a single digit
 */
		*tmpc++ = (mp_digit) (r & ((mp_word) MP_MASK));

/*
		send carry into next iteration
 */
		u       = (mp_digit) (r >> ((mp_word) DIGIT_BIT));
	}

/*
	store final carry [if any]
 */
	*tmpc++ = u;

/*
	now zero digits above the top
 */
	while (ix++ < olduse) {
		*tmpc++ = 0;
	}

	/* set used count */
	c->used = a->used + 1;
	mp_clamp(c);

	return MP_OKAY;
}

/******************************************************************************/
/*
	low level squaring, b = a*a, HAC pp.596-597, Algorithm 14.16
 */
#ifdef USE_SLOW_MPI
int s_mp_sqr (mp_int * a, mp_int * b)
{
	mp_int		t;
	int			res, ix, iy, pa;
	mp_word		r;
	mp_digit	u, tmpx, *tmpt;

	pa = a->used;
	if ((res = mp_init_size (&t, 2*pa + 1)) != MP_OKAY) {
		return res;
	}
	
/*
	default used is maximum possible size
 */
	t.used = 2*pa + 1;

	for (ix = 0; ix < pa; ix++) {
/*
		first calculate the digit at 2*ix
		calculate double precision result
 */
		r = ((mp_word) t.dp[2*ix]) +
			((mp_word)a->dp[ix])*((mp_word)a->dp[ix]);

/*
		store lower part in result
 */
		t.dp[ix+ix] = (mp_digit) (r & ((mp_word) MP_MASK));

/*
		get the carry
 */
		u = (mp_digit)(r >> ((mp_word) DIGIT_BIT));

/*
		left hand side of A[ix] * A[iy]
 */
		tmpx = a->dp[ix];

/*
		alias for where to store the results
 */
		tmpt = t.dp + (2*ix + 1);

		for (iy = ix + 1; iy < pa; iy++) {
/*
			first calculate the product
 */
			r = ((mp_word)tmpx) * ((mp_word)a->dp[iy]);

/*
			now calculate the double precision result, note we use addition
			instead of *2 since it's easier to optimize
 */
			r       = ((mp_word) *tmpt) + r + r + ((mp_word) u);

/*
			store lower part
 */
			*tmpt++ = (mp_digit) (r & ((mp_word) MP_MASK));

			/* get carry */
			u       = (mp_digit)(r >> ((mp_word) DIGIT_BIT));
		}
		/* propagate upwards */
		while (u != ((mp_digit) 0)) {
			r       = ((mp_word) *tmpt) + ((mp_word) u);
			*tmpt++ = (mp_digit) (r & ((mp_word) MP_MASK));
			u       = (mp_digit)(r >> ((mp_word) DIGIT_BIT));
		}
	}

	mp_clamp (&t);
	mp_exch (&t, b);
	mp_clear (&t);
	return MP_OKAY;
}
#endif /* USE_SLOW_MPI */

/******************************************************************************/
/*
	fast squaring

	This is the comba method where the columns of the product are computed
	first then the carries are computed.  This has the effect of making a very
	simple inner loop that is executed the most

	W2 represents the outer products and W the inner.

	A further optimizations is made because the inner products are of the 
	form "A * B * 2".  The *2 part does not need to be computed until the end
	which is good because 64-bit shifts are slow!

	Based on Algorithm 14.16 on pp.597 of HAC.
 */
int fast_s_mp_sqr (mp_int * a, mp_int * b)
{
	int     olduse, newused, res, ix, pa;
/*	FUTURE - lower this stack usage, this is around 1K!. */
	mp_word W2[MP_WARRAY], W[MP_WARRAY];

/*
	calculate size of product and allocate as required
 */
	pa = a->used;
	newused = pa + pa;
	if (b->alloc < newused) {
		if ((res = mp_grow (b, newused)) != MP_OKAY) {
			return res;
		}
	}

/*
	zero temp buffer (columns)
	Note that there are two buffers.  Since squaring requires a outer and inner
	product and the inner product requires computing a product and doubling
	it (a relatively expensive op to perform n**2 times if you don't have to)
	the inner and outer products are computed in different buffers.  This way
	the inner product can be doubled using n doublings instead of n**2
 */
	memset (W,  0, newused * sizeof (mp_word));
#ifndef USE_SSE
	memset (W2, 0, newused * sizeof (mp_word));
#endif

/*
	This computes the inner product.  To simplify the inner N**2 loop the
	multiplication by two is done afterwards in the N loop.
*/
	for (ix = 0; ix < pa; ix++) {
/*
		compute the outer product
		
		Note that every outer product is computed for a particular column 
		only once which means that there is no need to do a double precision
		addition into the W2[] array.
 */
#ifndef USE_SSE
		W2[ix + ix] = ((mp_word)a->dp[ix]) * ((mp_word)a->dp[ix]);
#else
		asm("movd    %0,%%xmm0			\n\t"	/* load a->dp[ix] */
			"movdq2q %%xmm0,%%mm0		\n\t"	/* get 64-bit version */
			"pmuludq %%xmm0,%%xmm0		\n\t"	/* square it */
			"movdqu  %%xmm0,(%1)		\n\t"	/* store it (8-byte result, 8-byte zero) */
			::"r"(a->dp[ix]), "r"(&(W2[ix+ix])));
#endif

		{
#ifndef USE_SSE
			register mp_digit tmpx;
#endif
			register mp_digit *tmpy;
			register mp_word *_W;
			register int iy;

/*
			copy of left side
 */
#ifndef USE_SSE
			tmpx = a->dp[ix];
#else
/*
			SSE we load tmpx into mm0 [note: loaded above]
 */
/*			asm (" movd %0, %%mm0 " :: "r"(a->dp[ix])); */
#endif

/*
			alias for right side
 */
			tmpy = a->dp + (ix + 1);

/*
			the column to store the result in
 */
			_W = W + (ix + ix + 1);

/*
			inner products
 */
			for (iy = ix + 1; iy < pa; iy++) {
#ifndef USE_SSE
				*_W++ += ((mp_word)tmpx) * ((mp_word)*tmpy++);
#else
/*
				SSE version
*/
				asm ("movd     (%0), %%mm1 \n\t"	/* load right side */
					"pmuludq  %%mm0,%%mm1 \n\t"		/* multiply into left side */
					"paddq    (%1),%%mm1 \n\t"		/* add 64-bit result out */
					"movq     %%mm1,(%1)"			/* store result */
					:: "r"(tmpy), "r"(_W));
/*
				update pointers 
*/
				++tmpy; 
				++_W;
#endif
			}
		}
	}

/*
	setup dest
 */
	olduse  = b->used;
	b->used = newused;

/*
	now compute digits

	We have to double the inner product sums, add in the  outer product sums,
	propagate carries and convert to single precision.
 */
	{
		register mp_digit *tmpb;

/*
		double first value, since the inner products are half of what
		they should be
 */
		tmpb = b->dp;
#ifndef USE_SSE
		W[0] += W[0] + W2[0];
#else
/*
		mm2 has W[ix-1]
*/
		asm("movq    (%0),%%mm2			\n\t"		/* load W[0] */
			"paddq  %%mm2,%%mm2			\n\t"		/* W[0] + W[0] */
			"paddq   (%1),%%mm2			\n\t"		/* W[0] + W[0] + W2[0] */
			::"r"(W),"r"(W2));
#endif

		for (ix = 1; ix < newused; ix++) {
#ifndef USE_SSE
/*
			double/add next digit
 */
			W[ix] += W[ix] + W2[ix];

/*
			propagate carry forwards [from the previous digit]
 */
			W[ix] = W[ix] + (W[ix - 1] >> ((mp_word) DIGIT_BIT));

/*
			store the current digit now that the carry isn't needed
*/
			*tmpb++ = (mp_digit) (W[ix - 1] & ((mp_word) MP_MASK));
#else
			asm( "movq (%0),%%mm0			\n\t"		/* load W[ix] */
				"movd %%mm2,%%eax			\n\t"		/* 32-bit version of W[ix-1] */
				"paddq %%mm0,%%mm0			\n\t"		/* W[ix] + W[ix] */
				"psrlq $28,%%mm2			\n\t"		/* W[ix-1] >> DIGIT_BIT ... must be 28 */
				"paddq (%1),%%mm0			\n\t"		/* W[ix] + W[ix] + W2[ix] */
				"andl  $268435455,%%eax		\n\t"		/* & with MP_MASK against W[ix-1] */
				"paddq %%mm0,%%mm2			\n\t"		/* W[ix] + W[ix] + W2[ix] + W[ix-1]>>DIGIT_BIT */
				"movl  %%eax,(%2)				"		/* store it */
			:: "r"(&W[ix]), "r"(&W2[ix]), "r"(tmpb):"%eax");
			++tmpb;
#endif
		}

#ifndef USE_SSE
/*
		set the last value.  Note even if the carry is zero this is required
		since the next step will not zero it if b originally had a value at
		b->dp[2*a.used]
*/
		*tmpb++ = (mp_digit) (W[(newused) - 1] & ((mp_word) MP_MASK));
#else
/*
		get last since we don't store into W[ix] anymore
*/
		asm("movd  %%mm2,%%eax			\n\t"
			"andl  $268435455,%%eax		\n\t"		/* & with MP_MASK against W[ix-1] */
			"movl  %%eax,(%0)				"		/* store it */
		::"r"(tmpb):"%eax");
		++tmpb;
#endif

/*
		clear high digits of b if there were any originally
 */
		for (; ix < olduse; ix++) {
			*tmpb++ = 0;
		}
	}
#ifdef USE_SSE
	asm("emms");
#endif

	mp_clamp (b);
	return MP_OKAY;
}

/******************************************************************************/
/*
	computes a = 2**b 

	Simple algorithm which zeroes the int, grows it then just sets one bit
	as required.
 */
int mp_2expt (mp_int * a, int b)
{
	int		res;

/*
	zero a as per default
 */
	mp_zero (a);

/*
	grow a to accomodate the single bit
 */
	if ((res = mp_grow (a, b / DIGIT_BIT + 1)) != MP_OKAY) {
		return res;
	}

/*
	set the used count of where the bit will go
 */
	a->used = b / DIGIT_BIT + 1;

/*
	put the single bit in its place
 */
	a->dp[b / DIGIT_BIT] = ((mp_digit)1) << (b % DIGIT_BIT);

	return MP_OKAY;
}

/******************************************************************************/
/*
	init an mp_init for a given size
 */
int mp_init_size (mp_int * a, int size)
{
/*
	pad size so there are always extra digits
 */
	size += (MP_PREC * 2) - (size % MP_PREC);	

/*
	alloc mem
 */
	a->dp = OPT_CAST(mp_digit) psCalloc (sizeof (mp_digit), size);
	if (a->dp == NULL) {
		return MP_MEM;
	}
	a->used  = 0;
	a->alloc = size;
	a->sign  = MP_ZPOS;

	return MP_OKAY;
}

/******************************************************************************/
/*
	low level addition, based on HAC pp.594, Algorithm 14.7
 */
int s_mp_add (mp_int * a, mp_int * b, mp_int * c)
{
	mp_int		*x;
	int			olduse, res, min, max;

/*
	find sizes, we let |a| <= |b| which means we have to sort them.  "x" will
	point to the input with the most digits
 */
	if (a->used > b->used) {
		min = b->used;
		max = a->used;
		x = a;
	} else {
		min = a->used;
		max = b->used;
		x = b;
	}

	/* init result */
	if (c->alloc < max + 1) {
		if ((res = mp_grow (c, max + 1)) != MP_OKAY) {
			return res;
		}
	}

/*
	get old used digit count and set new one
 */
	olduse = c->used;
	c->used = max + 1;

	{
		register mp_digit u, *tmpa, *tmpb, *tmpc;
		register int i;

		/* alias for digit pointers */

		/* first input */
		tmpa = a->dp;

		/* second input */
		tmpb = b->dp;

		/* destination */
		tmpc = c->dp;

		/* zero the carry */
		u = 0;
		for (i = 0; i < min; i++) {
/*
			Compute the sum at one digit, T[i] = A[i] + B[i] + U
 */
			*tmpc = *tmpa++ + *tmpb++ + u;

/*
			U = carry bit of T[i]
 */
			u = *tmpc >> ((mp_digit)DIGIT_BIT);

/*
			take away carry bit from T[i]
 */
			*tmpc++ &= MP_MASK;
		}

/*
		now copy higher words if any, that is in A+B if A or B has more digits add
		those in 
 */
		if (min != max) {
			for (; i < max; i++) {
				/* T[i] = X[i] + U */
				*tmpc = x->dp[i] + u;

				/* U = carry bit of T[i] */
				u = *tmpc >> ((mp_digit)DIGIT_BIT);

				/* take away carry bit from T[i] */
				*tmpc++ &= MP_MASK;
			}
		}

		/* add carry */
		*tmpc++ = u;

/*
		clear digits above oldused
 */
		for (i = c->used; i < olduse; i++) {
			*tmpc++ = 0;
		}
	}

	mp_clamp (c);
	return MP_OKAY;
}

/******************************************************************************/
#ifdef USE_SLOW_MPI
/*
	FUTURE - this is never needed, SLOW or not, because RSA exponents are
	always odd.
*/
int mp_invmod (mp_int * a, mp_int * b, mp_int * c)
{
	mp_int		x, y, u, v, A, B, C, D;
	int			res;

/*
	b cannot be negative
 */
	if (b->sign == MP_NEG || mp_iszero(b) == 1) {
		return MP_VAL;
	}

/*
	if the modulus is odd we can use a faster routine instead
 */
	if (mp_isodd (b) == 1) {
		return fast_mp_invmod (a, b, c);
	}

/*
	init temps
 */
	if ((res = _mp_init_multi(&x, &y, &u, &v,
			&A, &B, &C, &D)) != MP_OKAY) {
		return res;
	}

	/* x = a, y = b */
	if ((res = mp_copy (a, &x)) != MP_OKAY) {
		goto __ERR;
	}
	if ((res = mp_copy (b, &y)) != MP_OKAY) {
		goto __ERR;
	}

/*
	2. [modified] if x,y are both even then return an error!
 */
	if (mp_iseven (&x) == 1 && mp_iseven (&y) == 1) {
		res = MP_VAL;
		goto __ERR;
	}

/*
	3. u=x, v=y, A=1, B=0, C=0,D=1
 */
	if ((res = mp_copy (&x, &u)) != MP_OKAY) {
		goto __ERR;
	}
	if ((res = mp_copy (&y, &v)) != MP_OKAY) {
		goto __ERR;
	}
	mp_set (&A, 1);
	mp_set (&D, 1);

top:
/*
	4.  while u is even do
 */
	while (mp_iseven (&u) == 1) {
		/* 4.1 u = u/2 */
		if ((res = mp_div_2 (&u, &u)) != MP_OKAY) {
		goto __ERR;
		}
		/* 4.2 if A or B is odd then */
		if (mp_isodd (&A) == 1 || mp_isodd (&B) == 1) {
			/* A = (A+y)/2, B = (B-x)/2 */
			if ((res = mp_add (&A, &y, &A)) != MP_OKAY) {
				goto __ERR;
			}
			if ((res = mp_sub (&B, &x, &B)) != MP_OKAY) {
				goto __ERR;
			}
		}
		/* A = A/2, B = B/2 */
		if ((res = mp_div_2 (&A, &A)) != MP_OKAY) {
			goto __ERR;
		}
		if ((res = mp_div_2 (&B, &B)) != MP_OKAY) {
			goto __ERR;
		}
	}

/*
	5.  while v is even do
 */
	while (mp_iseven (&v) == 1) {
		/* 5.1 v = v/2 */
		if ((res = mp_div_2 (&v, &v)) != MP_OKAY) {
		goto __ERR;
		}
		/* 5.2 if C or D is odd then */
		if (mp_isodd (&C) == 1 || mp_isodd (&D) == 1) {
			/* C = (C+y)/2, D = (D-x)/2 */
			if ((res = mp_add (&C, &y, &C)) != MP_OKAY) {
				goto __ERR;
			}
			if ((res = mp_sub (&D, &x, &D)) != MP_OKAY) {
				goto __ERR;
			}
		}
		/* C = C/2, D = D/2 */
		if ((res = mp_div_2 (&C, &C)) != MP_OKAY) {
			goto __ERR;
		}
		if ((res = mp_div_2 (&D, &D)) != MP_OKAY) {
			goto __ERR;
		}
	}

/*
	6.  if u >= v then
 */
	if (mp_cmp (&u, &v) != MP_LT) {
		/* u = u - v, A = A - C, B = B - D */
		if ((res = mp_sub (&u, &v, &u)) != MP_OKAY) {
		goto __ERR;
		}

		if ((res = mp_sub (&A, &C, &A)) != MP_OKAY) {
		goto __ERR;
		}

		if ((res = mp_sub (&B, &D, &B)) != MP_OKAY) {
		goto __ERR;
		}
	} else {
		/* v - v - u, C = C - A, D = D - B */
		if ((res = mp_sub (&v, &u, &v)) != MP_OKAY) {
		goto __ERR;
		}

		if ((res = mp_sub (&C, &A, &C)) != MP_OKAY) {
		goto __ERR;
		}

		if ((res = mp_sub (&D, &B, &D)) != MP_OKAY) {
		goto __ERR;
		}
	}

/*
	if not zero goto step 4
 */
	if (mp_iszero (&u) == 0)
		goto top;

/*
	now a = C, b = D, gcd == g*v
 */

/*
	if v != 1 then there is no inverse
 */
	if (mp_cmp_d (&v, 1) != MP_EQ) {
		res = MP_VAL;
		goto __ERR;
	}

/*
	if its too low
 */
	while (mp_cmp_d(&C, 0) == MP_LT) {
		if ((res = mp_add(&C, b, &C)) != MP_OKAY) {
			goto __ERR;
		}
	}

/*
	too big
 */
	while (mp_cmp_mag(&C, b) != MP_LT) {
		if ((res = mp_sub(&C, b, &C)) != MP_OKAY) {
			goto __ERR;
		}
	}

/*
	C is now the inverse
 */
	mp_exch (&C, c);
	 res = MP_OKAY;
	__ERR:_mp_clear_multi (&x, &y, &u, &v, &A, &B, &C, &D);
	return res;
}
#endif /* USE_SLOW_MPI */

/******************************************************************************/

int fast_mp_invmod (mp_int * a, mp_int * b, mp_int * c)
{
	mp_int		x, y, u, v, B, D;
	int			res, neg;

/*
	2. [modified] b must be odd
 */
	if (mp_iseven (b) == 1) {
		return MP_VAL;
	}

/*
	init all our temps
 */
	if ((res = _mp_init_multi(&x, &y, &u, &v, &B, &D, NULL, NULL)) != MP_OKAY) {
		return res;
	}

/*
	x == modulus, y == value to invert
 */
	if ((res = mp_copy (b, &x)) != MP_OKAY) {
		goto __ERR;
	}

/*
	we need y = |a|
 */
	if ((res = mp_abs (a, &y)) != MP_OKAY) {
		goto __ERR;
	}

/*
	3. u=x, v=y, A=1, B=0, C=0,D=1
 */
	if ((res = mp_copy (&x, &u)) != MP_OKAY) {
		goto __ERR;
	}
	if ((res = mp_copy (&y, &v)) != MP_OKAY) {
		goto __ERR;
	}
	mp_set (&D, 1);

top:
/*
	4.  while u is even do
*/
	while (mp_iseven (&u) == 1) {
		/* 4.1 u = u/2 */
		if ((res = mp_div_2 (&u, &u)) != MP_OKAY) {
			goto __ERR;
		}
		/* 4.2 if B is odd then */
		if (mp_isodd (&B) == 1) {
			if ((res = mp_sub (&B, &x, &B)) != MP_OKAY) {
				goto __ERR;
			}
		}
		/* B = B/2 */
		if ((res = mp_div_2 (&B, &B)) != MP_OKAY) {
			goto __ERR;
		}
	}

/*
	5.  while v is even do
 */
	while (mp_iseven (&v) == 1) {
		/* 5.1 v = v/2 */
		if ((res = mp_div_2 (&v, &v)) != MP_OKAY) {
			goto __ERR;
		}
		/* 5.2 if D is odd then */
		if (mp_isodd (&D) == 1) {
			/* D = (D-x)/2 */
			if ((res = mp_sub (&D, &x, &D)) != MP_OKAY) {
				goto __ERR;
			}
		}
		/* D = D/2 */
		if ((res = mp_div_2 (&D, &D)) != MP_OKAY) {
			goto __ERR;
		}
	}

/*
	6.  if u >= v then
 */
	if (mp_cmp (&u, &v) != MP_LT) {
		/* u = u - v, B = B - D */
		if ((res = mp_sub (&u, &v, &u)) != MP_OKAY) {
			goto __ERR;
		}

		if ((res = mp_sub (&B, &D, &B)) != MP_OKAY) {
			goto __ERR;
		}
	} else {
		/* v - v - u, D = D - B */
		if ((res = mp_sub (&v, &u, &v)) != MP_OKAY) {
			goto __ERR;
		}

		if ((res = mp_sub (&D, &B, &D)) != MP_OKAY) {
		goto __ERR;
		}
	}

/*
	if not zero goto step 4
 */
	if (mp_iszero (&u) == 0) {
		goto top;
	}

/*
	now a = C, b = D, gcd == g*v
 */

/*
	if v != 1 then there is no inverse
 */
	if (mp_cmp_d (&v, 1) != MP_EQ) {
		res = MP_VAL;
		goto __ERR;
	}

/*
	b is now the inverse
 */
	neg = a->sign;
	while (D.sign == MP_NEG) {
		if ((res = mp_add (&D, b, &D)) != MP_OKAY) {
		goto __ERR;
		}
	}
	mp_exch (&D, c);
	c->sign = neg;
	res = MP_OKAY;

	__ERR:_mp_clear_multi (&x, &y, &u, &v, &B, &D, NULL, NULL);
	return res;
}

/******************************************************************************/
/*
	d = a + b (mod c)
 */
int mp_addmod (mp_int * a, mp_int * b, mp_int * c, mp_int * d)
{
	int			res;
	mp_int		t;

	if ((res = mp_init (&t)) != MP_OKAY) {
		return res;
	}

	if ((res = mp_add (a, b, &t)) != MP_OKAY) {
		mp_clear (&t);
		return res;
	}
	res = mp_mod (&t, c, d);
	mp_clear (&t);
	return res;
}

/******************************************************************************/
/*
	shrink a bignum
 */
int mp_shrink (mp_int * a)
{
	mp_digit *tmp;

	if (a->alloc != a->used && a->used > 0) {
		if ((tmp = psRealloc (a->dp, sizeof (mp_digit) * a->used)) == NULL) {
		return MP_MEM;
		}
		a->dp    = tmp;
		a->alloc = a->used;
	}
	return MP_OKAY;
}

/******************************************************************************/

