#include <sys/types.h>
#include <stdint.h>
#include "auth.h"
#include <Arduino.h>

#define SHA_CTX SHA1_CTX
#define SHATransform SHA1Transform
#define SHAInit SHA1Init
#define SHAUpdate SHA1Update
#define SHAFinal SHA1Final

/*
 *  SHA-1 in C
 *  By Steve Reid <steve@edmweb.com>
 *  100% Public Domain
 *
 *  Version:  $Id: sha1.c,v 1.6 2004/05/28 17:00:35 aland Exp $
 */

#define blk0(i) (block->l[i] = htonl(block->l[i]))

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */

#define htonl(x) (((x)<<24 & 0xFF000000UL) | ((x)<< 8 & 0x00FF0000UL) | ((x)>> 8 & 0x0000FF00UL) | ((x)>>24 & 0x000000FFUL))

#define blk0(i) (block->l[i] = htonl(block->l[i]))

#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(uint32_t state[5], const uint8_t buffer[64])
{
  uint32_t a, b, c, d, e;
  typedef union {
    uint8_t c[64];
    uint32_t l[16];
  } CHAR64LONG16;
  CHAR64LONG16 *block;
  uint8_t workspace[64];

    block = (CHAR64LONG16*)workspace;
    memcpy(block, buffer, 64);
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
}


/* SHA1Init - Initialize new context */

void SHA1Init(SHA1_CTX* context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(SHA1_CTX* context, const uint8_t* data, unsigned int len)
{
unsigned int i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1Transform(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(uint8_t digest[20], SHA1_CTX* context)
{
uint32_t i, j;
uint8_t finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)]
         >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
    }
    SHA1Update(context, (const unsigned char *)"\200", 1);
    while ((context->count[0] & 504) != 448) {
        SHA1Update(context, (const unsigned char *)"\0", 1);
    }
    SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++) {
        digest[i] = (uint8_t)
         ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }
    /* Wipe variables */
    i = j = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(&finalcount, 0, 8);
#ifdef SHA1HANDSOFF  /* make SHA1Transform overwrite it's own static vars */
    SHA1Transform(context->state, context->buffer);
#endif
}

void SHA1FinalNoLen(uint8_t digest[20], SHA1_CTX* context)
{
  uint32_t i, j;

    for (i = 0; i < 20; i++) {
        digest[i] = (uint8_t)
         ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }

    /* Wipe variables */
    i = j = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);

#ifdef SHA1HANDSOFF  /* make SHA1Transform overwrite it's own static vars */
    SHA1Transform(context->state, context->buffer);
#endif
}



/* MD5 message-digest algorithm */

/* This file is licensed under the LGPL, but is largely derived from
 * public domain source code
 */

/*
 *  FORCE MD5 TO USE OUR MD5 HEADER FILE!
 *
 *  If we don't do this, it might pick up the systems broken MD5.
 *  - Alan DeKok <aland@ox.org>
 */

void librad_md5_calc(unsigned char *output, unsigned char *input,
         unsigned int inputlen);

void librad_md5_calc(unsigned char *output, unsigned char *input,
         unsigned int inlen)
{
  MD5_CTX context;

  MD5Init(&context);
  MD5Update(&context, input, inlen);
  MD5Final(output, &context);
}

/*  The below was retrieved from
 *  http://www.openbsd.org/cgi-bin/cvsweb/~checkout~/src/sys/crypto/md5.c?rev=1.1
 *  with the following changes:
 *  #includes commented out.
 *  Support context->count as uint32_t[2] instead of uint64_t
 *  u_int* to uint*
 */

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

/*#include <sys/param.h>*/
/*#include <sys/systm.h>*/
/*#include <crypto/md5.h>*/

#define PUT_64BIT_LE(cp, value) do {        \
  (cp)[7] = (value)[1] >> 24;         \
  (cp)[6] = (value)[1] >> 16;         \
  (cp)[5] = (value)[1] >> 8;          \
  (cp)[4] = (value)[1];           \
  (cp)[3] = (value)[0] >> 24;         \
  (cp)[2] = (value)[0] >> 16;         \
  (cp)[1] = (value)[0] >> 8;          \
  (cp)[0] = (value)[0]; } while (0)

#define PUT_32BIT_LE(cp, value) do {          \
  (cp)[3] = (value) >> 24;          \
  (cp)[2] = (value) >> 16;          \
  (cp)[1] = (value) >> 8;           \
  (cp)[0] = (value); } while (0)

static uint8_t PADDING[MD5_BLOCK_LENGTH] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void
MD5Init(MD5_CTX *ctx)
{
  ctx->count[0] = 0;
  ctx->count[1] = 0;
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void
MD5Update(MD5_CTX *ctx, const unsigned char *input, size_t len)
{
  size_t have, need;

  /* Check how many bytes we already have and how many more we need. */
  have = (size_t)((ctx->count[0] >> 3) & (MD5_BLOCK_LENGTH - 1));
  need = MD5_BLOCK_LENGTH - have;

  /* Update bitcount */
/*  ctx->count += (uint64_t)len << 3;*/
  if ((ctx->count[0] += ((uint32_t)len << 3)) < (uint32_t)len) {
  /* Overflowed ctx->count[0] */
    ctx->count[1]++;
  }
  ctx->count[1] += ((uint32_t)len >> 29);

  

  if (len >= need) {
    if (have != 0) {
      memcpy(ctx->buffer + have, input, need);
      MD5Transform(ctx->state, ctx->buffer);
      input += need;
      len -= need;
      have = 0;
    }

    /* Process data in MD5_BLOCK_LENGTH-byte chunks. */
    while (len >= MD5_BLOCK_LENGTH) {
      MD5Transform(ctx->state, input);
      input += MD5_BLOCK_LENGTH;
      len -= MD5_BLOCK_LENGTH;
    }
  }

  /* Handle any remaining bytes of data. */
  if (len != 0)
    memcpy(ctx->buffer + have, input, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void
MD5Final(unsigned char digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx)
{
  uint8_t count[8];
  size_t padlen;
  int i;

  /* Convert count to 8 bytes in little endian order. */
  PUT_64BIT_LE(count, ctx->count);

  /* Pad out to 56 mod 64. */
  padlen = MD5_BLOCK_LENGTH -
      ((ctx->count[0] >> 3) & (MD5_BLOCK_LENGTH - 1));
  if (padlen < 1 + 8)
    padlen += MD5_BLOCK_LENGTH;
  MD5Update(ctx, PADDING, padlen - 8);    /* padlen - 8 <= 64 */
  MD5Update(ctx, count, 8);

  if (digest != NULL) {
    for (i = 0; i < 4; i++)
      PUT_32BIT_LE(digest + i * 4, ctx->state[i]);
  }
  bzero(ctx, sizeof(*ctx)); /* in case it's sensitive */
}


/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
  ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
void
MD5Transform(uint32_t state[4], const uint8_t block[MD5_BLOCK_LENGTH])
{
  uint32_t a, b, c, d, in[MD5_BLOCK_LENGTH / 4];

  for (a = 0; a < MD5_BLOCK_LENGTH / 4; a++) {
    in[a] = (uint32_t)(
        (uint32_t)(block[a * 4 + 0]) |
        (uint32_t)(block[a * 4 + 1]) <<  8 |
        (uint32_t)(block[a * 4 + 2]) << 16 |
        (uint32_t)(block[a * 4 + 3]) << 24);
  }

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];

  MD5STEP(F1, a, b, c, d, in[ 0] + 0xd76aa478,  7);
  MD5STEP(F1, d, a, b, c, in[ 1] + 0xe8c7b756, 12);
  MD5STEP(F1, c, d, a, b, in[ 2] + 0x242070db, 17);
  MD5STEP(F1, b, c, d, a, in[ 3] + 0xc1bdceee, 22);
  MD5STEP(F1, a, b, c, d, in[ 4] + 0xf57c0faf,  7);
  MD5STEP(F1, d, a, b, c, in[ 5] + 0x4787c62a, 12);
  MD5STEP(F1, c, d, a, b, in[ 6] + 0xa8304613, 17);
  MD5STEP(F1, b, c, d, a, in[ 7] + 0xfd469501, 22);
  MD5STEP(F1, a, b, c, d, in[ 8] + 0x698098d8,  7);
  MD5STEP(F1, d, a, b, c, in[ 9] + 0x8b44f7af, 12);
  MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
  MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
  MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122,  7);
  MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
  MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
  MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

  MD5STEP(F2, a, b, c, d, in[ 1] + 0xf61e2562,  5);
  MD5STEP(F2, d, a, b, c, in[ 6] + 0xc040b340,  9);
  MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
  MD5STEP(F2, b, c, d, a, in[ 0] + 0xe9b6c7aa, 20);
  MD5STEP(F2, a, b, c, d, in[ 5] + 0xd62f105d,  5);
  MD5STEP(F2, d, a, b, c, in[10] + 0x02441453,  9);
  MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
  MD5STEP(F2, b, c, d, a, in[ 4] + 0xe7d3fbc8, 20);
  MD5STEP(F2, a, b, c, d, in[ 9] + 0x21e1cde6,  5);
  MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6,  9);
  MD5STEP(F2, c, d, a, b, in[ 3] + 0xf4d50d87, 14);
  MD5STEP(F2, b, c, d, a, in[ 8] + 0x455a14ed, 20);
  MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905,  5);
  MD5STEP(F2, d, a, b, c, in[ 2] + 0xfcefa3f8,  9);
  MD5STEP(F2, c, d, a, b, in[ 7] + 0x676f02d9, 14);
  MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

  MD5STEP(F3, a, b, c, d, in[ 5] + 0xfffa3942,  4);
  MD5STEP(F3, d, a, b, c, in[ 8] + 0x8771f681, 11);
  MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
  MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
  MD5STEP(F3, a, b, c, d, in[ 1] + 0xa4beea44,  4);
  MD5STEP(F3, d, a, b, c, in[ 4] + 0x4bdecfa9, 11);
  MD5STEP(F3, c, d, a, b, in[ 7] + 0xf6bb4b60, 16);
  MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
  MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6,  4);
  MD5STEP(F3, d, a, b, c, in[ 0] + 0xeaa127fa, 11);
  MD5STEP(F3, c, d, a, b, in[ 3] + 0xd4ef3085, 16);
  MD5STEP(F3, b, c, d, a, in[ 6] + 0x04881d05, 23);
  MD5STEP(F3, a, b, c, d, in[ 9] + 0xd9d4d039,  4);
  MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
  MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
  MD5STEP(F3, b, c, d, a, in[2 ] + 0xc4ac5665, 23);

  MD5STEP(F4, a, b, c, d, in[ 0] + 0xf4292244,  6);
  MD5STEP(F4, d, a, b, c, in[7 ] + 0x432aff97, 10);
  MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
  MD5STEP(F4, b, c, d, a, in[5 ] + 0xfc93a039, 21);
  MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3,  6);
  MD5STEP(F4, d, a, b, c, in[3 ] + 0x8f0ccc92, 10);
  MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
  MD5STEP(F4, b, c, d, a, in[1 ] + 0x85845dd1, 21);
  MD5STEP(F4, a, b, c, d, in[8 ] + 0x6fa87e4f,  6);
  MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
  MD5STEP(F4, c, d, a, b, in[6 ] + 0xa3014314, 15);
  MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
  MD5STEP(F4, a, b, c, d, in[4 ] + 0xf7537e82,  6);
  MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
  MD5STEP(F4, c, d, a, b, in[2 ] + 0x2ad7d2bb, 15);
  MD5STEP(F4, b, c, d, a, in[9 ] + 0xeb86d391, 21);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

void password_to_key_md5(
      u_char *password,    /* IN */
      u_int   passwordlen, /* IN */
      u_char *engineID,    /* IN  - pointer to snmpEngineID  */
      u_int   engineLength,/* IN  - length of snmpEngineID */
      u_char *key)         /* OUT - pointer to caller 16-octet buffer */
   {
      MD5_CTX     MD;
      u_char     *cp, password_buf[64];
      u_long      password_index = 0;
      u_long      count = 0, i;

      MD5Init (&MD);   /* initialize MD5 */

      /**********************************************/
      /* Use while loop until we've done 1 Megabyte */
      /**********************************************/
      while (count < 1048576) {
         cp = password_buf;
         for (i = 0; i < 64; i++) {
             /*************************************************/
             /* Take the next octet of the password, wrapping */
             /* to the beginning of the password as necessary.*/
             /*************************************************/
             *cp++ = password[password_index++ % passwordlen];
         }
         MD5Update (&MD, password_buf, 64);
         count += 64;
      }
      MD5Final (key, &MD);          /* tell MD5 we're done */

  Serial.println("Intermediate for MD5: ");
  for(i=0;i<16;i++)
  {
    Serial.print(key[i], HEX);
  }

      /*****************************************************/
      /* Now localize the key with the engineID and pass   */
      /* through MD5 to produce final key                  */
      /* May want to ensure that engineLength <= 32,       */
      /* otherwise need to use a buffer larger than 64     */
      /*****************************************************/
      memcpy(password_buf, key, 16);
      memcpy(password_buf+16, engineID, engineLength);
      memcpy(password_buf+16+engineLength, key, 16);

      MD5Init(&MD);
      MD5Update(&MD, password_buf, 32+engineLength);
      MD5Final(key, &MD);
      return;
   }

void password_to_key_sha(
      u_char *password,    /* IN */
      u_int   passwordlen, /* IN */
      u_char *engineID,    /* IN  - pointer to snmpEngineID  */
      u_int   engineLength,/* IN  - length of snmpEngineID */
      u_char *key)         /* OUT - pointer to caller 20-octet buffer */
{
      SHA_CTX     SH;
      u_char     *cp, password_buf[72];
      u_long      password_index = 0;
      u_long      count = 0, i;

      SHAInit (&SH);   /* initialize SHA */

      /**********************************************/
      /* Use while loop until we've done 1 Megabyte */
      /**********************************************/
      while (count < 1048576) {
         cp = password_buf;
         for (i = 0; i < 64; i++) {
             /*************************************************/
             /* Take the next octet of the password, wrapping */
             /* to the beginning of the password as necessary.*/
             /*************************************************/
             *cp++ = password[password_index++ % passwordlen];
         }
         SHAUpdate (&SH, password_buf, 64);
         count += 64;
      }
      SHAFinal (key, &SH);          /* tell SHA we're done */


  Serial.println("Intermediate for SHA: ");
  for(i=0;i<20;i++)
  {
    Serial.print(key[i], HEX);
  }

      /*****************************************************/
      /* Now localize the key with the engineID and pass   */
      /* through SHA to produce final key                  */
      /* May want to ensure that engineLength <= 32,       */
      /* otherwise need to use a buffer larger than 72     */
      /*****************************************************/
      memcpy(password_buf, key, 20);
      memcpy(password_buf+20, engineID, engineLength);
      memcpy(password_buf+20+engineLength, key, 20);

      SHAInit(&SH);
      SHAUpdate(&SH, password_buf, 40+engineLength);
      SHAFinal(key, &SH);
      return;
}

  //password_to_key_md5(pass, passLen, engineID, engineIDLen, key);

  //password_to_key_sha(pass, passLen, engineID, engineIDLen, key);


void
lrad_hmac_sha1(const unsigned char *text, int text_len,
         const unsigned char *key, int key_len,
         unsigned char *digest)
{
        SHA1_CTX context;
        unsigned char k_ipad[65];    /* inner padding -
                                      * key XORd with ipad
                                      */
        unsigned char k_opad[65];    /* outer padding -
                                      * key XORd with opad
                                      */
        unsigned char tk[20];
        int i;
        /* if key is longer than 64 bytes reset it to key=SHA1(key) */
        if (key_len > 64) {

                SHA1_CTX      tctx;

                SHA1Init(&tctx);
                SHA1Update(&tctx, key, key_len);
                SHA1Final(tk, &tctx);

                key = tk;
                key_len = 20;
        }

#ifdef HMAC_SHA1_DATA_PROBLEMS
  if(sha1_data_problems)
  {
    int j,k;

    printf("\nhmac-sha1 key(%d): ", key_len);
    j=0; k=0;
    for (i = 0; i < key_len; i++) {
      if(j==4) {
        printf("_");
        j=0;
      }
      j++;

      printf("%02x", key[i]);
    }
    printf("\nDATA: (%d)    ",text_len);

    j=0; k=0;
    for (i = 0; i < text_len; i++) {
      if(k==20) {
        printf("\n            ");
        k=0;
        j=0;
      }
      if(j==4) {
        printf("_");
        j=0;
      }
      k++;
      j++;

      printf("%02x", text[i]);
    }
    printf("\n");
  }
#endif


        /*
         * the HMAC_SHA1 transform looks like:
         *
         * SHA1(K XOR opad, SHA1(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times

         * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        memset( k_ipad, 0, sizeof(k_ipad));
        memset( k_opad, 0, sizeof(k_opad));
        memcpy( k_ipad, key, key_len);
        memcpy( k_opad, key, key_len);

        /* XOR key with ipad and opad values */
        for (i = 0; i < 64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner SHA1
         */
        SHA1Init(&context);                   /* init context for 1st
                                              * pass */
        SHA1Update(&context, k_ipad, 64);      /* start with inner pad */
        SHA1Update(&context, text, text_len); /* then text of datagram */
        SHA1Final(digest, &context);          /* finish up 1st pass */
        /*
         * perform outer MD5
         */
        SHA1Init(&context);                   /* init context for 2nd
                                              * pass */
        SHA1Update(&context, k_opad, 64);     /* start with outer pad */
        SHA1Update(&context, digest, 20);     /* then results of 1st
                                              * hash */
        SHA1Final(digest, &context);          /* finish up 2nd pass */

#ifdef HMAC_SHA1_DATA_PROBLEMS
  if(sha1_data_problems)
  {
    int j;

    printf("\nhmac-sha1 mac(20): ");
    j=0;
    for (i = 0; i < 20; i++) {
      if(j==4) {
        printf("_");
        j=0;
      }
      j++;

      printf("%02x", digest[i]);
    }
    printf("\n");
  }
#endif
}


void hmac_md5(const unsigned char* text, int text_len, const unsigned char* key, int key_len, unsigned char* digest)
//unsigned char*  text;                /* pointer to data stream */
//int             text_len;            /* length of data stream */
//unsigned char*  key;                 /* pointer to authentication key */
//int             key_len;             /* length of authentication key */
//caddr_t         digest;              /* caller digest to be filled in */

{
        MD5_CTX context;
        unsigned char k_ipad[65];    /* inner padding -
                                      * key XORd with ipad
                                      */
        unsigned char k_opad[65];    /* outer padding -
                                      * key XORd with opad
                                      */
        unsigned char tk[16];
        int i;
        /* if key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64) {

                MD5_CTX      tctx;

                MD5Init(&tctx);
                MD5Update(&tctx, key, key_len);
                MD5Final(tk, &tctx);

                key = tk;
                key_len = 16;
        }

        /*
         * the HMAC_MD5 transform looks like:
         *
         * MD5(K XOR opad, MD5(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        /*bzero( k_ipad, sizeof k_ipad);
        bzero( k_opad, sizeof k_opad);
        bcopy( key, k_ipad, key_len);
        bcopy( key, k_opad, key_len);*/

        memset( k_ipad, 0, sizeof(k_ipad));
        memset( k_opad, 0, sizeof(k_opad));
        memcpy( k_ipad, key, key_len);
        memcpy( k_opad, key, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner MD5
         */
        MD5Init(&context);                   /* init context for 1st
                                              * pass */
        MD5Update(&context, k_ipad, 64);      /* start with inner pad */
        MD5Update(&context, text, text_len); /* then text of datagram */
        MD5Final(digest, &context);          /* finish up 1st pass */
        /*
         * perform outer MD5
         */
        MD5Init(&context);                   /* init context for 2nd
                                              * pass */
        MD5Update(&context, k_opad, 64);     /* start with outer pad */
        MD5Update(&context, digest, 16);     /* then results of 1st
                                              * hash */
        MD5Final(digest, &context);          /* finish up 2nd pass */
}
