/*
* AES using AES-NI instructions
* (C) 2009,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/* 
 * Modifications to add support for processing 15-blocks and 7-blocks in parallel
 * Modifications for pure C compatibility
 */

#include "Tcdefs.h"
#include "Endian.h"
#include "cpu.h"
#include "misc.h"
#include "Aes_Botan_aesni.h"

#if BYTE_ORDER == BIG_ENDIAN

#define BOTAN_ENDIAN_N2B(x) (x)
#define BOTAN_ENDIAN_B2N(x) (x)

#define BOTAN_ENDIAN_N2L(x) bswap_32(x)
#define BOTAN_ENDIAN_L2N(x) bswap_32(x)

#elif  BYTE_ORDER == LITTLE_ENDIAN

#define BOTAN_ENDIAN_N2L(x) (x)
#define BOTAN_ENDIAN_L2N(x) (x)

#define BOTAN_ENDIAN_N2B(x) bswap_32(x)
#define BOTAN_ENDIAN_B2N(x) bswap_32(x)

#endif

static __m128i aes_128_key_expansion(__m128i key, __m128i key_with_rcon)
   {
   key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(3,3,3,3));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   return _mm_xor_si128(key, key_with_rcon);
   }

/*
* The second half of the AES-256 key expansion (other half same as AES-128)
*/
static __m128i aes_256_key_expansion(__m128i key, __m128i key2)
   {
   __m128i key_with_rcon = _mm_aeskeygenassist_si128(key2, 0x00);
   key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(2,2,2,2));

   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
   return _mm_xor_si128(key, key_with_rcon);
   }



#define AES_ENC_15_ROUNDS(i)                     \
   do                                           \
      {  \
		K  = _mm_loadu_si128(key_mm + i); \
		B0 = _mm_aesenc_si128(B0, K); \
		B1 = _mm_aesenc_si128(B1, K); \
		B2 = _mm_aesenc_si128(B2, K); \
		B3 = _mm_aesenc_si128(B3, K); \
		B4 = _mm_aesenc_si128(B4, K); \
		B5 = _mm_aesenc_si128(B5, K); \
		B6 = _mm_aesenc_si128(B6, K); \
		B7 = _mm_aesenc_si128(B7, K); \
		B8 = _mm_aesenc_si128(B8, K); \
		B9 = _mm_aesenc_si128(B9, K); \
		B10 = _mm_aesenc_si128(B10, K); \
		B11 = _mm_aesenc_si128(B11, K); \
		B12 = _mm_aesenc_si128(B12, K); \
		B13 = _mm_aesenc_si128(B13, K); \
		B14 = _mm_aesenc_si128(B14, K); \
      } while(0)

#define AES_ENC_15_LAST_ROUNDS            \
   do                                           \
      { \
		K  = _mm_loadu_si128(key_mm + 14); \
		B0 = _mm_aesenclast_si128(B0, K); \
		B1 = _mm_aesenclast_si128(B1, K); \
		B2 = _mm_aesenclast_si128(B2, K); \
		B3 = _mm_aesenclast_si128(B3, K); \
		B4 = _mm_aesenclast_si128(B4, K); \
		B5 = _mm_aesenclast_si128(B5, K); \
		B6 = _mm_aesenclast_si128(B6, K); \
		B7 = _mm_aesenclast_si128(B7, K); \
		B8 = _mm_aesenclast_si128(B8, K); \
		B9 = _mm_aesenclast_si128(B9, K); \
		B10 = _mm_aesenclast_si128(B10, K); \
		B11 = _mm_aesenclast_si128(B11, K); \
		B12 = _mm_aesenclast_si128(B12, K); \
		B13 = _mm_aesenclast_si128(B13, K); \
		B14 = _mm_aesenclast_si128(B14, K); \
      } while(0)

#define AES_ENC_7_ROUNDS(i)                     \
   do                                           \
      {  \
		K  = _mm_loadu_si128(key_mm + i); \
		B0 = _mm_aesenc_si128(B0, K); \
		B1 = _mm_aesenc_si128(B1, K); \
		B2 = _mm_aesenc_si128(B2, K); \
		B3 = _mm_aesenc_si128(B3, K); \
		B4 = _mm_aesenc_si128(B4, K); \
		B5 = _mm_aesenc_si128(B5, K); \
		B6 = _mm_aesenc_si128(B6, K); \
      } while(0)

#define AES_ENC_7_LAST_ROUNDS            \
   do                                           \
      { \
		K  = _mm_loadu_si128(key_mm + 14); \
		B0 = _mm_aesenclast_si128(B0, K); \
		B1 = _mm_aesenclast_si128(B1, K); \
		B2 = _mm_aesenclast_si128(B2, K); \
		B3 = _mm_aesenclast_si128(B3, K); \
		B4 = _mm_aesenclast_si128(B4, K); \
		B5 = _mm_aesenclast_si128(B5, K); \
		B6 = _mm_aesenclast_si128(B6, K); \
      } while(0)

#define AES_ENC_4_ROUNDS(i)                     \
   do                                           \
      {  \
		K  = _mm_loadu_si128(key_mm + i); \
		B0 = _mm_aesenc_si128(B0, K); \
		B1 = _mm_aesenc_si128(B1, K); \
		B2 = _mm_aesenc_si128(B2, K); \
		B3 = _mm_aesenc_si128(B3, K); \
      } while(0)

#define AES_ENC_4_LAST_ROUNDS                \
   do                                           \
      {                                         \
	  K  = _mm_loadu_si128(key_mm + 14); \
      B0 = _mm_aesenclast_si128(B0, K);         \
      B1 = _mm_aesenclast_si128(B1, K);         \
      B2 = _mm_aesenclast_si128(B2, K);         \
      B3 = _mm_aesenclast_si128(B3, K);         \
      } while(0)

#define AES_ENC_3_ROUNDS(i)                     \
   do                                           \
      {  \
		K  = _mm_loadu_si128(key_mm + i); \
		B0 = _mm_aesenc_si128(B0, K); \
		B1 = _mm_aesenc_si128(B1, K); \
		B2 = _mm_aesenc_si128(B2, K); \
      } while(0)

#define AES_ENC_3_LAST_ROUNDS                \
   do                                           \
      {                                         \
	  K  = _mm_loadu_si128(key_mm + 14); \
      B0 = _mm_aesenclast_si128(B0, K);         \
      B1 = _mm_aesenclast_si128(B1, K);         \
      B2 = _mm_aesenclast_si128(B2, K);         \
      } while(0)

#define AES_ENC_2_ROUNDS(i)                     \
   do                                           \
      {  \
		K  = _mm_loadu_si128(key_mm + i); \
		B0 = _mm_aesenc_si128(B0, K); \
		B1 = _mm_aesenc_si128(B1, K); \
      } while(0)

#define AES_ENC_2_LAST_ROUNDS                \
   do                                           \
      {                                         \
	  K  = _mm_loadu_si128(key_mm + 14); \
      B0 = _mm_aesenclast_si128(B0, K);         \
      B1 = _mm_aesenclast_si128(B1, K);         \
      } while(0)

#define AES_DEC_15_ROUNDS(i)                     \
   do                                           \
      {  \
		K  = _mm_loadu_si128(key_mm + i); \
		B0 = _mm_aesdec_si128(B0, K); \
		B1 = _mm_aesdec_si128(B1, K); \
		B2 = _mm_aesdec_si128(B2, K); \
		B3 = _mm_aesdec_si128(B3, K); \
		B4 = _mm_aesdec_si128(B4, K); \
		B5 = _mm_aesdec_si128(B5, K); \
		B6 = _mm_aesdec_si128(B6, K); \
		B7 = _mm_aesdec_si128(B7, K); \
		B8 = _mm_aesdec_si128(B8, K); \
		B9 = _mm_aesdec_si128(B9, K); \
		B10 = _mm_aesdec_si128(B10, K); \
		B11 = _mm_aesdec_si128(B11, K); \
		B12 = _mm_aesdec_si128(B12, K); \
		B13 = _mm_aesdec_si128(B13, K); \
		B14 = _mm_aesdec_si128(B14, K); \
      } while(0)

#define AES_DEC_15_LAST_ROUNDS            \
   do                                           \
      { \
		K  = _mm_loadu_si128(key_mm + 14); \
		B0 = _mm_aesdeclast_si128(B0, K); \
		B1 = _mm_aesdeclast_si128(B1, K); \
		B2 = _mm_aesdeclast_si128(B2, K); \
		B3 = _mm_aesdeclast_si128(B3, K); \
		B4 = _mm_aesdeclast_si128(B4, K); \
		B5 = _mm_aesdeclast_si128(B5, K); \
		B6 = _mm_aesdeclast_si128(B6, K); \
		B7 = _mm_aesdeclast_si128(B7, K); \
		B8 = _mm_aesdeclast_si128(B8, K); \
		B9 = _mm_aesdeclast_si128(B9, K); \
		B10 = _mm_aesdeclast_si128(B10, K); \
		B11 = _mm_aesdeclast_si128(B11, K); \
		B12 = _mm_aesdeclast_si128(B12, K); \
		B13 = _mm_aesdeclast_si128(B13, K); \
		B14 = _mm_aesdeclast_si128(B14, K); \
      } while(0)

#define AES_DEC_7_ROUNDS(i)                     \
   do                                           \
      {  \
		K  = _mm_loadu_si128(key_mm + i); \
		B0 = _mm_aesdec_si128(B0, K); \
		B1 = _mm_aesdec_si128(B1, K); \
		B2 = _mm_aesdec_si128(B2, K); \
		B3 = _mm_aesdec_si128(B3, K); \
		B4 = _mm_aesdec_si128(B4, K); \
		B5 = _mm_aesdec_si128(B5, K); \
		B6 = _mm_aesdec_si128(B6, K); \
      } while(0)

#define AES_DEC_7_LAST_ROUNDS            \
   do                                           \
      { \
		K  = _mm_loadu_si128(key_mm + 14); \
		B0 = _mm_aesdeclast_si128(B0, K); \
		B1 = _mm_aesdeclast_si128(B1, K); \
		B2 = _mm_aesdeclast_si128(B2, K); \
		B3 = _mm_aesdeclast_si128(B3, K); \
		B4 = _mm_aesdeclast_si128(B4, K); \
		B5 = _mm_aesdeclast_si128(B5, K); \
		B6 = _mm_aesdeclast_si128(B6, K); \
      } while(0)

#define AES_DEC_4_ROUNDS(i)                     \
   do                                           \
      {  \
		K  = _mm_loadu_si128(key_mm + i); \
		B0 = _mm_aesdec_si128(B0, K); \
		B1 = _mm_aesdec_si128(B1, K); \
		B2 = _mm_aesdec_si128(B2, K); \
		B3 = _mm_aesdec_si128(B3, K); \
      } while(0)

#define AES_DEC_4_LAST_ROUNDS            \
   do                                           \
      { \
		K  = _mm_loadu_si128(key_mm + 14); \
		B0 = _mm_aesdeclast_si128(B0, K); \
		B1 = _mm_aesdeclast_si128(B1, K); \
		B2 = _mm_aesdeclast_si128(B2, K); \
		B3 = _mm_aesdeclast_si128(B3, K); \
      } while(0)

#define AES_DEC_3_ROUNDS(i)                     \
   do                                           \
      {  \
		K  = _mm_loadu_si128(key_mm + i); \
		B0 = _mm_aesdec_si128(B0, K); \
		B1 = _mm_aesdec_si128(B1, K); \
		B2 = _mm_aesdec_si128(B2, K); \
      } while(0)

#define AES_DEC_3_LAST_ROUNDS            \
   do                                           \
      { \
		K  = _mm_loadu_si128(key_mm + 14); \
		B0 = _mm_aesdeclast_si128(B0, K); \
		B1 = _mm_aesdeclast_si128(B1, K); \
		B2 = _mm_aesdeclast_si128(B2, K); \
      } while(0)

#define AES_DEC_2_ROUNDS(i)                     \
   do                                           \
      {  \
		K  = _mm_loadu_si128(key_mm + i); \
		B0 = _mm_aesdec_si128(B0, K); \
		B1 = _mm_aesdec_si128(B1, K); \
      } while(0)

#define AES_DEC_2_LAST_ROUNDS            \
   do                                           \
      { \
		K  = _mm_loadu_si128(key_mm + 14); \
		B0 = _mm_aesdeclast_si128(B0, K); \
		B1 = _mm_aesdeclast_si128(B1, K); \
      } while(0)

/*
* AES-256 Encryption
*/
void aes_botan_aesni_encrypt_4x(aes_encrypt_ctx *ctx, const byte* in, byte* out, uint_32t blocks)
   {
   const __m128i* in_mm = (const __m128i*)(in);
   __m128i* out_mm = (__m128i*)(out);

   const __m128i* key_mm = (const __m128i*)(ctx->ks);

   while(blocks >= 4)
      {
    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);
    __m128i B2 = _mm_loadu_si128(in_mm + 2);
    __m128i B3 = _mm_loadu_si128(in_mm + 3);

	// round-0
	__m128i K  = _mm_loadu_si128(key_mm);

	B0 = _mm_xor_si128(B0, K);
	B1 = _mm_xor_si128(B1, K);
	B2 = _mm_xor_si128(B2, K);
	B3 = _mm_xor_si128(B3, K);

	// round
	AES_ENC_4_ROUNDS (1);
	AES_ENC_4_ROUNDS (2);
	AES_ENC_4_ROUNDS (3);
	AES_ENC_4_ROUNDS (4);
	AES_ENC_4_ROUNDS (5);
	AES_ENC_4_ROUNDS (6);
	AES_ENC_4_ROUNDS (7);
	AES_ENC_4_ROUNDS (8);
	AES_ENC_4_ROUNDS (9);
	AES_ENC_4_ROUNDS (10);
	AES_ENC_4_ROUNDS (11);
	AES_ENC_4_ROUNDS (12);
	AES_ENC_4_ROUNDS (13);

	AES_ENC_4_LAST_ROUNDS;

	_mm_storeu_si128(out_mm + 0, B0);
	_mm_storeu_si128(out_mm + 1, B1);
	_mm_storeu_si128(out_mm + 2, B2);
	_mm_storeu_si128(out_mm + 3, B3);

      blocks -= 4;
      in_mm += 4;
      out_mm += 4;
      }

   if (blocks == 3)
      {
    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);
    __m128i B2 = _mm_loadu_si128(in_mm + 2);

	// round-0
	__m128i K  = _mm_loadu_si128(key_mm);

	B0 = _mm_xor_si128(B0, K);
	B1 = _mm_xor_si128(B1, K);
	B2 = _mm_xor_si128(B2, K);

	// round
	AES_ENC_3_ROUNDS (1);
	AES_ENC_3_ROUNDS (2);
	AES_ENC_3_ROUNDS (3);
	AES_ENC_3_ROUNDS (4);
	AES_ENC_3_ROUNDS (5);
	AES_ENC_3_ROUNDS (6);
	AES_ENC_3_ROUNDS (7);
	AES_ENC_3_ROUNDS (8);
	AES_ENC_3_ROUNDS (9);
	AES_ENC_3_ROUNDS (10);
	AES_ENC_3_ROUNDS (11);
	AES_ENC_3_ROUNDS (12);
	AES_ENC_3_ROUNDS (13);

	AES_ENC_3_LAST_ROUNDS;

	_mm_storeu_si128(out_mm + 0, B0);
	_mm_storeu_si128(out_mm + 1, B1);
	_mm_storeu_si128(out_mm + 2, B2);
	}
   else if (blocks == 2)
      {
    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);

	// round-0
	__m128i K  = _mm_loadu_si128(key_mm);

	B0 = _mm_xor_si128(B0, K);
	B1 = _mm_xor_si128(B1, K);

	// round
	AES_ENC_2_ROUNDS (1);
	AES_ENC_2_ROUNDS (2);
	AES_ENC_2_ROUNDS (3);
	AES_ENC_2_ROUNDS (4);
	AES_ENC_2_ROUNDS (5);
	AES_ENC_2_ROUNDS (6);
	AES_ENC_2_ROUNDS (7);
	AES_ENC_2_ROUNDS (8);
	AES_ENC_2_ROUNDS (9);
	AES_ENC_2_ROUNDS (10);
	AES_ENC_2_ROUNDS (11);
	AES_ENC_2_ROUNDS (12);
	AES_ENC_2_ROUNDS (13);

	AES_ENC_2_LAST_ROUNDS;

	_mm_storeu_si128(out_mm + 0, B0);
	_mm_storeu_si128(out_mm + 1, B1);
	}
   else if (blocks == 1)
      {
      __m128i B = _mm_loadu_si128(in_mm);
	  __m128i K  = _mm_loadu_si128(key_mm);

      B = _mm_xor_si128(B, K);

	  K  = _mm_loadu_si128(key_mm + 1);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 2);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 3);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 4);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 5);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 6);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 7);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 8);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 9);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 10);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 11);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 12);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 13);
      B = _mm_aesenc_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 14);
      B = _mm_aesenclast_si128(B, K);

      _mm_storeu_si128(out_mm, B);
      }
   }

#if CRYPTOPP_BOOL_X64
void aes_botan_aesni_encrypt_15way(aes_encrypt_ctx *ctx, const byte* in, byte* out)
{
	const __m128i* in_mm = (const __m128i*)(in);
	const __m128i* key_mm = (const __m128i*)(ctx->ks);	

    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);
    __m128i B2 = _mm_loadu_si128(in_mm + 2);
    __m128i B3 = _mm_loadu_si128(in_mm + 3);
    __m128i B4 = _mm_loadu_si128(in_mm + 4);
    __m128i B5 = _mm_loadu_si128(in_mm + 5);
    __m128i B6 = _mm_loadu_si128(in_mm + 6);
    __m128i B7 = _mm_loadu_si128(in_mm + 7);
    __m128i B8 = _mm_loadu_si128(in_mm + 8);
    __m128i B9 = _mm_loadu_si128(in_mm + 9);
    __m128i B10 = _mm_loadu_si128(in_mm + 10);
    __m128i B11 = _mm_loadu_si128(in_mm + 11);
    __m128i B12 = _mm_loadu_si128(in_mm + 12);
    __m128i B13 = _mm_loadu_si128(in_mm + 13);
    __m128i B14 = _mm_loadu_si128(in_mm + 14);

	// round-0
	__m128i K  = _mm_loadu_si128(key_mm);

	B0 = _mm_xor_si128(B0, K);
	B1 = _mm_xor_si128(B1, K);
	B2 = _mm_xor_si128(B2, K);
	B3 = _mm_xor_si128(B3, K);
	B4 = _mm_xor_si128(B4, K);
	B5 = _mm_xor_si128(B5, K);
	B6 = _mm_xor_si128(B6, K);
	B7 = _mm_xor_si128(B7, K);
	B8 = _mm_xor_si128(B8, K);
	B9 = _mm_xor_si128(B9, K);
	B10 = _mm_xor_si128(B10, K);
	B11 = _mm_xor_si128(B11, K);
	B12 = _mm_xor_si128(B12, K);
	B13 = _mm_xor_si128(B13, K);
	B14 = _mm_xor_si128(B14, K);

	// round
	AES_ENC_15_ROUNDS (1);
	AES_ENC_15_ROUNDS (2);
	AES_ENC_15_ROUNDS (3);
	AES_ENC_15_ROUNDS (4);
	AES_ENC_15_ROUNDS (5);
	AES_ENC_15_ROUNDS (6);
	AES_ENC_15_ROUNDS (7);
	AES_ENC_15_ROUNDS (8);
	AES_ENC_15_ROUNDS (9);
	AES_ENC_15_ROUNDS (10);
	AES_ENC_15_ROUNDS (11);
	AES_ENC_15_ROUNDS (12);
	AES_ENC_15_ROUNDS (13);

	AES_ENC_15_LAST_ROUNDS;

	_mm_storeu_si128((__m128i*)(out) + 0, B0);
	_mm_storeu_si128((__m128i*)(out) + 1, B1);
	_mm_storeu_si128((__m128i*)(out) + 2, B2);
	_mm_storeu_si128((__m128i*)(out) + 3, B3);
	_mm_storeu_si128((__m128i*)(out) + 4, B4);
	_mm_storeu_si128((__m128i*)(out) + 5, B5);
	_mm_storeu_si128((__m128i*)(out) + 6, B6);
	_mm_storeu_si128((__m128i*)(out) + 7, B7);
	_mm_storeu_si128((__m128i*)(out) + 8, B8);
	_mm_storeu_si128((__m128i*)(out) + 9, B9);
	_mm_storeu_si128((__m128i*)(out) + 10, B10);
	_mm_storeu_si128((__m128i*)(out) + 11, B11);
	_mm_storeu_si128((__m128i*)(out) + 12, B12);
	_mm_storeu_si128((__m128i*)(out) + 13, B13);
	_mm_storeu_si128((__m128i*)(out) + 14, B14);
}
#endif

void aes_botan_aesni_encrypt_7way(aes_encrypt_ctx *ctx, const byte* in, byte* out)
{
	const __m128i* in_mm = (const __m128i*)(in);
	const __m128i* key_mm = (const __m128i*)(ctx->ks);	

    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);
    __m128i B2 = _mm_loadu_si128(in_mm + 2);
    __m128i B3 = _mm_loadu_si128(in_mm + 3);
    __m128i B4 = _mm_loadu_si128(in_mm + 4);
    __m128i B5 = _mm_loadu_si128(in_mm + 5);
    __m128i B6 = _mm_loadu_si128(in_mm + 6);

	// round-0
	__m128i K  = _mm_loadu_si128(key_mm);

	B0 = _mm_xor_si128(B0, K);
	B1 = _mm_xor_si128(B1, K);
	B2 = _mm_xor_si128(B2, K);
	B3 = _mm_xor_si128(B3, K);
	B4 = _mm_xor_si128(B4, K);
	B5 = _mm_xor_si128(B5, K);
	B6 = _mm_xor_si128(B6, K);

	// round
	AES_ENC_7_ROUNDS (1);
	AES_ENC_7_ROUNDS (2);
	AES_ENC_7_ROUNDS (3);
	AES_ENC_7_ROUNDS (4);
	AES_ENC_7_ROUNDS (5);
	AES_ENC_7_ROUNDS (6);
	AES_ENC_7_ROUNDS (7);
	AES_ENC_7_ROUNDS (8);
	AES_ENC_7_ROUNDS (9);
	AES_ENC_7_ROUNDS (10);
	AES_ENC_7_ROUNDS (11);
	AES_ENC_7_ROUNDS (12);
	AES_ENC_7_ROUNDS (13);

	AES_ENC_7_LAST_ROUNDS;

	_mm_storeu_si128((__m128i*)(out) + 0, B0);
	_mm_storeu_si128((__m128i*)(out) + 1, B1);
	_mm_storeu_si128((__m128i*)(out) + 2, B2);
	_mm_storeu_si128((__m128i*)(out) + 3, B3);
	_mm_storeu_si128((__m128i*)(out) + 4, B4);
	_mm_storeu_si128((__m128i*)(out) + 5, B5);
	_mm_storeu_si128((__m128i*)(out) + 6, B6);
}

void aes_botan_aesni_encrypt_15x(aes_encrypt_ctx *ctx, const byte* in, byte* out, uint_32t blocks)
{
#if CRYPTOPP_BOOL_X64
	while (blocks >= 15)
	{
		aes_botan_aesni_encrypt_15way (ctx, in, out);
		blocks -= 15;
		in += 15 * 16;
		out += 15 * 16;
	}
#endif
	while (blocks >= 7)
	{
		aes_botan_aesni_encrypt_7way (ctx, in, out);
		blocks -= 7;
		in += 7 * 16;
		out += 7 * 16;
	}

	aes_botan_aesni_encrypt_4x (ctx, in, out, blocks);
}

void aes_botan_aesni_encrypt_7x(aes_encrypt_ctx *ctx, const byte* in, byte* out, uint_32t blocks)
{
	while (blocks >= 7)
	{
		aes_botan_aesni_encrypt_7way (ctx, in, out);
		blocks -= 7;
		in += 7 * 16;
		out += 7 * 16;
	}

	aes_botan_aesni_encrypt_4x (ctx, in, out, blocks);
}

/*
* AES-256 Decryption
*/
void aes_botan_aesni_decrypt_4x(aes_decrypt_ctx *ctx, const byte* in, byte* out, uint_32t blocks)
   {
   const __m128i* in_mm = (const __m128i*)(in);
   __m128i* out_mm = (__m128i*)(out);

   const __m128i* key_mm = (const __m128i*)(ctx->ks);

   while(blocks >= 4)
      {
    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);
    __m128i B2 = _mm_loadu_si128(in_mm + 2);
    __m128i B3 = _mm_loadu_si128(in_mm + 3);

	// round-0
	__m128i K  = _mm_loadu_si128(key_mm);

	B0 = _mm_xor_si128(B0, K);
	B1 = _mm_xor_si128(B1, K);
	B2 = _mm_xor_si128(B2, K);
	B3 = _mm_xor_si128(B3, K);

	// round
	AES_DEC_4_ROUNDS (1);
	AES_DEC_4_ROUNDS (2);
	AES_DEC_4_ROUNDS (3);
	AES_DEC_4_ROUNDS (4);
	AES_DEC_4_ROUNDS (5);
	AES_DEC_4_ROUNDS (6);
	AES_DEC_4_ROUNDS (7);
	AES_DEC_4_ROUNDS (8);
	AES_DEC_4_ROUNDS (9);
	AES_DEC_4_ROUNDS (10);
	AES_DEC_4_ROUNDS (11);
	AES_DEC_4_ROUNDS (12);
	AES_DEC_4_ROUNDS (13);

	AES_DEC_4_LAST_ROUNDS;

	_mm_storeu_si128(out_mm + 0, B0);
	_mm_storeu_si128(out_mm + 1, B1);
	_mm_storeu_si128(out_mm + 2, B2);
	_mm_storeu_si128(out_mm + 3, B3);

      blocks -= 4;
      in_mm += 4;
      out_mm += 4;
      }

   if (blocks == 3)
      {
    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);
    __m128i B2 = _mm_loadu_si128(in_mm + 2);

	// round-0
	__m128i K  = _mm_loadu_si128(key_mm);

	B0 = _mm_xor_si128(B0, K);
	B1 = _mm_xor_si128(B1, K);
	B2 = _mm_xor_si128(B2, K);

	// round
	AES_DEC_3_ROUNDS (1);
	AES_DEC_3_ROUNDS (2);
	AES_DEC_3_ROUNDS (3);
	AES_DEC_3_ROUNDS (4);
	AES_DEC_3_ROUNDS (5);
	AES_DEC_3_ROUNDS (6);
	AES_DEC_3_ROUNDS (7);
	AES_DEC_3_ROUNDS (8);
	AES_DEC_3_ROUNDS (9);
	AES_DEC_3_ROUNDS (10);
	AES_DEC_3_ROUNDS (11);
	AES_DEC_3_ROUNDS (12);
	AES_DEC_3_ROUNDS (13);

	AES_DEC_3_LAST_ROUNDS;

	_mm_storeu_si128(out_mm + 0, B0);
	_mm_storeu_si128(out_mm + 1, B1);
	_mm_storeu_si128(out_mm + 2, B2);
	}
   else if (blocks == 2)
      {
    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);

	// round-0
	__m128i K  = _mm_loadu_si128(key_mm);

	B0 = _mm_xor_si128(B0, K);
	B1 = _mm_xor_si128(B1, K);

	// round
	AES_DEC_2_ROUNDS (1);
	AES_DEC_2_ROUNDS (2);
	AES_DEC_2_ROUNDS (3);
	AES_DEC_2_ROUNDS (4);
	AES_DEC_2_ROUNDS (5);
	AES_DEC_2_ROUNDS (6);
	AES_DEC_2_ROUNDS (7);
	AES_DEC_2_ROUNDS (8);
	AES_DEC_2_ROUNDS (9);
	AES_DEC_2_ROUNDS (10);
	AES_DEC_2_ROUNDS (11);
	AES_DEC_2_ROUNDS (12);
	AES_DEC_2_ROUNDS (13);

	AES_DEC_2_LAST_ROUNDS;

	_mm_storeu_si128(out_mm + 0, B0);
	_mm_storeu_si128(out_mm + 1, B1);
	}
   else if (blocks == 1)
      {
      __m128i B = _mm_loadu_si128(in_mm);
	  __m128i K  = _mm_loadu_si128(key_mm);

      B = _mm_xor_si128(B, K);

	  K  = _mm_loadu_si128(key_mm + 1);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 2);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 3);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 4);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 5);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 6);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 7);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 8);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 9);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 10);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 11);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 12);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 13);
      B = _mm_aesdec_si128(B, K);
	  K  = _mm_loadu_si128(key_mm + 14);
      B = _mm_aesdeclast_si128(B, K);

      _mm_storeu_si128(out_mm, B);
      }
   }

#if CRYPTOPP_BOOL_X64
void aes_botan_aesni_decrypt_15way(aes_decrypt_ctx *ctx, const byte* in, byte* out)
{
	const __m128i* in_mm = (const __m128i*)(in);
	const __m128i* key_mm = (const __m128i*)(ctx->ks);	

    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);
    __m128i B2 = _mm_loadu_si128(in_mm + 2);
    __m128i B3 = _mm_loadu_si128(in_mm + 3);
    __m128i B4 = _mm_loadu_si128(in_mm + 4);
    __m128i B5 = _mm_loadu_si128(in_mm + 5);
    __m128i B6 = _mm_loadu_si128(in_mm + 6);
    __m128i B7 = _mm_loadu_si128(in_mm + 7);
    __m128i B8 = _mm_loadu_si128(in_mm + 8);
    __m128i B9 = _mm_loadu_si128(in_mm + 9);
    __m128i B10 = _mm_loadu_si128(in_mm + 10);
    __m128i B11 = _mm_loadu_si128(in_mm + 11);
    __m128i B12 = _mm_loadu_si128(in_mm + 12);
    __m128i B13 = _mm_loadu_si128(in_mm + 13);
    __m128i B14 = _mm_loadu_si128(in_mm + 14);

	// round-0
	__m128i K  = _mm_loadu_si128(key_mm);

	B0 = _mm_xor_si128(B0, K);
	B1 = _mm_xor_si128(B1, K);
	B2 = _mm_xor_si128(B2, K);
	B3 = _mm_xor_si128(B3, K);
	B4 = _mm_xor_si128(B4, K);
	B5 = _mm_xor_si128(B5, K);
	B6 = _mm_xor_si128(B6, K);
	B7 = _mm_xor_si128(B7, K);
	B8 = _mm_xor_si128(B8, K);
	B9 = _mm_xor_si128(B9, K);
	B10 = _mm_xor_si128(B10, K);
	B11 = _mm_xor_si128(B11, K);
	B12 = _mm_xor_si128(B12, K);
	B13 = _mm_xor_si128(B13, K);
	B14 = _mm_xor_si128(B14, K);

	// round
	AES_DEC_15_ROUNDS (1);
	AES_DEC_15_ROUNDS (2);
	AES_DEC_15_ROUNDS (3);
	AES_DEC_15_ROUNDS (4);
	AES_DEC_15_ROUNDS (5);
	AES_DEC_15_ROUNDS (6);
	AES_DEC_15_ROUNDS (7);
	AES_DEC_15_ROUNDS (8);
	AES_DEC_15_ROUNDS (9);
	AES_DEC_15_ROUNDS (10);
	AES_DEC_15_ROUNDS (11);
	AES_DEC_15_ROUNDS (12);
	AES_DEC_15_ROUNDS (13);

	AES_DEC_15_LAST_ROUNDS;

	_mm_storeu_si128((__m128i*)(out) + 0, B0);
	_mm_storeu_si128((__m128i*)(out) + 1, B1);
	_mm_storeu_si128((__m128i*)(out) + 2, B2);
	_mm_storeu_si128((__m128i*)(out) + 3, B3);
	_mm_storeu_si128((__m128i*)(out) + 4, B4);
	_mm_storeu_si128((__m128i*)(out) + 5, B5);
	_mm_storeu_si128((__m128i*)(out) + 6, B6);
	_mm_storeu_si128((__m128i*)(out) + 7, B7);
	_mm_storeu_si128((__m128i*)(out) + 8, B8);
	_mm_storeu_si128((__m128i*)(out) + 9, B9);
	_mm_storeu_si128((__m128i*)(out) + 10, B10);
	_mm_storeu_si128((__m128i*)(out) + 11, B11);
	_mm_storeu_si128((__m128i*)(out) + 12, B12);
	_mm_storeu_si128((__m128i*)(out) + 13, B13);
	_mm_storeu_si128((__m128i*)(out) + 14, B14);
}
#endif

void aes_botan_aesni_decrypt_7way(aes_decrypt_ctx *ctx, const byte* in, byte* out)
{
	const __m128i* in_mm = (const __m128i*)(in);
	const __m128i* key_mm = (const __m128i*)(ctx->ks);	

    __m128i B0 = _mm_loadu_si128(in_mm + 0);
    __m128i B1 = _mm_loadu_si128(in_mm + 1);
    __m128i B2 = _mm_loadu_si128(in_mm + 2);
    __m128i B3 = _mm_loadu_si128(in_mm + 3);
    __m128i B4 = _mm_loadu_si128(in_mm + 4);
    __m128i B5 = _mm_loadu_si128(in_mm + 5);
    __m128i B6 = _mm_loadu_si128(in_mm + 6);

	// round-0
	__m128i K  = _mm_loadu_si128(key_mm);

	B0 = _mm_xor_si128(B0, K);
	B1 = _mm_xor_si128(B1, K);
	B2 = _mm_xor_si128(B2, K);
	B3 = _mm_xor_si128(B3, K);
	B4 = _mm_xor_si128(B4, K);
	B5 = _mm_xor_si128(B5, K);
	B6 = _mm_xor_si128(B6, K);

	// round
	AES_DEC_7_ROUNDS (1);
	AES_DEC_7_ROUNDS (2);
	AES_DEC_7_ROUNDS (3);
	AES_DEC_7_ROUNDS (4);
	AES_DEC_7_ROUNDS (5);
	AES_DEC_7_ROUNDS (6);
	AES_DEC_7_ROUNDS (7);
	AES_DEC_7_ROUNDS (8);
	AES_DEC_7_ROUNDS (9);
	AES_DEC_7_ROUNDS (10);
	AES_DEC_7_ROUNDS (11);
	AES_DEC_7_ROUNDS (12);
	AES_DEC_7_ROUNDS (13);

	AES_DEC_7_LAST_ROUNDS;

	_mm_storeu_si128((__m128i*)(out) + 0, B0);
	_mm_storeu_si128((__m128i*)(out) + 1, B1);
	_mm_storeu_si128((__m128i*)(out) + 2, B2);
	_mm_storeu_si128((__m128i*)(out) + 3, B3);
	_mm_storeu_si128((__m128i*)(out) + 4, B4);
	_mm_storeu_si128((__m128i*)(out) + 5, B5);
	_mm_storeu_si128((__m128i*)(out) + 6, B6);
}

void aes_botan_aesni_decrypt_15x(aes_decrypt_ctx *ctx, const byte* in, byte* out, uint_32t blocks)
{
#if CRYPTOPP_BOOL_X64
	while (blocks >= 15)
	{
		aes_botan_aesni_decrypt_15way (ctx, in, out);
		blocks -= 15;
		in += 15 * 16;
		out += 15 * 16;
	}
#endif
	while (blocks >= 7)
	{
		aes_botan_aesni_decrypt_7way (ctx, in, out);
		blocks -= 7;
		in += 7 * 16;
		out += 7 * 16;
	}

	aes_botan_aesni_decrypt_4x (ctx, in, out, blocks);
}

void aes_botan_aesni_decrypt_7x(aes_decrypt_ctx *ctx, const byte* in, byte* out, uint_32t blocks)
{
	while (blocks >= 7)
	{
		aes_botan_aesni_decrypt_7way (ctx, in, out);
		blocks -= 7;
		in += 7 * 16;
		out += 7 * 16;
	}

	aes_botan_aesni_decrypt_4x (ctx, in, out, blocks);
}

/*
* AES-256 Key Schedule
*/
void aes_botan_aesni_set_key(aes_encrypt_ctx *ctxe, aes_decrypt_ctx *ctxd, const byte* key)
   {

   __m128i K0 = _mm_loadu_si128((const __m128i*)(key));
   __m128i K1 = _mm_loadu_si128((const __m128i*)(key + 16));

   __m128i K2 = aes_128_key_expansion(K0, _mm_aeskeygenassist_si128(K1, 0x01));
   __m128i K3 = aes_256_key_expansion(K1, K2);

   __m128i K4 = aes_128_key_expansion(K2, _mm_aeskeygenassist_si128(K3, 0x02));
   __m128i K5 = aes_256_key_expansion(K3, K4);

   __m128i K6 = aes_128_key_expansion(K4, _mm_aeskeygenassist_si128(K5, 0x04));
   __m128i K7 = aes_256_key_expansion(K5, K6);

   __m128i K8 = aes_128_key_expansion(K6, _mm_aeskeygenassist_si128(K7, 0x08));
   __m128i K9 = aes_256_key_expansion(K7, K8);

   __m128i K10 = aes_128_key_expansion(K8, _mm_aeskeygenassist_si128(K9, 0x10));
   __m128i K11 = aes_256_key_expansion(K9, K10);

   __m128i K12 = aes_128_key_expansion(K10, _mm_aeskeygenassist_si128(K11, 0x20));
   __m128i K13 = aes_256_key_expansion(K11, K12);

   __m128i K14 = aes_128_key_expansion(K12, _mm_aeskeygenassist_si128(K13, 0x40));

   __m128i* EK_mm = (__m128i*)(ctxe->ks);
   __m128i* DK_mm = (__m128i*)(ctxd->ks);

   _mm_storeu_si128(EK_mm     , K0);
   _mm_storeu_si128(EK_mm +  1, K1);
   _mm_storeu_si128(EK_mm +  2, K2);
   _mm_storeu_si128(EK_mm +  3, K3);
   _mm_storeu_si128(EK_mm +  4, K4);
   _mm_storeu_si128(EK_mm +  5, K5);
   _mm_storeu_si128(EK_mm +  6, K6);
   _mm_storeu_si128(EK_mm +  7, K7);
   _mm_storeu_si128(EK_mm +  8, K8);
   _mm_storeu_si128(EK_mm +  9, K9);
   _mm_storeu_si128(EK_mm + 10, K10);
   _mm_storeu_si128(EK_mm + 11, K11);
   _mm_storeu_si128(EK_mm + 12, K12);
   _mm_storeu_si128(EK_mm + 13, K13);
   _mm_storeu_si128(EK_mm + 14, K14);

   // Now generate decryption keys
   
   _mm_storeu_si128(DK_mm     , K14);
   _mm_storeu_si128(DK_mm +  1, _mm_aesimc_si128(K13));
   _mm_storeu_si128(DK_mm +  2, _mm_aesimc_si128(K12));
   _mm_storeu_si128(DK_mm +  3, _mm_aesimc_si128(K11));
   _mm_storeu_si128(DK_mm +  4, _mm_aesimc_si128(K10));
   _mm_storeu_si128(DK_mm +  5, _mm_aesimc_si128(K9));
   _mm_storeu_si128(DK_mm +  6, _mm_aesimc_si128(K8));
   _mm_storeu_si128(DK_mm +  7, _mm_aesimc_si128(K7));
   _mm_storeu_si128(DK_mm +  8, _mm_aesimc_si128(K6));
   _mm_storeu_si128(DK_mm +  9, _mm_aesimc_si128(K5));
   _mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(K4));
   _mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(K3));
   _mm_storeu_si128(DK_mm + 12, _mm_aesimc_si128(K2));
   _mm_storeu_si128(DK_mm + 13, _mm_aesimc_si128(K1));
   _mm_storeu_si128(DK_mm + 14, K0);
   }

#undef AES_ENC_4_ROUNDS
#undef AES_ENC_4_LAST_ROUNDS
#undef AES_DEC_4_ROUNDS
#undef AES_DEC_4_LAST_ROUNDS
