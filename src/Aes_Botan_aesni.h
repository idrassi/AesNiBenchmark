/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/


#include "Tcdefs.h"
#include "config.h"
#include "Aes.h"

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

void aes_botan_aesni_set_key(aes_encrypt_ctx *ctxe, aes_decrypt_ctx *ctxd, const byte* in_key);

#if CRYPTOPP_BOOL_X64
void aes_botan_aesni_encrypt_15x(aes_encrypt_ctx *instance, const byte* in_blk, byte* out_blk, uint_32t blocks);
#endif
void aes_botan_aesni_encrypt_7x(aes_encrypt_ctx *instance, const byte* in_blk, byte* out_blk, uint_32t blocks);
void aes_botan_aesni_encrypt_4x(aes_encrypt_ctx *instance, const byte* in_blk, byte* out_blk, uint_32t blocks);

#if CRYPTOPP_BOOL_X64
void aes_botan_aesni_decrypt_15x(aes_decrypt_ctx *instance, const byte* in_blk, byte* out_blk, uint_32t blocks);
#endif
void aes_botan_aesni_decrypt_7x(aes_decrypt_ctx *instance, const byte* in_blk, byte* out_blk, uint_32t blocks);
void aes_botan_aesni_decrypt_4x(aes_decrypt_ctx *ctx, const byte* in, byte* out, uint_32t blocks);


#ifdef __cplusplus
}
#endif