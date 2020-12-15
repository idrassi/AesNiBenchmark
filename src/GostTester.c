#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>
#include "Aes.h"
#include "Aes_Botan_aesni.h"
#include "cpu.h"
#include "utils.h"

#define ALIGN(a)	CRYPTOPP_ALIGN_DATA(a)


typedef struct {
	const char* key;
	const char* plaintext;
	const char* ciphertext;
} CIPHER_TEST;

typedef void (__cdecl CipherFunction) (unsigned char* key, unsigned char* input, unsigned long inputLen, unsigned char* output, int encrypt);

#define RtlGenRandom SystemFunction036
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);

int RunCipherTest (CipherFunction fn, CIPHER_TEST* vector, int count)
{
	static ALIGN (32) unsigned char input[64];
	static ALIGN (32) unsigned char output[64];
	static ALIGN (32) unsigned char key[32];
	int i;
	for (i = 0; i < count; i++)
	{
		HexStringToByteArray (vector[i].key, key);
		HexStringToByteArray (vector[i].plaintext, input);
		HexStringToByteArray (vector[i].ciphertext, output);
		fn (key, input, 16, input, 1);
		if (memcmp (input, output, 16))
			return 0;		
		fn (key, input, 16, input, 0);
		HexStringToByteArray (vector[i].plaintext, output);
		if (memcmp (input, output, 16))
			return 0;	

		HexStringToByteArray (vector[i].plaintext, input);
		HexStringToByteArray (vector[i].ciphertext, output);
		memcpy (input + 16, input, 16);
		memcpy (input + 32, input, 16);
		memcpy (input + 48, input, 16);

		memcpy (output + 16, output, 16);
		memcpy (output + 32, output, 16);
		memcpy (output + 48, output, 16);
		fn (key, input, 64, input, 1);
		if (memcmp (input, output, 64))
			return 0;

		fn (key, input, 64, input, 0);

		HexStringToByteArray (vector[i].plaintext, output);
		memcpy (output + 16, output, 16);
		memcpy (output + 32, output, 16);
		memcpy (output + 48, output, 16);

		if (memcmp (input, output, 64))
			return 0;
	}

	return 1;
}

double RunCipherBenchmark (CipherFunction fn, int encrypt, int extended)
{
	#define TEST_BLOCK_LEN 52428800
	#define TEST_BLOCK_COUNT 8

	unsigned char *input = (unsigned char*) _aligned_malloc (TEST_BLOCK_LEN, 32);
	static ALIGN (32) unsigned char key[32];
	unsigned long i = 0;
    double seconds;
	unsigned long loops = extended? 20*TEST_BLOCK_COUNT : TEST_BLOCK_COUNT;
	LARGE_INTEGER performanceCountStart, performanceCountEnd, performanceCountDiff, performanceCountFreq;

	QueryPerformanceFrequency (&performanceCountFreq);

	performanceCountDiff.QuadPart = 0;
	for (i = 0; i < loops; i++)
	{
		RtlGenRandom (input, TEST_BLOCK_LEN);
		RtlGenRandom (key, 32);
		QueryPerformanceCounter (&performanceCountStart);
		fn (key, input, TEST_BLOCK_LEN, input, encrypt);
		QueryPerformanceCounter (&performanceCountEnd);
		performanceCountDiff.QuadPart += performanceCountEnd.QuadPart - performanceCountStart.QuadPart;
	}

	_aligned_free (input);

	seconds = ((double) performanceCountDiff.QuadPart) / (double) performanceCountFreq.QuadPart;
    return  (double) TEST_BLOCK_LEN * (double) loops / (seconds * 1024.0 * 1024.0);
}

#define AES_TEST_COUNT 3
CIPHER_TEST aes_test_vectors[AES_TEST_COUNT] = {
	{"0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "dc95c078a2408989ad48a21492842087"},
	{"8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E", "8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E8E", "2F178F9BE7246F32D6CC007060ACFA0D"},
	{"2BD6459F82C5B300952C49104881FF482BD6459F82C5B300952C49104881FF48", "DFC295E9D04A30DB25940E4FCC64516F", "EA024714AD5C4D84EA024714AD5C4D84"}
};


#if CRYPTOPP_BOOL_X64
void __cdecl AesBotanAESNI15WayCipherFunction (unsigned char* key, unsigned char* input, unsigned long inputLen, unsigned char* output, int encrypt)
{
	aes_encrypt_ctx kse;
	aes_decrypt_ctx ksd;
	aes_botan_aesni_set_key(&kse, &ksd, key);

	if (encrypt)
		aes_botan_aesni_encrypt_15x(&kse, input, output, inputLen/16);
	else
		aes_botan_aesni_decrypt_15x(&ksd, input, output, inputLen/16);
}
#endif

void __cdecl AesBotanAESNI7WayCipherFunction (unsigned char* key, unsigned char* input, unsigned long inputLen, unsigned char* output, int encrypt)
{
	aes_encrypt_ctx kse;
	aes_decrypt_ctx ksd;
	aes_botan_aesni_set_key(&kse, &ksd, key);

	if (encrypt)
		aes_botan_aesni_encrypt_7x(&kse, input, output, inputLen/16);
	else
		aes_botan_aesni_decrypt_7x(&ksd, input, output, inputLen/16);
}

void __cdecl AesBotanAESNI4WayCipherFunction (unsigned char* key, unsigned char* input, unsigned long inputLen, unsigned char* output, int encrypt)
{
	aes_encrypt_ctx kse;
	aes_decrypt_ctx ksd;
	aes_botan_aesni_set_key(&kse, &ksd, key);

	if (encrypt)
		aes_botan_aesni_encrypt_4x(&kse, input, output, inputLen/16);
	else
		aes_botan_aesni_decrypt_4x(&ksd, input, output, inputLen/16);
}

int __cdecl main (int argc, char** argv)
{
	double p;
	DetectX86Features ();
#if CRYPTOPP_BOOL_X64
	printf("\n64-bit AES-NI Benchmark by Mounir IDRASSI (mounir@idrix.fr)\nVersion 2020-12-13\n\n");
#else
	printf("\n32-bit AES-NI Benchmark by Mounir IDRASSI (mounir@idrix.fr)\nVersion 2020-12-13\n\n");
#endif

	printf ("CPU has AES-NI extension: %s\n", g_hasAESNI? "YES" : "NO");

	printf("\n");
	
	if (g_hasAESNI)
	{
		printf("AES-NI 4-way: ");
		if (RunCipherTest (AesBotanAESNI4WayCipherFunction, aes_test_vectors, AES_TEST_COUNT))
		{
			printf ("ok (");
			p = RunCipherBenchmark (AesBotanAESNI4WayCipherFunction, 1, 1);
			printf("Enc = %.2f MB/s, ", p);
			p = RunCipherBenchmark (AesBotanAESNI4WayCipherFunction, 0, 1);
			printf("Dec = %.2f MB/s)\n", p);
		}
		else
			printf("error\n");

		printf("AES-NI 7-way: ");
		if (RunCipherTest (AesBotanAESNI7WayCipherFunction, aes_test_vectors, AES_TEST_COUNT))
		{
			printf ("ok (");
			p = RunCipherBenchmark (AesBotanAESNI7WayCipherFunction, 1, 1);
			printf("Enc = %.2f MB/s, ", p);
			p = RunCipherBenchmark (AesBotanAESNI7WayCipherFunction, 0, 1);
			printf("Dec = %.2f MB/s)\n",p);
		}
		else
			printf("error\n");

#if CRYPTOPP_BOOL_X64
		printf("AES-NI 15-way: ");
		if (RunCipherTest (AesBotanAESNI15WayCipherFunction, aes_test_vectors, AES_TEST_COUNT))
		{
			printf ("ok (");
			p = RunCipherBenchmark (AesBotanAESNI15WayCipherFunction, 1, 1);
			printf("Enc = %.2f MB/s, ", p);
			p = RunCipherBenchmark (AesBotanAESNI15WayCipherFunction, 0, 1);
			printf("Dec = %.2f MB/s)\n", p);
		}
		else
			printf("error\n");
#endif
	}
	else
		printf ("CPU Doesn't have AES-NI extension. Benchmark cannot proceed\n");

	printf("\nPress a key to quit...");

	while (!_kbhit ())
		Sleep (500);
	return 0;
}

