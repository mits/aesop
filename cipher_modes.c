/*
 * cipher_modes.c
 *
 *  Created on: Apr 11, 2013
 *      Author: mits
 */

#include <stdint.h>
#include <string.h>

#include "cipher_modes.h"

//#define DEBUG_CIPHER_MODES

#ifdef DEBUG_CIPHER_MODES
#include <stdio.h>
#endif

#define CEIL(x,y) (x % y) ? x/y+1 : x/y

/*
 * increase t by 1, as if it were a big endian number of size tlength
 */
void inc_t(uint8_t *t, int tlength)
{
	int i;
	i = tlength - 1;
	while(!(++t[i]) && i) i--;
}

#ifdef DEBUG_CIPHER_MODES
void print_block(uint8_t *b, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%.2x",b[i]);
	}
}
#endif

void ctr_mode(uint8_t * const data, const int length, uint8_t * ciphertext, void * const ciphercontext,
		const uint8_t * const nonce, int noncelength,
		void (*cipher)(uint8_t *plain, uint8_t *ciphertext, void *ciphercontext),
		const int cipherblocklength)
{
	int i,j, blocks, offset, limit;
	uint8_t t[cipherblocklength], o[cipherblocklength];
	blocks = CEIL(length,cipherblocklength)
			;
#ifdef DEBUG_CIPHER_MODES
	printf("blocks: %d\n", blocks);
#endif

	//copy nonce to the last bytes of the counter vector
	memcpy(t+(cipherblocklength-noncelength), nonce, noncelength);
	for (i = 0; i < blocks; i++) {
		if (i) inc_t(t, cipherblocklength);

#ifdef DEBUG_CIPHER_MODES
		printf("t: ");
		print_block(t, cipherblocklength);
		printf("\n");
#endif
		cipher(t, o, ciphercontext);
		offset = cipherblocklength * i;

		limit = (length - offset >= cipherblocklength) ?
				cipherblocklength : length - offset;

#ifdef DEBUG_CIPHER_MODES
		printf("o: ");
		print_block(o, cipherblocklength);
		printf("\n");
		printf("d: ");
		print_block(&(data[offset]), limit);
		printf("\n");
#endif

		for (j = 0; j < limit; j++) {
			ciphertext[offset + j] = data[offset + j] ^ o[j];
		}

#ifdef DEBUG_CIPHER_MODES
		printf("c: ");
		print_block(&(ciphertext[offset]), limit);
		printf("\n");
#endif
	}
}

inline void shift_1_left(uint8_t *data, int datalen)
{
	int i;
	uint8_t bit, oldbit;
	oldbit = 0;
	for (i = datalen - 1; i >= 0; i--) {
		bit = (data[i] & 0x80) >> 7;
		data[i] = (data[i] << 1) | oldbit;
		oldbit = bit;
	}
}

inline void shift_1_right(uint8_t *data, int datalen)
{
	int i;
	uint8_t bit, oldbit;
	oldbit = 0;
	for (i = 0; i < datalen; i++) {
		bit = (data[i] & 0x01) << 7;
		data[i] = (data[i] >> 1) | oldbit;
		oldbit = bit;
	}
}


/*
 *
 */
void omac_setup(struct omac_context_128 * ctx, void * const ciphercontext,
		void (*cipher)(uint8_t *plain, uint8_t *ciphertext, void *ciphercontext),
		const int cipherblocklength, const int taglength)
{
	ctx->cipher = cipher;
	ctx->cipherblocklength = cipherblocklength;
	ctx->ciphercontext = ciphercontext;
	ctx->taglength = taglength;
	uint8_t temp[cipherblocklength];
	//Lu serves as both L and Lu in the algorithm description
	//but we don't need to save L, so we save some space
	uint8_t msb;
	memset(temp, 0, cipherblocklength);
	cipher(temp, ctx->Lu, ciphercontext);

#ifdef DEBUG_CIPHER_MODES
	printf("L: ");
	print_block(ctx->Lu, cipherblocklength);
	printf("\n");
#endif

	msb = ctx->Lu[0] & 0x80;
	shift_1_left(ctx->Lu, cipherblocklength);

#ifdef DEBUG_CIPHER_MODES
	printf("Lu temp: ");
	print_block(ctx->Lu, cipherblocklength);
	printf("\n");
#endif

	if (msb) {
		if (cipherblocklength == 16) ctx->Lu[15] ^= 0x87;
		else if (cipherblocklength == 8) ctx->Lu[7] ^= 0x1b;
	}

#ifdef DEBUG_CIPHER_MODES
	printf("Lu: ");
	print_block(ctx->Lu, cipherblocklength);
	printf("\n");
#endif

	memcpy(ctx->Lu2, ctx->Lu, cipherblocklength);
	msb = ctx->Lu2[0] & 0x80;
	shift_1_left(ctx->Lu2, cipherblocklength);
	if (msb) {
		if (cipherblocklength == 16) ctx->Lu2[15] ^= 0x87;
		else if (cipherblocklength == 8) ctx->Lu2[7] ^= 0x1b;
	}
#ifdef DEBUG_CIPHER_MODES
	printf("Lu2: ");
	print_block(ctx->Lu2, cipherblocklength);
	printf("\n");
#endif
}

void omac2_setup(struct omac_context_128 * ctx, void * const ciphercontext,
		void (*cipher)(uint8_t *plain, uint8_t *ciphertext, void *ciphercontext),
		const int cipherblocklength, const int taglength)
{
	ctx->cipher = cipher;
	ctx->cipherblocklength = cipherblocklength;
	ctx->ciphercontext = ciphercontext;
	ctx->taglength = taglength;
	uint8_t temp[cipherblocklength];
	//Lu serves as both L and Lu in the algorithm description
	//but we don't need to save L, so we save some space
	uint8_t msb, lsb;
	memset(temp, 0, cipherblocklength);
	cipher(temp, ctx->Lu, ciphercontext);
	//Lu2 will actually be Lu-1, copy L into it, before it is replaced by Lu
	memcpy(ctx->Lu2, ctx->Lu, cipherblocklength);
	//compute Lu	uint8_t asdf[1000];

	msb = ctx->Lu[0] & 0x80;
	shift_1_left(ctx->Lu, cipherblocklength);
	if (msb) {
		if (cipherblocklength == 16) ctx->Lu[15] ^= 0x87;
		else if (cipherblocklength == 8) ctx->Lu[7] ^= 0x1b;
	}
	lsb = ctx->Lu2[cipherblocklength - 1] & 0x01;
	shift_1_right(ctx->Lu2, cipherblocklength);
	if (lsb) {
		ctx->Lu2[0] ^= 0x80;
		if (cipherblocklength == 16) ctx->Lu2[15] ^= 0x43;
		else if (cipherblocklength == 8) ctx->Lu2[7] ^= 0x0d;
	}
}


/*
 * omac function
 * needs a cipher function that can encrypt in-place
 */
void omac(uint8_t * const data, int const length,
		struct omac_context_128 * const ctx, uint8_t *tag)
{
	int i, b;
	int blocks;
	int offset;
	int cbl = ctx->cipherblocklength;
	blocks = CEIL(length, ctx->cipherblocklength);
	if (!blocks) blocks = 1;
	uint8_t temp[cbl];
	memset(temp, 0, cbl);
	for (i = 0; i < blocks - 1; i++) {
		offset = i * cbl;
		for (b = 0; b < cbl; b++) {
			temp[b] ^= data[offset + b];
		}
		ctx->cipher(temp, temp, ctx->ciphercontext);
	}
	offset = (blocks - 1) * cbl;
	if (length == blocks * cbl) {
		for (b = 0; b < cbl; b++) {
			temp[b] ^= data[offset + b];
			temp[b] ^= ctx->Lu[b];
		}
	} else {
		uint8_t last[cbl];
		int remaining;
		remaining = length - offset;
		memcpy(last, &(data[offset]), remaining);
		last[remaining] = 0x80;
		if (remaining + 1 < cbl)
			memset(&(last[remaining + 1]), 0, cbl - remaining - 1);
		for (b = 0; b < cbl; b++) {
			temp[b] ^= last[b] ^ ctx->Lu2[b];
		}
	}

#ifdef DEBUG_CIPHER_MODES
	printf("temp: ");
	print_block(temp, cbl);
	printf("\n");
#endif

	// temp is now X[m]
	ctx->cipher(temp, temp, ctx->ciphercontext); //temp is now T
	memcpy(tag, temp, ctx->taglength);
}

/*
 * the same omac as above, but, input is t(n) || data
 * TODO: reuse code
 */
void omac_with_eax_t(uint8_t eax_t, const uint8_t * const data, int const length,
		struct omac_context_128 * const ctx, uint8_t *tag)
{
	int i, b;
	int blocks;
	int offset;
	int cbl = ctx->cipherblocklength;
	blocks = CEIL(length, ctx->cipherblocklength);
//there is always 1 block, the one with t(n), the next line is wrong here
//	if (!blocks) blocks = 1;
	uint8_t temp[cbl];
	memset(temp, 0, cbl);
// the added part
	temp[cbl-1] = eax_t;
	if (blocks) ctx->cipher(temp, temp, ctx->ciphercontext);
//end of the added part
	for (i = 0; i < blocks - 1; i++) {
		offset = i * cbl;
		for (b = 0; b < cbl; b++) {
			temp[b] ^= data[offset + b];
		}
		ctx->cipher(temp, temp, ctx->ciphercontext);
	}
	offset = (blocks - 1) * cbl;
	if (length == blocks * cbl) {
		for (b = 0; b < cbl; b++) {
//also added: if (blocks) : do not xor if no actual data exist
			if (blocks) temp[b] ^= data[offset + b];
			temp[b] ^= ctx->Lu[b];
		}
	} else {
		uint8_t last[cbl];
		int remaining;
		remaining = length - offset;
		memcpy(last, &(data[offset]), remaining);
		last[remaining] = 0x80;
		if (remaining + 1 < cbl)
			memset(&(last[remaining + 1]), 0, cbl - remaining - 1);
		for (b = 0; b < cbl; b++) {
			temp[b] ^= last[b] ^ ctx->Lu2[b];
		}
	}
	// temp is now X[m]
	ctx->cipher(temp, temp, ctx->ciphercontext); //temp is now T
	memcpy(tag, temp, ctx->taglength);


}

void eax_setup(struct eax_context *ctx, int noncelength, void * const ciphercontext,
		void (*cipher)(uint8_t *plain, uint8_t *ciphertext, void *keyschedule),
		const int cipherblocklength, void * const omac_context, const int taglength)
{
	ctx->cipher = cipher;
	ctx->cipherblocklength = cipherblocklength;
	ctx->ciphercontext = ciphercontext;
	ctx->noncelength = noncelength;
	ctx->omac_context = omac_context;
	ctx->taglength = taglength;
}

void eax_encrypt(uint8_t * const data, const int length, uint8_t *ciphertext,
		uint8_t * const header, const int headerlength,
		uint8_t * const nonce, uint8_t *tag, struct eax_context * const ctx)
{
	int cbl = ctx->cipherblocklength;
	uint8_t nn[cbl];
	uint8_t hh[cbl];
	uint8_t tt[cbl];
	omac_with_eax_t(0, nonce, ctx->noncelength, ctx->omac_context, nn);

#ifdef DEBUG_CIPHER_MODES
	printf("nn: ");
	print_block(nn, ctx->cipherblocklength);
	printf("\n");
#endif

	omac_with_eax_t(1, header, headerlength,  ctx->omac_context, hh);

#ifdef DEBUG_CIPHER_MODES
	printf("hh: ");
	print_block(hh, ctx->cipherblocklength);
	printf("\n");
#endif

	ctr_mode(data, length, ciphertext, ctx->ciphercontext, nn, cbl,
			ctx->cipher, ctx->cipherblocklength);

	omac_with_eax_t(2, ciphertext, length, ctx->omac_context, tt);
	int i;
	for (i = 0; i < cbl; i++) {
		tt[i] = tt[i] ^ nn[i] ^ hh[i];
	}
	memcpy(tag, tt, ctx->taglength);
}

/**
 * return 0 if all ok,
 * nonzero if invalid
 * if return value is 0 the resulting plaintext will be in data
 */
int eax_decrypt(uint8_t * const ciphertext, const int length, uint8_t *data,
		uint8_t * const header, const int headerlength,
		uint8_t * const nonce, uint8_t * const tag, struct eax_context * const ctx)
{
	int cbl = ctx->cipherblocklength;
	uint8_t nn[cbl];
	uint8_t hh[cbl];
	uint8_t tt[cbl];
	omac_with_eax_t(0, nonce, ctx->noncelength, ctx->omac_context, nn);

#ifdef DEBUG_CIPHER_MODES
	printf("nn: ");
	print_block(nn, ctx->cipherblocklength);
	printf("\n");
#endif

	omac_with_eax_t(1, header, headerlength,  ctx->omac_context, hh);

#ifdef DEBUG_CIPHER_MODES
	printf("hh: ");
	print_block(hh, ctx->cipherblocklength);
	printf("\n");
#endif

	omac_with_eax_t(2, ciphertext, length, ctx->omac_context, tt);

#ifdef DEBUG_CIPHER_MODES
	printf("tt: ");
	print_block(tt, ctx->cipherblocklength);
	printf("\n");
#endif

	int i;
	for (i = 0; i < cbl; i++) {
		tt[i] = tt[i] ^ nn[i] ^ hh[i];
		// tt is the tag, check each byte in the same loop
		if (tt[i] != tag[i]) return -1; //invalid
	}
	ctr_mode(ciphertext, length, data, ctx->ciphercontext, nn, cbl,
			ctx->cipher, ctx->cipherblocklength);
	return 0; // success
}

