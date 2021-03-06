/*
 * Copyright (C) 2013 Dimitris Tsitsipis <mitsarionas@gmail.com>
 *
 * This file is part of aesop.
 *
 *  aesop is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  aesop is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with aesop.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>

#include <string.h>

#include "aesop.h"

#define Nk_128 4
#define Nr_128 10
#define Nb 4

#ifdef DEBUG_AES
#include <stdio.h>
#define DPRINT(...) printf(__VA_ARGS__)
#else
#define DPRINT(...)
#endif

//TODO: check it works for big endian
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define MC0 3
#define MC1 2
#define MC2 1
#define MC3 0
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define MC0 0
#define MC1 1
#define MC2 2
#define MC3 3
#endif

typedef union
{
	uint32_t word;
	uint8_t bytes[4];
} word_u;

uint32_t sub_word(uint32_t word);
uint32_t rot_word();
static uint8_t sbox[];
//static uint8_t inv_sbox[];
static uint32_t Rcon[];
inline uint32_t pack_bytes(uint8_t *bytes);
inline uint8_t mul2(uint8_t b);
inline word_u mix_columns(word_u s);
inline void add_round_key(word_u *data, uint32_t *w);



/*
 * print a word, compensating for endianness
 */
void print_word(word_u theword)
{
	DPRINT("%.2x%.2x%.2x%.2x",theword.bytes[MC0],
			theword.bytes[MC1],theword.bytes[MC2],theword.bytes[MC3]);
	DPRINT("%.8x", theword.word);
}

void print_state(word_u *state)
{
	int i;
	for (i = 0; i < Nb; i++) {
		print_word(state[i]);
	}
	DPRINT("\n");
}

void aes_key_setup_128(uint8_t *key, struct aes_context_128 *ctx)
{
	int i;
	uint32_t temp;
	memcpy(ctx->key, key, AES_KEY_SIZE_128);
/*	for (i = 0; i < Nk_128; i++) {
		w[i] = (key[4*i] << 24) + (key[4*i+1] << 16) +(key[4*i+2] << 8) + key[4*i+3];
	}
*/
	ctx->keyschedule[0] = (key[0] << 24)  + (key[1] << 16)  + (key[2] << 8)  + key[3];
	ctx->keyschedule[1] = (key[4] << 24)  + (key[5] << 16)  + (key[6] << 8)  + key[7];
	ctx->keyschedule[2] = (key[8] << 24)  + (key[9] << 16)  + (key[10] << 8) + key[11];
	ctx->keyschedule[3] = (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
	for (i = Nk_128; i < Nb * (Nr_128 + 1); i++) {
		DPRINT("i: %d\n", i);
		temp = ctx->keyschedule[i-1];
		if (i % Nk_128 == 0) {
			DPRINT("rot: %x\n", rot_word(temp));
			DPRINT("subword: %x\n", sub_word(rot_word(temp)));
			DPRINT("rcon: %x\n", Rcon[i/Nk_128]);
			temp = sub_word(rot_word(temp)) ^ Rcon[i/Nk_128];
			DPRINT("after xor: %x\n", temp);
		}
		ctx->keyschedule[i] = ctx->keyschedule[i-Nk_128] ^ temp;
		DPRINT("final: %x\n",w[i]);
	}
}

void aes_128_encrypt(uint8_t *plain, uint8_t *ciphertext,
		struct aes_context_128 *ctx)
{
	int i;
	uint32_t *w;
	word_u state[Nb],state2[Nb];
	w = ctx->keyschedule;
	//initial state and add_round_key in one
	state[0].word = pack_bytes(plain);
	state[0].word = w[0]^pack_bytes(plain);
	state[1].word = w[1]^pack_bytes(&(plain[4]));
	state[2].word = w[2]^pack_bytes(&(plain[8]));
	state[3].word = w[3]^pack_bytes(&(plain[12]));
#ifdef DEBUG_AES
	print_state(state);
#endif
	for (i = 1; i<= Nr_128; i++) {
#ifdef DEBUG_AES
		DPRINT("start: ");
		print_state(state);
#endif
		//sub_bytes and shift rows together
		state2[0].bytes[MC0] = sbox[state[0].bytes[MC0]];
		state2[1].bytes[MC0] = sbox[state[1].bytes[MC0]];
		state2[2].bytes[MC0] = sbox[state[2].bytes[MC0]];
		state2[3].bytes[MC0] = sbox[state[3].bytes[MC0]];
		state2[0].bytes[MC1] = sbox[state[1].bytes[MC1]];
		state2[1].bytes[MC1] = sbox[state[2].bytes[MC1]];
		state2[2].bytes[MC1] = sbox[state[3].bytes[MC1]];
		state2[3].bytes[MC1] = sbox[state[0].bytes[MC1]];
		state2[0].bytes[MC2] = sbox[state[2].bytes[MC2]];
		state2[1].bytes[MC2] = sbox[state[3].bytes[MC2]];
		state2[2].bytes[MC2] = sbox[state[0].bytes[MC2]];
		state2[3].bytes[MC2] = sbox[state[1].bytes[MC2]];
		state2[0].bytes[MC3] = sbox[state[3].bytes[MC3]];
		state2[1].bytes[MC3] = sbox[state[0].bytes[MC3]];
		state2[2].bytes[MC3] = sbox[state[1].bytes[MC3]];
		state2[3].bytes[MC3] = sbox[state[2].bytes[MC3]];
#ifdef DEBUG_AES
		DPRINT("rows:  ");
		print_state(state2);
#endif
		if (i < Nr_128) {
			state[0] = mix_columns(state2[0]);
			state[1] = mix_columns(state2[1]);
			state[2] = mix_columns(state2[2]);
			state[3] = mix_columns(state2[3]);
#ifdef DEBUG_AES
			DPRINT("cols:  ");
			print_state(state);
#endif
		} else {
			state[0] = state2[0];
			state[1] = state2[1];
			state[2] = state2[2];
			state[3] = state2[3];
		}
		add_round_key(state, &(w[4*i]));
	}
#ifdef DEBUG_AES
	DPRINT("result: ");
	print_state(state);
#endif
	ciphertext[0] = state[0].bytes[MC0];
	ciphertext[1] = state[0].bytes[MC1];
	ciphertext[2] = state[0].bytes[MC2];
	ciphertext[3] = state[0].bytes[MC3];
	ciphertext[4] = state[1].bytes[MC0];
	ciphertext[5] = state[1].bytes[MC1];
	ciphertext[6] = state[1].bytes[MC2];
	ciphertext[7] = state[1].bytes[MC3];
	ciphertext[8] = state[2].bytes[MC0];
	ciphertext[9] = state[2].bytes[MC1];
	ciphertext[10] = state[2].bytes[MC2];
	ciphertext[11] = state[2].bytes[MC3];
	ciphertext[12] = state[3].bytes[MC0];
	ciphertext[13] = state[3].bytes[MC1];
	ciphertext[14] = state[3].bytes[MC2];
	ciphertext[15] = state[3].bytes[MC3];
}

inline word_u mix_columns(word_u s)
{
	word_u res;
	uint8_t s2[4];

	s2[0] = mul2(s.bytes[MC0]);
	s2[1] = mul2(s.bytes[MC1]);
	s2[2] = mul2(s.bytes[MC2]);
	s2[3] = mul2(s.bytes[MC3]);
	res.bytes[MC0] = s2[0] ^
			s2[1] ^ s.bytes[MC1] ^
			s.bytes[MC2] ^
			s.bytes[MC3];
	res.bytes[MC1] = s.bytes[MC0] ^
			s2[1] ^
			s2[2] ^ s.bytes[MC2] ^
			s.bytes[MC3];
	res.bytes[MC2] = s.bytes[MC0] ^
			s.bytes[MC1] ^
			s2[2] ^
			s2[3] ^ s.bytes[MC3];
	res.bytes[MC3] = s2[0]^ s.bytes[MC0] ^
			s.bytes[MC1] ^
			s.bytes[MC2] ^
			s2[3];
	return res;
}

inline uint8_t mul2(uint8_t b)
{
	return (b & 0x80) ? b<<1 : (b<<1)^0x1b;
}

/*
uint8_t mul3(uint8_t b)
{
	return (b && 0x80) ? (b<<1)^b : (b<<1)^0x1b^b;
}

*/

inline void add_round_key(word_u *data, uint32_t *w)
{
	data[0].word ^= w[0];
	data[1].word ^= w[1];
	data[2].word ^= w[2];
	data[3].word ^= w[3];
}

/*
 * pack bytes, in machine's endiannes
 */
uint32_t pack_bytes(uint8_t *bytes)
{
	return (bytes[0] << 24)  + (bytes[1] << 16)  +
			(bytes[2] << 8)  + bytes[3];
}

uint32_t sub_word(uint32_t word)
{
	word_u res;
	word_u w;
	w.word = word;
	res.bytes[0] = sbox[w.bytes[0]];
	res.bytes[1] = sbox[w.bytes[1]];
	res.bytes[2] = sbox[w.bytes[2]];
	res.bytes[3] = sbox[w.bytes[3]];
	return res.word;
}

uint32_t rot_word(uint32_t word)
{
	return (word << 8) | (word >> 24);
}

static uint8_t sbox[256] =
 {0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76
 ,0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0
 ,0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15
 ,0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75
 ,0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84
 ,0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf
 ,0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8
 ,0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2
 ,0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73
 ,0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb
 ,0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79
 ,0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08
 ,0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a
 ,0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e
 ,0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf
 ,0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16
 };

/*
static uint8_t inv_sbox[256] =
{0x52 ,0x09 ,0x6a ,0xd5 ,0x30 ,0x36 ,0xa5 ,0x38 ,0xbf ,0x40 ,0xa3 ,0x9e ,0x81 ,0xf3 ,0xd7 ,0xfb
,0x7c ,0xe3 ,0x39 ,0x82 ,0x9b ,0x2f ,0xff ,0x87 ,0x34 ,0x8e ,0x43 ,0x44 ,0xc4 ,0xde ,0xe9 ,0xcb
,0x54 ,0x7b ,0x94 ,0x32 ,0xa6 ,0xc2 ,0x23 ,0x3d ,0xee ,0x4c ,0x95 ,0x0b ,0x42 ,0xfa ,0xc3 ,0x4e
,0x08 ,0x2e ,0xa1 ,0x66 ,0x28 ,0xd9 ,0x24 ,0xb2 ,0x76 ,0x5b ,0xa2 ,0x49 ,0x6d ,0x8b ,0xd1 ,0x25
,0x72 ,0xf8 ,0xf6 ,0x64 ,0x86 ,0x68 ,0x98 ,0x16 ,0xd4 ,0xa4 ,0x5c ,0xcc ,0x5d ,0x65 ,0xb6 ,0x92
,0x6c ,0x70 ,0x48 ,0x50 ,0xfd ,0xed ,0xb9 ,0xda ,0x5e ,0x15 ,0x46 ,0x57 ,0xa7 ,0x8d ,0x9d ,0x84
,0x90 ,0xd8 ,0xab ,0x00 ,0x8c ,0xbc ,0xd3 ,0x0a ,0xf7 ,0xe4 ,0x58 ,0x05 ,0xb8 ,0xb3 ,0x45 ,0x06
,0xd0 ,0x2c ,0x1e ,0x8f ,0xca ,0x3f ,0x0f ,0x02 ,0xc1 ,0xaf ,0xbd ,0x03 ,0x01 ,0x13 ,0x8a ,0x6b
,0x3a ,0x91 ,0x11 ,0x41 ,0x4f ,0x67 ,0xdc ,0xea ,0x97 ,0xf2 ,0xcf ,0xce ,0xf0 ,0xb4 ,0xe6 ,0x73
,0x96 ,0xac ,0x74 ,0x22 ,0xe7 ,0xad ,0x35 ,0x85 ,0xe2 ,0xf9 ,0x37 ,0xe8 ,0x1c ,0x75 ,0xdf ,0x6e
,0x47 ,0xf1 ,0x1a ,0x71 ,0x1d ,0x29 ,0xc5 ,0x89 ,0x6f ,0xb7 ,0x62 ,0x0e ,0xaa ,0x18 ,0xbe ,0x1b
,0xfc ,0x56 ,0x3e ,0x4b ,0xc6 ,0xd2 ,0x79 ,0x20 ,0x9a ,0xdb ,0xc0 ,0xfe ,0x78 ,0xcd ,0x5a ,0xf4
,0x1f ,0xdd ,0xa8 ,0x33 ,0x88 ,0x07 ,0xc7 ,0x31 ,0xb1 ,0x12 ,0x10 ,0x59 ,0x27 ,0x80 ,0xec ,0x5f
,0x60 ,0x51 ,0x7f ,0xa9 ,0x19 ,0xb5 ,0x4a ,0x0d ,0x2d ,0xe5 ,0x7a ,0x9f ,0x93 ,0xc9 ,0x9c ,0xef
,0xa0 ,0xe0 ,0x3b ,0x4d ,0xae ,0x2a ,0xf5 ,0xb0 ,0xc8 ,0xeb ,0xbb ,0x3c ,0x83 ,0x53 ,0x99 ,0x61
,0x17 ,0x2b ,0x04 ,0x7e ,0xba ,0x77 ,0xd6 ,0x26 ,0xe1 ,0x69 ,0x14 ,0x63 ,0x55 ,0x21 ,0x0c ,0x7d
};
*/

/*
 * (we do not need values further than Rcon[10] in aes 128)
 */
static uint32_t Rcon[16] = {0x8d000000, 0x01000000, 0x02000000, 0x04000000,
		0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
		0x1b000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000,
		0x4d000000, 0x9a000000};

