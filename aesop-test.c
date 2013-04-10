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

#include <stdio.h>

#include "aesop.h"

uint8_t plain[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
		0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};

uint8_t key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

//uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2,
//		0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};



int main(int argc, char *argv[])
{
	uint32_t w[44];
	uint8_t ciphertext[16];
	int i;
//	for (i = 0; i < 1000000; i++) {
		aes_key_setup_128(key, w);
//	}
//	for (i = 0; i < 44; i++) {
//		printf("%d: %x\n",i, w[i]);
//	}
	for (i = 0; i < 1000000; i++) {
		aes_128_encrypt(plain, ciphertext, w);
	}
		for (i = 0; i < 16; i++) {
			printf("%d: %x\n",i, ciphertext[i]);
		}
//	aes_128_encrypt(plain, ciphertext, w);




	return 0;
}
