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

#include <string.h>

#include "aesop.h"

#include "cipher_modes.h"

uint8_t plain[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
		0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};

uint8_t key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

//uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2,
//		0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};


void str2bytearray(char *str, uint8_t *bytes)
{
	int i;
	char *strptr;
	strptr = str;
	for (i = 0; i < strlen(str); i++) {
		sscanf(strptr, "%2hhx", &(bytes[i]));
		strptr+=2;
	}
}

int main(int argc, char *argv[])
{
	uint8_t ciphertext[100];
	int i;
	char tvstr[] = "6bc1bee22e409f96e93d7e117393172a"
			    "ae2d8a571e03ac9c9eb76fac45af8e51"
			    "30c81c46a35ce411e5fbc1191a0a52ef";
			//    "f69f2445df4f9b17ad2b417be66c3710";

	char keystr[] = "2b7e151628aed2a6abf7158809cf4f3c";
	char noncestr[] = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
//	char tvstr[] = "1a47cb4933";
//	char keystr[] = "01f74ad64077f2e704c0f60ada3dd523";
//	char noncestr[] = "70c3db4f0d26368400a10ed05d2bff5e";
	char headerstr[] = "234a3463c1264ac6";


//	char keystr[] = "000102030405060708090a0b0c0d0e0f";
//	char tvstr[] = "";
//	char noncestr[] = "";
//	char headerstr[] = "";

//	char keystr[] = "000102030405060708090a0b0c0d0e0f";
//	char tvstr[] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c";
//	char noncestr[] = "000102030405060708090a0b0c0d0e";
//	char headerstr[] = "000102030405060708090a0b0c0d";

//	char keystr[] = "233952DEE4D5ED5F9B9C6D6FF80FF478";
//	char tvstr[] =  "00000000000000000000000000000001";
//	char noncestr[] = "62EC67F9C3A4A407FCB2A8C49031A8B3";
//	char headerstr[] = "6BFB914FD07EAE6B";


	int tvlen = strlen(tvstr) / 2;
	int noncelen = strlen(noncestr) / 2;
	int headerlen = strlen(headerstr) / 2;

	uint8_t tv[4 * 16];
	uint8_t decv[4 * 16];
	uint8_t nonce[16];
	uint8_t header[16];
	uint8_t tag[16];

	str2bytearray(keystr, key);
	str2bytearray(tvstr, tv);
	str2bytearray(noncestr, nonce);
	str2bytearray(headerstr, header);

	struct aes_context_128 aesctx;
	struct omac_context_128 omacctx;
	struct eax_context eaxctx;

	aes_key_setup_128(key, &aesctx);
	omac_setup(&omacctx, &aesctx, aes_128_encrypt, 16, 16);
//	eax_setup(&eaxctx, 16, &aesctx, aes_128_encrypt, 16, &omacctx, 16);
	eax_setup(&eaxctx, noncelen, &aesctx, aes_128_encrypt, 16, &omacctx, 16);



//	void (*asdf)(uint8_t);
//	asdf = ({void l_anonymous_functions_name (uint8_t a) {printf("%d",a);} &l_anonymous_functions_name;});
//	asdf(1);
//	printf("\n");

//	uint8_t tag[16];
//	omac_with_eax_t(1, tv, tvlen, &omacctx, tag);
//	printf("tv: ");
//	for (i = 0; i < tvlen; i++) {
//		printf("%.2x", tv[i]);test
//	}
//	printf("\n");
//	printf("tag: ");
//	for (i = 0; i < 16; i++) {
//		printf("%.2x", tag[i]);
//	}
//	printf("\n");

	printf("EAX test: \n");
	printf("nonce: ");
	for (i = 0; i < noncelen; i++) {
		printf("%.2x", nonce[i]);
	}
	printf("\n");

	printf("header: ");
	for (i = 0; i < headerlen; i++) {
		printf("%.2x", header[i]);
	}
	printf("\n");


	eax_encrypt(tv, tvlen, ciphertext, header, headerlen, nonce, tag, &eaxctx);

	printf("ciphertext: ");
	for (i = 0; i < tvlen; i++) {
		printf("%.2x", ciphertext[i]);
	}
	printf("\n");

	printf("tag: ");
	for (i = 0; i < 16; i++) {
		printf("%.2x", tag[i]);
	}
	printf("\n");

	printf("EAX decryption: \n");
	printf("nonce: ");
	for (i = 0; i < noncelen; i++) {
		printf("%.2x", nonce[i]);
	}
	printf("\n");

	printf("header: ");
	for (i = 0; i < headerlen; i++) {
		printf("%.2x", header[i]);
	}
	printf("\n");

	int res;
	res = eax_decrypt(ciphertext, tvlen, decv, header, headerlen, nonce, tag, &eaxctx);
	printf("decryption valid? %d\n", res);
	printf("decrypted: ");
	for (i = 0; i < 16; i++) {
		printf("%.2x", decv[i]);
	}
	printf("\n");

//	for (i = 0; i < 44; i++) {
//		printf("%d: %x\n",i, w[i]);
//	}
//	for (i = 0; i < 1000000; i++) {
//		aes_128_encrypt(plain, ciphertext, w);
//	}
//		for (i = 0; i < 16; i++) {
//			printf("%d: %x\n",i, ciphertext[i]);
//		}
//	aes_128_encrypt(plain, ciphertext, w);




	return 0;
}
