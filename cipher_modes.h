/*
 * cipher_modes.h
 *
 *  Created on: Apr 11, 2013
 *      Author: mits
 */

#ifndef CIPHER_MODES_H_
#define CIPHER_MODES_H_


struct omac_context_128
{
	uint8_t Lu[16];
	uint8_t Lu2[16];
	void (*cipher)(uint8_t *plain, uint8_t *ciphertext, void *ciphercontext);
	int cipherblocklength;
	void * ciphercontext;
	int taglength;
};

struct eax_context
{
	int noncelength;
	void *ciphercontext;
	void (*cipher)(uint8_t *plain, uint8_t *ciphertext, void *keyschedule);
	int cipherblocklength;
	void *omac_context;
	int taglength;
};

//struct omac_context_64
//{
//	uint8_t Lu[8];
//	uint8_t Lu2[8];
//};

void ctr_mode(uint8_t *data, int length, uint8_t *ciphertext, void *ciphercontext,
		const uint8_t * const nonce, int noncelength,
		void (*cipher)(uint8_t *plain, uint8_t *ciphertext, void *ciphercontext),
		int cipherblocklength);

void inc_t(uint8_t *t, int tlength);

void omac_setup(struct omac_context_128 * ctx, void * const ciphercontext,
		void (*cipher)(uint8_t *plain, uint8_t *ciphertext, void *ciphercontext),
		const int cipherblocklength, const int taglength);

void omac2_setup(struct omac_context_128 * ctx, void * const ciphercontext,
		void (*cipher)(uint8_t *plain, uint8_t *ciphertext, void *ciphercontext),
		const int cipherblocklength, const int taglength);


void omac(uint8_t * const data, int const length,
		struct omac_context_128 * const ctx, uint8_t *tag);

void eax_setup(struct eax_context *ctx, int const noncelength, void * const ciphercontext,
		void (*cipher)(uint8_t *plain, uint8_t *ciphertext, void *keyschedule),
		const int cipherblocklength, void * const omac_context, const int taglength);

void eax_encrypt(uint8_t * const data, const int length, uint8_t *ciphertext,
		uint8_t * const header, const int headerlength,
		uint8_t * const nonce, uint8_t *tag, struct eax_context * const ctx);

int eax_decrypt(uint8_t * const ciphertext, int const length, uint8_t *data,
		uint8_t * const header, const int headerlength,
		uint8_t * const nonce, uint8_t * const tag, struct eax_context * const ctx);

#endif /* CIPHER_MODES_H_ */
