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

#ifndef AES_H_
#define AES_H_

#include <stdint.h>

void aes_key_setup_128(uint8_t *key, uint32_t *w);
aes_128_encrypt(uint8_t *plain, uint8_t *ciphertext, uint32_t *w);


#endif /* AES_H_ */
