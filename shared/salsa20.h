/*
 * cryptpe -- Encryption tool for PE binaries
 * (C) 2012-2016 Martin Wolters
 *
 * This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://sam.zoy.org/wtfpl/COPYING for more details.
 */

#ifndef SALSA20_H_
#define SALSA20_H_

#define SALSA20_KEY_SIZE	32
#define SALSA20_BLOCK_SIZE	64
#define SALSA20_NONCE_SIZE	16

typedef struct salsa20_ctx_t {
	uint8_t state[64];
	uint8_t key[32];
	uint8_t nonce[16];
	size_t ksize;
} salsa20_ctx_t;

salsa20_ctx_t salsa20_init(const uint8_t *key, const uint8_t *nonce, const size_t ksize);
uint8_t *salsa20_gen_block(salsa20_ctx_t *ctx);

#endif