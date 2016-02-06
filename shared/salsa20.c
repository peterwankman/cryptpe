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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "salsa20.h"

#define rotl(x, n) (((x) << n) | ((x) >> (32 - n)))
#define lend(a, b, c, d) ((a) | ((b) << 8) | ((c) << 16) | (d << 24))

static const uint8_t sigma[16] = {
    0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
    0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b
};

static const uint8_t tau[16] = {
    0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x31,
    0x36, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b
};

/* double round */
static void dround(uint32_t *y) {
    y[ 4] = y[ 4] ^ rotl((y[ 0] + y[12]),  7);
    y[ 8] = y[ 8] ^ rotl((y[ 4] + y[ 0]),  9);
    y[12] = y[12] ^ rotl((y[ 8] + y[ 4]), 13);
    y[ 0] = y[ 0] ^ rotl((y[12] + y[ 8]), 18);
    y[ 9] = y[ 9] ^ rotl((y[ 5] + y[ 1]),  7);
    y[13] = y[13] ^ rotl((y[ 9] + y[ 5]),  9);
    y[ 1] = y[ 1] ^ rotl((y[13] + y[ 9]), 13);
    y[ 5] = y[ 5] ^ rotl((y[ 1] + y[13]), 18);
    y[14] = y[14] ^ rotl((y[10] + y[ 6]),  7);
    y[ 2] = y[ 2] ^ rotl((y[14] + y[10]),  9);
    y[ 6] = y[ 6] ^ rotl((y[ 2] + y[14]), 13);
    y[10] = y[10] ^ rotl((y[ 6] + y[ 2]), 18);
    y[ 3] = y[ 3] ^ rotl((y[15] + y[11]),  7);
    y[ 7] = y[ 7] ^ rotl((y[ 3] + y[15]),  9);
    y[11] = y[11] ^ rotl((y[ 7] + y[ 3]), 13);
    y[15] = y[15] ^ rotl((y[11] + y[ 7]), 18);
    y[ 1] = y[ 1] ^ rotl((y[ 0] + y[ 3]),  7);
    y[ 2] = y[ 2] ^ rotl((y[ 1] + y[ 0]),  9);
    y[ 3] = y[ 3] ^ rotl((y[ 2] + y[ 1]), 13);
    y[ 0] = y[ 0] ^ rotl((y[ 3] + y[ 2]), 18);
    y[ 6] = y[ 6] ^ rotl((y[ 5] + y[ 4]),  7);
    y[ 7] = y[ 7] ^ rotl((y[ 6] + y[ 5]),  9);
    y[ 4] = y[ 4] ^ rotl((y[ 7] + y[ 6]), 13);
    y[ 5] = y[ 5] ^ rotl((y[ 4] + y[ 7]), 18);
    y[11] = y[11] ^ rotl((y[10] + y[ 9]),  7);
    y[ 8] = y[ 8] ^ rotl((y[11] + y[10]),  9);
    y[ 9] = y[ 9] ^ rotl((y[ 8] + y[11]), 13);
    y[10] = y[10] ^ rotl((y[ 9] + y[ 8]), 18);
    y[12] = y[12] ^ rotl((y[15] + y[14]),  7);
    y[13] = y[13] ^ rotl((y[12] + y[15]),  9);
    y[14] = y[14] ^ rotl((y[13] + y[12]), 13);
    y[15] = y[15] ^ rotl((y[14] + y[13]), 18);
}

static void salsa20(uint8_t *in) {
    size_t i;
    uint32_t x[16];
    uint32_t o[16];

    for(i = 0; i < 16; i++) {
        o[i] = x[i] = lend(in[i * 4], in[i * 4 + 1], in[i * 4 + 2], in[i * 4 + 3]);
    }

    for(i = 0; i < 10; i++)
        dround(x);

    for(i = 0; i < 16; i++) {
        o[i] += x[i];
        in[i * 4] = o[i];
        in[i * 4 + 1] = (o[i] >> 8);
        in[i * 4 + 2] = (o[i] >> 16);
        in[i * 4 + 3] = (o[i] >> 24);
    }
}

static void expand(uint8_t *x, const uint8_t *k, const uint8_t *n, const size_t n_bytes) {
    size_t i;
    const uint8_t *c, *l;

    if(n_bytes == 32) {
        c = sigma;
        l = k + 16;
    } else {
        c = tau;
        l = k;
    }

    for(i = 0; i < 4; i++) {
        x[i]        = c[i];
        x[i + 20]   = c[i + 4];
        x[i + 40]   = c[i + 8];
        x[i + 60]   = c[i + 12];
    }

    memcpy(x + 4,  k, 16);
    memcpy(x + 24, n, 16);
    memcpy(x + 44, l, 16);
}

static void increment(uint8_t *n) {
    int carry = 0;
    size_t offs = 8;

    do {
        if(n[offs] == 0xff)
            carry = 1;
        else
            carry = 0;

        n[offs]++;
        offs++;
    } while((offs < 16) && carry);
}

salsa20_ctx_t salsa20_init(const uint8_t *key, const uint8_t *nonce, const size_t ksize) {
	salsa20_ctx_t out;

	memset(out.state, 0, 64);
	memcpy(out.key, key, 32);
	memcpy(out.nonce, nonce, 16);	
	out.ksize = ksize;

	return out;
}

uint8_t *salsa20_gen_block(salsa20_ctx_t *ctx) {
	expand(ctx->state, ctx->key, ctx->nonce, ctx->ksize);
	salsa20(ctx->state);
	increment(ctx->nonce);

	return ctx->state;
}