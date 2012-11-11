/*
 * cryptpe -- Encryption tool for PE binaries
 * (C) 2012 Martin Wolters
 *
 * This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://sam.zoy.org/wtfpl/COPYING for more details.
 */

#ifndef RC4_H_
#define RC4_H_

#define RC4_KEY_SIZE	16

#define rc4_drop(n, ctx)    rc4_gen(NULL, n, ctx)

typedef struct {
    unsigned char i, j, s[256];
} rc4_ctx_t;

rc4_ctx_t rc4_init(unsigned char *key, unsigned int l);
void rc4_gen(unsigned char *stream, unsigned int l, rc4_ctx_t *c);

#endif
