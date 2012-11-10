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

#include "rc4.h"
#include "types.h"

rc4_ctx_t rc4_init(uchar *key, uint l) {
    uint i;
    uchar j, temp;
    rc4_ctx_t out;

    for(i = 0; i < 256; i++)
        out.s[i] = i;

    j = 0;
    for(i = 0; i < 256; i++) {
        j = j + out.s[i] + key[i % l];
        temp = out.s[i]; out.s[i] = out.s[j]; out.s[j] = temp;
    }

    out.i = out.j = 0;
    return out;
}

void rc4_gen(uchar *stream, uint l, rc4_ctx_t *c) {
    uint n;
    uchar temp;

    for(n = 0; n < l; n++) {
        c->i++;
        c->j += c->s[c->i];
        temp = c->s[c->i]; c->s[c->i] = c->s[c->j]; c->s[c->j] = temp;

        if(stream)
            stream[n] = c->s[(c->s[c->i] + c->s[c->j]) & 255];
    }
}
