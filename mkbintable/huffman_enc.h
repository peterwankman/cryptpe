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

#ifndef HUFFMAN_ENC_H_
#define HUFFMAN_ENC_H_

#include "..\shared\huffman.h"

hfm_node_t *maketree(uint8_t *in, size_t len);
uint8_t *encode_tree(hfm_node_t *root, size_t *size);
hfm_cdb_t *make_codebook(hfm_node_t *root);
uint8_t *encode(uint8_t *in, size_t insize, hfm_cdb_t *codebook, size_t *charsize);
void free_tree(hfm_node_t *node);

#endif