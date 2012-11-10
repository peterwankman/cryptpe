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

#include "..\shared\huffman.h"

#ifndef HUFFMAN_DEC_H_
#define HUFFMAN_DEC_H_

hfm_node_t *reconstruct_tree(uchar *in);
uchar *decode(uchar *in, hfm_node_t *root, size_t len);
void free_tree(hfm_node_t *node);

#endif