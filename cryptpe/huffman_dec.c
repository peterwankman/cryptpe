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

#include <stdlib.h>

#include "..\shared\types.h"
#include "..\shared\huffman.h"

static uchar get_bits(uchar *in, size_t *offs, size_t n) {
	size_t byteoffs = (*offs) / 8;
	size_t bitoffs = (*offs) & 7;

	*offs += n;
	if(n == 1)
		return (in[byteoffs] >> (7 - bitoffs)) & 1;
	else
		return (in[byteoffs] << bitoffs) ^ (in[byteoffs + 1] >> (8 - bitoffs));
}

static hfm_node_t *reconstruct_node(uchar *in, size_t *offs) {
	hfm_node_t *out;
	uchar bit = get_bits(in, offs, 1);

	if((out = malloc(sizeof(hfm_node_t))) == NULL)
		return NULL;

	if(bit == 0) {
		out->left = out->right = NULL;
		out->c = get_bits(in, offs, 8);
		return out;
	} else {
		out->left = reconstruct_node(in, offs);
		out->right = reconstruct_node(in, offs);
		return out;
	}
	return out;
}

hfm_node_t *reconstruct_tree(uchar *in) {
	size_t start = 0;
	return reconstruct_node(in, &start);
}

uchar *decode(uchar *in, hfm_node_t *root, size_t len) {
	size_t nchar, pos;
	hfm_node_t *node;
	uchar *out;

	if((out = malloc(len)) == NULL)
		return NULL;

	nchar = pos = 0;
	node = root;
	do {		
		if(!(node->left)) {
			out[nchar++] = node->c;			
			node = root;
		} else {			
			if((in[pos / 8] >> (7 - (pos & 7))) & 1) {
				node = node->right;
			} else {
				node = node->left;
			}
			pos++;
		}		
	} while(nchar < len);

	return out;
}

void free_tree(hfm_node_t *node) {
	if(node->left)
		free_tree(node->left);
	if(node->right)
		free_tree(node->right);
	free(node);
}