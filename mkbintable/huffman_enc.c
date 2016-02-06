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
#include <stdlib.h>
#include <string.h>

#include "huffman_enc.h"

static hfm_node_t *makenode(int weight, uint8_t c, hfm_node_t *left, hfm_node_t *right, hfm_node_t *parent) {
	hfm_node_t *out = malloc(sizeof(hfm_node_t));
	if(!out)
		return NULL;

	out->weight = weight;
	out->c = c;
	out->left = left;
	out->right = right;
	out->parent = parent;

	return out;
}

static void findlowest(hfm_node_t **tree, size_t size, int *node1, int *node2) {
	uint32_t idx1, idx2, i, buf;
	
	*node1 = *node2 = INT_MAX;

	for(i = 0; (i < size) && (tree[i]->parent != NULL); i++); idx1 = i;
	if(i >= size)
		return;

	for(++i; (i < size) && (tree[i]->parent != NULL); i++); idx2 = i;
	if(i >= size)
		return;
	
	if(tree[idx1]->weight > tree[idx2]->weight) {
		buf = idx1;
		idx1 = idx2;
		idx2 = buf;
	}

	for(i++; i < size; i++) {
		if(!tree[i]->parent) {
			if(tree[i]->weight <= tree[idx1]->weight) {
				idx2 = idx1;
				idx1 = i;
			} else if(tree[i]->weight <= tree[idx2]->weight)
				idx2 = i;
		}	
	}

	*node1 = idx1;
	*node2 = idx2;
}

hfm_node_t *maketree(uint8_t *in, size_t len) {
	uint32_t freq[256], i, j = 0;
	int low1, low2;
	hfm_node_t *tree[511];

	memset(freq, 0, 256 * sizeof(uint32_t));

	for(i = 0; i < len; i++)
		freq[in[i]]++;

	for(i = 0; i < 256; i++)
		if(freq[i])
			tree[j++] = makenode(freq[i], i, NULL, NULL, NULL);			
	
	findlowest(tree, j, &low1, &low2);
	do {
		tree[j] = makenode(tree[low1]->weight + tree[low2]->weight, '\0', tree[low1], tree[low2], NULL);
		tree[low1]->parent = tree[j];
		tree[low2]->parent = tree[j];

		findlowest(tree, ++j, &low1, &low2);
	} while(low1 != low2);

	return tree[j - 1];
}

static void add_bits(uint8_t *c, size_t nbits, uint8_t *str, size_t *size) {
	int outpos, outoffs, bit;
	int inpos, inoffs = 0;
	
	do {
		outpos = (*size) / 8;
		outoffs = (*size) % 8;
		inpos = inoffs / 8;

		bit = (c[inpos] >> (7 - (inoffs % 8))) & 1;
		str[outpos] |= (bit << (7 - outoffs));
		(*size)++;
		inoffs++;
	} while(--nbits);	
}

static void encode_node(hfm_node_t *node, uint8_t *tree, size_t *size) {
	uint8_t NIL = 0, ONE = 0x80;
	if(node->left == NULL) {
		add_bits(&NIL, 1, tree, size);
		add_bits(&(node->c), 8, tree, size);		
	} else {
		add_bits(&ONE, 1, tree, size);
		encode_node(node->left, tree, size);
		encode_node(node->right, tree, size);
	}
}

uint8_t *encode_tree(hfm_node_t *root, size_t *charsize) {
	uint8_t *tree = malloc(320);
	size_t bitsize;

	bitsize = (*charsize) = 0;
	if(tree == NULL)
		return NULL;

	memset(tree, 0, 320);
	encode_node(root, tree, &bitsize);
	
	*charsize = bitsize / 8;
	*charsize += (bitsize % 8)?1:0;

	return tree;
}

static void walk_tree(hfm_node_t *node, hfm_cdb_t in, hfm_cdb_t *codebook) {
	hfm_cdb_t left = in, right = in;
	uint8_t NIL = 0, ONE = 0x80;

	if(node->left == NULL) {		
		codebook[node->c] = in;
	} else {
		add_bits(&NIL, 1, left.val, &left.len);
		add_bits(&ONE, 1, right.val, &right.len);
		walk_tree(node->left, left, codebook);
		walk_tree(node->right, right, codebook);
	}
}

hfm_cdb_t *make_codebook(hfm_node_t *root) {
	hfm_cdb_t *out, zero;

	if((out = malloc(256 * sizeof(hfm_cdb_t))) == NULL)
		return NULL;	

	zero.len = 0;
	memset(zero.val, 0, 32);

	walk_tree(root, zero, out);

	return out;
}

uint8_t *encode(uint8_t *in, size_t insize, hfm_cdb_t *codebook, size_t *charsize) {
	size_t i, bitsize = 0;
	uint8_t *out;
	*charsize = 0;
	
	for(i = 0; i < insize; i++) 
		bitsize += codebook[in[i]].len;
	
	*charsize = (bitsize / 8) + ((bitsize % 8) ? 1 : 0);

	if((out = malloc(*charsize)) == NULL)
		return NULL;

	memset(out, 0, *charsize);
	bitsize = 0;

	for(i = 0; i < insize; i++)
		add_bits(codebook[in[i]].val, codebook[in[i]].len, out, &bitsize);
		
	return out;
}

void free_tree(hfm_node_t *node) {
	if(node->left)
		free_tree(node->left);
	if(node->right)
		free_tree(node->right);
	free(node);
}