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
#include <Windows.h>

#include "bintable.h"
#include "rlevel.h"
#include "huffman_dec.h"
#include "loader.h"

#include "..\shared\salsa20.h"

int main(int argc, char **argv) {
	salsa20_ctx_t salsa20_ctx;
	uint8_t *salsa20_buf, *decoded, rlevel = detrlvl();
	int i;
	hfm_node_t *root;
	int retval;

	salsa20_ctx = salsa20_init(key, nonce, SALSA20_KEY_SIZE);

	for(i = 0; i < sizeof(tree); i++) {
		if(!(i % SALSA20_BLOCK_SIZE))
			salsa20_buf = salsa20_gen_block(&salsa20_ctx);
		tree[i] ^= salsa20_buf[i % SALSA20_BLOCK_SIZE] ^ rlevel;
	}
	root = reconstruct_tree(tree);

	for(i = 0; i < sizeof(binary); i++) {
		if(!(i % SALSA20_BLOCK_SIZE))
			salsa20_buf = salsa20_gen_block(&salsa20_ctx);
		binary[i] ^= salsa20_buf[i % SALSA20_BLOCK_SIZE];
	}

	decoded = decode(binary, root, file_size);
	free_tree(root);

	for(i = 0; i < sizeof(binary); i++)
		if(2 * i + rlevel) decoded[1] ^= rlevel;

	retval = load(decoded, argc, argv);
	
	free(decoded);
	return retval;
}