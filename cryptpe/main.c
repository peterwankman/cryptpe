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

#include <Windows.h>

#include "bintable.h"
#include "huffman_dec.h"
#include "loader.h"

#include "..\shared\types.h"
#include "..\shared\rc4.h"

int main(int argc, char **argv) {
	rc4_ctx_t rc4_ctx;
	uchar rc4_buf[320], *decoded, num = 0;
	int i;
	hfm_node_t *root;

#ifndef _DEBUG
	__asm {
		mov eax, fs:[30h]
		mov eax, [eax+68h]
		and eax, 0x70
		test eax, eax
		je SkipAssign
	}
	num = 0x5c;
#endif

SkipAssign:
	rc4_ctx = rc4_init(rc4_key, RC4_KEY_SIZE);
	rc4_drop(3072, &rc4_ctx);

	rc4_gen(rc4_buf, 320, &rc4_ctx);
	for(i = 0; i < sizeof(tree); i++)
		tree[i] ^= rc4_buf[i] ^ num;
	root = reconstruct_tree(tree);

	for(i = 0; i < sizeof(binary); i++) {
		if(!(i % sizeof(rc4_buf)))
			rc4_gen(rc4_buf, sizeof(rc4_buf), &rc4_ctx);
		binary[i] ^= rc4_buf[i % sizeof(rc4_buf)];		
	}

	decoded = decode(binary, root, file_size);
	load(decoded, argc, argv);

	free(decoded);
	free_tree(root);
	return EXIT_SUCCESS;
}