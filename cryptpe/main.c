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
		/*	Code to hide the debugger detector */
		mov eax, label
		_emit 0xeb		/* EB FF	JMP -1 The Disassembler should lose sync here. */
		jmp eax			/* FF E0	Note the FF coming from the previous instruction. */
		_emit 0x8d
		_emit 0xff

		/* Debugger detector, part I */
label:
		mov eax, fs:[30h]
		mov eax, [eax+68h]

		mov ebx, label2
		_emit 0xeb		/* Same as above, ebx this time, because */
		jmp ebx			/* we use eax to test for the debugger. */
label2:
		and eax, 0x70
		test eax, eax
		je SkipAssign	/* If there is no debugger present, skip */
	}
	num = 0x5c;			/* xor the encoded tree with garbage */
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