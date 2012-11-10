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

#ifndef HUFFMAN_H_
#define HUFFMAN_H_

typedef struct hfm_node_t {
	int weight;
	uchar c;
	struct hfm_node_t *left, *right, *parent;
} hfm_node_t;

typedef struct {
	uchar val[32];
	size_t len;
} hfm_cdb_t;

#endif