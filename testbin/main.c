/*
 * testbin -- Example program for cryptpe
 * (C) 2012-2016 Martin Wolters
 *
 * This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://sam.zoy.org/wtfpl/COPYING for more details.
 */

#include <stdio.h>

int main(int argc, char **argv) {
	int i;
	
	printf("argc = %d\n", argc);
	for(i = 0; i < argc; i++)
		printf("argv[%d] = '%s'\n", i, argv[i]);

	return 0;
}