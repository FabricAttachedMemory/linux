/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "../zbridge.h"

/*
 * desbk - write all 1910 book descriptors so that the first 512 are for
 * interleave group 0, the next 512 are for interleave group 1, etc. up
 * to the maximum of 1910.
 */
int fd;

void dump_entry(int offset)
{
	struct desc_ioctl_rep reg_values = {NULL};

	reg_values.offset = offset;
	reg_values.bits.valid = 0;
	reg_values.bits.book = 0;
	reg_values.bits.interleave_group = 0;
	ioctl(fd, DESBK_READ_OFF, &reg_values);
	printf("%d\t0x%lx\t0x%x\t0x%x\t%d\n", offset, reg_values.value,
		reg_values.bits.interleave_group, reg_values.bits.book,
		reg_values.bits.valid);
} /* book_w */

int main(int argc, char *argv[])
{
	char *fname = "/dev/descioctl";
	int offset;
	int bk_count;
	int opt = 0;

	while ((opt = getopt(argc, argv, "b:")) != 1) {
		switch(opt) {
		case 'b':
			bk_count = atoi(optarg);
			break;
		case '?':
		default:
			printf("tabledump [-b <book_count>]\n");
			break;
		}
		break;
	}

	if (bk_count == 0) {
		bk_count = DESBK_VALID_ENTRIES;
	}

	fd = open(fname, O_RDWR);
	if (fd == -1) {
		/* Could not open file. */
		return -1;
	}

	printf("Book Descriptor Table:\n");
	printf("Entry\tValue\t\tInlv\tBook\tValid\n");

	for (offset = 0; offset < bk_count; offset++) {
		dump_entry(offset);
	}

	return 0;
} /* main */
