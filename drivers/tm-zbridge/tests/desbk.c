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
struct desc_ioctl_rep reg_values = {NULL};

void book_w(int offset, int interleave, int book)
{
	reg_values.offset = -1;
	reg_values.needs_eviction = (uint64_t *)-1;
	reg_values.bits.valid = 1;
	reg_values.bits.book = book;
	reg_values.bits.interleave_group = interleave;
	ioctl(fd, DESBK_PUT, &reg_values);
	reg_values.offset = offset;
	reg_values.bits.valid = 0;
	reg_values.bits.book = 0;
	reg_values.bits.interleave_group = 0;
	ioctl(fd, DESBK_READ_OFF, &reg_values);
	if (reg_values.bits.book != book ||
		reg_values.bits.interleave_group != interleave ||
		reg_values.bits.valid != 1) {
		printf("Book did not return verified write: offset=%d, book=%d (should be %d), interleave=%d (should be %d), valid bit is %d\n",
			offset, reg_values.bits.book, book,
			reg_values.bits.interleave_group, interleave,
			reg_values.bits.valid);
	}
} /* book_w */

int main(void)
{
	char *fname = "/dev/descioctl";
	int interleave;
	int book;
	int offset = 0;


	fd = open(fname, O_RDWR);
	if (fd == -1) {
		/* Could not open file. */
		return -1;
	}

	for (interleave = 0; interleave < 4; interleave++) {
		for (book = 0; book < 512; book++) {
			book_w(offset, interleave, book);
			if (++offset >= DESBK_VALID_ENTRIES)
				return 0;
		}
	}
	return 0;
} /* main */
