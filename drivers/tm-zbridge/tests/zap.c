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
 * zap - reset the book descriptors to zero.
 */

int main(int argc, char *argv[])
{
	int fd;
	char *fname = "/dev/descioctl";
	struct desc_ioctl_rep reg_values = {NULL};

	fd = open(fname, O_RDWR);
	if (fd == -1) {
		/* Could not open file. */
		return -1;
	}

	ioctl(fd, DESBK_ZAP, &reg_values);

	return 0;
} /* main */
