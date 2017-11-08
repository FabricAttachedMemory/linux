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


/**
 * Author: Justin Vreeland <justin.mcd.vreeland@hpe.com>
 *
 * This tests ioctl interface for zbridge module
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

int fd;
struct desc_ioctl_rep reg_values;

void test_book_w()
{
	reg_values.offset = 5;
	reg_values.value = 0x6;
	ioctl(fd, DESBK_PUT, &reg_values);
	if (reg_values.offset != 5 || reg_values.value != 0x6) {
		printf("Book did not return verified write\n");
	}
} // test_book_w

void test_booklet_w()
{
	reg_values.offset = 5;
	reg_values.value = 0xFFF0000;
	ioctl(fd, DESBL_PUT, &reg_values);
	if (reg_values.offset != 5 || reg_values.value != 0xFFF0000) {
		printf("Booklet did not return verified write\n");
	}
} // test_booklet_w

void test_book_r()
{
	reg_values.offset = 5;
	reg_values.value = 0x65;
	ioctl(fd, DESBK_READ_OFF, &reg_values);
	if (reg_values.offset != 5 || reg_values.value != 0x6) {
		printf("0x%llx\n", reg_values.value);
		printf("Book did not read the proper values\n");
	}
} // test_book_read_r

void test_booklet_r()
{
	reg_values.offset = 5;
	reg_values.value = 0x65;
	ioctl(fd, DESBL_READ_OFF, &reg_values);
	if (reg_values.offset != 5 || reg_values.value != 0xFFF0000) {
		printf("0x%llx\n", reg_values.value);
		printf("Booklet did not read the proper values\n");
	}
} // test_book_read_r

void test_book_read_high()
{
	reg_values.offset = 1000000;
	// check errno for actual value
	if (ioctl(fd, DESBK_READ_OFF, &reg_values) != -1) {
		printf("Book did not produce proper error\n");
	}
} // test_book_read_high

void test_book_read_low()
{
	// Why am I checking and uint for a negative value
	reg_values.offset = -1;
	// check errno for actual value
	if (ioctl(fd, DESBK_READ_OFF, &reg_values) != -1) {
		printf("Book did not produce proper error\n");
	}
} // test_book_read_high

void test_structure_bitfields()
{
	// set valid
	memset(&reg_values, 0, sizeof(struct desc_ioctl_rep));
	reg_values.value = DES_VALID;
	if (reg_values.bits.valid != 0x1) {
		printf("Valid not valid\n");
	}

	memset(&reg_values, 0, sizeof(struct desc_ioctl_rep));
	reg_values.value = DES_RS1;
	if (reg_values.bits.reserved1 != (DES_RS1 >> 1)) {
		printf("Reserved not valid\n");
	}

	memset(&reg_values, 0, sizeof(struct desc_ioctl_rep));
	reg_values.value = DES_BOOKLET;
	if (reg_values.bits.booklet != (DES_BOOKLET >> 16)) {
		printf("Booklet not valid\n");
	}

	memset(&reg_values, 0, sizeof(struct desc_ioctl_rep));
	reg_values.value = DES_BOOK;
	if (reg_values.bits.book != (DES_BOOK >> 33)) {
		printf("Book not valid\n");
	}

	memset(&reg_values, 0, sizeof(struct desc_ioctl_rep));
	reg_values.value = DES_INTERLEAVE;
	if (reg_values.bits.interleave_group != (DES_INTERLEAVE >> 46)) {
		printf("Interleave not valid\n");
	}

	memset(&reg_values, 0, sizeof(struct desc_ioctl_rep));
	reg_values.value = DES_RS2;
	if (reg_values.bits.reserved2 != (DES_RS2 >> 53)) {
		printf("Reserved 2 not valid\n");
	}
}

int main(void)
{
	char *fname = "/dev/descioctl";

	fd = open(fname, O_RDWR);
	if (fd == -1) {
		// error stuff that needs to be accounted for
		return -1;
	}

	test_book_w();
	test_booklet_w();
	test_book_r();
	test_booklet_r();
	test_book_read_high();
	test_book_read_low();
	test_structure_bitfields();

	return 0;
} // main
