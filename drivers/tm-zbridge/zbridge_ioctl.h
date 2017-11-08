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

#ifndef ZBRIDGE_IOCTL_H
#define ZBRIDGE_IOCTL_H

struct desc_ioctl_rep {
	int offset;
	uint64_t needs_eviction;	   /* LZA that needs eviction */
	union {
		uint64_t value;
		struct bits {
			uint64_t valid : 1;
			uint64_t reserved1 : 15;		/* 16 */
			uint64_t booklet : 17;			/* 33 */
			uint64_t book : 13;			/* 46 */
			uint64_t interleave_group : 7;		/* 53 */
			uint64_t reserved2 : 11;		/* 64 */
		} bits;
	};
};

/* Use the ZAP_IOCTL define to identify the temporary feature */
#define ZAP_IOCTL 1

#define MY_MAGIC '!'
#define DESBK_READ_OFF _IOWR(MY_MAGIC, 0, struct desc_ioctl_rep)
#define DESBL_READ_OFF _IOWR(MY_MAGIC, 1, struct desc_ioctl_rep)
#define DESBK_PUT _IOWR(MY_MAGIC, 2, struct desc_ioctl_rep)
#define DESBL_PUT _IOWR(MY_MAGIC, 3, struct desc_ioctl_rep)
#define ZB_COMMIT _IOWR(MY_MAGIC, 4, void *)
#ifdef ZAP_IOCTL
#define DESBK_ZAP _IOWR(MY_MAGIC, 5, struct desc_ioctl_rep)
#define DESBL_ZAP _IOWR(MY_MAGIC, 6, struct desc_ioctl_rep)
#endif /* ZAP_IOCTL */

#define COMMIT_SIZE		(8 * 1024 * 1024)
#define COMMIT_REGISTER_SIZE	(64 * 1024)
#define COMMIT_HSR_MASK		0x000000000000FFFF

#endif /* ZBRIDGE_IOCTL_H */
