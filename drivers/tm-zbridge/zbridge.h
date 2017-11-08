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

#ifndef ZBRIDGE_H
#define ZBRIDGE_H

#include <linux/ioctl.h>
#include <linux/netlink.h> /* copy_from_user() in zbridge_ioctl.c */
#include "zbridge_ioctl.h"

extern int zbridge_verbose;
#define PR_VERBOSE1(a...) { if (zbridge_verbose) pr_info(a); }
#define PR_VERBOSE2(a...) { if (zbridge_verbose > 1) pr_info(a); }
#define PR_VERBOSE3(a...) { if (zbridge_verbose > 2) pr_info(a); }

/* zbridge_environment values */
#define TM_OR_TMAS	1
#define FAME		2
#define SELF_HOSTED	3

#define NUM_ENCLOSURES	8		/* possible enclosures */
#define NUM_NODES	10		/* possible nodes per enclosure */

#define DESCRIPTOR_SIZE 8		/* 64 bits */
#define DESCRIPTORS_PER_TABLE 1910
#define DERSCRIPTORS_TABLES 2		/* 2 tables: book and booklet */
#define NVM_BK_SEC_DEFAULT_ADDR  0x00E00000000

#define DES_VALID	0x0000000000000001
#define DES_RS1		0x000000000000FFFE
#define DES_BOOKLET	0x00000001FFFF0000
#define DES_BOOK	0x00003FFE00000000
#define DES_INTERLEAVE	0x001FC00000000000
#define DES_RS2		0xFFE0000000000000
#define DES_LZA_BK	0x001FFFFE00000000	/* bits [52:16] */
#define DES_LZA_BL	0x001FFFFFFFFF0000	/* bits [52:33] */
#define PA_BK_MASK	0x00000000FFFFFFFF	/* bits [32:0] */
#define PA_BL_MASK	0x000000000000FFFF	/* bits [15:0] */

#define DES_INTERLEAVE_SHIFT	46

/* sysfs */
#define SYSFS_SET "set"
#define SYSFS_PUT "put"

enum {
	DES_A_UNSPEC,
	DES_A_OFFSET,
	DES_A_VALUE,
	__DES_A_MAX,
};

enum DESCS {
	BOOK,
	BOOKLET
};


#define DES_A_MAX (__DES_A_MAX - 1)

enum {
	DES_C_UNSPEC,
	DESBK_C_READ,
	DESBL_C_READ,
	DESBK_C_WRITE,
	DESBL_C_WRITE,
	DES_C_RESPOND,
	__DES_C_MAX,
};

#define DES_C_MAX (__DES_C_MAX - 1)

int desc_sysfs_init(void);
void desc_sysfs_exit(void);

int desc_ioctl_init(void);
void desc_ioctl_exit(void);

uint64_t pa_to_lza(uint64_t);
int zbridge_get_bk_count(void);
uint32_t zbridge_get_bk_size(void);
uint64_t zbridge_get_nvm_bk(void);

void write_desbk_full(int, uint64_t);
void write_desbl_full(int, uint64_t);

void write_full_descriptor(void *addr, int offset, uint64_t value);
uint64_t read_offset_value(void *addr, int offset);

uint64_t read_book_offset_value(int offset);
uint64_t read_booklet_offset_value(int offset);

void zbridge_notify_init(void);
void zbridge_notify_delete(void);

#define INLV_DEFAULT_ADDR 0x00C28000000
#define INLV_SIZE		(8 * 1024)
#define INLV_ENTRIES		128
#define INLV_COPIES		4
#define INLV_COPY_SELECT	18
#define INLV_ENTRY_SELECT	6

/* Interleave Table Entry Register 0 */
#define INLV_VALID		0x0000000000000001	/* valid entry */
#define INLV_WAYS		0x00000000000000F0	/* modules in group */
#define INLV_MODULE_SIZE	0x00000000FFFF0000	/* in G */
#define INLV_NB_INTLV_LO	0x0000000700000000	/* bits from bit 6 */
#define INLV_NB_INTLV_HI	0x0000007000000000	/* bits above nb_size */
#define INLV_NB_SIZE		0x00003F0000000000	/* num LZA bits in size
							 *  of NVM modules
							 */
struct inlv_reg0_bits {
	uint8_t   valid        : 1;
	uint8_t   reserved1    : 3;
	uint8_t   ways         : 4;
	uint8_t   reserved2    : 8;
	uint16_t  module_size  : 16;
	uint8_t   nb_intlv_lo  : 3;
	uint8_t   reserved3    : 1;
	uint8_t   nb_intlv_hi  : 3;
	uint8_t   reserved4    : 1;
	uint8_t   nb_size      : 6;
	uint16_t  reserved5    : 16;
};

union inlv_reg0 {
	struct inlv_reg0_bits	bits;
	uint64_t		data;
};

/* Interleave Table Entry Register 1 */

#define INLV_CID0	0x00000000000007FF	/* destination CID */
#define INLV_CID1	0x0000000007FF0000	/* destination CID */
#define INLV_CID2	0x000007FF00000000	/* destination CID */
#define INLV_CID3	0x07FF000000000000	/* destination CID */

/* For hardcoding the one node case. */
#define DEFAULT_INLV_CID0	0x008
#define DEFAULT_INLV_CID1	0x009
#define DEFAULT_INLV_CID2	0x00A
#define DEFAULT_INLV_CID3	0x00B

struct inlv_reg1_bits {
	uint16_t cid1      : 11;
	uint16_t reserved1 : 5;
	uint16_t cid2      : 11;
	uint16_t reserved2 : 5;
	uint16_t cid3      : 11;
	uint16_t reserved3 : 5;
	uint16_t cid4      : 11;
	uint16_t reserved4 : 5;
};

union inlv_reg1 {
	struct inlv_reg1_bits		bits;
	uint64_t		data;
};

/* Interleave Table Entry Register 2 */

#define INLV_CID4	0x00000000000007FF	/* destination CID */
#define INLV_CID5	0x0000000007FF0000	/* destination CID */
#define INLV_CID6	0x000007FF00000000	/* destination CID */
#define INLV_CID7	0x07FF000000000000	/* destination CID */

struct inlv_reg2_bits {
	uint16_t cid5      : 11;
	uint16_t reserved1 : 5;
	uint16_t cid6      : 11;
	uint16_t reserved2 : 5;
	uint16_t cid7      : 11;
	uint16_t reserved3 : 5;
	uint16_t cid8      : 11;
	uint16_t reserved4 : 5;
};

union inlv_reg2 {
	struct inlv_reg2_bits    bits;
	uint64_t     data;
};

struct inlv_entry {
	union inlv_reg0     reg0;
	union inlv_reg1     reg1;
	union inlv_reg2     reg2;
	uint64_t reserved1;
	uint64_t reserved2;
	uint64_t reserved3;
	uint64_t reserved4;
	uint64_t reserved5;
};

#define FRWL_DEFAULT_ADDR	0x00C18000000
#define FRWL_SIZE		(8 * 1024 * 1024)
#define FRWL_ENTRIES		(1024 * 1024)
#define FRWL_COPIES		4
#define FRWL_COPY_SELECT	6

#define DESBK_DEFAULT_ADDR	0xEFB54000000
#define DESBK_SIZE		(16 * 1024)
#define DESBK_ENTRIES		(2048)
#define DESBK_VALID_ENTRIES	(1906)
#define DESBK_COPIES		4
#define DESBK_COPY_SELECT	18
#define DESBK_ENTRY_SELECT	3

#define DESBL_DEFAULT_ADDR 0xEFB50000000
#define DESBL_SIZE		(16384)
#define DESBL_ENTRIES		(2048)
#define DESBL_VALID_ENTRIES	(2048)
#define DESBL_COPIES		4
#define DESBL_COPY_SELECT	18
#define DESBK_ENTRY_SELECT	3

#define ZBCSR_DEFAULT_ADDR	0xEFB58000000
#define ZBCSR_SIZE		(1024 * 1024)

/* Region within the zbridge CSRs for error registers */
#define ZBCSR_ERR_OFFSET	0xD8000
#define ZBCSR_ERR_SIZE		(4*1024)

#define COMMIT_DEFAULT_ADDR	0xEFB5C000000

#define NVM_BK_DEFAULT_ADDR	0x01600000000
#define DEFAULT_BK_SIZE		(8 * 1024) /* in MB */
#define DEFAULT_BK_COUNT	1906

#define NVM_BKLT_DEFAULT_ADDR	0xEFB68000000
#define NVM_BKLT_SIZE		128 /* in MB */

/* ZBCSR register offsets */
#define NVM_MAP_FUNC_ID			0x0000
#define NVM_MAP_FUNC_CLASS		0x0008
#define NVM_MAP_BCS			0x0020
#define NVM_MAP_ERR_PRI_STATUS		0x0080
#define NVM_MAP_ERR_ALL_STATUS		0x0088
#define NVM_MAP_ERR_ENABLE		0x00A8
#define NVM_MAP_CONTAINMENT_STATE0	0x0400
#define NVM_MAP_CONTAINMENT_STATE1	0x0408
#define NVM_MAP_CONTAINMENT_STATE2	0x0410
#define NVM_MAP_CONTAINMENT_STATE3	0x0418
#define NVM_MAP_ERR_HFELOG0		0x0450
#define NVM_MAP_ERR_HFELOG1		0x0458

/* bitmask for error types */
#define NRE_UPGRADE		0x0000000000000001
#define HWE_SEEN		0x0000000000000002
#define HWA_SEEN		0x0000000000000004
#define HFE_WR_INVALID		0x0000000000000008
#define HFE_WR_FWBLOCKED	0x0000000000000010
#define HFE_SIZE_ILLEGAL	0x0000000000000020
#define HFE_RD_INVALID		0x0000000000000040
#define HFE_RD_FWBLOCKED	0x0000000000000080
#define HFE_MODE_ILLEGAL	0x0000000000000100
#define HFE_GZ_WR_NFEE_COH	0x0000000000000200
#define HFE_GZ_UP		0x0000000000000400
#define HFE_GZ_RD_NFEE_COH	0x0000000000000800
#define HFE_GZ_PW		0x0000000000001000
#define HFE_GZ_PME_NC		0x0000000000002000
#define HFE_GZ_PME_COH		0x0000000000004000
#define HFE_GZ_NFEE_NC		0x0000000000008000
#define HFE_GZ_ICE_NC		0x0000000000010000
#define HFE_GZ_ICE_COH		0x0000000000020000
#define HFE_GZ_IC_NC		0x0000000000040000
#define HFE_GZ_IC_COH		0x0000000000080000
#define HFE_GZ_FEE_NC		0x0000000000100000
#define HFE_GZ_FEE_COH		0x0000000000200000
#define HFE_GZ_CEC_NC		0x0000000000400000
#define HFE_GZ_CEC_COH		0x0000000000800000
#define HFE_GZ_AE_WR		0x0000000001000000
#define HFE_GZ_AE_RD		0x0000000002000000
#define HFE_CONTAINED		0x0000000004000000
#define NRE_GZ_UR		0x0000000008000000
#define NRE_GZ_MP		0x0000000010000000

/* desbk_get_slot values for needs_eviction return */
#define NO_EVICTION_SLOT_VACANT ((uint64_t)-1)
#define NO_EVICTION_SLOT_FILLED   ((uint64_t)-2)

#define ZBCOMMIT_MAJOR	251
#define ZBCOMMIT_MINOR	0

int desbk_get_slot(uint64_t, void *, int *, uint64_t *);
int desbk_put_slot(int, uint64_t, void *);
int desbl_get_slot(uint64_t, void *, int *, uint64_t *);
int desbl_put_slot(int, uint64_t, void *);
int desbk_read_slot(int, void *, uint64_t *);
int desbl_read_slot(int, void *, uint64_t *);
int test_desbk_get_put(void);
void test_walk_checkerboard(void);
int zbridge_init_des(int, int);
void zbridge_exit_des(void);
int zbridge_get_environment(void);
void dump_error_regs(void);
uint64_t zbridge_get_containment(int reg_num);
int zbridge_pa_to_process(uint64_t start_addr, uint64_t size);
int desbk_find_ilv(int ilv);
void zbridge_write_error(void);
#ifdef ZAP_IOCTL
int zbridge_zap_desbk(void);
int zbridge_zap_desbl(void);
int zbridge_get_allow_zap(void);
#endif /* ZAP_IOCTL */
#endif /* ZBRIDGE_H */
