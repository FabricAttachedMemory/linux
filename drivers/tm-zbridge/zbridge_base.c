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

/*
 * Module to initialize and acces Zbridge tables
 */

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/cdev.h>

#include "zbridge.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hewlett Packard Enterprise");
MODULE_DESCRIPTION("Module to access Zbridge tables");

static int verbose;
int zbridge_verbose;
module_param(verbose, int, S_IRUGO);
MODULE_PARM_DESC(verbose, "Amount of printk info. 0 is quiet; 3 is max. (0)");

static bool init_zero = 1;
module_param(init_zero, bool, S_IRUGO);
MODULE_PARM_DESC(init_zero, " Zero table before using (T)");

static bool init_frwl;
module_param(init_frwl, bool, S_IRUGO);
MODULE_PARM_DESC(init_frwl, " Initialze firewall table before using (F)");

static bool init_inlv;
module_param(init_inlv, bool, S_IRUGO);
MODULE_PARM_DESC(init_inlv, " Initialze interleave table. Default is 4T/node. True programs 1T/node (F)");

static bool init_desbk;
module_param(init_desbk, bool, S_IRUGO);
MODULE_PARM_DESC(init_desbk, " Initialze Descriptor Book table to sequential books across nodes. Done after init_zero, if init_zero is specified. (F)");

static bool self_test;
module_param(self_test, bool, S_IRUGO);
MODULE_PARM_DESC(self_test, " Run self-test at initializtion time (F)");

#ifdef ZAP_IOCTL
static bool allow_zap;
module_param(allow_zap, bool, S_IRUGO);
MODULE_PARM_DESC(allow_zap, " Allow reset of descriptors for demos (F)");
#endif /* ZAP_IOCTL */

static ulong zbcsr;
module_param(zbcsr, ulong, S_IRUGO);
MODULE_PARM_DESC(zbcsr, " Location of the Zbridge CSRs (0)");

static ulong desbk;
module_param(desbk, ulong, S_IRUGO);
MODULE_PARM_DESC(desbk, " Location of the descriptor book table (0)");

static ulong desbl;
module_param(desbl, ulong, S_IRUGO);
MODULE_PARM_DESC(desbl, " Location of the descriptor booklet table (0)");

static ulong frwl;
module_param(frwl, ulong, S_IRUGO);
MODULE_PARM_DESC(frwl, " Location of the firewall table (0)");

static ulong inlv;
module_param(inlv, ulong, S_IRUGO);
MODULE_PARM_DESC(inlv, " Location of the interleave table (0)");

static ulong nvm_bk;
module_param(nvm_bk, ulong, S_IRUGO);
MODULE_PARM_DESC(nvm_bk, " Location of the apertures books (0)");

static uint bk_size;
module_param(bk_size, uint, S_IRUGO);
MODULE_PARM_DESC(bk_size, " Size of books in M (0)");

static uint bk_count;
module_param(bk_count, uint, S_IRUGO);
MODULE_PARM_DESC(bk_count, " Number of books in entire aperture space e.g. 1906 (0)");

static ulong nvm_bklt;
module_param(nvm_bklt, ulong, S_IRUGO);
MODULE_PARM_DESC(nvm_bklt, " Location of the apertures booklets (0)");

static ulong nvm_bklt_size;
module_param(nvm_bklt_size, ulong, S_IRUGO);
MODULE_PARM_DESC(nvm_bklt_size, " Size of booklet region in M (0)");

static ulong commit;
module_param(commit, ulong, S_IRUGO);
MODULE_PARM_DESC(commit, " Location of Zbridge Write Commit/Containment HSR (0)");

uint64_t current_commit_hsr;
uint64_t current_contain0;
uint64_t current_contain1;
uint64_t current_contain2;
uint64_t current_contain3;
static void *desbk_table;
static void *desbk_nonsec_table;
static void *desbl_table;
static void *inlv_table;
static void *frwl_table;
static void *commit_table;
static void *zbmap_table;
static int acpi_zbridge;
static int zbridge_environment;

static int zbridge_acpi_add(struct acpi_device *);
static int zbridge_acpi_remove(struct acpi_device *);

struct zbcommit_dev {
	int __iomem *membase;
	struct cdev cdev;
};

static const struct acpi_device_id zbridge_device_ids[] = {
	{"HWPE0002", 0},
	{"", 0},
};
MODULE_DEVICE_TABLE(acpi, zbridge_device_ids);

static struct acpi_driver zbridge_acpi_driver = {
	.name = "zbridge",
	.ids = zbridge_device_ids,
	.ops = {
		.add = zbridge_acpi_add,
		.remove = zbridge_acpi_remove,
		},
};

/*
 * pa_to_lza converts a physical address in the aperture region to
 * the LZA (logical z-address). If the given pa is invalid (not in
 * the aperture region, it returns -1.
 */
uint64_t pa_to_lza(uint64_t pa)
{
	uint64_t lza;
	uint64_t desc_lza;
	uint64_t pa_low;
	int desc_entry;
	uint64_t m_bk_size;
	uint64_t m_bklt_size;

	/* Compute book and booklet aperture region size in MB. */
	m_bk_size = (uint64_t) bk_size*(1024*1024);
	m_bklt_size = (uint64_t) nvm_bklt_size*(1024*1024);
	PR_VERBOSE3("pa_to_lza pa = 0x%llx nvm_bk = 0x%lx nvm_bk end = 0x%llx bk_size %d bk_count %d m_bk_size %ld\n",
		pa, (long) nvm_bk, (nvm_bk + (m_bk_size*bk_count)),
		bk_size, bk_count, (long int) m_bk_size);
	/* is this pa in the book aperture region? */
	if ((pa >= (uint64_t) nvm_bk) &&
		(pa < (nvm_bk + (m_bk_size*bk_count)))) {

		/* Find the corresponding descriptor */
		desc_entry =  (pa - nvm_bk) / m_bk_size;

		/* read the descriptor */
		desc_lza = read_book_offset_value(desc_entry);
		PR_VERBOSE3("read_book_offset_value(%d) returns 0x%lx\n",
			desc_entry, (unsigned long) desc_lza);
		if (!(desc_lza & DES_VALID)) {
			/* this descriptor is not valid */
			PR_VERBOSE1("Book descriptor %d not valid\n",
				desc_entry);
			return (uint64_t)-1;
		}

		/* mask out everything but the LZA in bits 52:33 */
		desc_lza = desc_lza & DES_LZA_BK;

		/* mask out everything but PA[32:0] */
		pa_low = pa & PA_BK_MASK;

		/* LZA[52:33] = desc.LZA[52:33]. LZA[32:0] = PA[32:0]. */
		lza = desc_lza | pa_low;

		return lza;
	}
	/* is this pa in the booklet aperture region? */
	if ((pa >= (uint64_t) nvm_bklt) &&
		(pa < (nvm_bklt + m_bklt_size))) {

		/* Find the corresponding descriptor */
		desc_entry =  (pa - nvm_bklt) / m_bklt_size;

		/* read the descriptor */
		desc_lza = read_booklet_offset_value(desc_entry);
		PR_VERBOSE3("read_booklet_offset_value(%d) returns 0x%lx\n",
			desc_entry, (unsigned long) desc_lza);
		if (!(desc_lza & DES_VALID)) {
			/* this descriptor is not valid */
			PR_VERBOSE3("booklet descriptor not valid\n");
			return (uint64_t)-1;
		}

		/* mask out everything but the LZA in bits 52:16 */
		desc_lza = desc_lza & DES_LZA_BL;

		/* mask out everything but PA[15:0] */
		pa_low = pa & PA_BL_MASK;

		/* LZA[52:16] = des.LZA[52:16]. LZA[15:0] = PA[15:0]. */
		lza = desc_lza | pa_low;

		return lza;
	}
	/*
	 * ERS algorithm has a comment that in this else case forward
	 * request with PA to Zbridge Register/CSR address decoder.
	 */
	return (uint64_t) -1;
}
EXPORT_SYMBOL(pa_to_lza);

int zbridge_get_bk_count(void)
{
	return bk_count;
}

uint32_t zbridge_get_bk_size(void)
{
	/* in M */
	return bk_size;
}

uint64_t zbridge_get_nvm_bk(void)
{
	return nvm_bk;
}

#ifdef ZAP_IOCTL
int zbridge_get_allow_zap(void)
{
	return allow_zap;
}
#endif /* ZAP_IOCTL */

int zbridge_get_environment(void)
{
	return zbridge_environment;
}

static void print_error_detail(uint64_t reg)
{
	if (reg & NRE_UPGRADE)
		PR_VERBOSE2("\t\tnre_upgrade+\n");
	if (reg & HWE_SEEN)
		PR_VERBOSE2("\t\thwe_seen+\n");
	if (reg & HWA_SEEN)
		PR_VERBOSE2("\t\thwa_seen+\n");
	if (reg & HFE_WR_INVALID)
		PR_VERBOSE2("\t\thfe_wr_invalid+\n");
	if (reg & HFE_WR_FWBLOCKED)
		PR_VERBOSE2("\t\thfe_wr_fwblocked+\n");
	if (reg & HFE_SIZE_ILLEGAL)
		PR_VERBOSE2("\t\thfe_size_illegal+\n");
	if (reg & HFE_RD_INVALID)
		PR_VERBOSE2("\t\thfe_rd_invalid+\n");
	if (reg & HFE_RD_FWBLOCKED)
		PR_VERBOSE2("\t\thfe_rd_fwblocked+\n");
	if (reg & HFE_MODE_ILLEGAL)
		PR_VERBOSE2("\t\thfe_mode_illegal+\n");
	if (reg & HFE_GZ_WR_NFEE_COH)
		PR_VERBOSE2("\t\thfe_gz_wr_nfee_coh+\n");
	if (reg & HFE_GZ_UP)
		PR_VERBOSE2("\t\thfe_gz_up+\n");
	if (reg & HFE_GZ_RD_NFEE_COH)
		PR_VERBOSE2("\t\thfe_gz_rd_nfee_coh+\n");
	if (reg & HFE_GZ_PW)
		PR_VERBOSE2("\t\thfe_gz_pw+\n");
	if (reg & HFE_GZ_PME_NC)
		PR_VERBOSE2("\t\thfe_gz_pme_nc+\n");
	if (reg & HFE_GZ_PME_COH)
		PR_VERBOSE2("\t\thfe_gz_pme_coh+\n");
	if (reg & HFE_GZ_NFEE_NC)
		PR_VERBOSE2("\t\thfe_gz_nfee_nc+\n");
	if (reg & HFE_GZ_ICE_NC)
		PR_VERBOSE2("\t\thfe_gz_ice_nc+\n");
	if (reg & HFE_GZ_ICE_COH)
		PR_VERBOSE2("\t\thfe_gz_ice_coh+\n");
	if (reg & HFE_GZ_IC_NC)
		PR_VERBOSE2("\t\thfe_gz_ic_nc+\n");
	if (reg & HFE_GZ_IC_COH)
		PR_VERBOSE2("\t\thfe_gz_ic_coh+\n");
	if (reg & HFE_GZ_FEE_NC)
		PR_VERBOSE2("\t\thfe_gz_fee_nc+\n");
	if (reg & HFE_GZ_FEE_COH)
		PR_VERBOSE2("\t\thfe_gz_fee_coh+\n");
	if (reg & HFE_GZ_CEC_NC)
		PR_VERBOSE2("\t\thfe_gz_cec_nc+\n");
	if (reg & HFE_GZ_CEC_COH)
		PR_VERBOSE2("\t\thfe_gz_cec_coh+\n");
	if (reg & HFE_GZ_AE_WR)
		PR_VERBOSE2("\t\thfe_gz_ae_wr+\n");
	if (reg & HFE_GZ_AE_RD)
		PR_VERBOSE2("\t\thfe_gz_ae_rd+\n");
	if (reg & HFE_CONTAINED)
		PR_VERBOSE2("\t\thfe_contained+\n");
	if (reg & NRE_GZ_UR)
		PR_VERBOSE2("\t\tnre_gz_ur+\n");
	if (reg & NRE_GZ_MP)
		PR_VERBOSE2("\t\tnre_gz_mp+\n");
}

void dump_error_regs(void)
{
	uint64_t func_id;
	uint64_t func_class;
	uint64_t bcs;
	uint64_t enable;
	uint64_t pri_status;
	uint64_t all_status;
	uint64_t contain0;
	uint64_t contain1;
	uint64_t contain2;
	uint64_t contain3;
	uint64_t hfelog0;
	uint64_t hfelog1;

	func_id = readq((uint64_t *)(zbmap_table+NVM_MAP_FUNC_ID));
	func_class = readq((uint64_t *)(zbmap_table+NVM_MAP_FUNC_CLASS));
	bcs = readq((uint64_t *)(zbmap_table+NVM_MAP_BCS));
	enable = readq((uint64_t *)(zbmap_table+NVM_MAP_ERR_ENABLE));
	pri_status = readq((uint64_t *)(zbmap_table+NVM_MAP_ERR_PRI_STATUS));
	all_status = readq((uint64_t *)(zbmap_table+NVM_MAP_ERR_ALL_STATUS));
	contain0 = readq((uint64_t *)(zbmap_table+NVM_MAP_CONTAINMENT_STATE0));
	contain1 = readq((uint64_t *)(zbmap_table+NVM_MAP_CONTAINMENT_STATE1));
	contain2 = readq((uint64_t *)(zbmap_table+NVM_MAP_CONTAINMENT_STATE2));
	contain3 = readq((uint64_t *)(zbmap_table+NVM_MAP_CONTAINMENT_STATE3));
	hfelog0 = readq((uint64_t *)(zbmap_table+NVM_MAP_ERR_HFELOG0));
	hfelog1 = readq((uint64_t *)(zbmap_table+NVM_MAP_ERR_HFELOG1));

	PR_VERBOSE1("Error Register Dump\n");
	PR_VERBOSE1("\tNVM_MAP_FUNC_ID\t0x%llx\n", func_id);
	PR_VERBOSE1("\tNVM_MAP_FUNC_CLASS\t0x%llx\n", func_class);
	PR_VERBOSE1("\tNVM_MAP_BCS\t0x%llx\n", bcs);
	PR_VERBOSE1("\tNVM_MAP_ERR_ENABLE\t0x%llx\n", enable);

	if (zbridge_verbose > 1)
		print_error_detail(enable);

	PR_VERBOSE1("\tNVM_MAP_ERR_PRI_STATUS\t0x%llx\n", pri_status);

	if (zbridge_verbose > 1)
		print_error_detail(pri_status);

	PR_VERBOSE1("\tNVM_MAP_ERR_ALL_STATUS\t0x%llx\n", all_status);

	if (zbridge_verbose > 1)
		print_error_detail(all_status);

	PR_VERBOSE1("\tNVM_MAP_CONTAINMENT_STATE0\t0x%llx\n", contain0);
	PR_VERBOSE1("\tNVM_MAP_CONTAINMENT_STATE1\t0x%llx\n", contain1);
	PR_VERBOSE1("\tNVM_MAP_CONTAINMENT_STATE2\t0x%llx\n", contain2);
	PR_VERBOSE1("\tNVM_MAP_CONTAINMENT_STATE3\t0x%llx\n", contain3);
	PR_VERBOSE1("\tNVM_MAP_ERR_HFELOG0\t0x%llx\n", hfelog0);
	PR_VERBOSE1("\tNVM_MAP_ERR_HFELOG1\t0x%llx\n", hfelog1);
}
EXPORT_SYMBOL(dump_error_regs);

/*
 * Write all four copies of the descriptor. The physical address bits
 * 19:18 select the copy of the descriptor table within the SOC 64M address
 * range for DESBK from 0xEFB_5400_0000 to 0xEFB_57FF_FFFF.
*/
void write_full_descriptor(void *addr, int offset, uint64_t value)
{
	int copy;

	uint64_t *target_addr;

	for (copy = 0; copy < DESBK_COPIES; copy++) {
		target_addr = (uint64_t *)(
				(uint64_t) addr +
				(offset * sizeof(uint64_t)) +
				(copy << DESBK_COPY_SELECT));

		writeq(value, target_addr);
	}
}

uint64_t zbridge_get_containment(int reg_num)
{
	switch (reg_num) {
	case 0:
		return readq((uint64_t *)(zbmap_table +
				NVM_MAP_CONTAINMENT_STATE0));
	case 1:
		return readq((uint64_t *)(zbmap_table +
				NVM_MAP_CONTAINMENT_STATE1));
	case 2:
		return readq((uint64_t *)(zbmap_table +
				NVM_MAP_CONTAINMENT_STATE2));
	case 3:
		return readq((uint64_t *)(zbmap_table +
				NVM_MAP_CONTAINMENT_STATE3));
	default: 
		PR_VERBOSE1("zbridge_get_containment passed bad arg %d\n", reg_num);
	}
	return (uint64_t)-1;
}

int check_WRITE_COMMIT(void)
{
	void *hsr_register;
	uint64_t commit_hsr;

	/* Issue DSB barrier isntruction before the HSR read */
#if defined(__aarch64__)
	dsb(sy);
#endif

	/*
	 * Load the HA_WRITE_COMMIT_CONTAINMENT_HSR. The "& 0x7f" is to
	 * make sure the cpu count does not excede 128 which is the number
	 * of Hardware engines for the HSR.
	 */
	hsr_register = commit_table + ((get_cpu() & 0x7f) *
			COMMIT_REGISTER_SIZE);
	commit_hsr = readq(hsr_register) & COMMIT_HSR_MASK;

	/* The 16 bit counter wraps, so just look for a different value. */
	if (commit_hsr != current_commit_hsr) {
		/* We have an error. */
		uint64_t contain0;
		uint64_t contain1;
		uint64_t contain2;
		uint64_t contain3;

		PR_VERBOSE3("current commit_hsr is %ld commit_hsr for cpu %d is %ld\n",
			(long)current_commit_hsr, get_cpu(), (long)commit_hsr);
		/* Update the current state */
		current_commit_hsr = commit_hsr;

		/* check to interleave containment CSR to see which inlv */
		contain0 = readq((uint64_t *)(zbmap_table +
				NVM_MAP_CONTAINMENT_STATE0));
		contain1 = readq((uint64_t *)(zbmap_table +
				NVM_MAP_CONTAINMENT_STATE1));
		contain2 = readq((uint64_t *)(zbmap_table +
				NVM_MAP_CONTAINMENT_STATE2));
		contain3 = readq((uint64_t *)(zbmap_table +
				NVM_MAP_CONTAINMENT_STATE3));

		if (current_contain0 != contain0) {
			PR_VERBOSE1("contain0 changed from 0x%llx to 0x%llx\n",
				current_contain0, contain0);
			current_contain0 = contain0;
		}
		if (current_contain1 != contain1) {
			PR_VERBOSE1("contain1 changed from 0x%llx to 0x%llx\n",
				current_contain1, contain1);
			current_contain1 = contain1;
		}
		if (current_contain2 != contain2) {
			PR_VERBOSE1("contain2 changed from 0x%llx to 0x%llx\n",
				current_contain2, contain2);
			current_contain2 = contain2;
		}
		if (current_contain3 != contain3) {
			PR_VERBOSE1("contain3 changed from 0x%llx to 0x%llx\n",
				current_contain3, contain3);
			current_contain3 = contain3;
		}
		return 1;
	}
	return 0;
}

void write_desbk_full(int offset, uint64_t value)
{
	if (check_WRITE_COMMIT())
		PR_VERBOSE1("NVM in containment!\n");

	/* Write the new descriptor */
	write_full_descriptor(desbk_nonsec_table, offset, value);

	if (check_WRITE_COMMIT())
		PR_VERBOSE1("NVM in containment!\n");
}

void write_desbl_full(int offset, uint64_t value)
{
	write_full_descriptor(desbl_table, offset, value);
}

/*
 * These functions mask out the values other than what the function
 * is writing.
*/
void write_desbk_entry(int offset, uint64_t value)
{
	uint64_t new_val = 0;
	/* Restricting the fields should not be needed but it's an inexpensive
	 * check and cycles are cheap
	 * fairly sure Linux already has bit manipulation routines
	 *	clear fields                    restrict fields
	 *	this should be better tested
	 */
	new_val = (((uint64_t *)desbk_nonsec_table)[offset] & ~DES_BOOK)
		| (value & DES_BOOK);

	write_full_descriptor(desbk_nonsec_table, offset, new_val);
}

void write_desbl_entry(int offset, uint64_t value)
{
	uint64_t new_val = 0;

	new_val = (((uint64_t *)desbl)[offset] & ~DES_BOOKLET)
		| (value & DES_BOOKLET);

	write_full_descriptor(desbl_table, offset, new_val);
}

static void write_valid_descript_entry(void *addr, int offset, uint64_t value)
{
	uint64_t new_val = 0;

	new_val = (((uint64_t *)addr)[offset] & ~DES_VALID)
		| (value & DES_VALID);

	write_full_descriptor(addr, offset, new_val);
}

/* should the following 3 functions be macros */
uint64_t read_offset_value(void *addr, int offset)
{
	return (readq(addr+(uint64_t)(offset * sizeof(uint64_t))));
}

uint64_t read_book_offset_value(int offset)
{
	return read_offset_value(desbk_nonsec_table, offset);
}

uint64_t read_booklet_offset_value(int offset)
{
	return read_offset_value(desbl_table, offset);
}

/* Check for duplicates */
static int check_duplicates(void *addr, uint64_t value)
{
	size_t i;

	for (i = 0; i < bk_count; i++)
		if (value == ((uint64_t *)addr)[i])
			return -EINVAL;

	return 0;
}

/* Check to make sure someone isn't trying to write an in appropriate value */
static int check_value(uint64_t value)
{
	int ret = 0;

	ret |= check_duplicates(desbk_table, value);
	ret |= check_duplicates(desbl_table, value);

	return ret;
}

int des_init(void)
{
	int ret;

	if (!bk_size) {
		bk_size = DEFAULT_BK_SIZE;
		PR_VERBOSE1("NVM book size set to SoC default address\n");
	}
	if (!bk_count) {
		bk_count = DEFAULT_BK_COUNT;
		PR_VERBOSE1("NVM book count set to SoC default\n");
	}

	/* If no parameter set, use the SoC default address. */
	if (!desbk)
		desbk = DESBK_DEFAULT_ADDR;
	if (!desbl)
		desbl = DESBL_DEFAULT_ADDR;

	PR_VERBOSE1("des: bk_size %d bk_count %d\n", bk_size, bk_count);

	desbk_table = ioremap(desbk, (((DESBK_COPIES-1) << DESBK_COPY_SELECT)
				+ DESBK_SIZE));
	desbl_table = ioremap(desbl, (((DESBL_COPIES-1) << DESBL_COPY_SELECT)
				+ DESBL_SIZE));

	if (!desbk_table || !desbl_table) {
		pr_err("Descriptor table mapping failed\n");
		ret = -EINVAL;
		goto end;
	}

	/* The non secure descriptors start at the 5th entry. */
	desbk_nonsec_table = desbk_table + 0x20;

	PR_VERBOSE2("des: desbk 0x%p, desbl 0x%p, ioremap size %d",
		desbk_table, desbl_table,
		(((DESBK_COPIES-1) << DESBK_COPY_SELECT) + DESBK_SIZE));

	ret = desc_sysfs_init();
	if (ret) {
		PR_VERBOSE1("Sysfs creation failed\n");
		goto clean_sysfs;
	}

	ret = desc_ioctl_init();
	if (ret) {
		pr_err("Registering the ioctl device failed with %d\n", ret);
		goto clean_ioctl;
	}

	goto end;

clean_ioctl:

	desc_ioctl_exit();

clean_sysfs:

	desc_sysfs_exit();

end:
	return ret;

}


/* initialize the firewall table to read write access for all. */
int frwl_init(void)
{
	int ret = 0;

	/* Check for null memory address */
	if (!frwl) {
		PR_VERBOSE1("Firewall table location set to SoC default address\n");
		frwl = FRWL_DEFAULT_ADDR;
	}

	/*
	 * There are 4 copies of the 8M firewall table in the MFT.
	 * The layout of the firewall copies is interleaved. So
	 * ioremap the 32M space.
	 */
	frwl_table = ioremap(frwl, (32*1024*1024));

	if (!frwl_table) {
		pr_err("Firewall table Mapping failed\n");
		ret = -EINVAL;
		goto end;
	}

	PR_VERBOSE2("zbridge: frwl_table %p frwl_table size=%d\n", frwl_table,
		(32*1024*1024));

	if (init_frwl) {
		uint64_t entry;
		uint64_t copy;
		uint64_t *target;

		for (entry = 0; entry < FRWL_ENTRIES; entry++) {
			for (copy = 0; copy < FRWL_COPIES; copy++) {
				/* Enable read/write access to all Books */
				target = (uint64_t *) ((uint64_t)frwl_table |
					((entry & 0x00000007) << 3) |
					((entry & 0x000FFFF8) << 5) |
					(copy << FRWL_COPY_SELECT));
				writeq(0x3, target); /* means RW for all */
			}
		}
	}
end:
	return ret;
}

static struct inlv_entry inlv_setup[INLV_ENTRIES];

int inlv_init(void)
{
	int ret = 0, i;
	int node, enclosure;
	uint64_t entry;
	uint64_t copy;
	uint64_t *target_addr;


	/* Check for null memory address */
	if (!inlv) {
		PR_VERBOSE1("Interleave table location set to default SoC address\n");
		inlv = INLV_DEFAULT_ADDR;
	}

	inlv_table = ioremap(inlv, (((INLV_COPIES-1) << INLV_COPY_SELECT)
				+ INLV_SIZE));

	if (!inlv_table) {
		pr_err("Interleave table Mapping failed\n");
		ret = -EINVAL;
		goto end;
	}

	PR_VERBOSE1("zbridge: inlv_table %p\n", inlv_table);

	/* Zero out the setup array */
	memset(&inlv_setup, 0x00, (sizeof(*inlv_setup) * INLV_ENTRIES));

	if (!init_inlv)
		goto end;

	/* Create intlereave entry for each enclosure and node. */
	for (enclosure = 0; enclosure < NUM_ENCLOSURES; enclosure++) {
		for (node = 0; node < NUM_NODES; node++) {
			i = (enclosure * NUM_NODES) + node;

			inlv_setup[i].reg0.bits.valid = 1;
			inlv_setup[i].reg0.bits.ways = 4;
			inlv_setup[i].reg0.bits.module_size = 256;
			inlv_setup[i].reg0.bits.nb_intlv_lo = 4;
			inlv_setup[i].reg0.bits.nb_intlv_hi = 2;
			inlv_setup[i].reg0.bits.nb_size = 38;
			inlv_setup[i].reg1.bits.cid1 = (enclosure << 8) |
							(node << 4) | 0x8;
			inlv_setup[i].reg1.bits.cid2 = (enclosure << 8) |
							(node << 4) | 0x9;
			inlv_setup[i].reg1.bits.cid3 = (enclosure << 8) |
							(node << 4) | 0xA;
			inlv_setup[i].reg1.bits.cid4 = (enclosure << 8) |
							(node << 4) | 0xB;
		}
	}

	/* Copy interleave table to zbridge */
	for (entry = 0; entry < INLV_ENTRIES; entry++) {
		for (copy = 0; copy < INLV_COPIES; copy++) {
			target_addr = (uint64_t *)
				(((uint64_t)inlv_table) |
				(entry << INLV_ENTRY_SELECT) |
				(copy << INLV_COPY_SELECT));
			/* Set only the first 3 regs in interleave table */
			writeq(inlv_setup[entry].reg0.data,
				(void *) &target_addr[0]);
			writeq(inlv_setup[entry].reg1.data,
				(void *) &target_addr[1]);
			writeq(inlv_setup[entry].reg2.data,
				(void *) &target_addr[2]);
		}
	}

end:
	return ret;
}

int zbcsr_init(void)
{
	int ret = 0;

	/* Check for null zbcsr address */
	if (!zbcsr) {
		PR_VERBOSE1("Zbridge CSR table location set to SoC default address\n");
		zbcsr = ZBCSR_DEFAULT_ADDR;
	}

	zbmap_table = ioremap(zbcsr+ZBCSR_ERR_OFFSET, ZBCSR_ERR_SIZE);

	if (!zbmap_table) {
		pr_err("Zbridge CSR MAP table Mapping failed\n");
		ret = -EINVAL;
		goto end;
	}

	PR_VERBOSE2("zbridge: zbmap_table %p\n", zbmap_table);

	current_contain0 =
		readq((uint64_t *)(zbmap_table+NVM_MAP_CONTAINMENT_STATE0));
	current_contain1 =
		readq((uint64_t *)(zbmap_table+NVM_MAP_CONTAINMENT_STATE1));
	current_contain2 =
		readq((uint64_t *)(zbmap_table+NVM_MAP_CONTAINMENT_STATE2));
	current_contain3 =
		readq((uint64_t *)(zbmap_table+NVM_MAP_CONTAINMENT_STATE3));

	dump_error_regs();
end:
	return ret;
}

/* Called when zbcommit data device file is opened. */
static int zbcommit_open(struct inode *inode, struct file *filp)
{
	struct zbcommit_dev *dev =
		container_of(inode->i_cdev, struct zbcommit_dev, cdev);

	PR_VERBOSE3("in zbcommit_open\n");
	filp->private_data = dev;

	PR_VERBOSE3("zbcommit_open returns 0 for success\n");
	return 0;
}

/* Called when process closes zbcommit data device file. */
static int zbcommit_release(struct inode *inode, struct file *filp)
{
	PR_VERBOSE3("in zbcommit_release\n");
	return 0;
}

/* Called when a process mmap from the zbcommit data file. */
static int zbcommit_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long vsize = vma->vm_end - vma->vm_start;
	unsigned long psize = COMMIT_SIZE - offset;

	if (vsize > psize) {
		PR_VERBOSE3("zbcommit_mmap: vsize of mmap is too big\n");
		return -EINVAL;
	}
	/* Use the global commit physaddr that is setup for FAME/TMAS. */
	offset += commit;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	if (io_remap_pfn_range(vma, vma->vm_start,
				offset >> PAGE_SHIFT,
				vsize,
				vma->vm_page_prot)) {
		PR_VERBOSE3("zbcommit_mmap: remap_pfn_range failed\n");
		return -EAGAIN;
	}

	return 0;
}

static struct file_operations fops_zbcommit = {
	.owner	= THIS_MODULE,
	.mmap	= zbcommit_mmap,
	.open	= zbcommit_open,
	.release = zbcommit_release,
};

static ssize_t zbc_cdev_show_size(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE-2, "%d\n", COMMIT_SIZE);
}

static int zbc_dev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	/* Create /dev/zbcommit with permission 444 */
	add_uevent_var(env, "DEVMODE=%#o", 0444);
	return 0;
}

static dev_t zb_dev;
static int zb_major;
static struct zbcommit_dev zbc_dev;
static struct device *zbc_device;
static DEVICE_ATTR(size, S_IRUGO, zbc_cdev_show_size, NULL);
static struct class *zbc_cdev_class;
#define ZBC_CDEV_NAME "zbcommit"

static void zb_setup_cdev(struct cdev *dev, int minor,
	struct file_operations *fops) {
	int err, devno;
	int ret;

	/* Get a dynamic MAJOR/MINOR */
	ret = alloc_chrdev_region(&zb_dev, 0, 1, "zbcommit");
	PR_VERBOSE3("zbcommit: called alloc_chrdev_region\n");
	if (ret) {
		PR_VERBOSE1("Can't get chrdev region for zbcommit\n");
		return;
	}
	zb_major = MAJOR(zb_dev);
	devno = MKDEV(zb_major, minor);
	PR_VERBOSE3("zbcommit: zb_major is %d\n", zb_major);

	zbc_cdev_class = class_create(THIS_MODULE, ZBC_CDEV_NAME);
	if (IS_ERR(zbc_cdev_class)) {
		PR_VERBOSE3("cdev class_create error\n");
		return;
	}
	zbc_cdev_class->dev_uevent = zbc_dev_uevent;
	cdev_init(dev, fops);
	dev->ops = fops;
	err = cdev_add(dev, devno, 1);
	/* Fail gracefully if need be */
	if (err) {
		PR_VERBOSE3("Error %d adding zbcommit%d", err, minor);
		cdev_del(dev);
		return;
	}
	zbc_device = device_create(zbc_cdev_class, NULL, devno, dev,
		ZBC_CDEV_NAME);
	if (IS_ERR(zbc_device)) {
		PR_VERBOSE3("Error in device_create");
		cdev_del(dev);
		return;
	}
	device_create_file(zbc_device, &dev_attr_size);
}

int commit_init(void)
{
	int ret = 0;

	/* Check for null commit address */
	if (!commit) {
		PR_VERBOSE1("Commit HSR table location set to SoC default address\n");
		commit = COMMIT_DEFAULT_ADDR;
	}

	/* There are 4 copies of the 8M firewall table in the MFT */
	commit_table = ioremap(commit, COMMIT_SIZE);

	if (!commit_table) {
		pr_err("Commit HSR table Mapping failed\n");
		return -EINVAL;
	}

	PR_VERBOSE2("zbridge: commit_table 0x%p\n", commit_table);

	/*
	 * Load the HA_WRITE_COMMIT_CONTAINMENT_HSR for thread 0 and
	 * initialize the global current count.
	 */
	current_commit_hsr = readq(commit_table) & COMMIT_HSR_MASK;

	PR_VERBOSE3("Initializing current_commit_hsr to %ld\n",
		(long)current_commit_hsr);

	/*
	 * Create a character device so that libpmem can map the
	 * Write Commit HSR for the pmem_drain() to detect write
	 * errors.
	 */
	zb_setup_cdev(&(zbc_dev.cdev), 0, &fops_zbcommit);
	zbc_dev.membase = commit_table;
	PR_VERBOSE3("zbcommit: zbridge write commit at 0x%p\n", zbc_dev.membase);

	return ret;
}

int nvm_bk_init(void)
{
	int ret = 0;

	/* Check for null nvm address */
	if (!nvm_bk) {
		PR_VERBOSE1("NVM Apertures book location set to SoC default address\n");
		nvm_bk = NVM_BK_DEFAULT_ADDR;
	}

	return ret;
}

int nvm_bklt_init(void)
{
	int ret = 0;

	/* Check for null nvm_bklt address */
	if (!nvm_bklt) {
		PR_VERBOSE1("NVM Aperture Booklet location set to SoC default address\n");
		nvm_bklt = NVM_BKLT_DEFAULT_ADDR;
	}

	if (!nvm_bklt_size) {
		PR_VERBOSE1("NVM Aperture Booklet region size set to SoC default size\n");
		nvm_bklt_size = NVM_BKLT_SIZE;
	}
	PR_VERBOSE2("zbridge: nvm_bklt=0x%p nvm_bklt_size=%lu\n",
			(void *)nvm_bklt, (unsigned long)nvm_bklt_size);

	/* Rememeber bklt_size is in M */

	return ret;
}

void des_exit(void)
{
	desc_sysfs_exit();
	desc_ioctl_exit();
}

static void zbridge_unmap(void)
{
	if (desbk_table)
		iounmap(desbk_table);
	if (desbl_table)
		iounmap(desbl_table);
	if (inlv_table)
		iounmap(inlv_table);
	if (frwl_table)
		iounmap(frwl_table);
	if (commit_table)
		iounmap(commit_table);
	if (zbmap_table)
		iounmap(zbmap_table);
}

static int zbridge_acpi_add(struct acpi_device *device)
{
	uint64_t temp;
	acpi_status status;

	acpi_zbridge = 1;
	status = acpi_evaluate_integer(device->handle, "_HRV", NULL, &temp);
	if (ACPI_FAILURE(status)) {
		PR_VERBOSE3("zbridge_acpi_add: evaluation of _HRV failed.\n");
		/* Don't want to fail the whole init if _HRV is not found. */
		return 0;
	} else
		PR_VERBOSE1("zbridge_acpi_add: Zbridge hardware revision is %d\n", (int) temp);
	PR_VERBOSE3("Found ACPI object HWPE0002\n");

	return 0;
}

static int zbridge_acpi_remove(struct acpi_device *device)
{
	return 0;
}

int zbridge_init(void)
{
	int ret;
	int ivshm_count = 0;

	zbridge_verbose = verbose;
	acpi_zbridge = 0;
	ret = acpi_bus_register_driver(&zbridge_acpi_driver);
	if (ret != 0)
		/*
		 * Expect non-zero return on platforms without a zbridge
		 * ACPI object.
		 */
		PR_VERBOSE3("acpi_bus_register_driver returns %d and acpi_zbridge is %d\n", ret, acpi_zbridge);

	/*
	 * If the zbridge ACPI object is not found, then we are either
	 * running in FAME mode or self-hosted. In FAME mode, we will find 7
	 * iv shared memory regions. If we don't find those, assume we are in
	 * self-hosted, where zbridge is not used at all.
	 */
	if (acpi_zbridge == 0) {
		struct pci_dev *ivshm_dev = NULL;

		/*
		 * The current platform does not have an ACPI object
		 * for the zbridge device expected on real hardware
		 * and TMAS. Check that all address space parameters
		 * have been specified.
		 */
		do {
			struct device mydev;
			uint32_t cfg_lo, cfg_hi;
			int ret;

			ivshm_dev = pci_get_device(0x1af4, 0x1110, ivshm_dev);
			if (ivshm_dev == NULL)
				break;
			mydev = ivshm_dev->dev;
			ret = pci_read_config_dword(ivshm_dev, 0x18, &cfg_lo);
			ret = pci_read_config_dword(ivshm_dev, 0x1C, &cfg_hi);
			switch (ivshm_count++) {
			case 0:
				if (nvm_bk == 0)
					nvm_bk = (((uint64_t)cfg_hi << 32)
						| (cfg_lo & 0xFFFFFFF0));
				if (bk_size == 0)
					bk_size = 8;
				PR_VERBOSE3("nvm_bk is 0x%lx\n", nvm_bk);
				break;
			case 1:
				if (zbcsr == 0)
					zbcsr = (((uint64_t)cfg_hi << 32)
						| (cfg_lo & 0xFFFFFFF0));
				PR_VERBOSE3("zbcsr is 0x%lx\n", zbcsr);
				break;
			case 2:
				if (desbk == 0)
					desbk = (((uint64_t)cfg_hi << 32)
						| (cfg_lo & 0xFFFFFFF0));
				PR_VERBOSE3("desbk is 0x%lx\n", desbk);
				break;
			case 3:
				if (desbl == 0)
					desbl = (((uint64_t)cfg_hi << 32)
						| (cfg_lo & 0xFFFFFFF0));
				PR_VERBOSE3("desbl is 0x%lx\n", desbl);
				break;
			case 4:
				if (frwl == 0)
					frwl = (((uint64_t)cfg_hi << 32)
						| (cfg_lo & 0xFFFFFFF0));
				PR_VERBOSE3("frwl is 0x%lx\n", frwl);
				break;
			case 5:
				if (inlv == 0)
					inlv = (((uint64_t)cfg_hi << 32)
						| (cfg_lo & 0xFFFFFFF0));
				PR_VERBOSE3("inlv is 0x%lx\n", inlv);
				break;
			case 6:
				if (commit == 0)
					commit = (((uint64_t)cfg_hi << 32)
						| (cfg_lo & 0xFFFFFFF0));
				PR_VERBOSE3("commit is 0x%lx\n", commit);
				break;
			case 7:
				if (nvm_bklt == 0)
					nvm_bklt = (((uint64_t)cfg_hi << 32)
						| (cfg_lo & 0xFFFFFFF0));
				PR_VERBOSE3("nvm_bklt is 0x%lx\n", nvm_bklt);
				break;
			}
		} while (ivshm_dev != NULL);
		PR_VERBOSE3("Found %d ivshm regions\n", ivshm_count);
	}
	if (acpi_zbridge) {
		zbridge_environment = TM_OR_TMAS;
		pr_info("zbridge: running on TMAS/hardware\n");
	} else if (ivshm_count == 7) {
		zbridge_environment = FAME;
		pr_info("zbridge: running on FAME\n");
	} else {
		zbridge_environment = SELF_HOSTED;
		pr_info("zbridge: running on self-hosted platform\n");
		/* Assume that zbridge does nothing in self-hosted. */
		return 0;
	}

	ret = frwl_init();
	if (ret != 0) {
		pr_err("Firewall initialization failed (%d)\n", ret);
		goto err;
	}
	ret = inlv_init();
	if (ret != 0) {
		pr_err("Interleave table initialization failed (%d)\n", ret);
		goto err;
	}
	ret = zbcsr_init();
	if (ret != 0) {
		pr_err("Zbridge CSR initialization failed (%d)\n", ret);
		goto err;
	}
	ret = commit_init();
	if (ret != 0) {
		pr_err("Zbridge Commit HSR initialization failed (%d)\n", ret);
		goto err;
	}
	ret = des_init();
	if (ret != 0) {
		pr_err("Descriptor table initialization failed (%d)\n", ret);
		goto err;
	}
	ret = nvm_bk_init();
	if (ret != 0) {
		pr_err("Book Aperture initialization failed (%d)\n", ret);
		goto err;
	}
	ret = nvm_bklt_init();
	if (ret != 0) {
		pr_err("Booklet Aperture initialization failed (%d)\n", ret);
		goto err;
	}

	zbridge_notify_init();
	zbridge_init_des(init_zero, init_desbk);

	if (self_test) {
		test_desbk_get_put();
		test_walk_checkerboard();
	}

	return ret;
err:
	zbridge_unmap();
	return ret;
}

void zbridge_exit(void)
{

	if (zbridge_environment == SELF_HOSTED) {
		return;
	}

	acpi_bus_unregister_driver(&zbridge_acpi_driver);
	des_exit();
	zbridge_unmap();
	zbridge_notify_delete();
	zbridge_exit_des();
	/* remove the character device */
	if (zbc_device)
		device_remove_file(zbc_device, &dev_attr_size);
	if (!IS_ERR(zbc_cdev_class))
		device_destroy(zbc_cdev_class, zbc_device->devt);
	if (&(zbc_dev.cdev))
		cdev_del(&(zbc_dev.cdev));
	if (!IS_ERR(zbc_cdev_class))
		class_destroy(zbc_cdev_class);
	/* free up character device numbers */
	if (zb_dev)
		unregister_chrdev_region(zb_dev, 1);
}

module_init(zbridge_init);
module_exit(zbridge_exit);
