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

#include "zbridge.h"
#include <linux/notifier.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm.h>

extern unsigned long kallsyms_lookup_name(const char *);
static int zbridge_notifier(struct notifier_block *, unsigned long, void *);
extern uint64_t current_contain0;
extern uint64_t current_contain1;
extern uint64_t current_contain2;
extern uint64_t current_contain3;

/*
 * zbridge_notify_init - at zbridge driver init time, register a function on
 * the sea_notify_chain notification chain. This is called during the aarch64
 * SEA handling. It is called after the virtual faulting address have been
 * determined to NOT be in user space.
 */
struct sea_handler_data {
	unsigned long addr;
	unsigned int esr;
	struct pt_regs *regs;
	int recovered; /* set to 1 if callback recovered from the error */
};

static struct notifier_block zbridge_notify_sea = {
	.notifier_call = zbridge_notifier
};

void zbridge_notify_init(void)
{
	int ret;
	char reg_func_name[30] = "sea_register_handler_chain";
	int (*sea_register_handler_chain)(struct notifier_block *);

	/*
	 * Look up the symbol for the sea_register_handler_chain() so
	 * module will work on all kernels.
	 */
	sea_register_handler_chain =
		(void *)kallsyms_lookup_name(reg_func_name);
	if (sea_register_handler_chain == 0) {
		PR_VERBOSE1("Kernel version does not support the sea_register_handler_chain\n");
		return;
	}

	ret = (*sea_register_handler_chain)(&zbridge_notify_sea);
	if (ret)
		PR_VERBOSE1("sea_register_handler_chain() returned %d\n", ret);
}

void zbridge_notify_delete(void)
{
	int ret;
	char unreg_func_name[32] = "sea_unregister_handler_chain";
	int (*sea_unregister_handler_chain)(struct notifier_block *);

	sea_unregister_handler_chain =
		(void *)kallsyms_lookup_name(unreg_func_name);
	if (sea_unregister_handler_chain == 0) {
		PR_VERBOSE1("Kernel version does not support the sea_unregister_handler_chain\n");
		return;
	}
	ret = (*sea_unregister_handler_chain)(&zbridge_notify_sea);
	if (ret)
		PR_VERBOSE1("sea_unregister_handler_chain returned %d\n", ret);
}

static int is_fam(void *vaddr)
{
	struct task_struct *task = current;
	struct vm_area_struct *vma;
	struct mm_struct *mm;

	mm = task->mm;
	vma = find_vma(mm, (long unsigned int)vaddr);
	if (!vma)
		return 0;
	/* Look at the vma inode to see if it is from lfs. */
	if (vma->vm_file == NULL || vma->vm_file->f_inode == NULL ||
		vma->vm_file->f_inode->i_sb == NULL ||
		vma->vm_file->f_inode->i_sb->s_type == NULL)
		return 0;
	if (strcmp(vma->vm_file->f_inode->i_sb->s_type->name, "tmfs") == 0)
		return 1;

	return 0;
}

static int zbridge_notifier(struct notifier_block *nb,
	unsigned long val, void *data)
{
	struct sea_handler_data *sea_data = (struct sea_handler_data *) data;

	/* is this address in NVM? */
	if (!is_fam((void *)sea_data->addr)) {
		/* not an NVM address we care about. */
		PR_VERBOSE1("zbridge_notifier given an non-FAM addr.\n");
		return NOTIFY_DONE;
	}

	/* send SIGBUS to the process. */
	force_sig(SIGBUS, current);

	/* Print out some interesting error registers. */
	dump_error_regs();

	/* Return that the error has been recovered. */
	sea_data->recovered = 1;

	return NOTIFY_STOP;
}

#define WITHIN(A, B, C) ((A >= B) && (A < C))
int zbridge_pa_to_process(uint64_t start_addr, uint64_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	uint64_t vma_start_PA, vma_end_PA, end_addr;
	int ret = 0; /* return number of SIGBUSed processes */
	

	end_addr = start_addr + size;
	/* Go through each process */
	for_each_process(task) {
		/* Go through each VMA */
		mm = task->mm;
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			/* If VMA maps to error PA, sigbus the process. */
			vma_start_PA = (uint64_t)virt_to_phys((void *)vma->vm_start);
			vma_end_PA = (uint64_t)virt_to_phys((void *)vma->vm_end);
			if (WITHIN(vma_start_PA, start_addr, end_addr) ||
				WITHIN(vma_end_PA, start_addr, end_addr)) {
				PR_VERBOSE3("SIGBUS to pid %d\n", task->pid);
				force_sig(SIGBUS, task);
				ret++;
			}
		}
	}
	return ret;
}

static uint64_t reg_to_cur_contain(int reg)
{
	switch (reg) {
	case 0: 
		return current_contain0;
	case 1: 
		return current_contain1;
	case 2: 
		return current_contain2;
	case 3: 
		return current_contain3;
	}
	return (uint64_t)-1;
}

static void update_current_contain(int reg, uint32_t new_cs)
{
	switch (reg) {
	case 0: 
		current_contain0 = new_cs;
	case 1: 
		current_contain1 = new_cs;
	case 2: 
		current_contain2 = new_cs;
	case 3: 
		current_contain3 = new_cs;
	}
	return;
}

#define ILV_MASK 0x00000003
void zbridge_write_error(void)
{
	uint32_t ilv;
	uint64_t cs, cur_cs;
	int reg, i, ret;

	/* Lock descriptor table */
	/* Compare the NVM_MAP_CONTINAMENT_STATE to find error ilv */
	for (reg = 0; reg < 4; reg++) {
		cs = zbridge_get_containment(reg);
		cur_cs = reg_to_cur_contain(reg);
		if (cs != cur_cs) {
			for (i = 0; i < 32; i++, cs=cs>>2, cur_cs=cur_cs>>2) {
				if ((cs&ILV_MASK) != (cur_cs&ILV_MASK)) {
					ilv = (reg*32) + i;
					PR_VERBOSE3("Error ILV %d state is %lld\n", (int)ilv, (long long int)(cs&ILV_MASK));
					if ((cs&ILV_MASK) != 0) {
						ret = desbk_find_ilv(ilv);
					}
				}
			}
			update_current_contain(reg, cs);
		}
	}
	/* Unlock descriptor table */
	return;
}
