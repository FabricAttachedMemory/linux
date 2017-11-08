#include <asm/io.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/types.h>

#ifdef CONFIG_ARM64
#include <asm/cacheflush.h>
#include <asm/memory.h>
#endif

#ifdef CONFIG_X86_64
#include <asm/special_insns.h>
#endif

#include "flushtm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hewlett Packard Enterprise");
MODULE_DESCRIPTION("Module to flush caches");

/*
 * Same code written for libpmem's arm64 version
 * the kernel symbol for __flush_dcache_area is not exporte
 */

#ifdef CONFIG_ARM64
#define _aarch64_clean_and_invalidate(addr)\
	asm volatile("dc\tcivac, %0" : : "r" (addr) : "memory")
#endif

static void tm_flush_dcache_area(void *addr, size_t len)
{
	uintptr_t uptr;

	for (uptr = (uintptr_t)addr & ~(FLUSH_ALIGN - 1);
		uptr < (uintptr_t)addr + len; uptr += FLUSH_ALIGN) {

#ifdef CONFIG_ARM64
		_aarch64_clean_and_invalidate((char *)uptr);
#endif
#ifdef CONFIG_X86_64
		clflush((char *)uptr);
#endif
	}
}

void flushtm_dcache_phys_area(phys_addr_t addr, uint64_t len)
{
	phys_addr_t page_addr;
	void *page;

	/* round down to page and adjust length acordingly */
	len += (uintptr_t)addr & (PAGE_SIZE - 1);
	page_addr = (uintptr_t)addr & ~(PAGE_SIZE - 1);

	page = ioremap_cache(page_addr, len);
	tm_flush_dcache_area(page, len);
	iounmap(page);
}
EXPORT_SYMBOL(flushtm_dcache_phys_area);

/* flush (write-back) and invalidate in x86 land */
void clean_and_invalidate_cpu_cache(void *args)
{

	pr_info("clean_and_invalidate...\n");

#ifdef CONFIG_X86_64
	wbinvd();
#endif
#ifdef CONFIG_ARM64
	/*
	 * flush all of arm64 on one CPU by set/way - Fun!
	 * This almost certainly doesn't work
	 * I have four main concerns.
	 *
	 * 1) Does this stop all CPUs that may have dirty caches
	 * 2) Is this "fast" enough. See the comment for on_each_cpu()
	 * 3) Can cachelines still be migrated under these circumstances
	 * 4) Since these are not broadcast it sems possible that another CPU
	 *    could retain invalid data in their L2 cache even if it was invalidated
	 *    in another CPUs L1 cache.
	 */
	__flush_dcache_all();
#endif
}

static int flush_all_cpus(struct notifier_block *nb, unsigned long ev, void *p)
{

	/*
	 * What does fast mean?
	 */
	on_each_cpu(clean_and_invalidate_cpu_cache, NULL, 0);


	return 0;
}


static struct notifier_block panic_block = {
	.notifier_call = flush_all_cpus,
	.priority = 1, /* becuause why not */
};

static struct notifier_block reboot_block = {
	.notifier_call = flush_all_cpus,
	.priority = 1, /* becuase why not */
};


int flushtm_init(void)
{
	register_reboot_notifier(&reboot_block);
	atomic_notifier_chain_register(&panic_notifier_list, &panic_block);

	/*
	 * I don't believe I need the NMI from the previous version. Plus
	 * the nmi code seems to only exist for x86_64
	 */
	return 0;
}

void flushtm_exit(void)
{
	unregister_reboot_notifier(&reboot_block);
	atomic_notifier_chain_unregister(&panic_notifier_list, &panic_block);

	/* once more don't believe I need the NMI stuff or the stop CPUs stuff */
}

module_init(flushtm_init);
module_exit(flushtm_exit);
