#include "tmfs_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/compat.h>
#include <linux/swap.h>
#include <linux/falloc.h>
#include <linux/uio.h>

int tmfs_verbose = 0;
module_param(tmfs_verbose, int, S_IRUGO);
MODULE_PARM_DESC(tmfs_verbose, "increase amount of printk info (0)");

static int tmfs_debug = 0;
module_param(tmfs_debug, int, S_IRUGO);
MODULE_PARM_DESC(tmfs_debug, "force legacy userspace lookups (0)");

#define BAD_LZA		(~0UL)	// equivalence is coincidental
#define NO_EVICTION_DESC_VACANT	((uint64_t)-1)
#define NO_EVICTION_DESC_FILLED	((uint64_t)-2)

struct lfs_cached_vma {
	struct list_head list;
	struct vm_area_struct *vma;
	unsigned long faulted_book;
	unsigned long va_shelf_offset;
};

enum ADDRESS_MODES {	/* make sure this agrees with lfs_fuse.py */
	MODE_NONE = 0,
	MODE_FAME,	// FAME direct flat shadow space, no zbridge
	MODE_FAME_DESC,	// FAME direct flat shadow space, do call zbridge
	MODE_1906_DESC,	// TMAS, zbridge preloads DESBK, no zbridge calls
	MODE_FULL_DESC,	// TM(AS), the desired state
	// Added to support an optimization here that's backwards
	// compatible with an older lfs_shadow.py.  It also keeps a newer
        // lfs_fuse --shadow from working with an older tmfs.
	MODE_FALLBACK   // Use legacy ops
};

#define LZA_MAP_ADDR_FALLBACK 0		// instead of a lot of comments

static tmfs_global_t G = { 0, MODE_NONE, 0 };

/* Certain modes do not need to speak to zbridge and/or flushtm.
   Conditional statements using those modes should actually preclude
   the calls, but if they sneak out, force failure.  See the Makefile
   to enable zbridge and/or flushtm calls.
*/
#ifndef USE_ZBRIDGE_APIS

int desbk_get_slot(uint64_t lza, void *owner, int *slot, uint64_t *evicted)
{
	return -1;	// always fail
}

int desbk_put_slot(int slot, uint64_t lza, void *owner)
{
	return -1;	// always fail
}

#ifndef USE_FLUSHTM_APIS

void flushtm_dcache_phys_area(phys_addr_t addr, uint64_t len)
{
	PR_VERBOSE2("%s: using no-op interface\n", __func__);
	return;         // no-op
}

#endif

#endif

#define XATTR_MSG_SIZE	256

/* Encapsulation for code reuse */
int spoof_getxattr(struct inode *inode, char *msg, void *resp, size_t respsize)
{
	int ret;

	ret = tmfs_getxattr(inode, msg, (char *)resp, respsize);
	// sometimes resp is binary, printk up to a NULL could be a problem
	PR_VERBOSE2("    spoof_getxattr(%s) -> %d bytes\n", msg, ret);
	return ret;
}

/**
 * Read globals; called from dir.c::tmfs_permission() which is called early
 * and often.  That routine is too messy to pull into a private routine for
 * this one tweak.  Make this a singleton.
 */

/**
 * lfs_obtain_globals - Read data from user space for general use
 * @inode:	input for spoof_getxattr
 *
 * Gets global data from lfs_fuse, some of which is calculated by lfs_shadow
 * and some of which comes back from the Librarian DB.  Returns a pointer
 * to the globals or NULL on read error.  Passing in a NULL inode clears
 * the current globals, useful for restarting LFS without a module reload.
 */
tmfs_global_t *lfs_obtain_globals(struct inode *inode)
{
	static char resp[XATTR_MSG_SIZE], *inp;	// don't assign inp here...
	unsigned long book_size, tmp;

	if (!inode) {	// umount during lfs_fuse shutdown
		pr_info("lfs: cleanup after umount or FuSE shutdown\n");
		memset(&G, 0, sizeof(G));
		return NULL;
	}

	if (G.book_size)	/* Singleton sentinel good for all modes */
		return &G;

	if (spoof_getxattr(inode,
			   "_obtain_booksize_addrmode_aperbase",
			   resp,
			   sizeof(resp)) < 0)
		return NULL;

	inp = resp;	// ...because compiler optimizes it "once" somehow
	if (kstrtoul(strsep(&inp, ","), 10, &book_size) < 0)
		{ pr_err("lfs: bad book_size\n"); return NULL; }
	if (!book_size)
		{ pr_err("Book size cannot be zero\n"); return NULL; }

	if (kstrtoul(strsep(&inp, ","), 10, &tmp) < 0)
		{ pr_err("lfs: bad addr_mode\n"); return NULL; }
	G.addr_mode = tmp;
	if (kstrtoul(strsep(&inp, ","), 10, &tmp) < 0)
		{ pr_err("lfs: bad aper_base\n"); return NULL; }
	G.aper_base = tmp;
	PR_VERBOSE1("    book_size, addr_mode, aper_base = %lu, %lu, 0x%lx\n",
		G.book_size, G.addr_mode, G.aper_base);

	memset(&(G.shadow_igstart), 0, sizeof(G.shadow_igstart));
	if (G.addr_mode == MODE_FAME || G.addr_mode == MODE_FAME_DESC) {
		int groupId;

		if (spoof_getxattr(inode,
			   "_obtain_shadow_igstart",
			   &(G.shadow_igstart),
			   sizeof(G.shadow_igstart)) < 0)
			return NULL;
		if (tmfs_verbose > 1)
			for (groupId = 0; groupId < 128; groupId++)
				if (G.shadow_igstart[groupId])
					pr_info("    IG %d shadow @ 0x%p\n",
						groupId,
						(void *)G.shadow_igstart[groupId]);

	}

	G.book_size = book_size;	// NOW set it
	return &G;
}

int lfs_modal_lza2map_addr(
	unsigned long file_byteoff,
	unsigned long lza,
	unsigned long *map_addr)
{
	unsigned long shelf_book_offset, ig_book_num, ig, aper_num, desc_num;
	int ret = 0;

	shelf_book_offset = file_byteoff % G.book_size;
	switch (G.addr_mode) {

	case MODE_FAME:
	case MODE_FAME_DESC:	// from lfs_shadow.py::shadow_offset()
		ig_book_num = lza >> 33;	// 20-bit combo
		ig = ig_book_num >> 13;		// top 7 bits, final
		ig_book_num &= 8191;		// 13-bit mask, final
		*map_addr = G.shadow_igstart[ig] +
			    (ig_book_num * G.book_size) +
			    shelf_book_offset;
		break;

	case MODE_1906_DESC:
		/* Assume 1:1 mapping between descriptor and aperture, and
		   that Zbridge driver has preprogrammed the descriptors. */

		/* Extract relative book number from LZA */
		desc_num = ((lza >> 33) & ((1 << 13) - 1));
		aper_num = desc_num;

		/* Aperture physical starting address */
		*map_addr = G.aper_base + 
			    (aper_num * G.book_size) +
			    shelf_book_offset;

		PR_VERBOSE2("    lza = 0x%lx -> IG=%lu, IGbook=%lu\n",
			lza,
			((lza >> 46) & ((1 << 7) - 1)),
			((lza >> 33) & ((1 << 13) - 1))
		);
		PR_VERBOSE2("    desc_num = %lu\n", desc_num);
		PR_VERBOSE2("    aper_num = %lu\n", aper_num);
		break;

	case MODE_FULL_DESC:
		/* Call zbridge (later) to get a slot for the returned LZA.
		   map_addr is calculated after getting that slot.  Leave
		   that call deferred so this routine can be called by
		   actors that only want an LZA and not a map_addr. */

		*map_addr = 0;		/* nothing to see, move along */
		break;

	case MODE_FALLBACK:
		/* Fake it so lfs_book2lza_populate() works, even though
		   the cache it builds will not be used in this mode. */

		*map_addr = 0;		/* nothing to see, move along */
		break;

	default:    // MODE_NONE should not be seen here
		pr_err("    BAD MODE %lu\n", G.addr_mode);
		ret = -EINVAL;

	}
	return ret;
}

/**
 * lfs_obtain_lza_map_addr - turn a file offset into an LZA & physical address.
 * Multiple routines call this with different offset "granularities".
 * @inode:	Contains info about the backing "file" (shelf).  It's also
 *		used in communications with user space, if needed.
 * @file_byteoff: File-relative byte offset, can be "byte-accurate" i.e.,
 *              it may not be page-aligned.
 * @comm:	Command name of the faulting process (debug/tracking only)
 * @pid:	Process ID of the command (debug/tracking only)
 * @lza:	Returned LZA of book containing byte_offset
 * @map_addr:	Returned physical address, may be 0.  It is "byte-accurate";
 *		page masking/shifting may be needed before use, and that's
 *		the caller's problem.
 * @up_book2lza: Returned callback (function pointer) to release semaphore
 * Return: <0 for errors (-EXXX)
 *         0: aka LZA_MAP_ADDR_FALLBACK, caller should take appropriate action
 * 	   1: value was already cached, no call to user space (minor)
 * 	   2: value was retrieved from user space and is now cached (major)
 *         if > 0 this routine returns with book2lza_rw_sema locked
 * First check the existing radix tree for the offset.   Failing that,
 * call user space to get the LZA (and, depending on platform address mode)
 * the physical address associated with a given offset (page) in a shelf.
 * The call to user space comes "through" the inode so the offset can be
 * turned into a the containing book and LZA.  Book-level results can be
 * cached to handle other pages that are contained within the same book.
 */

int lfs_obtain_lza_map_addr(
	struct inode *inode,
	unsigned long file_byteoff,
	char *comm,
	pid_t pid,
	unsigned long *lza,
	unsigned long *map_addr,
	void (**up_book2lza)(struct rw_semaphore *sem)
	)
{
	int ret;
	static char out_buf[XATTR_MSG_SIZE], in_buf[XATTR_MSG_SIZE];
	char *inp;
	unsigned long addr_mode;

	PR_VERBOSE2("%s(enter)\n", __func__);
	*up_book2lza = NULL;	// help weed out errors :-)

	// Was lfs_fuse started with --shadow_file?
	if (G.addr_mode == MODE_FALLBACK)
		return LZA_MAP_ADDR_FALLBACK;

	// FIXME: do this again after a trip to user space
	if (file_byteoff > inode->i_size)
		return -ENOMEM;

	/* Start with down_write because it can be downgraded to a read sema.
	   You can't start with a read lock and upgrade to a write. */

	down_write(&lfs_book2lza_rw_sema);
	ret = lfs_book2lza_lookup(inode, file_byteoff, lza, map_addr);
	if (ret) {
		*up_book2lza = up_read;
		downgrade_write(&lfs_book2lza_rw_sema);
		return 1;
	} 
	*up_book2lza = up_write;

	memset(out_buf, 0, sizeof(out_buf));
	memset(in_buf, 0, sizeof(in_buf));

	snprintf(out_buf, sizeof(out_buf), "%s,%s,%d,%lu",
		"_obtain_lza_for_page_fault", comm, pid, file_byteoff);

	// Many ways to fail
	ret = -1;
	if (spoof_getxattr(inode, out_buf, in_buf, sizeof(in_buf)) < 0)
		goto up_and_out;
	inp = in_buf;	// Trust me, don't do this in the declarations
	if (!strcmp(inp, "FALLBACK")) {
		ret = 0;
		goto up_and_out;
	}
	if (!strcmp(inp, "ERROR"))
		goto up_and_out;
	if (kstrtoul(strsep(&inp, ","), 10, &addr_mode) < 0)
		goto up_and_out;
	if (addr_mode != G.addr_mode) {
		PR_VERBOSE2("Wrong mode, sent mode = %lu, G.addr_mode = %lu\n",
			addr_mode, G.addr_mode);
		goto up_and_out;
	}
	if (kstrtoul(strsep(&inp, ","), 10, lza) < 0)
		goto up_and_out;
	if (kstrtoul(strsep(&inp, ","), 10, map_addr) < 0)
		goto up_and_out;

	/* Value(s) are valid, set up for return */

	PR_VERBOSE2("    lza = %lu (0x%lx)\n", *lza, *lza);
	PR_VERBOSE2("    user space map_addr = %lu (0x%lx)\n",
		*map_addr, *map_addr);

	ret = lfs_modal_lza2map_addr(file_byteoff, *lza, map_addr);
	if (ret < 0)
		goto up_and_out;

	PR_VERBOSE2("    final map_addr = 0x%lx\n", *map_addr);
	lfs_book2lza_cache(inode, file_byteoff, *lza, *map_addr);
	return 2;

up_and_out:
	(*up_book2lza)(&lfs_book2lza_rw_sema);
	return ret;
}

/* arch/arm64 has one of its own */

#ifndef __phys_to_pfn
#define __phys_to_pfn(p) ((p) >> PAGE_SHIFT)
#endif

/* Mimosa did this under ASmapping->i_mmap_mutex.  By 4.1 that's a semaphore
 * but no one seems to mess with it.  It was also called twice, on entry
 * and after an optional bmap(), but that's different in LFS.
 */

static int resized(
	struct inode *inode,
	struct vm_fault *vmf)
{
	return vmf->pgoff >= round_up(inode->i_size, PAGE_SIZE);
}

/**
 * lfs_vma_list_setup - setup and initialize the VMA per descriptor slot lists
 *
 * Invoked once on driver initialize from tmfs_init().
 */

void lfs_vma_list_setup(void)
{
	int index;

	PR_VERBOSE2("%s(enter)\n", __func__);

	for (index = 0; index < DESCRIPTOR_SLOTS ; ++index)
		INIT_LIST_HEAD(&G.desbk_slot2mappers[index]);

	return;
}

/* Should be called with a protective lock around G.desbk_slot2mappers */
static void lfs_vma_list_print(unsigned long slot)
{
	struct list_head *pos;
	struct lfs_cached_vma *lcv;

	if (tmfs_verbose < 3)
		return;
	pr_info("current list of VMAs at slot = %lu\n", slot);
	list_for_each(pos, &G.desbk_slot2mappers[slot]) {
		lcv = list_entry(pos, struct lfs_cached_vma, list);
		pr_info("    vma = 0x%p\n", lcv->vma);
	}
}

/**
 * lfs_add_vma_to_slot_list - insert a VMA on a list
 * @vma:          vma pointer to insert
 * @faulted_book: shelf relative book number (0..n)
 * @slot:         descriptor slot number (0..n)
 * @userVA:       user virtual address for current fault
 * @file_byteoff: byte offset into file for current fault
 *
 * Given a descriptor slot number insert the given VMA unless it is
 * already on the list.
 *
 * A write lock on the rw_semaphore is required when calling this routine.
 */

int lfs_add_vma_to_slot_list(
	struct vm_area_struct *vma,
	unsigned long faulted_book,
	unsigned long slot,
	void *userVA,
	unsigned long file_byteoff)
{
	struct lfs_cached_vma *lcv;
	struct list_head *pos;
	unsigned long va_offset;
	unsigned long va_shelf_offset;

	PR_VERBOSE2("%s(enter)\n", __func__);

	if (slot > DESCRIPTOR_SLOTS) {
		pr_err("TMFS: slot %lu > %d\n", slot, DESCRIPTOR_SLOTS);
		return -EINVAL;
	};

	/* Determine if VMA is already on the list */
	PR_VERBOSE2("    search at slot = %lu for vma = 0x%p\n", slot, vma);
	list_for_each(pos, &G.desbk_slot2mappers[slot]) {
		lcv = list_entry(pos, struct lfs_cached_vma, list);
		PR_VERBOSE2("    vma = 0x%p\n", lcv->vma);
		if (lcv->vma == vma) {
			PR_VERBOSE2("    VMA already on list\n");
			return 1;
		}
	}
	PR_VERBOSE2("    adding VMA 0x%p to end of list\n", vma);

	lcv = kmalloc(sizeof(struct lfs_cached_vma), GFP_KERNEL);
	if (!lcv) {
		pr_err("TMFS: kmalloc(VMA cache item) failed\n");
		return -ENOMEM;
	};
	lcv->vma = vma;
	lcv->faulted_book = faulted_book;

	/* Faulting VA offset from start of VMA range */
	va_offset = ((u64)userVA - vma->vm_start);

	/* Zero based shelf offset relative to start of VMA range */
	va_shelf_offset = (file_byteoff - va_offset);

	lcv->va_shelf_offset = va_shelf_offset;

	PR_VERBOSE2("    faulted_book = %lu (0x%lx)\n",
		lcv->faulted_book, lcv->faulted_book);
	PR_VERBOSE2("    va_offset = %lu (0x%lx)\n",
		va_offset, va_offset);
	PR_VERBOSE2("    va_shelf_offset = %lu (0x%lx)\n",
		lcv->va_shelf_offset, lcv->va_shelf_offset);

	list_add(&lcv->list, &G.desbk_slot2mappers[slot]);

	lfs_vma_list_print(slot);

	return 0;
}

/**
 * lfs_remove_vma_from_list_slot - remove a VMA from a list
 * @vma:        pointer to vma
 * @slot:       descriptor slot number (0..n)
 *
 * Given a descriptor slot number insert the given VMA unless it is
 * already on the list.
 *
 * A write lock on the rw_semaphore is required when calling this routine.
 */

void lfs_remove_vma_from_list_slot(
	struct vm_area_struct *vma,
	unsigned long slot)
{
	struct lfs_cached_vma *lcv;
	struct list_head *pos, *tmp;

	PR_VERBOSE2("%s(enter)\n", __func__);

	BUG_ON(slot > DESCRIPTOR_SLOTS);

	PR_VERBOSE2("    search at slot = %lu for vma = 0x%p\n", slot, vma);

	list_for_each_safe(pos, tmp, &G.desbk_slot2mappers[slot]) {
		lcv = list_entry(pos, struct lfs_cached_vma, list);
		if (lcv->vma == vma) {
			PR_VERBOSE2("    VMA = 0x%p, removing\n", lcv->vma);
			list_del(pos);
			kfree(lcv);
			return;
		}
	}

	lfs_vma_list_print(slot);

	return;
}

/**
 * lfs_remove_vma_from_list_global - remove a VMA from a all lists
 * @vma:        pointer to vma
 *
 * Given a VMA search all lists and remove it if found.
 */

void lfs_remove_vma_from_list_global(
	struct vm_area_struct *vma)
{
	struct lfs_cached_vma *lcv;
	struct list_head *pos, *tmp, *cur_list;
	int slot;

	PR_VERBOSE2("%s(enter)\n", __func__);

	PR_VERBOSE2("    search all lists for vma = 0x%p\n", vma);

	for (slot = 0; slot < DESCRIPTOR_SLOTS; slot++) {
		cur_list = &G.desbk_slot2mappers[slot];
		list_for_each_safe(pos, tmp, cur_list){
			lcv = list_entry(pos, struct lfs_cached_vma, list);
			if (lcv->vma == vma) {
				PR_VERBOSE2("    VMA @ 0x%p, slot = %d, removing\n", lcv->vma, slot);
				list_del(pos);
				kfree(lcv);
				break;
			}
		}

		if (!list_empty(&G.desbk_slot2mappers[slot]))
			lfs_vma_list_print(slot);
	}

	return;
}

/**
 * lfs_zap_vma_list - walk the list of VMAs using a slot and zap PTEs
 * @slot:       descriptor slot number (0..n)
 *
 * Given a descriptor slot number, walk its list of (vma, faulted_book)
 * values.  Calculate the faulting book virtual address range and
 * invalidate the PTE mappings.   Then remove the item from the list.
 *
 */

void lfs_zap_vma_list(
	unsigned long slot)
{
	struct lfs_cached_vma *lcv;
	struct list_head *pos, *tmp;
	unsigned long remaining_bytes;
	int ret;

	PR_VERBOSE2("%s(enter)\n", __func__);

	list_for_each_safe(pos, tmp, &G.desbk_slot2mappers[slot]) {
		/* xxx_end is an absolute number one-beyond the real end */
		unsigned long vma_base_book, zap_start, zap_end, zap_size;

		lcv = list_entry(pos, struct lfs_cached_vma, list);

		vma_base_book = lcv->va_shelf_offset / G.book_size;

		/* Should never happen, unless earlier calculations are bad */
		BUG_ON(lcv->faulted_book < vma_base_book);

		PR_VERBOSE3("    vma_base_book = %lu (0x%lx)\n",
			vma_base_book, vma_base_book);
		PR_VERBOSE3("    va_shelf_offset = %lu (0x%lx)\n",
			lcv->va_shelf_offset, lcv->va_shelf_offset);
		PR_VERBOSE3("    book to evict = %lu (0x%lx)\n",
			lcv->faulted_book, lcv->faulted_book);

		/* Bytes from vm_start to next book boundary */
		remaining_bytes = (G.book_size - (lcv->va_shelf_offset % G.book_size));

		if (lcv->faulted_book == vma_base_book) {
			zap_start = lcv->vma->vm_start;
			zap_end = zap_start + remaining_bytes;
		} else {
			zap_start = (lcv->vma->vm_start + remaining_bytes) +
				(lcv->faulted_book - vma_base_book - 1) * G.book_size;
			zap_end = zap_start + G.book_size;
		}

		PR_VERBOSE3("    remaining_bytes = %lu (0x%lx)\n",
			remaining_bytes, remaining_bytes);
		PR_VERBOSE3("    zap_start = %lu (0x%lx)\n",
			zap_start, zap_start);

		if (zap_end > lcv->vma->vm_end)
			zap_end = lcv->vma->vm_end;

		PR_VERBOSE3("    zap_end = %lu (0x%lx)\n",
			zap_end, zap_end);

		zap_size = zap_end - zap_start;

		PR_VERBOSE3("    zap_size = %lu (0x%lx)\n", zap_size, zap_size);

		PR_VERBOSE2("    zap_vma_ptes(0x%p, 0x%lx, 0x%lx)\n",
			lcv->vma, zap_start, zap_size);

		ret = zap_vma_ptes(lcv->vma, zap_start, zap_size);

		if (ret)
			pr_warn("zap failed\n");
		else {
			list_del(pos);	// Because it's no longer mapped.
			kfree(lcv);
		}
	}
	WARN_ON(!list_empty(&G.desbk_slot2mappers[slot]));
}


/**
 * lfs_obtain_desbk_slot - helper to grab a descriptor, promotes code reuse
 * @lza:	LZA for which a descriptor slot is needed
 * @owner:	Pointer to a struct to which the slot is "locked"
 * @desbk_slot:	The assigned slot number on success
 * @evicted_lza: The previous occupant of desbk_slot if thrashing has started.
 *
 * Returns 0 on success also setting desbk_slot and evicted_lza as needed.
 * Returns -EXXXX on failure, mostly pass-through from zbridge API.
 */

int lfs_obtain_desbk_slot(
	void *owner,
	unsigned long file_byteoff,
	unsigned long lza,
	unsigned long *map_addr,
	int *desbk_slot,
	uint64_t *evicted_lza)
{
	int ret = 0;

	switch (G.addr_mode) {

	case MODE_FAME_DESC:	/* both of these call zbridge */
	case MODE_FULL_DESC:
		if ((ret = desbk_get_slot(lza, owner, desbk_slot, evicted_lza)) < 0) {
			pr_err("    desbk_get_slot failed\n");
			return ret;
		}

		/* Remember: zbridge has now locked DESBK to "owner" */
		PR_VERBOSE2("    desbk_slot = %d, evicted_lza = 0x%llx\n",
			*desbk_slot, *evicted_lza);

		if (G.addr_mode == MODE_FAME_DESC) { // No apertures, it's a...
			BUG_ON(!*map_addr);	     // ...flatspace address
			break;		
		}

		/* slot gives aperture offset, then add final book offset.
		   NOTE: This address is NOT cached locally, but desbk_slot
		   is effectively cached by the zbridge driver. */
		*map_addr = G.aper_base + (*desbk_slot * G.book_size) +
				(file_byteoff % G.book_size);

		break;

	default: /* Use sentinel values for non-zbridge address modes */
		*desbk_slot = -1;
		*evicted_lza = (uint64_t)-1L;

	}
	PR_VERBOSE2("    FINAL map_addr = 0x%lx\n", *map_addr);

	/* If there is an existing LZA to be overwritten, clean it out.
	   Do it before we add our current VMA to the slot list */
	if ((*evicted_lza != NO_EVICTION_DESC_VACANT) &&
		(*evicted_lza != NO_EVICTION_DESC_FILLED)) {
		phys_addr_t flush_addr = (*map_addr - (*map_addr % G.book_size));
		lfs_zap_vma_list(*desbk_slot);
		flushtm_dcache_phys_area(flush_addr, G.book_size);
	}
	return ret;
}

/**
 * lfs_filemap_fault - read in file data for page fault handling
 * @vmf:        struct vm_fault containing details of the fault
 *
 * Invoked via the vma operations vector for a mapped memory
 * region to insert a virtual to physical mapping during a page fault.
 */

int lfs_filemap_fault(
	struct vm_fault *vmf)
{
	int ret = 0;
	void *userVA = (void *) vmf->address;
	struct vm_area_struct *vma = vmf->vma;
	struct task_struct *owner = vma->vm_mm->owner;
	struct file *vm_file = vma->vm_file;
	struct address_space *ASmapping = vm_file->f_mapping;
	struct inode *inode = ASmapping->host;
	blkcnt_t file_blkoff = vmf->pgoff;
	unsigned long file_byteoff, map_addr, pfn;
	unsigned long lza;
	uint64_t evicted_lza;
	int retflags = VM_FAULT_NOPAGE;
	int desbk_slot = -1;
	void (*up_book2lza)(struct rw_semaphore *sem);

	PR_VERBOSE2("%s(enter)\n    %s:%d %s fault @ %lu, userVA = 0x%p\n",
		__func__,
		owner->comm,
		owner->pid,
		vmf->flags & FAULT_FLAG_WRITE ? "write" : "read",
		file_blkoff,
		userVA)
	PR_VERBOSE3("    inode = 0x%p, vma->vm_flags = 0x%08lx\n",
		inode,
		vma->vm_flags);

	/*
	* These are both 4k on TMFS but I don't know why.  Hardcoded in FuSE?
	*/
	BUG_ON(1UL << inode->i_blkbits != inode->i_sb->s_blocksize);

	file_byteoff = file_blkoff * inode->i_sb->s_blocksize;

	PR_VERBOSE3("    file_byteoff = %lu (0x%lx)\n", file_byteoff, file_byteoff);

	ret = lfs_obtain_lza_map_addr(inode, file_byteoff,
		owner->comm, owner->pid,
		&lza, &map_addr, &up_book2lza);

	if (ret == LZA_MAP_ADDR_FALLBACK)
		return filemap_fault(vmf);
	if (ret < 0) 
		return VM_FAULT_SIGBUS;

	/* It's at least 1, values are valid and rw_sema is locked.
	   The callout to user space is time-consuming. */
	if (resized(inode, vmf)) {
		/* FIXME: clean out the cache to force faulting */
		up_book2lza(&lfs_book2lza_rw_sema);
		PR_VERBOSE1("    file was resized down\n");
		return VM_FAULT_SIGBUS;
	}
	if (ret == 2)
		retflags |= VM_FAULT_MAJOR;

	/* If we can't unwind it then we run the risk of data corruption. */

	if (lfs_obtain_desbk_slot(owner, file_byteoff, lza, &map_addr, &desbk_slot, &evicted_lza) < 0) {
		up_book2lza(&lfs_book2lza_rw_sema);
		return VM_FAULT_SIGBUS;
	}

	/* If it can't be saved for later eviction, it can't be used now. */
	if (desbk_slot >= 0) {
		unsigned long faulted_book = file_byteoff / G.book_size;
		PR_VERBOSE2("    faulted_book = %lu (0x%lx)\n", faulted_book, faulted_book);
		if (lfs_add_vma_to_slot_list(vma, faulted_book, desbk_slot, userVA, file_byteoff) < 0) {
			desbk_put_slot(-1, 0, owner);	/* release lock */
			up_book2lza(&lfs_book2lza_rw_sema);
			pr_err("    add_vma_to_slot failed()\n");
			return VM_FAULT_SIGBUS;
		}
	}

	// FINALLY map it in.  Maybe.
	file_update_time(vm_file);
	pfn = __phys_to_pfn(map_addr);
	vma->vm_flags |= VM_PFNMAP;	// See all the BUG_ONs in...
	ret = vm_insert_pfn(vma, (u64)userVA, pfn);

	PR_VERBOSE2("    vm_insert_pfn(0x%lx) ret = %d\n", pfn, ret);

	/* On error, unwind caching.  Don't forget zbridge lock.  RTFS. */
	if (ret && ret != -EBUSY) {
		if (desbk_slot >= 0) {
			lfs_remove_vma_from_list_slot(vma, desbk_slot);
			desbk_put_slot(-1, 0, owner);
		}
		up_book2lza(&lfs_book2lza_rw_sema);
		pr_err("    vm_insert_pfn failed ret = %d\n", ret);
		return VM_FAULT_SIGBUS;
	}
	if (desbk_slot >= 0)
		desbk_put_slot(desbk_slot, lza, owner);

	up_book2lza(&lfs_book2lza_rw_sema);

	vmf->page = NULL;
	return retflags;
}

/**
 * Handle filesystem FAM read/write
 */
ssize_t lfs_file_read_write(
	struct kiocb *iocb,
	struct iov_iter *iter)
{
	struct file *vm_file = iocb->ki_filp;
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	struct tmfs_conn *fc = get_tmfs_conn(inode);
	unsigned long map_addr;
	void __iomem *fam_map;
	loff_t offset = iocb->ki_pos;
	loff_t book_offset;
	size_t cur_cnt = 0;
	size_t tot_cnt = 0;
	size_t tot_len = iov_iter_count(iter);
	size_t cur_len = tot_len;
	unsigned long lza;
	loff_t i_size = i_size_read(inode);
	size_t cur_pos = offset + tot_len;
	ssize_t err;
	void (*up_book2lza)(struct rw_semaphore *sem);
	int desbk_slot = -1;
	uint64_t evicted_lza;

	PR_VERBOSE2("%s(enter)\n", __func__);
	PR_VERBOSE2("    type = 0x%x, tot_len = %ld, offset = %lld, nr_segs = %lu, i_size = %llu\n",
		iter->type, tot_len, offset, iter->nr_segs, i_size);
	PR_VERBOSE2("    owner->pid = %d, owner->comm = %s\n", current->pid, current->comm);

	if (iov_iter_rw(iter) == WRITE) {
		err = generic_write_checks(iocb, iter);

		if (err <= 0) {
			PR_VERBOSE2("    generic_write_checks(err = %ld)\n", err);
			return err;
		}

		if (cur_pos > i_size) {
			PR_VERBOSE2("    tmfs_do_truncate(cur_pos = %ld)\n", cur_pos);
			spin_lock(&fc->lock);
			i_size_write(inode, (offset + tot_len));
			spin_unlock(&fc->lock);
			tmfs_do_truncate(vm_file);
		}
	} else if (iov_iter_rw(iter) == READ) {
		if (offset > i_size) {
			PR_VERBOSE2("    read seek beyond EOF\n");
			return 0;	// FIXME: -ESOMETHING?
		}
		if (offset + tot_len > i_size) {
			cur_len = tot_len = (i_size - offset);
			PR_VERBOSE2("    truncate read passed EOF\n");
		}
	} else
		return -EIO;

	if (!tot_len)
		return 0;

	while (tot_cnt < tot_len) {
		int ret;

		/* Break up transfer if it crosses a book boundary */
		book_offset = offset % G.book_size;
		if ((book_offset + tot_len) > G.book_size) {
			PR_VERBOSE2("    *** split transfer\n");
			cur_len = G.book_size - book_offset;
		}

		ret = lfs_obtain_lza_map_addr(inode, offset,
			current->comm, current->pid,
			&lza, &map_addr, &up_book2lza);

		if (ret == LZA_MAP_ADDR_FALLBACK)
			return -EINVAL;	/* not in this address mode */
		if (ret < 0)
			return -EIO;	// FIXME: why not "ret" ?

		/* rw_sema is locked.  There's no VMA so map, transfer 
		   and unmap here. */

		if (lfs_obtain_desbk_slot(current, offset, lza, &map_addr, &desbk_slot, &evicted_lza) < 0) {
			up_book2lza(&lfs_book2lza_rw_sema);
			return -EFAULT;
		}

		PR_VERBOSE2("    tot_cnt = %ld, cur_len = %ld, offset = %lld, map_addr = 0x%lx\n",
			tot_cnt, cur_len, offset, map_addr);

		fam_map = ioremap_cache(map_addr, cur_len);
		if (!fam_map) {
			up_book2lza(&lfs_book2lza_rw_sema);
			pr_err("    ioremap_cache -> NULL\n");
			return -EFAULT;
		}

		/* Setup descriptor before we do the read/write */
		if (desbk_slot >= 0)
			desbk_put_slot(desbk_slot, lza, current);

		if (iov_iter_rw(iter) == READ) {

			cur_cnt = copy_to_iter(fam_map, cur_len, iter);

			PR_VERBOSE2("    read = %ld, remaining = %ld\n",
				cur_cnt, iov_iter_count(iter));

		} else if (iov_iter_rw(iter) == WRITE) {

			cur_cnt = copy_from_iter(fam_map, cur_len, iter);

			PR_VERBOSE2("    written = %ld, remaining = %ld\n",
				cur_cnt, iov_iter_count(iter));
		}

		iocb->ki_pos += cur_cnt;

		iounmap(fam_map);

		up_book2lza(&lfs_book2lza_rw_sema);

		if (!cur_cnt)
			return -EFAULT;

		tot_cnt += cur_cnt;
		offset += cur_cnt;
	}

	file_accessed(vm_file);
	return tot_cnt;
}

/**
 * lfs_obtain_lza_and_book_offset - return a book aligned LZA and book offset
 *     for a given shelf and byte offset into that shelf
 * @vm_file:          file structure for given shelf
 * @file_offset:      byte offset into given shelf
 * @book_aligned_lza: book aligned LZA for a given shelf offset
 * @book_offset:      byte offset within the book for a given shelf offset
 			FIXME that's not what the math is doing!!!
 *
 * Wrapper for obtain_lza_map_addr() for actors that ignore map_addr and don't
 * reserve a descriptor.  The only known caller is the atomics driver.
 *
 * Failure: return -errno, *book_aligned_lza and *book_offset are undefined
 * Success: return 0,      *book_aligned_lza and *book_offset are valid
 */

int lfs_obtain_lza_and_book_offset(
	struct file *file,
	uint64_t file_offset,
	uint64_t *book_aligned_lza,
	uint64_t *book_offset)
{
	struct inode *inode = file->f_inode;
	unsigned long junk, lza = BAD_LZA;
	void (*up_book2lza)(struct rw_semaphore *sem);
	int ret = 0;

	PR_VERBOSE2("%s(enter)\n", __func__);

	if (strcmp(inode->i_sb->s_type->name, "tmfs"))
		return -EINVAL;

	ret = lfs_obtain_lza_map_addr(inode, file_offset,
		current->comm, current->pid,
		&lza, &junk, &up_book2lza);
	if (ret == LZA_MAP_ADDR_FALLBACK)
		ret = -EINVAL;	/* not in this address mode */
	if (ret < 0)
		return ret;
	// lfs_book2lza_rw_sema is now locked.

	*book_aligned_lza = (uint64_t) lza;
	*book_offset = (uint64_t) (file_offset % G.book_size);
	up_book2lza(&lfs_book2lza_rw_sema);
	return 0;	/* success; ignore minor/major fault status */
}
EXPORT_SYMBOL(lfs_obtain_lza_and_book_offset);

/**
 * lfs_fsync - flush the caches associated with a file range
 * @file:	file to sync
 * @start:	offset in bytes of the beginning of data range to sync
 * @end:	offset in bytes of the end of data range (inclusive)
 * @datasync:	if non-zero only flush user data and not metadata (ignored)
 *
 * Handle fsync() on a given file given a starting and ending byte.
 */
int lfs_fsync(
	struct file *file,
	loff_t start,
	loff_t end,
	int datasync)
{
	struct inode *inode = file->f_mapping->host;
	unsigned long file_byteoff = start;
	unsigned long map_addr;
	unsigned long lza;
	void (*up_book2lza)(struct rw_semaphore *sem);
	unsigned long flush_size;
	int ret;
	loff_t i_size = i_size_read(inode);
	int desbk_slot = -1;
	uint64_t evicted_lza;

	PR_VERBOSE2("%s(enter)\n", __func__);
	PR_VERBOSE2("    start = %llu (0x%llx)\n", start, start);
	PR_VERBOSE2("    end = %llu (0x%llx)\n", end, end);
	PR_VERBOSE2("    datasync = 0x%x\n", datasync);

	if (is_bad_inode(inode))
		return -EIO;

	if (end > i_size) 
		end = i_size;

	inode_lock(inode);

	/* Flush each book overlapped by range passed in */
	while (file_byteoff < end) {

		// This should be a cache hit
		ret = lfs_obtain_lza_map_addr(inode, file_byteoff,
			current->comm, current->pid,
			&lza, &map_addr, &up_book2lza);
		if (ret == LZA_MAP_ADDR_FALLBACK) {
			inode_unlock(inode);
			return 0; /* FALLBACK is a no-op FIXME how so? */
		}
		if (ret < 0) {
			inode_unlock(inode);
			return -EIO;
		}

		/* lfs_book2lza_rw_sema is now locked */

		if (lfs_obtain_desbk_slot(current, file_byteoff, lza,
			&map_addr, &desbk_slot, &evicted_lza) < 0) {
			up_book2lza(&lfs_book2lza_rw_sema);
			return -EIO;
		}

		/* Flush to the end of the book or the end of the request */
		flush_size = (G.book_size - (file_byteoff % G.book_size));
		if ((file_byteoff + flush_size) > end)
			flush_size = ((end - file_byteoff) + 1);

		PR_VERBOSE2("    flush @ file_byteoff = %lu (0x%lx)\n",
			file_byteoff, file_byteoff);
		PR_VERBOSE2("    map_addr = %lu (0x%lx)\n",
			map_addr, map_addr);
		PR_VERBOSE2("    flush_size = %lu (0x%lx)\n",
			flush_size, flush_size);
		PR_VERBOSE2("    lza = 0x%lx\n", lza);

		/* No need to flush if a descriptor was never setup or was evicted */
		if (evicted_lza != NO_EVICTION_DESC_FILLED) {
			desbk_put_slot(-1, 0, current);	/* release lock */
			up_book2lza(&lfs_book2lza_rw_sema);
			file_byteoff += flush_size;
			PR_VERBOSE2("    no descriptor present, skip flush\n");
			continue;
		}

		if (desbk_slot >= 0)
			desbk_put_slot(desbk_slot, lza, current);

		flushtm_dcache_phys_area(map_addr, flush_size);

		up_book2lza(&lfs_book2lza_rw_sema);

		file_byteoff += flush_size;
	}

	inode_unlock(inode);

	/* Update file access time? Skipping for now for performance reasons */

	return 0;
}
