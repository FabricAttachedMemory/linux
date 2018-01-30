/*
 * APIs to cache the mapping of a shelf's ordinal book number to an LZA,
 * essentially the results of whatever AllocationPolicy was used to create
 * a shelf.  The cache is expressed as a radix tree indexed by shelf
 * ordinal book number.   The radix tree is rooted in the inode's mapping
 * (address space) private fields.
*/

#include "tmfs_i.h"

static tmfs_global_t *G = NULL;

DECLARE_RWSEM(lfs_book2lza_rw_sema);	// Probably a performance bottleneck

/**
 * lfs_book2lza_setup - setup radix tree for newly created file
 * @file:       file structure for newly created file
 *
 * Invoked from multiple places, must be re-entrant.
 * A write lock on the rw_sema must be held by the caller.
 * FIXME: can I move those mechanics in here and the other lfs_book2lza_xxxx?
 */

void lfs_book2lza_setup(
	struct file *file)
{
	struct address_space *f_mapping;
	struct tmfs_book_cache *tbc = NULL;

	PR_VERBOSE2("%s(enter)\n", __func__);
	if (!(G = lfs_obtain_globals(file->f_inode))) {
		pr_err("    Can't obtain LFS globals, this is really bad!\n");
		return;		// This should never happen
	}
	if (tmfs_verbose > 3)
		dump_stack();

	f_mapping = file->f_mapping;
	if (!f_mapping) {
		pr_err("%s: file is not mature\n", __func__);
		return;
	}

	// GFP_KERNEL allocations: no spinlocks.  Just in case I need it.
	tbc = kzalloc(sizeof(struct tmfs_book_cache), GFP_KERNEL);
	if (tbc)
		INIT_RADIX_TREE(&tbc->book2lza_root, GFP_KERNEL);
	else {
		pr_err("%s: -ENOMEM for tbc\n", __func__);
		return;		// go with whatever is there
	}

	// User context only!!!  Has it been done already?
	spin_lock(&f_mapping->private_lock);
	if (f_mapping->private_data)
		kfree(tbc);
	else
		f_mapping->private_data = tbc;
	spin_unlock(&f_mapping->private_lock);

	PR_VERBOSE2("    f_mapping->private_data = 0x%p, tbc = 0x%p\n",
		f_mapping->private_data, tbc);
}

/**
 * lfs_book2lza_cache - update a file's book2lza with data from user space
 * @inode:	  the file of interest, should have radix tree cache set up
 * @file_byteoff: byte offset into shelf, provides cache index
 * @lza:          LZA of shelf-relative book
 * @map_addr:     starting physical address (FAME modes)
 *
 * Invoked to save work for the next page fault in the same book (LZA).
 * A write lock on the rw_sema must be held by the caller.
 * FIXME: can I move those mechanics in here and the other lfs_book2lza_xxxx?
 */

void lfs_book2lza_cache(
	struct inode *inode,		// The file
	unsigned long file_byteoff,	// Into the file
	unsigned long lza,		// Retrieved from user space
	unsigned long map_addr)		// Related physical address of book
{
	struct tmfs_book_cache *tbc = inode->i_mapping->private_data;
	struct tmfs_book2lza_data *b2l_book_data;
	unsigned long shelf_book_num;
	int ret;

	PR_VERBOSE2("%s(enter)\n", __func__);

	if (tbc == NULL) {
		/* This is really a bug, but a BUG_ON crash doesn't help.
		   Without caching, every page fault will call user space,
		   MAJOR FAULTS will be a large number, and performance
		   will suck.  But it will work.
		*/
		pr_err("%s: ASmapping->private_data == NULL\n", __func__);
		return;
	}

	shelf_book_num = (file_byteoff / G->book_size);

	/* Perhaps it's already cached?  This was called with down_write(). */

	b2l_book_data = radix_tree_lookup(&tbc->book2lza_root, shelf_book_num);

	PR_VERBOSE2("    shelf_book_num = %lu -> b2l_book_data = 0x%p\n",
		shelf_book_num, b2l_book_data);

	if (b2l_book_data != NULL)
		return;

	/* Nope.  Save the base physical address of this book.  It may be
	   a direct map address or an aperture slot depending on address
	   mode.  For caching purposes it doesn't matter.
	*/

	PR_VERBOSE2("    book2lza cache miss, inserting now\n");

	b2l_book_data = kmalloc(sizeof(struct tmfs_book2lza_data), GFP_KERNEL);

	if (b2l_book_data == NULL)
		/* Again, not a bug, but performance will take a hit */
		pr_warn("%s: kmalloc(book2lza) failed\n", __func__);
	else {
		b2l_book_data->lza = lza;
		b2l_book_data->book_phys = (map_addr - (map_addr % G->book_size));
		ret = radix_tree_insert(
			&tbc->book2lza_root, shelf_book_num, b2l_book_data);
		PR_VERBOSE2("    new book2lza (0x%p), book_phys = 0x%llx, lza = 0x%llx\n",
			b2l_book_data,
			b2l_book_data->book_phys,
			b2l_book_data->lza);
	}
}

/* MAP_POPULATE, lite version.   Get all the book LZA data now
   and preload the radix tree.  No, don't actually map it, just
   avoid future trips to user space on faults.  Binary data is
   returned.  Even though it's not needed for G.addr_mode == FALLBACK,
   do it anyhow to pay the price seen by "real" mmap modes.
*/
int lfs_book2lza_populate(struct inode *inode,
			  unsigned long file_byteoff,
			  unsigned long file_bytes)
{
	unsigned long shelf_book_num, PABO;	// Page-Aligned Byte Offset
	int nbooks, nbytes, ret;

	// MFT: 40 nodes == 20,000 books.  Each element of the response array
	// is one 64 bit book LZA.  It "feels right" to get at least
	// 50 books in a pass.  This comes off the kernel stack of 8k so 
	// go easy.  64 uint64_t == 512 bytes of that space.  Then a
	// "worst case" mapping of 10k books -> 10k / 64 == 156 round trips.

	uint64_t response[64];

	PR_VERBOSE2("%s(%lu bytes @ offset 0x%lx)\n",
		__func__, file_bytes, file_byteoff);

	shelf_book_num = file_byteoff % G->book_size;
	nbooks = (file_bytes / G->book_size) + 1;

	PABO = ret = 0;
	down_write(&lfs_book2lza_rw_sema);
	do {
		char request[64];
		unsigned int i, wanted_bytes;

		wanted_bytes = nbooks * sizeof(response[0]);
		i = sizeof(response);
		if (wanted_bytes > i)
			wanted_bytes = i;

		snprintf(request, sizeof(request), "%s,%lu,%u",
			"_obtain_lza_for_map_populate",
			shelf_book_num, wanted_bytes);
		nbytes = spoof_getxattr(
			inode, request, response, sizeof(response));
		if (nbytes < 0) {
			ret = nbytes;
			break;
		}
		if (!strncmp((char *)response, "ERROR", 5)) {
			ret = -ENOTTY;
			break;
		}

		// for each uint64_t in the response array:
		//    reconstruct the LZA, get a map_addr, and cache them
		for (i = 0; i < nbytes / sizeof(response[0]); i++) {
			unsigned long bookID, map_addr;

			bookID = (unsigned long)(response[i]);
			PR_VERBOSE2("   book %5lu @ LZA 0x%p\n",
				shelf_book_num, (void *)bookID);

			// This specifically does NOT do obtain_desbk_slot!
			// The intent of this exercise is to avoid user
			// space interaction in page faults.
			ret = lfs_modal_lza2map_addr(PABO, bookID, &map_addr);
			if (ret < 0)
				break;
			lfs_book2lza_cache(inode, PABO, bookID, map_addr);

			shelf_book_num++;
			PABO += G->book_size;
			nbooks--;
		}
	} while (nbooks > 0 && !ret && nbytes && nbytes == sizeof(response));
	up_write(&lfs_book2lza_rw_sema);
	return ret;	// Leave the forward progress in the LZA cache
}
			
/**
 * lfs_book2lza_lookup - search for cached book data
 * @inode:	The file, has the ASmapping
 * @file_byteoff: byte offset into shelf
 * @lza:        LZA of book if match is found, in all address modes
 * @map_addr:   map_addr for page if match is found, in FAME address modes
 *
 * A read or write lock on the rw_sema must be held by the caller.
 * FIXME: can I move those mechanics in here and the other lfs_book2lza_xxxx?
 * Invoked from the fault handler; searches for cached book data from the
 * first fault of a page in the given book. If cached data is found,
 * calculate and return the physical address to map for fault resolution.
 * Zero is returned if no match is found, else 1.
 */

int lfs_book2lza_lookup(
	struct inode *inode,
	unsigned long file_byteoff,
	unsigned long *lza,
	unsigned long *map_addr)
{
	struct tmfs_book_cache *tbc = inode->i_mapping->private_data;
	struct tmfs_book2lza_data *book_data;
	unsigned long shelf_book_num;

	PR_VERBOSE2("%s(enter)\n", __func__);

	if (!tbc) {
		pr_err("%s: private_data == NULL\n", __func__);
		return 0;
	}
	shelf_book_num = (file_byteoff / G->book_size);

	book_data = radix_tree_lookup(&tbc->book2lza_root, shelf_book_num);

	PR_VERBOSE2("    shelf_book_num = %lu -> b2l_book_data = 0x%p\n", 
		shelf_book_num, book_data);

	if (book_data == NULL) {
		PR_VERBOSE2("    book2lza cache miss\n");
		return 0;
	}
	*lza = book_data->lza;
	*map_addr = (book_data->book_phys + (file_byteoff % G->book_size));

	PR_VERBOSE2("    book2lza cache hit (0x%p), lza = 0x%lx, book_phys = 0x%llx, map_addr = 0x%lx\n",
		book_data, *lza, book_data->book_phys, *map_addr);

	return 1;
}

/**
 * lfs_book2lza_teardown - delete LZA cache radix tree, usually on file removal
 * @inode:      inode structure for file being removed
 *
 * Invoked on file unlink to tear down file radix trees
 * A write lock on the rw_sema must be held by the caller.
 * FIXME: can I move those mechanics in here and the other lfs_book2lza_xxxx?
 */

void lfs_book2lza_teardown(
	struct inode *inode)
{
	struct tmfs_book_cache *tbc = inode->i_mapping->private_data;
	struct radix_tree_iter iter;
	void *rd;
	void **slot;

	PR_VERBOSE2("%s(enter)\n", __func__);

	/* tbc can be NULL for renamed files (lfs zeroing process) */
	if (!tbc)
		return;

	/* There's no documented way to cleanup and delete the root pointer.
	   Reuse is highly probable but FIXME it poses a memory leak. */

	radix_tree_for_each_slot(slot, &tbc->book2lza_root, &iter, 0) {
		rd = radix_tree_delete(&tbc->book2lza_root, iter.index);
		kfree(rd);
		PR_VERBOSE2("    iter.index = %lu, book2lza rd = 0x%p)\n",
			iter.index, rd);
	}
}

