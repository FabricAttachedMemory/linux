/*
  LFS: Plagiarized, modified routines to be included in tables in file.c.
  These all have (external) declarations in tmfs_i.h.

  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/* LFS additions to file.c */

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

ssize_t lfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	struct tmfs_conn *fc = get_tmfs_conn(inode);
	ssize_t retval = 0;

	/*
	 * In auto invalidate mode, always update attributes on read.
	 * Otherwise, only update if we attempt to read past EOF (to ensure
	 * i_size is up to date).
	 */
	if (fc->auto_inval_data ||
	    (iocb->ki_pos + iov_iter_count(to) > i_size_read(inode))) {
		int err;
		err = tmfs_update_attributes(inode, NULL, iocb->ki_filp, NULL);
		if (err)
			return err;
	}

	retval = lfs_file_read_write(iocb, to);

	/* Return status or fall through for legacy handling */
	if (retval != -EINVAL)
		return retval;

	return generic_file_read_iter(iocb, to);
}

ssize_t lfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	ssize_t written = 0;
	ssize_t written_buffered = 0;
	struct inode *inode = mapping->host;
	ssize_t err;
	loff_t endbyte = 0;
	ssize_t retval = 0;

	if (get_tmfs_conn(inode)->writeback_cache) {
		/* Update size (EOF optimization) and mode (SUID clearing) */
		err = tmfs_update_attributes(mapping->host, NULL, file, NULL);
		if (err)
			return err;

		inode_lock(inode);
		retval = lfs_file_read_write(iocb, from);
		inode_unlock(inode);

		/* Return status or fall through for legacy handling */
		if (retval != -EINVAL)
			return retval;

		return generic_file_write_iter(iocb, from);
	}

	lfs_book2lza_setup(file);	// Greg, why is this done here? dir.c?
	inode_lock(inode);
	retval = lfs_file_read_write(iocb, from);
	inode_unlock(inode);

	/* Return status or fall through for legacy handling */
	if (retval != -EINVAL)
		return retval;

	inode_lock(inode);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);

	err = generic_write_checks(iocb, from);
	if (err <= 0)
		goto out;

	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {
		loff_t pos = iocb->ki_pos;
		written = generic_file_direct_write(iocb, from);
		if (written < 0 || !iov_iter_count(from))
			goto out;

		pos += written;

		written_buffered = tmfs_perform_write(file, mapping, from, pos);
		if (written_buffered < 0) {
			err = written_buffered;
			goto out;
		}
		endbyte = pos + written_buffered - 1;

		err = filemap_write_and_wait_range(file->f_mapping, pos,
						   endbyte);
		if (err)
			goto out;

		invalidate_mapping_pages(file->f_mapping,
					 pos >> PAGE_SHIFT,
					 endbyte >> PAGE_SHIFT);

		written += written_buffered;
		iocb->ki_pos = pos + written_buffered;
	} else {
		written = tmfs_perform_write(file, mapping, from, iocb->ki_pos);
		if (written >= 0)
			iocb->ki_pos += written;
	}
out:
	current->backing_dev_info = NULL;
	inode_unlock(inode);

	return written ? written : err;
}

/*
 * Write back dirty pages now, because there may not be any suitable
 * open files later. LFS: not static so lfs.c can see it.
 */
void lfs_vma_close(struct vm_area_struct *vma)
{
	PR_VERBOSE2("lfs_vma_close() vma = 0x%p\n", vma);

	filemap_write_and_wait(vma->vm_file->f_mapping);

	lfs_remove_vma_from_list_global(vma);
}

int lfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_mapping->host;
	unsigned long nbytes;
	int ret;

	PR_VERBOSE2("%s(enter)\n", __func__);

	lfs_book2lza_setup(file);	// Greg, why is this done here? dir.c?

	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		tmfs_link_write_file(file);

	file_accessed(file);
	vma->vm_ops = &tmfs_file_vm_ops;

	// dump_stack();

	nbytes = (unsigned long)(vma->vm_end) - (unsigned long)(vma->vm_start);
	ret = lfs_book2lza_populate(inode, vma->vm_pgoff << PAGE_SHIFT, nbytes);
	if (ret < 0)
		return ret;

	/*
	The flags are partially from mm/mmap.h definition of VM_SPECIAL.
	VM_PFNMAP is held off until fault resolution in lfs.c.
	Any one of these flags will circumvent mmapc.::vma_merge().
	Additionally, the presence of vm_ops->vma_close will halt others
	since it's ass-u-med that does per-vma cleanup and maybe the
	rest of the kernel should not mess with it.

	VM_IO		Owned by device driver, not for casual/normal mem use
	VM_DONTEXPAND	Disable merge/expand by mremap, see remap_pfn_range
	VM_DONTDUMP	Omit from core dump
	VM_PFNMAP	Will be set when mapping actually occurs in lfs.c
	*/
	
	vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;

	PR_VERBOSE2("    vma = 0x%p, flags = 0x%lu\n", vma, vma->vm_flags);
	PR_VERBOSE2("    vm_start = 0x%lx, vm_end = 0x%lx\n",
		vma->vm_start, vma->vm_end);

	return 0;
}
