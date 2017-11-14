/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "tmfs_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/parser.h>
#include <linux/statfs.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/exportfs.h>
#include <linux/posix_acl.h>
#include <linux/pid_namespace.h>

MODULE_AUTHOR("Miklos Szeredi <miklos@szeredi.hu>");
MODULE_DESCRIPTION("Filesystem in Userspace");
MODULE_LICENSE("GPL");

static struct kmem_cache *tmfs_inode_cachep;
struct list_head tmfs_conn_list;
DEFINE_MUTEX(tmfs_mutex);

static int set_global_limit(const char *val, struct kernel_param *kp);

unsigned max_user_bgreq;
module_param_call(max_user_bgreq, set_global_limit, param_get_uint,
		  &max_user_bgreq, 0644);
__MODULE_PARM_TYPE(max_user_bgreq, "uint");
MODULE_PARM_DESC(max_user_bgreq,
 "Global limit for the maximum number of backgrounded requests an "
 "unprivileged user can set");

unsigned max_user_congthresh;
module_param_call(max_user_congthresh, set_global_limit, param_get_uint,
		  &max_user_congthresh, 0644);
__MODULE_PARM_TYPE(max_user_congthresh, "uint");
MODULE_PARM_DESC(max_user_congthresh,
 "Global limit for the maximum congestion threshold an "
 "unprivileged user can set");

#define TMFS_SUPER_MAGIC 0x65735546

#define TMFS_DEFAULT_BLKSIZE 512

/** Maximum number of outstanding background requests */
#define TMFS_DEFAULT_MAX_BACKGROUND 12

/** Congestion starts at 75% of maximum */
#define TMFS_DEFAULT_CONGESTION_THRESHOLD (TMFS_DEFAULT_MAX_BACKGROUND * 3 / 4)

struct tmfs_mount_data {
	int fd;
	unsigned rootmode;
	kuid_t user_id;
	kgid_t group_id;
	unsigned fd_present:1;
	unsigned rootmode_present:1;
	unsigned user_id_present:1;
	unsigned group_id_present:1;
	unsigned default_permissions:1;
	unsigned allow_other:1;
	unsigned max_read;
	unsigned blksize;
};

struct tmfs_forget_link *tmfs_alloc_forget(void)
{
	return kzalloc(sizeof(struct tmfs_forget_link), GFP_KERNEL);
}

static struct inode *tmfs_alloc_inode(struct super_block *sb)
{
	struct inode *inode;
	struct tmfs_inode *fi;

	inode = kmem_cache_alloc(tmfs_inode_cachep, GFP_KERNEL);
	if (!inode)
		return NULL;

	fi = get_tmfs_inode(inode);
	fi->i_time = 0;
	fi->nodeid = 0;
	fi->nlookup = 0;
	fi->attr_version = 0;
	fi->writectr = 0;
	fi->orig_ino = 0;
	fi->state = 0;
	INIT_LIST_HEAD(&fi->write_files);
	INIT_LIST_HEAD(&fi->queued_writes);
	INIT_LIST_HEAD(&fi->writepages);
	init_waitqueue_head(&fi->page_waitq);
	mutex_init(&fi->mutex);
	fi->forget = tmfs_alloc_forget();
	if (!fi->forget) {
		kmem_cache_free(tmfs_inode_cachep, inode);
		return NULL;
	}

	return inode;
}

static void tmfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(tmfs_inode_cachep, inode);
}

static void tmfs_destroy_inode(struct inode *inode)
{
	struct tmfs_inode *fi = get_tmfs_inode(inode);
	BUG_ON(!list_empty(&fi->write_files));
	BUG_ON(!list_empty(&fi->queued_writes));
	mutex_destroy(&fi->mutex);
	kfree(fi->forget);
	call_rcu(&inode->i_rcu, tmfs_i_callback);
}

static void tmfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (inode->i_sb->s_flags & MS_ACTIVE) {
		struct tmfs_conn *fc = get_tmfs_conn(inode);
		struct tmfs_inode *fi = get_tmfs_inode(inode);
		tmfs_queue_forget(fc, fi->forget, fi->nodeid, fi->nlookup);
		fi->forget = NULL;
	}
}

static int tmfs_remount_fs(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	if (*flags & MS_MANDLOCK)
		return -EINVAL;

	return 0;
}

/*
 * ino_t is 32-bits on 32-bit arch. We have to squash the 64-bit value down
 * so that it will fit.
 */
static ino_t tmfs_squash_ino(u64 ino64)
{
	ino_t ino = (ino_t) ino64;
	if (sizeof(ino_t) < sizeof(u64))
		ino ^= ino64 >> (sizeof(u64) - sizeof(ino_t)) * 8;
	return ino;
}

void tmfs_change_attributes_common(struct inode *inode, struct tmfs_attr *attr,
				   u64 attr_valid)
{
	struct tmfs_conn *fc = get_tmfs_conn(inode);
	struct tmfs_inode *fi = get_tmfs_inode(inode);

	fi->attr_version = ++fc->attr_version;
	fi->i_time = attr_valid;

	inode->i_ino     = tmfs_squash_ino(attr->ino);
	inode->i_mode    = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	set_nlink(inode, attr->nlink);
	inode->i_uid     = make_kuid(&init_user_ns, attr->uid);
	inode->i_gid     = make_kgid(&init_user_ns, attr->gid);
	inode->i_blocks  = attr->blocks;
	inode->i_atime.tv_sec   = attr->atime;
	inode->i_atime.tv_nsec  = attr->atimensec;
	/* mtime from server may be stale due to local buffered write */
	if (!fc->writeback_cache || !S_ISREG(inode->i_mode)) {
		inode->i_mtime.tv_sec   = attr->mtime;
		inode->i_mtime.tv_nsec  = attr->mtimensec;
		inode->i_ctime.tv_sec   = attr->ctime;
		inode->i_ctime.tv_nsec  = attr->ctimensec;
	}

	if (attr->blksize != 0)
		inode->i_blkbits = ilog2(attr->blksize);
	else
		inode->i_blkbits = inode->i_sb->s_blocksize_bits;

	/*
	 * Don't set the sticky bit in i_mode, unless we want the VFS
	 * to check permissions.  This prevents failures due to the
	 * check in may_delete().
	 */
	fi->orig_i_mode = inode->i_mode;
	if (!fc->default_permissions)
		inode->i_mode &= ~S_ISVTX;

	fi->orig_ino = attr->ino;
}

void tmfs_change_attributes(struct inode *inode, struct tmfs_attr *attr,
			    u64 attr_valid, u64 attr_version)
{
	struct tmfs_conn *fc = get_tmfs_conn(inode);
	struct tmfs_inode *fi = get_tmfs_inode(inode);
	bool is_wb = fc->writeback_cache;
	loff_t oldsize;
	struct timespec old_mtime;

	spin_lock(&fc->lock);
	if ((attr_version != 0 && fi->attr_version > attr_version) ||
	    test_bit(TMFS_I_SIZE_UNSTABLE, &fi->state)) {
		spin_unlock(&fc->lock);
		return;
	}

	old_mtime = inode->i_mtime;
	tmfs_change_attributes_common(inode, attr, attr_valid);

	oldsize = inode->i_size;
	/*
	 * In case of writeback_cache enabled, the cached writes beyond EOF
	 * extend local i_size without keeping userspace server in sync. So,
	 * attr->size coming from server can be stale. We cannot trust it.
	 */
	if (!is_wb || !S_ISREG(inode->i_mode))
		i_size_write(inode, attr->size);
	spin_unlock(&fc->lock);

	if (!is_wb && S_ISREG(inode->i_mode)) {
		bool inval = false;

		if (oldsize != attr->size) {
			truncate_pagecache(inode, attr->size);
			inval = true;
		} else if (fc->auto_inval_data) {
			struct timespec new_mtime = {
				.tv_sec = attr->mtime,
				.tv_nsec = attr->mtimensec,
			};

			/*
			 * Auto inval mode also checks and invalidates if mtime
			 * has changed.
			 */
			if (!timespec_equal(&old_mtime, &new_mtime))
				inval = true;
		}

		if (inval)
			invalidate_inode_pages2(inode->i_mapping);
	}
}

static void tmfs_init_inode(struct inode *inode, struct tmfs_attr *attr)
{
	inode->i_mode = attr->mode & S_IFMT;
	inode->i_size = attr->size;
	inode->i_mtime.tv_sec  = attr->mtime;
	inode->i_mtime.tv_nsec = attr->mtimensec;
	inode->i_ctime.tv_sec  = attr->ctime;
	inode->i_ctime.tv_nsec = attr->ctimensec;
	if (S_ISREG(inode->i_mode)) {
		tmfs_init_common(inode);
		tmfs_init_file_inode(inode);
	} else if (S_ISDIR(inode->i_mode))
		tmfs_init_dir(inode);
	else if (S_ISLNK(inode->i_mode))
		tmfs_init_symlink(inode);
	else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		 S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		tmfs_init_common(inode);
		init_special_inode(inode, inode->i_mode,
				   new_decode_dev(attr->rdev));
	} else
		BUG();
}

int tmfs_inode_eq(struct inode *inode, void *_nodeidp)
{
	u64 nodeid = *(u64 *) _nodeidp;
	if (get_node_id(inode) == nodeid)
		return 1;
	else
		return 0;
}

static int tmfs_inode_set(struct inode *inode, void *_nodeidp)
{
	u64 nodeid = *(u64 *) _nodeidp;
	get_tmfs_inode(inode)->nodeid = nodeid;
	return 0;
}

struct inode *tmfs_iget(struct super_block *sb, u64 nodeid,
			int generation, struct tmfs_attr *attr,
			u64 attr_valid, u64 attr_version)
{
	struct inode *inode;
	struct tmfs_inode *fi;
	struct tmfs_conn *fc = get_tmfs_conn_super(sb);

 retry:
	inode = iget5_locked(sb, nodeid, tmfs_inode_eq, tmfs_inode_set, &nodeid);
	if (!inode)
		return NULL;

	if ((inode->i_state & I_NEW)) {
		inode->i_flags |= S_NOATIME;
		if (!fc->writeback_cache || !S_ISREG(attr->mode))
			inode->i_flags |= S_NOCMTIME;
		inode->i_generation = generation;
		tmfs_init_inode(inode, attr);
		unlock_new_inode(inode);
	} else if ((inode->i_mode ^ attr->mode) & S_IFMT) {
		/* Inode has changed type, any I/O on the old should fail */
		make_bad_inode(inode);
		iput(inode);
		goto retry;
	}

	fi = get_tmfs_inode(inode);
	spin_lock(&fc->lock);
	fi->nlookup++;
	spin_unlock(&fc->lock);
	tmfs_change_attributes(inode, attr, attr_valid, attr_version);

	return inode;
}

int tmfs_reverse_inval_inode(struct super_block *sb, u64 nodeid,
			     loff_t offset, loff_t len)
{
	struct inode *inode;
	pgoff_t pg_start;
	pgoff_t pg_end;

	inode = ilookup5(sb, nodeid, tmfs_inode_eq, &nodeid);
	if (!inode)
		return -ENOENT;

	tmfs_invalidate_attr(inode);
	forget_all_cached_acls(inode);
	if (offset >= 0) {
		pg_start = offset >> PAGE_SHIFT;
		if (len <= 0)
			pg_end = -1;
		else
			pg_end = (offset + len - 1) >> PAGE_SHIFT;
		invalidate_inode_pages2_range(inode->i_mapping,
					      pg_start, pg_end);
	}
	iput(inode);
	return 0;
}

void tmfs_lock_inode(struct inode *inode)
{
	if (!get_tmfs_conn(inode)->parallel_dirops)
		mutex_lock(&get_tmfs_inode(inode)->mutex);
}

void tmfs_unlock_inode(struct inode *inode)
{
	if (!get_tmfs_conn(inode)->parallel_dirops)
		mutex_unlock(&get_tmfs_inode(inode)->mutex);
}

static void tmfs_umount_begin(struct super_block *sb)
{
	tmfs_abort_conn(get_tmfs_conn_super(sb));

	// LFS: clear globals in expectation of an lfs_fuse.py restart
	lfs_obtain_globals(NULL);
}

static void tmfs_send_destroy(struct tmfs_conn *fc)
{
	struct tmfs_req *req = fc->destroy_req;
	if (req && fc->conn_init) {
		fc->destroy_req = NULL;
		req->in.h.opcode = TMFS_DESTROY;
		__set_bit(FR_FORCE, &req->flags);
		__clear_bit(FR_BACKGROUND, &req->flags);
		tmfs_request_send(fc, req);
		tmfs_put_request(fc, req);
	}
}

static void tmfs_put_super(struct super_block *sb)
{
	struct tmfs_conn *fc = get_tmfs_conn_super(sb);

	tmfs_send_destroy(fc);

	tmfs_abort_conn(fc);
	mutex_lock(&tmfs_mutex);
	list_del(&fc->entry);
	tmfs_ctl_remove_conn(fc);
	mutex_unlock(&tmfs_mutex);

	tmfs_conn_put(fc);
}

static void convert_tmfs_statfs(struct kstatfs *stbuf, struct tmfs_kstatfs *attr)
{
	stbuf->f_type    = TMFS_SUPER_MAGIC;
	stbuf->f_bsize   = attr->bsize;
	stbuf->f_frsize  = attr->frsize;
	stbuf->f_blocks  = attr->blocks;
	stbuf->f_bfree   = attr->bfree;
	stbuf->f_bavail  = attr->bavail;
	stbuf->f_files   = attr->files;
	stbuf->f_ffree   = attr->ffree;
	stbuf->f_namelen = attr->namelen;
	/* fsid is left zero */
}

static int tmfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct tmfs_conn *fc = get_tmfs_conn_super(sb);
	TMFS_ARGS(args);
	struct tmfs_statfs_out outarg;
	int err;

	if (!tmfs_allow_current_process(fc)) {
		buf->f_type = TMFS_SUPER_MAGIC;
		return 0;
	}

	memset(&outarg, 0, sizeof(outarg));
	args.in.numargs = 0;
	args.in.h.opcode = TMFS_STATFS;
	args.in.h.nodeid = get_node_id(d_inode(dentry));
	args.out.numargs = 1;
	args.out.args[0].size = sizeof(outarg);
	args.out.args[0].value = &outarg;
	err = tmfs_simple_request(fc, &args);
	if (!err)
		convert_tmfs_statfs(buf, &outarg.st);
	return err;
}

enum {
	OPT_FD,
	OPT_ROOTMODE,
	OPT_USER_ID,
	OPT_GROUP_ID,
	OPT_DEFAULT_PERMISSIONS,
	OPT_ALLOW_OTHER,
	OPT_MAX_READ,
	OPT_BLKSIZE,
	OPT_ERR
};

static const match_table_t tokens = {
	{OPT_FD,			"fd=%u"},
	{OPT_ROOTMODE,			"rootmode=%o"},
	{OPT_USER_ID,			"user_id=%u"},
	{OPT_GROUP_ID,			"group_id=%u"},
	{OPT_DEFAULT_PERMISSIONS,	"default_permissions"},
	{OPT_ALLOW_OTHER,		"allow_other"},
	{OPT_MAX_READ,			"max_read=%u"},
	{OPT_BLKSIZE,			"blksize=%u"},
	{OPT_ERR,			NULL}
};

static int tmfs_match_uint(substring_t *s, unsigned int *res)
{
	int err = -ENOMEM;
	char *buf = match_strdup(s);
	if (buf) {
		err = kstrtouint(buf, 10, res);
		kfree(buf);
	}
	return err;
}

static int parse_tmfs_opt(char *opt, struct tmfs_mount_data *d, int is_bdev)
{
	char *p;
	memset(d, 0, sizeof(struct tmfs_mount_data));
	d->max_read = ~0;
	d->blksize = TMFS_DEFAULT_BLKSIZE;

	while ((p = strsep(&opt, ",")) != NULL) {
		int token;
		int value;
		unsigned uv;
		substring_t args[MAX_OPT_ARGS];
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case OPT_FD:
			if (match_int(&args[0], &value))
				return 0;
			d->fd = value;
			d->fd_present = 1;
			break;

		case OPT_ROOTMODE:
			if (match_octal(&args[0], &value))
				return 0;
			if (!tmfs_valid_type(value))
				return 0;
			d->rootmode = value;
			d->rootmode_present = 1;
			break;

		case OPT_USER_ID:
			if (tmfs_match_uint(&args[0], &uv))
				return 0;
			d->user_id = make_kuid(current_user_ns(), uv);
			if (!uid_valid(d->user_id))
				return 0;
			d->user_id_present = 1;
			break;

		case OPT_GROUP_ID:
			if (tmfs_match_uint(&args[0], &uv))
				return 0;
			d->group_id = make_kgid(current_user_ns(), uv);
			if (!gid_valid(d->group_id))
				return 0;
			d->group_id_present = 1;
			break;

		case OPT_DEFAULT_PERMISSIONS:
			d->default_permissions = 1;
			break;

		case OPT_ALLOW_OTHER:
			d->allow_other = 1;
			break;

		case OPT_MAX_READ:
			if (match_int(&args[0], &value))
				return 0;
			d->max_read = value;
			break;

		case OPT_BLKSIZE:
			if (!is_bdev || match_int(&args[0], &value))
				return 0;
			d->blksize = value;
			break;

		default:
			return 0;
		}
	}

	if (!d->fd_present || !d->rootmode_present ||
	    !d->user_id_present || !d->group_id_present)
		return 0;

	return 1;
}

static int tmfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct tmfs_conn *fc = get_tmfs_conn_super(sb);

	seq_printf(m, ",user_id=%u", from_kuid_munged(&init_user_ns, fc->user_id));
	seq_printf(m, ",group_id=%u", from_kgid_munged(&init_user_ns, fc->group_id));
	if (fc->default_permissions)
		seq_puts(m, ",default_permissions");
	if (fc->allow_other)
		seq_puts(m, ",allow_other");
	if (fc->max_read != ~0)
		seq_printf(m, ",max_read=%u", fc->max_read);
	if (sb->s_bdev && sb->s_blocksize != TMFS_DEFAULT_BLKSIZE)
		seq_printf(m, ",blksize=%lu", sb->s_blocksize);
	return 0;
}

static void tmfs_iqueue_init(struct tmfs_iqueue *fiq)
{
	memset(fiq, 0, sizeof(struct tmfs_iqueue));
	init_waitqueue_head(&fiq->waitq);
	INIT_LIST_HEAD(&fiq->pending);
	INIT_LIST_HEAD(&fiq->interrupts);
	fiq->forget_list_tail = &fiq->forget_list_head;
	fiq->connected = 1;
}

static void tmfs_pqueue_init(struct tmfs_pqueue *fpq)
{
	memset(fpq, 0, sizeof(struct tmfs_pqueue));
	spin_lock_init(&fpq->lock);
	INIT_LIST_HEAD(&fpq->processing);
	INIT_LIST_HEAD(&fpq->io);
	fpq->connected = 1;
}

void tmfs_conn_init(struct tmfs_conn *fc)
{
	memset(fc, 0, sizeof(*fc));
	spin_lock_init(&fc->lock);
	init_rwsem(&fc->killsb);
	refcount_set(&fc->count, 1);
	atomic_set(&fc->dev_count, 1);
	init_waitqueue_head(&fc->blocked_waitq);
	init_waitqueue_head(&fc->reserved_req_waitq);
	tmfs_iqueue_init(&fc->iq);
	INIT_LIST_HEAD(&fc->bg_queue);
	INIT_LIST_HEAD(&fc->entry);
	INIT_LIST_HEAD(&fc->devices);
	atomic_set(&fc->num_waiting, 0);
	fc->max_background = TMFS_DEFAULT_MAX_BACKGROUND;
	fc->congestion_threshold = TMFS_DEFAULT_CONGESTION_THRESHOLD;
	fc->khctr = 0;
	fc->polled_files = RB_ROOT;
	fc->blocked = 0;
	fc->initialized = 0;
	fc->connected = 1;
	fc->attr_version = 1;
	get_random_bytes(&fc->scramble_key, sizeof(fc->scramble_key));
	fc->pid_ns = get_pid_ns(task_active_pid_ns(current));
}
EXPORT_SYMBOL_GPL(tmfs_conn_init);

void tmfs_conn_put(struct tmfs_conn *fc)
{
	if (refcount_dec_and_test(&fc->count)) {
		if (fc->destroy_req)
			tmfs_request_free(fc->destroy_req);
		put_pid_ns(fc->pid_ns);
		fc->release(fc);
	}
}
EXPORT_SYMBOL_GPL(tmfs_conn_put);

struct tmfs_conn *tmfs_conn_get(struct tmfs_conn *fc)
{
	refcount_inc(&fc->count);
	return fc;
}
EXPORT_SYMBOL_GPL(tmfs_conn_get);

static struct inode *tmfs_get_root_inode(struct super_block *sb, unsigned mode)
{
	struct tmfs_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.mode = mode;
	attr.ino = TMFS_ROOT_ID;
	attr.nlink = 1;
	return tmfs_iget(sb, 1, 0, &attr, 0, 0);
}

struct tmfs_inode_handle {
	u64 nodeid;
	u32 generation;
};

static struct dentry *tmfs_get_dentry(struct super_block *sb,
				      struct tmfs_inode_handle *handle)
{
	struct tmfs_conn *fc = get_tmfs_conn_super(sb);
	struct inode *inode;
	struct dentry *entry;
	int err = -ESTALE;

	if (handle->nodeid == 0)
		goto out_err;

	inode = ilookup5(sb, handle->nodeid, tmfs_inode_eq, &handle->nodeid);
	if (!inode) {
		struct tmfs_entry_out outarg;
		const struct qstr name = QSTR_INIT(".", 1);

		if (!fc->export_support)
			goto out_err;

		err = tmfs_lookup_name(sb, handle->nodeid, &name, &outarg,
				       &inode);
		if (err && err != -ENOENT)
			goto out_err;
		if (err || !inode) {
			err = -ESTALE;
			goto out_err;
		}
		err = -EIO;
		if (get_node_id(inode) != handle->nodeid)
			goto out_iput;
	}
	err = -ESTALE;
	if (inode->i_generation != handle->generation)
		goto out_iput;

	entry = d_obtain_alias(inode);
	if (!IS_ERR(entry) && get_node_id(inode) != TMFS_ROOT_ID)
		tmfs_invalidate_entry_cache(entry);

	return entry;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

static int tmfs_encode_fh(struct inode *inode, u32 *fh, int *max_len,
			   struct inode *parent)
{
	int len = parent ? 6 : 3;
	u64 nodeid;
	u32 generation;

	if (*max_len < len) {
		*max_len = len;
		return  FILEID_INVALID;
	}

	nodeid = get_tmfs_inode(inode)->nodeid;
	generation = inode->i_generation;

	fh[0] = (u32)(nodeid >> 32);
	fh[1] = (u32)(nodeid & 0xffffffff);
	fh[2] = generation;

	if (parent) {
		nodeid = get_tmfs_inode(parent)->nodeid;
		generation = parent->i_generation;

		fh[3] = (u32)(nodeid >> 32);
		fh[4] = (u32)(nodeid & 0xffffffff);
		fh[5] = generation;
	}

	*max_len = len;
	return parent ? 0x82 : 0x81;
}

static struct dentry *tmfs_fh_to_dentry(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	struct tmfs_inode_handle handle;

	if ((fh_type != 0x81 && fh_type != 0x82) || fh_len < 3)
		return NULL;

	handle.nodeid = (u64) fid->raw[0] << 32;
	handle.nodeid |= (u64) fid->raw[1];
	handle.generation = fid->raw[2];
	return tmfs_get_dentry(sb, &handle);
}

static struct dentry *tmfs_fh_to_parent(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	struct tmfs_inode_handle parent;

	if (fh_type != 0x82 || fh_len < 6)
		return NULL;

	parent.nodeid = (u64) fid->raw[3] << 32;
	parent.nodeid |= (u64) fid->raw[4];
	parent.generation = fid->raw[5];
	return tmfs_get_dentry(sb, &parent);
}

static struct dentry *tmfs_get_parent(struct dentry *child)
{
	struct inode *child_inode = d_inode(child);
	struct tmfs_conn *fc = get_tmfs_conn(child_inode);
	struct inode *inode;
	struct dentry *parent;
	struct tmfs_entry_out outarg;
	const struct qstr name = QSTR_INIT("..", 2);
	int err;

	if (!fc->export_support)
		return ERR_PTR(-ESTALE);

	err = tmfs_lookup_name(child_inode->i_sb, get_node_id(child_inode),
			       &name, &outarg, &inode);
	if (err) {
		if (err == -ENOENT)
			return ERR_PTR(-ESTALE);
		return ERR_PTR(err);
	}

	parent = d_obtain_alias(inode);
	if (!IS_ERR(parent) && get_node_id(inode) != TMFS_ROOT_ID)
		tmfs_invalidate_entry_cache(parent);

	return parent;
}

static const struct export_operations tmfs_export_operations = {
	.fh_to_dentry	= tmfs_fh_to_dentry,
	.fh_to_parent	= tmfs_fh_to_parent,
	.encode_fh	= tmfs_encode_fh,
	.get_parent	= tmfs_get_parent,
};

static const struct super_operations tmfs_super_operations = {
	.alloc_inode    = tmfs_alloc_inode,
	.destroy_inode  = tmfs_destroy_inode,
	.evict_inode	= tmfs_evict_inode,
	.write_inode	= tmfs_write_inode,
	.drop_inode	= generic_delete_inode,
	.remount_fs	= tmfs_remount_fs,
	.put_super	= tmfs_put_super,
	.umount_begin	= tmfs_umount_begin,
	.statfs		= tmfs_statfs,
	.show_options	= tmfs_show_options,
};

static void sanitize_global_limit(unsigned *limit)
{
	if (*limit == 0)
		*limit = ((totalram_pages << PAGE_SHIFT) >> 13) /
			 sizeof(struct tmfs_req);

	if (*limit >= 1 << 16)
		*limit = (1 << 16) - 1;
}

static int set_global_limit(const char *val, struct kernel_param *kp)
{
	int rv;

	rv = param_set_uint(val, kp);
	if (rv)
		return rv;

	sanitize_global_limit((unsigned *)kp->arg);

	return 0;
}

static void process_init_limits(struct tmfs_conn *fc, struct tmfs_init_out *arg)
{
	int cap_sys_admin = capable(CAP_SYS_ADMIN);

	if (arg->minor < 13)
		return;

	sanitize_global_limit(&max_user_bgreq);
	sanitize_global_limit(&max_user_congthresh);

	if (arg->max_background) {
		fc->max_background = arg->max_background;

		if (!cap_sys_admin && fc->max_background > max_user_bgreq)
			fc->max_background = max_user_bgreq;
	}
	if (arg->congestion_threshold) {
		fc->congestion_threshold = arg->congestion_threshold;

		if (!cap_sys_admin &&
		    fc->congestion_threshold > max_user_congthresh)
			fc->congestion_threshold = max_user_congthresh;
	}
}

static void process_init_reply(struct tmfs_conn *fc, struct tmfs_req *req)
{
	struct tmfs_init_out *arg = &req->misc.init_out;

	if (req->out.h.error || arg->major != TMFS_KERNEL_VERSION)
		fc->conn_error = 1;
	else {
		unsigned long ra_pages;

		process_init_limits(fc, arg);

		if (arg->minor >= 6) {
			ra_pages = arg->max_readahead / PAGE_SIZE;
			if (arg->flags & TMFS_ASYNC_READ)
				fc->async_read = 1;
			if (!(arg->flags & TMFS_POSIX_LOCKS))
				fc->no_lock = 1;
			if (arg->minor >= 17) {
				if (!(arg->flags & TMFS_FLOCK_LOCKS))
					fc->no_flock = 1;
			} else {
				if (!(arg->flags & TMFS_POSIX_LOCKS))
					fc->no_flock = 1;
			}
			if (arg->flags & TMFS_ATOMIC_O_TRUNC)
				fc->atomic_o_trunc = 1;
			if (arg->minor >= 9) {
				/* LOOKUP has dependency on proto version */
				if (arg->flags & TMFS_EXPORT_SUPPORT)
					fc->export_support = 1;
			}
			if (arg->flags & TMFS_BIG_WRITES)
				fc->big_writes = 1;
			if (arg->flags & TMFS_DONT_MASK)
				fc->dont_mask = 1;
			if (arg->flags & TMFS_AUTO_INVAL_DATA)
				fc->auto_inval_data = 1;
			if (arg->flags & TMFS_DO_READDIRPLUS) {
				fc->do_readdirplus = 1;
				if (arg->flags & TMFS_READDIRPLUS_AUTO)
					fc->readdirplus_auto = 1;
			}
			if (arg->flags & TMFS_ASYNC_DIO)
				fc->async_dio = 1;
			if (arg->flags & TMFS_WRITEBACK_CACHE)
				fc->writeback_cache = 1;
			if (arg->flags & TMFS_PARALLEL_DIROPS)
				fc->parallel_dirops = 1;
			if (arg->flags & TMFS_HANDLE_KILLPRIV)
				fc->handle_killpriv = 1;
			if (arg->time_gran && arg->time_gran <= 1000000000)
				fc->sb->s_time_gran = arg->time_gran;
			if ((arg->flags & TMFS_POSIX_ACL)) {
				fc->default_permissions = 1;
				fc->posix_acl = 1;
				fc->sb->s_xattr = tmfs_acl_xattr_handlers;
			}
		} else {
			ra_pages = fc->max_read / PAGE_SIZE;
			fc->no_lock = 1;
			fc->no_flock = 1;
		}

		fc->sb->s_bdi->ra_pages =
				min(fc->sb->s_bdi->ra_pages, ra_pages);
		fc->minor = arg->minor;
		fc->max_write = arg->minor < 5 ? 4096 : arg->max_write;
		fc->max_write = max_t(unsigned, 4096, fc->max_write);
		fc->conn_init = 1;
	}
	tmfs_set_initialized(fc);
	wake_up_all(&fc->blocked_waitq);
}

static void tmfs_send_init(struct tmfs_conn *fc, struct tmfs_req *req)
{
	struct tmfs_init_in *arg = &req->misc.init_in;

	arg->major = TMFS_KERNEL_VERSION;
	arg->minor = TMFS_KERNEL_MINOR_VERSION;
	arg->max_readahead = fc->sb->s_bdi->ra_pages * PAGE_SIZE;
	arg->flags |= TMFS_ASYNC_READ | TMFS_POSIX_LOCKS | TMFS_ATOMIC_O_TRUNC |
		TMFS_EXPORT_SUPPORT | TMFS_BIG_WRITES | TMFS_DONT_MASK |
		TMFS_SPLICE_WRITE | TMFS_SPLICE_MOVE | TMFS_SPLICE_READ |
		TMFS_FLOCK_LOCKS | TMFS_HAS_IOCTL_DIR | TMFS_AUTO_INVAL_DATA |
		TMFS_DO_READDIRPLUS | TMFS_READDIRPLUS_AUTO | TMFS_ASYNC_DIO |
		TMFS_WRITEBACK_CACHE | TMFS_NO_OPEN_SUPPORT |
		TMFS_PARALLEL_DIROPS | TMFS_HANDLE_KILLPRIV | TMFS_POSIX_ACL;
	req->in.h.opcode = TMFS_INIT;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(*arg);
	req->in.args[0].value = arg;
	req->out.numargs = 1;
	/* Variable length argument used for backward compatibility
	   with interface version < 7.5.  Rest of init_out is zeroed
	   by do_get_request(), so a short reply is not a problem */
	req->out.argvar = 1;
	req->out.args[0].size = sizeof(struct tmfs_init_out);
	req->out.args[0].value = &req->misc.init_out;
	req->end = process_init_reply;
	tmfs_request_send_background(fc, req);
}

static void tmfs_free_conn(struct tmfs_conn *fc)
{
	WARN_ON(!list_empty(&fc->devices));
	kfree_rcu(fc, rcu);
}

static int tmfs_bdi_init(struct tmfs_conn *fc, struct super_block *sb)
{
	int err;
	char *suffix = "";

	if (sb->s_bdev) {
		suffix = "-tmfsblk";
		/*
		 * sb->s_bdi points to blkdev's bdi however we want to redirect
		 * it to our private bdi...
		 */
		bdi_put(sb->s_bdi);
		sb->s_bdi = &noop_backing_dev_info;
	}
	err = super_setup_bdi_name(sb, "%u:%u%s", MAJOR(fc->dev),
				   MINOR(fc->dev), suffix);
	if (err)
		return err;

	sb->s_bdi->ra_pages = (VM_MAX_READAHEAD * 1024) / PAGE_SIZE;
	/* tmfs does it's own writeback accounting */
	sb->s_bdi->capabilities = BDI_CAP_NO_ACCT_WB | BDI_CAP_STRICTLIMIT;

	/*
	 * For a single tmfs filesystem use max 1% of dirty +
	 * writeback threshold.
	 *
	 * This gives about 1M of write buffer for memory maps on a
	 * machine with 1G and 10% dirty_ratio, which should be more
	 * than enough.
	 *
	 * Privileged users can raise it by writing to
	 *
	 *    /sys/class/bdi/<bdi>/max_ratio
	 */
	bdi_set_max_ratio(sb->s_bdi, 1);

	return 0;
}

struct tmfs_dev *tmfs_dev_alloc(struct tmfs_conn *fc)
{
	struct tmfs_dev *fud;

	fud = kzalloc(sizeof(struct tmfs_dev), GFP_KERNEL);
	if (fud) {
		fud->fc = tmfs_conn_get(fc);
		tmfs_pqueue_init(&fud->pq);

		spin_lock(&fc->lock);
		list_add_tail(&fud->entry, &fc->devices);
		spin_unlock(&fc->lock);
	}

	return fud;
}
EXPORT_SYMBOL_GPL(tmfs_dev_alloc);

void tmfs_dev_free(struct tmfs_dev *fud)
{
	struct tmfs_conn *fc = fud->fc;

	if (fc) {
		spin_lock(&fc->lock);
		list_del(&fud->entry);
		spin_unlock(&fc->lock);

		tmfs_conn_put(fc);
	}
	kfree(fud);
}
EXPORT_SYMBOL_GPL(tmfs_dev_free);

static int tmfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct tmfs_dev *fud;
	struct tmfs_conn *fc;
	struct inode *root;
	struct tmfs_mount_data d;
	struct file *file;
	struct dentry *root_dentry;
	struct tmfs_req *init_req;
	int err;
	int is_bdev = sb->s_bdev != NULL;

	err = -EINVAL;
	if (sb->s_flags & MS_MANDLOCK)
		goto err;

	sb->s_flags &= ~(MS_NOSEC | MS_I_VERSION);

	if (!parse_tmfs_opt(data, &d, is_bdev))
		goto err;

	if (is_bdev) {
#ifdef CONFIG_BLOCK
		err = -EINVAL;
		if (!sb_set_blocksize(sb, d.blksize))
			goto err;
#endif
	} else {
		sb->s_blocksize = PAGE_SIZE;
		sb->s_blocksize_bits = PAGE_SHIFT;
	}
	sb->s_magic = TMFS_SUPER_MAGIC;
	sb->s_op = &tmfs_super_operations;
	sb->s_xattr = tmfs_xattr_handlers;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;
	sb->s_export_op = &tmfs_export_operations;

	file = fget(d.fd);
	err = -EINVAL;
	if (!file)
		goto err;

	if ((file->f_op != &tmfs_dev_operations) ||
	    (file->f_cred->user_ns != &init_user_ns))
		goto err_fput;

	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	err = -ENOMEM;
	if (!fc)
		goto err_fput;

	tmfs_conn_init(fc);
	fc->release = tmfs_free_conn;

	fud = tmfs_dev_alloc(fc);
	if (!fud)
		goto err_put_conn;

	fc->dev = sb->s_dev;
	fc->sb = sb;
	err = tmfs_bdi_init(fc, sb);
	if (err)
		goto err_dev_free;

	/* Handle umasking inside the tmfs code */
	if (sb->s_flags & MS_POSIXACL)
		fc->dont_mask = 1;
	sb->s_flags |= MS_POSIXACL;

	fc->default_permissions = d.default_permissions;
	fc->allow_other = d.allow_other;
	fc->user_id = d.user_id;
	fc->group_id = d.group_id;
	fc->max_read = max_t(unsigned, 4096, d.max_read);

	/* Used by get_root_inode() */
	sb->s_fs_info = fc;

	err = -ENOMEM;
	root = tmfs_get_root_inode(sb, d.rootmode);
	sb->s_d_op = &tmfs_root_dentry_operations;
	root_dentry = d_make_root(root);
	if (!root_dentry)
		goto err_dev_free;
	/* Root dentry doesn't have .d_revalidate */
	sb->s_d_op = &tmfs_dentry_operations;

	init_req = tmfs_request_alloc(0);
	if (!init_req)
		goto err_put_root;
	__set_bit(FR_BACKGROUND, &init_req->flags);

	if (is_bdev) {
		fc->destroy_req = tmfs_request_alloc(0);
		if (!fc->destroy_req)
			goto err_free_init_req;
	}

	mutex_lock(&tmfs_mutex);
	err = -EINVAL;
	if (file->private_data)
		goto err_unlock;

	err = tmfs_ctl_add_conn(fc);
	if (err)
		goto err_unlock;

	list_add_tail(&fc->entry, &tmfs_conn_list);
	sb->s_root = root_dentry;
	file->private_data = fud;
	mutex_unlock(&tmfs_mutex);
	/*
	 * atomic_dec_and_test() in fput() provides the necessary
	 * memory barrier for file->private_data to be visible on all
	 * CPUs after this
	 */
	fput(file);

	tmfs_send_init(fc, init_req);

	return 0;

 err_unlock:
	mutex_unlock(&tmfs_mutex);
 err_free_init_req:
	tmfs_request_free(init_req);
 err_put_root:
	dput(root_dentry);
 err_dev_free:
	tmfs_dev_free(fud);
 err_put_conn:
	tmfs_conn_put(fc);
 err_fput:
	fput(file);
 err:
	return err;
}

static struct dentry *tmfs_mount(struct file_system_type *fs_type,
		       int flags, const char *dev_name,
		       void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data, tmfs_fill_super);
}

static void tmfs_kill_sb_anon(struct super_block *sb)
{
	struct tmfs_conn *fc = get_tmfs_conn_super(sb);

	if (fc) {
		down_write(&fc->killsb);
		fc->sb = NULL;
		up_write(&fc->killsb);
	}

	kill_anon_super(sb);
}

static struct file_system_type tmfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "tmfs",
	.fs_flags	= FS_HAS_SUBTYPE,
	.mount		= tmfs_mount,
	.kill_sb	= tmfs_kill_sb_anon,
};
MODULE_ALIAS_FS("tmfs");

#ifdef CONFIG_BLOCK
static struct dentry *tmfs_mount_blk(struct file_system_type *fs_type,
			   int flags, const char *dev_name,
			   void *raw_data)
{
	return mount_bdev(fs_type, flags, dev_name, raw_data, tmfs_fill_super);
}

static void tmfs_kill_sb_blk(struct super_block *sb)
{
	struct tmfs_conn *fc = get_tmfs_conn_super(sb);

	if (fc) {
		down_write(&fc->killsb);
		fc->sb = NULL;
		up_write(&fc->killsb);
	}

	kill_block_super(sb);
}

static struct file_system_type tmfsblk_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "tmfsblk",
	.mount		= tmfs_mount_blk,
	.kill_sb	= tmfs_kill_sb_blk,
	.fs_flags	= FS_REQUIRES_DEV | FS_HAS_SUBTYPE,
};
MODULE_ALIAS_FS("tmfsblk");

static inline int register_tmfsblk(void)
{
	return register_filesystem(&tmfsblk_fs_type);
}

static inline void unregister_tmfsblk(void)
{
	unregister_filesystem(&tmfsblk_fs_type);
}
#else
static inline int register_tmfsblk(void)
{
	return 0;
}

static inline void unregister_tmfsblk(void)
{
}
#endif

static void tmfs_inode_init_once(void *foo)
{
	struct inode *inode = foo;

	inode_init_once(inode);
}

static int __init tmfs_fs_init(void)
{
	int err;

	tmfs_inode_cachep = kmem_cache_create("tmfs_inode",
					      sizeof(struct tmfs_inode), 0,
					      SLAB_HWCACHE_ALIGN|SLAB_ACCOUNT,
					      tmfs_inode_init_once);
	err = -ENOMEM;
	if (!tmfs_inode_cachep)
		goto out;

	err = register_tmfsblk();
	if (err)
		goto out2;

	err = register_filesystem(&tmfs_fs_type);
	if (err)
		goto out3;

	return 0;

 out3:
	unregister_tmfsblk();
 out2:
	kmem_cache_destroy(tmfs_inode_cachep);
 out:
	return err;
}

static void tmfs_fs_cleanup(void)
{
	unregister_filesystem(&tmfs_fs_type);
	unregister_tmfsblk();

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(tmfs_inode_cachep);
}

static struct kobject *tmfs_kobj;

static int tmfs_sysfs_init(void)
{
	int err;

	tmfs_kobj = kobject_create_and_add("tmfs", fs_kobj);
	if (!tmfs_kobj) {
		err = -ENOMEM;
		goto out_err;
	}

	err = sysfs_create_mount_point(tmfs_kobj, "connections");
	if (err)
		goto out_tmfs_unregister;

	return 0;

 out_tmfs_unregister:
	kobject_put(tmfs_kobj);
 out_err:
	return err;
}

static void tmfs_sysfs_cleanup(void)
{
	sysfs_remove_mount_point(tmfs_kobj, "connections");
	kobject_put(tmfs_kobj);
}

static int __init tmfs_init(void)
{
	int res;

	printk(KERN_INFO "tmfs init (API version %i.%i)\n",
	       TMFS_KERNEL_VERSION, TMFS_KERNEL_MINOR_VERSION);

	INIT_LIST_HEAD(&tmfs_conn_list);
	res = tmfs_fs_init();
	if (res)
		goto err;

	res = tmfs_dev_init();
	if (res)
		goto err_fs_cleanup;

	res = tmfs_sysfs_init();
	if (res)
		goto err_dev_cleanup;

	res = tmfs_ctl_init();
	if (res)
		goto err_sysfs_cleanup;

	sanitize_global_limit(&max_user_bgreq);
	sanitize_global_limit(&max_user_congthresh);

	lfs_vma_list_setup();  //LFS

	pr_info("tmfs init (API version %i.%i) ",
		TMFS_KERNEL_VERSION, TMFS_KERNEL_MINOR_VERSION);

#ifdef USE_ZBRIDGE_APIS // LFS
	pr_cont("(full Zbridge interaction)");
#else
	pr_cont("(Zbridge no-op)");
#endif

#ifdef USE_FLUSHTM_APIS // LFS
	pr_cont("(full Flushtm interaction)\n");
#else
	pr_cont("(Flushtm no-op)\n");
#endif

	return 0;

 err_sysfs_cleanup:
	tmfs_sysfs_cleanup();
 err_dev_cleanup:
	tmfs_dev_cleanup();
 err_fs_cleanup:
	tmfs_fs_cleanup();
 err:
	pr_err("tmfs init failed\n");
	return res;
}

static void __exit tmfs_exit(void)
{
	printk(KERN_DEBUG "tmfs exit\n");

	tmfs_ctl_cleanup();
	tmfs_sysfs_cleanup();
	tmfs_fs_cleanup();
	tmfs_dev_cleanup();
}

module_init(tmfs_init);
module_exit(tmfs_exit);
