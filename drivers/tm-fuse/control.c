/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "tmfs_i.h"

#include <linux/init.h>
#include <linux/module.h>

#define TMFS_CTL_SUPER_MAGIC 0x65735543

/*
 * This is non-NULL when the single instance of the control filesystem
 * exists.  Protected by tmfs_mutex
 */
static struct super_block *tmfs_control_sb;

static struct tmfs_conn *tmfs_ctl_file_conn_get(struct file *file)
{
	struct tmfs_conn *fc;
	mutex_lock(&tmfs_mutex);
	fc = file_inode(file)->i_private;
	if (fc)
		fc = tmfs_conn_get(fc);
	mutex_unlock(&tmfs_mutex);
	return fc;
}

static ssize_t tmfs_conn_abort_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct tmfs_conn *fc = tmfs_ctl_file_conn_get(file);
	if (fc) {
		tmfs_abort_conn(fc);
		tmfs_conn_put(fc);
	}
	return count;
}

static ssize_t tmfs_conn_waiting_read(struct file *file, char __user *buf,
				      size_t len, loff_t *ppos)
{
	char tmp[32];
	size_t size;

	if (!*ppos) {
		long value;
		struct tmfs_conn *fc = tmfs_ctl_file_conn_get(file);
		if (!fc)
			return 0;

		value = atomic_read(&fc->num_waiting);
		file->private_data = (void *)value;
		tmfs_conn_put(fc);
	}
	size = sprintf(tmp, "%ld\n", (long)file->private_data);
	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t tmfs_conn_limit_read(struct file *file, char __user *buf,
				    size_t len, loff_t *ppos, unsigned val)
{
	char tmp[32];
	size_t size = sprintf(tmp, "%u\n", val);

	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t tmfs_conn_limit_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos, unsigned *val,
				     unsigned global_limit)
{
	unsigned long t;
	unsigned limit = (1 << 16) - 1;
	int err;

	if (*ppos)
		return -EINVAL;

	err = kstrtoul_from_user(buf, count, 0, &t);
	if (err)
		return err;

	if (!capable(CAP_SYS_ADMIN))
		limit = min(limit, global_limit);

	if (t > limit)
		return -EINVAL;

	*val = t;

	return count;
}

static ssize_t tmfs_conn_max_background_read(struct file *file,
					     char __user *buf, size_t len,
					     loff_t *ppos)
{
	struct tmfs_conn *fc;
	unsigned val;

	fc = tmfs_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	val = fc->max_background;
	tmfs_conn_put(fc);

	return tmfs_conn_limit_read(file, buf, len, ppos, val);
}

static ssize_t tmfs_conn_max_background_write(struct file *file,
					      const char __user *buf,
					      size_t count, loff_t *ppos)
{
	unsigned uninitialized_var(val);
	ssize_t ret;

	ret = tmfs_conn_limit_write(file, buf, count, ppos, &val,
				    max_user_bgreq);
	if (ret > 0) {
		struct tmfs_conn *fc = tmfs_ctl_file_conn_get(file);
		if (fc) {
			fc->max_background = val;
			tmfs_conn_put(fc);
		}
	}

	return ret;
}

static ssize_t tmfs_conn_congestion_threshold_read(struct file *file,
						   char __user *buf, size_t len,
						   loff_t *ppos)
{
	struct tmfs_conn *fc;
	unsigned val;

	fc = tmfs_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	val = fc->congestion_threshold;
	tmfs_conn_put(fc);

	return tmfs_conn_limit_read(file, buf, len, ppos, val);
}

static ssize_t tmfs_conn_congestion_threshold_write(struct file *file,
						    const char __user *buf,
						    size_t count, loff_t *ppos)
{
	unsigned uninitialized_var(val);
	ssize_t ret;

	ret = tmfs_conn_limit_write(file, buf, count, ppos, &val,
				    max_user_congthresh);
	if (ret > 0) {
		struct tmfs_conn *fc = tmfs_ctl_file_conn_get(file);
		if (fc) {
			fc->congestion_threshold = val;
			tmfs_conn_put(fc);
		}
	}

	return ret;
}

static const struct file_operations tmfs_ctl_abort_ops = {
	.open = nonseekable_open,
	.write = tmfs_conn_abort_write,
	.llseek = no_llseek,
};

static const struct file_operations tmfs_ctl_waiting_ops = {
	.open = nonseekable_open,
	.read = tmfs_conn_waiting_read,
	.llseek = no_llseek,
};

static const struct file_operations tmfs_conn_max_background_ops = {
	.open = nonseekable_open,
	.read = tmfs_conn_max_background_read,
	.write = tmfs_conn_max_background_write,
	.llseek = no_llseek,
};

static const struct file_operations tmfs_conn_congestion_threshold_ops = {
	.open = nonseekable_open,
	.read = tmfs_conn_congestion_threshold_read,
	.write = tmfs_conn_congestion_threshold_write,
	.llseek = no_llseek,
};

static struct dentry *tmfs_ctl_add_dentry(struct dentry *parent,
					  struct tmfs_conn *fc,
					  const char *name,
					  int mode, int nlink,
					  const struct inode_operations *iop,
					  const struct file_operations *fop)
{
	struct dentry *dentry;
	struct inode *inode;

	BUG_ON(fc->ctl_ndents >= TMFS_CTL_NUM_DENTRIES);
	dentry = d_alloc_name(parent, name);
	if (!dentry)
		return NULL;

	fc->ctl_dentry[fc->ctl_ndents++] = dentry;
	inode = new_inode(tmfs_control_sb);
	if (!inode)
		return NULL;

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_uid = fc->user_id;
	inode->i_gid = fc->group_id;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	/* setting ->i_op to NULL is not allowed */
	if (iop)
		inode->i_op = iop;
	inode->i_fop = fop;
	set_nlink(inode, nlink);
	inode->i_private = fc;
	d_add(dentry, inode);
	return dentry;
}

/*
 * Add a connection to the control filesystem (if it exists).  Caller
 * must hold tmfs_mutex
 */
int tmfs_ctl_add_conn(struct tmfs_conn *fc)
{
	struct dentry *parent;
	char name[32];

	if (!tmfs_control_sb)
		return 0;

	parent = tmfs_control_sb->s_root;
	inc_nlink(d_inode(parent));
	sprintf(name, "%u", fc->dev);
	parent = tmfs_ctl_add_dentry(parent, fc, name, S_IFDIR | 0500, 2,
				     &simple_dir_inode_operations,
				     &simple_dir_operations);
	if (!parent)
		goto err;

	if (!tmfs_ctl_add_dentry(parent, fc, "waiting", S_IFREG | 0400, 1,
				 NULL, &tmfs_ctl_waiting_ops) ||
	    !tmfs_ctl_add_dentry(parent, fc, "abort", S_IFREG | 0200, 1,
				 NULL, &tmfs_ctl_abort_ops) ||
	    !tmfs_ctl_add_dentry(parent, fc, "max_background", S_IFREG | 0600,
				 1, NULL, &tmfs_conn_max_background_ops) ||
	    !tmfs_ctl_add_dentry(parent, fc, "congestion_threshold",
				 S_IFREG | 0600, 1, NULL,
				 &tmfs_conn_congestion_threshold_ops))
		goto err;

	return 0;

 err:
	tmfs_ctl_remove_conn(fc);
	return -ENOMEM;
}

/*
 * Remove a connection from the control filesystem (if it exists).
 * Caller must hold tmfs_mutex
 */
void tmfs_ctl_remove_conn(struct tmfs_conn *fc)
{
	int i;

	if (!tmfs_control_sb)
		return;

	for (i = fc->ctl_ndents - 1; i >= 0; i--) {
		struct dentry *dentry = fc->ctl_dentry[i];
		d_inode(dentry)->i_private = NULL;
		d_drop(dentry);
		dput(dentry);
	}
	drop_nlink(d_inode(tmfs_control_sb->s_root));
}

static int tmfs_ctl_fill_super(struct super_block *sb, void *data, int silent)
{
	static const struct tree_descr empty_descr = {""};
	struct tmfs_conn *fc;
	int err;

	err = simple_fill_super(sb, TMFS_CTL_SUPER_MAGIC, &empty_descr);
	if (err)
		return err;

	mutex_lock(&tmfs_mutex);
	BUG_ON(tmfs_control_sb);
	tmfs_control_sb = sb;
	list_for_each_entry(fc, &tmfs_conn_list, entry) {
		err = tmfs_ctl_add_conn(fc);
		if (err) {
			tmfs_control_sb = NULL;
			mutex_unlock(&tmfs_mutex);
			return err;
		}
	}
	mutex_unlock(&tmfs_mutex);

	return 0;
}

static struct dentry *tmfs_ctl_mount(struct file_system_type *fs_type,
			int flags, const char *dev_name, void *raw_data)
{
	return mount_single(fs_type, flags, raw_data, tmfs_ctl_fill_super);
}

static void tmfs_ctl_kill_sb(struct super_block *sb)
{
	struct tmfs_conn *fc;

	mutex_lock(&tmfs_mutex);
	tmfs_control_sb = NULL;
	list_for_each_entry(fc, &tmfs_conn_list, entry)
		fc->ctl_ndents = 0;
	mutex_unlock(&tmfs_mutex);

	kill_litter_super(sb);
}

static struct file_system_type tmfs_ctl_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "tmfsctl",
	.mount		= tmfs_ctl_mount,
	.kill_sb	= tmfs_ctl_kill_sb,
};
MODULE_ALIAS_FS("tmfsctl");

int __init tmfs_ctl_init(void)
{
	return register_filesystem(&tmfs_ctl_fs_type);
}

void __exit tmfs_ctl_cleanup(void)
{
	unregister_filesystem(&tmfs_ctl_fs_type);
}
