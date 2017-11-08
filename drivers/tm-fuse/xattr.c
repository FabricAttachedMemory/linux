/*
 * TMFS: Filesystem in Userspace
 * Copyright (C) 2001-2016  Miklos Szeredi <miklos@szeredi.hu>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "tmfs_i.h"

#include <linux/xattr.h>
#include <linux/posix_acl_xattr.h>

int tmfs_setxattr(struct inode *inode, const char *name, const void *value,
		  size_t size, int flags)
{
	struct tmfs_conn *fc = get_tmfs_conn(inode);
	TMFS_ARGS(args);
	struct tmfs_setxattr_in inarg;
	int err;

	if (fc->no_setxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	inarg.flags = flags;
	args.in.h.opcode = TMFS_SETXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 3;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = strlen(name) + 1;
	args.in.args[1].value = name;
	args.in.args[2].size = size;
	args.in.args[2].value = value;
	err = tmfs_simple_request(fc, &args);
	if (err == -ENOSYS) {
		fc->no_setxattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err) {
		tmfs_invalidate_attr(inode);
		tmfs_update_ctime(inode);
	}
	return err;
}

ssize_t tmfs_getxattr(struct inode *inode, const char *name, void *value,
		      size_t size)
{
	struct tmfs_conn *fc = get_tmfs_conn(inode);
	TMFS_ARGS(args);
	struct tmfs_getxattr_in inarg;
	struct tmfs_getxattr_out outarg;
	ssize_t ret;

	if (fc->no_getxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	args.in.h.opcode = TMFS_GETXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = strlen(name) + 1;
	args.in.args[1].value = name;
	/* This is really two different operations rolled into one */
	args.out.numargs = 1;
	if (size) {
		args.out.argvar = 1;
		args.out.args[0].size = size;
		args.out.args[0].value = value;
	} else {
		args.out.args[0].size = sizeof(outarg);
		args.out.args[0].value = &outarg;
	}
	ret = tmfs_simple_request(fc, &args);
	if (!ret && !size)
		ret = min_t(ssize_t, outarg.size, XATTR_SIZE_MAX);
	if (ret == -ENOSYS) {
		fc->no_getxattr = 1;
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static int tmfs_verify_xattr_list(char *list, size_t size)
{
	size_t origsize = size;

	while (size) {
		size_t thislen = strnlen(list, size);

		if (!thislen || thislen == size)
			return -EIO;

		size -= thislen + 1;
		list += thislen + 1;
	}

	return origsize;
}

ssize_t tmfs_listxattr(struct dentry *entry, char *list, size_t size)
{
	struct inode *inode = d_inode(entry);
	struct tmfs_conn *fc = get_tmfs_conn(inode);
	TMFS_ARGS(args);
	struct tmfs_getxattr_in inarg;
	struct tmfs_getxattr_out outarg;
	ssize_t ret;

	if (!tmfs_allow_current_process(fc))
		return -EACCES;

	if (fc->no_listxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	args.in.h.opcode = TMFS_LISTXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	/* This is really two different operations rolled into one */
	args.out.numargs = 1;
	if (size) {
		args.out.argvar = 1;
		args.out.args[0].size = size;
		args.out.args[0].value = list;
	} else {
		args.out.args[0].size = sizeof(outarg);
		args.out.args[0].value = &outarg;
	}
	ret = tmfs_simple_request(fc, &args);
	if (!ret && !size)
		ret = min_t(ssize_t, outarg.size, XATTR_LIST_MAX);
	if (ret > 0 && size)
		ret = tmfs_verify_xattr_list(list, ret);
	if (ret == -ENOSYS) {
		fc->no_listxattr = 1;
		ret = -EOPNOTSUPP;
	}
	return ret;
}

int tmfs_removexattr(struct inode *inode, const char *name)
{
	struct tmfs_conn *fc = get_tmfs_conn(inode);
	TMFS_ARGS(args);
	int err;

	if (fc->no_removexattr)
		return -EOPNOTSUPP;

	args.in.h.opcode = TMFS_REMOVEXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = strlen(name) + 1;
	args.in.args[0].value = name;
	err = tmfs_simple_request(fc, &args);
	if (err == -ENOSYS) {
		fc->no_removexattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err) {
		tmfs_invalidate_attr(inode);
		tmfs_update_ctime(inode);
	}
	return err;
}

static int tmfs_xattr_get(const struct xattr_handler *handler,
			 struct dentry *dentry, struct inode *inode,
			 const char *name, void *value, size_t size)
{
	return tmfs_getxattr(inode, name, value, size);
}

static int tmfs_xattr_set(const struct xattr_handler *handler,
			  struct dentry *dentry, struct inode *inode,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	if (!value)
		return tmfs_removexattr(inode, name);

	return tmfs_setxattr(inode, name, value, size, flags);
}

static const struct xattr_handler tmfs_xattr_handler = {
	.prefix = "",
	.get    = tmfs_xattr_get,
	.set    = tmfs_xattr_set,
};

const struct xattr_handler *tmfs_xattr_handlers[] = {
	&tmfs_xattr_handler,
	NULL
};

const struct xattr_handler *tmfs_acl_xattr_handlers[] = {
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
	&tmfs_xattr_handler,
	NULL
};
