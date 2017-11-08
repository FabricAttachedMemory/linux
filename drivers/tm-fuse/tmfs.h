/*
    This file defines the kernel interface of TMFS
    Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    This -- and only this -- header file may also be distributed under
    the terms of the BSD Licence as follows:

    Copyright (C) 2001-2007 Miklos Szeredi. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    SUCH DAMAGE.
*/

/*
 * This file defines the kernel interface of TMFS
 *
 * Protocol changelog:
 *
 * 7.9:
 *  - new tmfs_getattr_in input argument of GETATTR
 *  - add lk_flags in tmfs_lk_in
 *  - add lock_owner field to tmfs_setattr_in, tmfs_read_in and tmfs_write_in
 *  - add blksize field to tmfs_attr
 *  - add file flags field to tmfs_read_in and tmfs_write_in
 *
 * 7.10
 *  - add nonseekable open flag
 *
 * 7.11
 *  - add IOCTL message
 *  - add unsolicited notification support
 *  - add POLL message and NOTIFY_POLL notification
 *
 * 7.12
 *  - add umask flag to input argument of open, mknod and mkdir
 *  - add notification messages for invalidation of inodes and
 *    directory entries
 *
 * 7.13
 *  - make max number of background requests and congestion threshold
 *    tunables
 *
 * 7.14
 *  - add splice support to tmfs device
 *
 * 7.15
 *  - add store notify
 *  - add retrieve notify
 *
 * 7.16
 *  - add BATCH_FORGET request
 *  - TMFS_IOCTL_UNRESTRICTED shall now return with array of 'struct
 *    tmfs_ioctl_iovec' instead of ambiguous 'struct iovec'
 *  - add TMFS_IOCTL_32BIT flag
 *
 * 7.17
 *  - add TMFS_FLOCK_LOCKS and TMFS_RELEASE_FLOCK_UNLOCK
 *
 * 7.18
 *  - add TMFS_IOCTL_DIR flag
 *  - add TMFS_NOTIFY_DELETE
 *
 * 7.19
 *  - add TMFS_FALLOCATE
 *
 * 7.20
 *  - add TMFS_AUTO_INVAL_DATA
 *
 * 7.21
 *  - add TMFS_READDIRPLUS
 *  - send the requested events in POLL request
 *
 * 7.22
 *  - add TMFS_ASYNC_DIO
 *
 * 7.23
 *  - add TMFS_WRITEBACK_CACHE
 *  - add time_gran to tmfs_init_out
 *  - add reserved space to tmfs_init_out
 *  - add FATTR_CTIME
 *  - add ctime and ctimensec to tmfs_setattr_in
 *  - add TMFS_RENAME2 request
 *  - add TMFS_NO_OPEN_SUPPORT flag
 *
 *  7.24
 *  - add TMFS_LSEEK for SEEK_HOLE and SEEK_DATA support
 *
 *  7.25
 *  - add TMFS_PARALLEL_DIROPS
 *
 *  7.26
 *  - add TMFS_HANDLE_KILLPRIV
 *  - add TMFS_POSIX_ACL
 */

#ifndef _LINUX_TMFS_H
#define _LINUX_TMFS_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/*
 * Version negotiation:
 *
 * Both the kernel and userspace send the version they support in the
 * INIT request and reply respectively.
 *
 * If the major versions match then both shall use the smallest
 * of the two minor versions for communication.
 *
 * If the kernel supports a larger major version, then userspace shall
 * reply with the major version it supports, ignore the rest of the
 * INIT message and expect a new INIT message from the kernel with a
 * matching major version.
 *
 * If the library supports a larger major version, then it shall fall
 * back to the major protocol version sent by the kernel for
 * communication and reply with that major version (and an arbitrary
 * supported minor version).
 */

/** Version number of this interface */
#define TMFS_KERNEL_VERSION 7

/** Minor version number of this interface */
#define TMFS_KERNEL_MINOR_VERSION 26

/** The node ID of the root inode */
#define TMFS_ROOT_ID 1

/* Make sure all structures are padded to 64bit boundary, so 32bit
   userspace works under 64bit kernels */

struct tmfs_attr {
	uint64_t	ino;
	uint64_t	size;
	uint64_t	blocks;
	uint64_t	atime;
	uint64_t	mtime;
	uint64_t	ctime;
	uint32_t	atimensec;
	uint32_t	mtimensec;
	uint32_t	ctimensec;
	uint32_t	mode;
	uint32_t	nlink;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	rdev;
	uint32_t	blksize;
	uint32_t	padding;
};

struct tmfs_kstatfs {
	uint64_t	blocks;
	uint64_t	bfree;
	uint64_t	bavail;
	uint64_t	files;
	uint64_t	ffree;
	uint32_t	bsize;
	uint32_t	namelen;
	uint32_t	frsize;
	uint32_t	padding;
	uint32_t	spare[6];
};

struct tmfs_file_lock {
	uint64_t	start;
	uint64_t	end;
	uint32_t	type;
	uint32_t	pid; /* tgid */
};

/**
 * Bitmasks for tmfs_setattr_in.valid
 */
#define FATTR_MODE	(1 << 0)
#define FATTR_UID	(1 << 1)
#define FATTR_GID	(1 << 2)
#define FATTR_SIZE	(1 << 3)
#define FATTR_ATIME	(1 << 4)
#define FATTR_MTIME	(1 << 5)
#define FATTR_FH	(1 << 6)
#define FATTR_ATIME_NOW	(1 << 7)
#define FATTR_MTIME_NOW	(1 << 8)
#define FATTR_LOCKOWNER	(1 << 9)
#define FATTR_CTIME	(1 << 10)

/**
 * Flags returned by the OPEN request
 *
 * FOPEN_DIRECT_IO: bypass page cache for this open file
 * FOPEN_KEEP_CACHE: don't invalidate the data cache on open
 * FOPEN_NONSEEKABLE: the file is not seekable
 */
#define FOPEN_DIRECT_IO		(1 << 0)
#define FOPEN_KEEP_CACHE	(1 << 1)
#define FOPEN_NONSEEKABLE	(1 << 2)

/**
 * INIT request/reply flags
 *
 * TMFS_ASYNC_READ: asynchronous read requests
 * TMFS_POSIX_LOCKS: remote locking for POSIX file locks
 * TMFS_FILE_OPS: kernel sends file handle for fstat, etc... (not yet supported)
 * TMFS_ATOMIC_O_TRUNC: handles the O_TRUNC open flag in the filesystem
 * TMFS_EXPORT_SUPPORT: filesystem handles lookups of "." and ".."
 * TMFS_BIG_WRITES: filesystem can handle write size larger than 4kB
 * TMFS_DONT_MASK: don't apply umask to file mode on create operations
 * TMFS_SPLICE_WRITE: kernel supports splice write on the device
 * TMFS_SPLICE_MOVE: kernel supports splice move on the device
 * TMFS_SPLICE_READ: kernel supports splice read on the device
 * TMFS_FLOCK_LOCKS: remote locking for BSD style file locks
 * TMFS_HAS_IOCTL_DIR: kernel supports ioctl on directories
 * TMFS_AUTO_INVAL_DATA: automatically invalidate cached pages
 * TMFS_DO_READDIRPLUS: do READDIRPLUS (READDIR+LOOKUP in one)
 * TMFS_READDIRPLUS_AUTO: adaptive readdirplus
 * TMFS_ASYNC_DIO: asynchronous direct I/O submission
 * TMFS_WRITEBACK_CACHE: use writeback cache for buffered writes
 * TMFS_NO_OPEN_SUPPORT: kernel supports zero-message opens
 * TMFS_PARALLEL_DIROPS: allow parallel lookups and readdir
 * TMFS_HANDLE_KILLPRIV: fs handles killing suid/sgid/cap on write/chown/trunc
 * TMFS_POSIX_ACL: filesystem supports posix acls
 */
#define TMFS_ASYNC_READ		(1 << 0)
#define TMFS_POSIX_LOCKS	(1 << 1)
#define TMFS_FILE_OPS		(1 << 2)
#define TMFS_ATOMIC_O_TRUNC	(1 << 3)
#define TMFS_EXPORT_SUPPORT	(1 << 4)
#define TMFS_BIG_WRITES		(1 << 5)
#define TMFS_DONT_MASK		(1 << 6)
#define TMFS_SPLICE_WRITE	(1 << 7)
#define TMFS_SPLICE_MOVE	(1 << 8)
#define TMFS_SPLICE_READ	(1 << 9)
#define TMFS_FLOCK_LOCKS	(1 << 10)
#define TMFS_HAS_IOCTL_DIR	(1 << 11)
#define TMFS_AUTO_INVAL_DATA	(1 << 12)
#define TMFS_DO_READDIRPLUS	(1 << 13)
#define TMFS_READDIRPLUS_AUTO	(1 << 14)
#define TMFS_ASYNC_DIO		(1 << 15)
#define TMFS_WRITEBACK_CACHE	(1 << 16)
#define TMFS_NO_OPEN_SUPPORT	(1 << 17)
#define TMFS_PARALLEL_DIROPS    (1 << 18)
#define TMFS_HANDLE_KILLPRIV	(1 << 19)
#define TMFS_POSIX_ACL		(1 << 20)

/**
 * TMCD INIT request/reply flags
 *
 * TMCD_UNRESTRICTED_IOCTL:  use unrestricted ioctl
 */
#define TMCD_UNRESTRICTED_IOCTL	(1 << 0)

/**
 * Release flags
 */
#define TMFS_RELEASE_FLUSH	(1 << 0)
#define TMFS_RELEASE_FLOCK_UNLOCK	(1 << 1)

/**
 * Getattr flags
 */
#define TMFS_GETATTR_FH		(1 << 0)

/**
 * Lock flags
 */
#define TMFS_LK_FLOCK		(1 << 0)

/**
 * WRITE flags
 *
 * TMFS_WRITE_CACHE: delayed write from page cache, file handle is guessed
 * TMFS_WRITE_LOCKOWNER: lock_owner field is valid
 */
#define TMFS_WRITE_CACHE	(1 << 0)
#define TMFS_WRITE_LOCKOWNER	(1 << 1)

/**
 * Read flags
 */
#define TMFS_READ_LOCKOWNER	(1 << 1)

/**
 * Ioctl flags
 *
 * TMFS_IOCTL_COMPAT: 32bit compat ioctl on 64bit machine
 * TMFS_IOCTL_UNRESTRICTED: not restricted to well-formed ioctls, retry allowed
 * TMFS_IOCTL_RETRY: retry with new iovecs
 * TMFS_IOCTL_32BIT: 32bit ioctl
 * TMFS_IOCTL_DIR: is a directory
 *
 * TMFS_IOCTL_MAX_IOV: maximum of in_iovecs + out_iovecs
 */
#define TMFS_IOCTL_COMPAT	(1 << 0)
#define TMFS_IOCTL_UNRESTRICTED	(1 << 1)
#define TMFS_IOCTL_RETRY	(1 << 2)
#define TMFS_IOCTL_32BIT	(1 << 3)
#define TMFS_IOCTL_DIR		(1 << 4)

#define TMFS_IOCTL_MAX_IOV	256

/**
 * Poll flags
 *
 * TMFS_POLL_SCHEDULE_NOTIFY: request poll notify
 */
#define TMFS_POLL_SCHEDULE_NOTIFY (1 << 0)

enum tmfs_opcode {
	TMFS_LOOKUP	   = 1,
	TMFS_FORGET	   = 2,  /* no reply */
	TMFS_GETATTR	   = 3,
	TMFS_SETATTR	   = 4,
	TMFS_READLINK	   = 5,
	TMFS_SYMLINK	   = 6,
	TMFS_MKNOD	   = 8,
	TMFS_MKDIR	   = 9,
	TMFS_UNLINK	   = 10,
	TMFS_RMDIR	   = 11,
	TMFS_RENAME	   = 12,
	TMFS_LINK	   = 13,
	TMFS_OPEN	   = 14,
	TMFS_READ	   = 15,
	TMFS_WRITE	   = 16,
	TMFS_STATFS	   = 17,
	TMFS_RELEASE       = 18,
	TMFS_FSYNC         = 20,
	TMFS_SETXATTR      = 21,
	TMFS_GETXATTR      = 22,
	TMFS_LISTXATTR     = 23,
	TMFS_REMOVEXATTR   = 24,
	TMFS_FLUSH         = 25,
	TMFS_INIT          = 26,
	TMFS_OPENDIR       = 27,
	TMFS_READDIR       = 28,
	TMFS_RELEASEDIR    = 29,
	TMFS_FSYNCDIR      = 30,
	TMFS_GETLK         = 31,
	TMFS_SETLK         = 32,
	TMFS_SETLKW        = 33,
	TMFS_ACCESS        = 34,
	TMFS_CREATE        = 35,
	TMFS_INTERRUPT     = 36,
	TMFS_BMAP          = 37,
	TMFS_DESTROY       = 38,
	TMFS_IOCTL         = 39,
	TMFS_POLL          = 40,
	TMFS_NOTIFY_REPLY  = 41,
	TMFS_BATCH_FORGET  = 42,
	TMFS_FALLOCATE     = 43,
	TMFS_READDIRPLUS   = 44,
	TMFS_RENAME2       = 45,
	TMFS_LSEEK         = 46,

	/* TMCD specific operations */
	TMCD_INIT          = 4096,
};

enum tmfs_notify_code {
	TMFS_NOTIFY_POLL   = 1,
	TMFS_NOTIFY_INVAL_INODE = 2,
	TMFS_NOTIFY_INVAL_ENTRY = 3,
	TMFS_NOTIFY_STORE = 4,
	TMFS_NOTIFY_RETRIEVE = 5,
	TMFS_NOTIFY_DELETE = 6,
	TMFS_NOTIFY_CODE_MAX,
};

/* The read buffer is required to be at least 8k, but may be much larger */
#define TMFS_MIN_READ_BUFFER 8192

#define TMFS_COMPAT_ENTRY_OUT_SIZE 120

struct tmfs_entry_out {
	uint64_t	nodeid;		/* Inode ID */
	uint64_t	generation;	/* Inode generation: nodeid:gen must
					   be unique for the fs's lifetime */
	uint64_t	entry_valid;	/* Cache timeout for the name */
	uint64_t	attr_valid;	/* Cache timeout for the attributes */
	uint32_t	entry_valid_nsec;
	uint32_t	attr_valid_nsec;
	struct tmfs_attr attr;
};

struct tmfs_forget_in {
	uint64_t	nlookup;
};

struct tmfs_forget_one {
	uint64_t	nodeid;
	uint64_t	nlookup;
};

struct tmfs_batch_forget_in {
	uint32_t	count;
	uint32_t	dummy;
};

struct tmfs_getattr_in {
	uint32_t	getattr_flags;
	uint32_t	dummy;
	uint64_t	fh;
};

#define TMFS_COMPAT_ATTR_OUT_SIZE 96

struct tmfs_attr_out {
	uint64_t	attr_valid;	/* Cache timeout for the attributes */
	uint32_t	attr_valid_nsec;
	uint32_t	dummy;
	struct tmfs_attr attr;
};

#define TMFS_COMPAT_MKNOD_IN_SIZE 8

struct tmfs_mknod_in {
	uint32_t	mode;
	uint32_t	rdev;
	uint32_t	umask;
	uint32_t	padding;
};

struct tmfs_mkdir_in {
	uint32_t	mode;
	uint32_t	umask;
};

struct tmfs_rename_in {
	uint64_t	newdir;
};

struct tmfs_rename2_in {
	uint64_t	newdir;
	uint32_t	flags;
	uint32_t	padding;
};

struct tmfs_link_in {
	uint64_t	oldnodeid;
};

struct tmfs_setattr_in {
	uint32_t	valid;
	uint32_t	padding;
	uint64_t	fh;
	uint64_t	size;
	uint64_t	lock_owner;
	uint64_t	atime;
	uint64_t	mtime;
	uint64_t	ctime;
	uint32_t	atimensec;
	uint32_t	mtimensec;
	uint32_t	ctimensec;
	uint32_t	mode;
	uint32_t	unused4;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	unused5;
};

struct tmfs_open_in {
	uint32_t	flags;
	uint32_t	unused;
};

struct tmfs_create_in {
	uint32_t	flags;
	uint32_t	mode;
	uint32_t	umask;
	uint32_t	padding;
};

struct tmfs_open_out {
	uint64_t	fh;
	uint32_t	open_flags;
	uint32_t	padding;
};

struct tmfs_release_in {
	uint64_t	fh;
	uint32_t	flags;
	uint32_t	release_flags;
	uint64_t	lock_owner;
};

struct tmfs_flush_in {
	uint64_t	fh;
	uint32_t	unused;
	uint32_t	padding;
	uint64_t	lock_owner;
};

struct tmfs_read_in {
	uint64_t	fh;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	read_flags;
	uint64_t	lock_owner;
	uint32_t	flags;
	uint32_t	padding;
};

#define TMFS_COMPAT_WRITE_IN_SIZE 24

struct tmfs_write_in {
	uint64_t	fh;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	write_flags;
	uint64_t	lock_owner;
	uint32_t	flags;
	uint32_t	padding;
};

struct tmfs_write_out {
	uint32_t	size;
	uint32_t	padding;
};

#define TMFS_COMPAT_STATFS_SIZE 48

struct tmfs_statfs_out {
	struct tmfs_kstatfs st;
};

struct tmfs_fsync_in {
	uint64_t	fh;
	uint32_t	fsync_flags;
	uint32_t	padding;
};

struct tmfs_setxattr_in {
	uint32_t	size;
	uint32_t	flags;
};

struct tmfs_getxattr_in {
	uint32_t	size;
	uint32_t	padding;
};

struct tmfs_getxattr_out {
	uint32_t	size;
	uint32_t	padding;
};

struct tmfs_lk_in {
	uint64_t	fh;
	uint64_t	owner;
	struct tmfs_file_lock lk;
	uint32_t	lk_flags;
	uint32_t	padding;
};

struct tmfs_lk_out {
	struct tmfs_file_lock lk;
};

struct tmfs_access_in {
	uint32_t	mask;
	uint32_t	padding;
};

struct tmfs_init_in {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	max_readahead;
	uint32_t	flags;
};

#define TMFS_COMPAT_INIT_OUT_SIZE 8
#define TMFS_COMPAT_22_INIT_OUT_SIZE 24

struct tmfs_init_out {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	max_readahead;
	uint32_t	flags;
	uint16_t	max_background;
	uint16_t	congestion_threshold;
	uint32_t	max_write;
	uint32_t	time_gran;
	uint32_t	unused[9];
};

#define TMCD_INIT_INFO_MAX 4096

struct tmcd_init_in {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	unused;
	uint32_t	flags;
};

struct tmcd_init_out {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	unused;
	uint32_t	flags;
	uint32_t	max_read;
	uint32_t	max_write;
	uint32_t	dev_major;		/* chardev major */
	uint32_t	dev_minor;		/* chardev minor */
	uint32_t	spare[10];
};

struct tmfs_interrupt_in {
	uint64_t	unique;
};

struct tmfs_bmap_in {
	uint64_t	block;
	uint32_t	blocksize;
	uint32_t	padding;
};

struct tmfs_bmap_out {
	uint64_t	block;
};

struct tmfs_ioctl_in {
	uint64_t	fh;
	uint32_t	flags;
	uint32_t	cmd;
	uint64_t	arg;
	uint32_t	in_size;
	uint32_t	out_size;
};

struct tmfs_ioctl_iovec {
	uint64_t	base;
	uint64_t	len;
};

struct tmfs_ioctl_out {
	int32_t		result;
	uint32_t	flags;
	uint32_t	in_iovs;
	uint32_t	out_iovs;
};

struct tmfs_poll_in {
	uint64_t	fh;
	uint64_t	kh;
	uint32_t	flags;
	uint32_t	events;
};

struct tmfs_poll_out {
	uint32_t	revents;
	uint32_t	padding;
};

struct tmfs_notify_poll_wakeup_out {
	uint64_t	kh;
};

struct tmfs_fallocate_in {
	uint64_t	fh;
	uint64_t	offset;
	uint64_t	length;
	uint32_t	mode;
	uint32_t	padding;
};

struct tmfs_in_header {
	uint32_t	len;
	uint32_t	opcode;
	uint64_t	unique;
	uint64_t	nodeid;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	pid;
	uint32_t	padding;
};

struct tmfs_out_header {
	uint32_t	len;
	int32_t		error;
	uint64_t	unique;
};

struct tmfs_dirent {
	uint64_t	ino;
	uint64_t	off;
	uint32_t	namelen;
	uint32_t	type;
	char name[];
};

#define TMFS_NAME_OFFSET offsetof(struct tmfs_dirent, name)
#define TMFS_DIRENT_ALIGN(x) \
	(((x) + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))
#define TMFS_DIRENT_SIZE(d) \
	TMFS_DIRENT_ALIGN(TMFS_NAME_OFFSET + (d)->namelen)

struct tmfs_direntplus {
	struct tmfs_entry_out entry_out;
	struct tmfs_dirent dirent;
};

#define TMFS_NAME_OFFSET_DIRENTPLUS \
	offsetof(struct tmfs_direntplus, dirent.name)
#define TMFS_DIRENTPLUS_SIZE(d) \
	TMFS_DIRENT_ALIGN(TMFS_NAME_OFFSET_DIRENTPLUS + (d)->dirent.namelen)

struct tmfs_notify_inval_inode_out {
	uint64_t	ino;
	int64_t		off;
	int64_t		len;
};

struct tmfs_notify_inval_entry_out {
	uint64_t	parent;
	uint32_t	namelen;
	uint32_t	padding;
};

struct tmfs_notify_delete_out {
	uint64_t	parent;
	uint64_t	child;
	uint32_t	namelen;
	uint32_t	padding;
};

struct tmfs_notify_store_out {
	uint64_t	nodeid;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	padding;
};

struct tmfs_notify_retrieve_out {
	uint64_t	notify_unique;
	uint64_t	nodeid;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	padding;
};

/* Matches the size of tmfs_write_in */
struct tmfs_notify_retrieve_in {
	uint64_t	dummy1;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	dummy2;
	uint64_t	dummy3;
	uint64_t	dummy4;
};

/* Device ioctls: */
#define TMFS_DEV_IOC_CLONE	_IOR(229, 0, uint32_t)

struct tmfs_lseek_in {
	uint64_t	fh;
	uint64_t	offset;
	uint32_t	whence;
	uint32_t	padding;
};

struct tmfs_lseek_out {
	uint64_t	offset;
};

#endif /* _LINUX_TMFS_H */
