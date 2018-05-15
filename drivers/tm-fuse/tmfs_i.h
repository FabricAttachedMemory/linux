/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#ifndef _FS_TMFS_I_H
#define _FS_TMFS_I_H

#include "tmfs.h"
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/poll.h>
#include <linux/workqueue.h>
#include <linux/kref.h>
#include <linux/xattr.h>
#include <linux/pid_namespace.h>
#include <linux/refcount.h>

/* LFS additions - begin */

extern int tmfs_verbose;

#define PR_VERBOSE1(a...) { if (tmfs_verbose) pr_info(a); }
#define PR_VERBOSE2(a...) { if (tmfs_verbose > 1) pr_info(a); }
#define PR_VERBOSE3(a...) { if (tmfs_verbose > 2) pr_info(a); }

/** These should be in <build>/include/linux/miscdevice.h */
#define TMFS_MINOR 240
#define TMCD_MINOR 241

/* LFS additions - end */

/** Max number of pages that can be used in a single read request */
#define TMFS_MAX_PAGES_PER_REQ 32

/** Bias for fi->writectr, meaning new writepages must not be sent */
#define TMFS_NOWRITE INT_MIN

/** It could be as large as PATH_MAX, but would that have any uses? */
#define TMFS_NAME_MAX 1024

/** Number of dentries for each connection in the control filesystem */
#define TMFS_CTL_NUM_DENTRIES 5

/** Number of page pointers embedded in tmfs_req */
#define TMFS_REQ_INLINE_PAGES 1

/** List of active connections */
extern struct list_head tmfs_conn_list;

/** Global mutex protecting tmfs_conn_list and the control filesystem */
extern struct mutex tmfs_mutex;

/** Module parameters */
extern unsigned max_user_bgreq;
extern unsigned max_user_congthresh;

#define MAX_PHYS_RANGES		128

extern unsigned long long tmfs_phys_base[MAX_PHYS_RANGES];
extern unsigned long long tmfs_phys_bound[MAX_PHYS_RANGES];

/* One forget request */
struct tmfs_forget_link {
	struct tmfs_forget_one forget_one;
	struct tmfs_forget_link *next;
};

/* LFS additions - begin */

/* Book data for a given shelf, keyed by book number */
struct tmfs_book2lza_data {

	/* Book LZA */
	uint64_t lza;

	/* Starting physical/aperture address of the book */
	uint64_t book_phys;
};

/* Global data gets read as soon as an inode exists for spoof_getxattr */
#define DESCRIPTOR_SLOTS 1906

typedef struct {
	unsigned long book_size, addr_mode, aper_base, bii_mode;
	struct list_head desbk_slot2mappers[DESCRIPTOR_SLOTS];
	unsigned long shadow_igstart[128];      // copy of lfs_shadow::_igstart
} tmfs_global_t;

/* Radix tree roots for book data caching (struct address_map ->private_data) */
struct tmfs_book_cache {
	struct radix_tree_root book2lza_root;
};

/* Defined in file_lfs.c; alternate APIs for tables defined in file.c */
ssize_t lfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to);
ssize_t lfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from);
void lfs_vma_close(struct vm_area_struct *vma);
int lfs_file_mmap(struct file *file, struct vm_area_struct *vma);
ssize_t lfs_file_read_write(struct kiocb *, struct iov_iter *);
void lfs_vma_list_setup(void);
void lfs_remove_vma_from_list_global(struct vm_area_struct *);

/* Defined in lfs.c, same deal */
extern struct rw_semaphore lfs_book2lza_rw_sema;
int lfs_filemap_fault(struct vm_fault *vmf);
tmfs_global_t *lfs_obtain_globals(struct inode *);
void lfs_book2lza_setup(struct file *);
void lfs_book2lza_cache(struct inode *, unsigned long, unsigned long, unsigned long);
int lfs_book2lza_populate(struct inode *, unsigned long, unsigned long);
int lfs_book2lza_lookup(struct inode *, unsigned long, unsigned long *, unsigned long *);
void lfs_book2lza_teardown(struct inode *);
int lfs_fsync(struct file *, loff_t, loff_t, int);
int lfs_modal_lza2map_addr(unsigned long, unsigned long, unsigned long *);

/* Returns -EXXXX or length of returned data */
int spoof_getxattr(struct inode *inode, char *req, void *resp, size_t size);

/* Switch direction of reference: unmodified lfs.c routines that are called
   by table replacement APIs
*/
void tmfs_link_write_file(struct file *);
ssize_t tmfs_perform_write(struct kiocb *, struct address_space *, struct iov_iter *, loff_t);
void tmfs_do_truncate(struct file *);

/* This table is referenced in lfs.c, but same "direction" of reference */
extern const struct vm_operations_struct tmfs_file_vm_ops;

/* From zbridge */
int desbk_get_slot(uint64_t, void *, int *, uint64_t *);
int desbk_put_slot(int, uint64_t, void *);

/* From flushtm */
void flushtm_dcache_phys_area(phys_addr_t, uint64_t);

/* LFS additions - end */

/** TMFS inode */
struct tmfs_inode {
	/** Inode data */
	struct inode inode;

	/** Unique ID, which identifies the inode between userspace
	 * and kernel */
	u64 nodeid;

	/** Number of lookups on this inode */
	u64 nlookup;

	/** The request used for sending the FORGET message */
	struct tmfs_forget_link *forget;

	/** Time in jiffies until the file attributes are valid */
	u64 i_time;

	/** The sticky bit in inode->i_mode may have been removed, so
	    preserve the original mode */
	umode_t orig_i_mode;

	/** 64 bit inode number */
	u64 orig_ino;

	/** Version of last attribute change */
	u64 attr_version;

	/** Files usable in writepage.  Protected by fc->lock */
	struct list_head write_files;

	/** Writepages pending on truncate or fsync */
	struct list_head queued_writes;

	/** Number of sent writes, a negative bias (TMFS_NOWRITE)
	 * means more writes are blocked */
	int writectr;

	/** Waitq for writepage completion */
	wait_queue_head_t page_waitq;

	/** List of writepage requestst (pending or sent) */
	struct list_head writepages;

	/** Miscellaneous bits describing inode state */
	unsigned long state;

	/** Lock for serializing lookup and readdir for back compatibility*/
	struct mutex mutex;
};

/** TMFS inode state bits */
enum {
	/** Advise readdirplus  */
	TMFS_I_ADVISE_RDPLUS,
	/** Initialized with readdirplus */
	TMFS_I_INIT_RDPLUS,
	/** An operation changing file size is in progress  */
	TMFS_I_SIZE_UNSTABLE,
};

struct tmfs_conn;

/** TMFS specific file data */
struct tmfs_file {
	/** Fuse connection for this file */
	struct tmfs_conn *fc;

	/** Request reserved for flush and release */
	struct tmfs_req *reserved_req;

	/** Kernel file handle guaranteed to be unique */
	u64 kh;

	/** File handle used by userspace */
	u64 fh;

	/** Node id of this file */
	u64 nodeid;

	/** Refcount */
	refcount_t count;

	/** FOPEN_* flags returned by open */
	u32 open_flags;

	/** Entry on inode's write_files list */
	struct list_head write_entry;

	/** RB node to be linked on tmfs_conn->polled_files */
	struct rb_node polled_node;

	/** Wait queue head for poll */
	wait_queue_head_t poll_wait;

	/** Has flock been performed on this file? */
	bool flock:1;
};

/** One input argument of a request */
struct tmfs_in_arg {
	unsigned size;
	const void *value;
};

/** The request input */
struct tmfs_in {
	/** The request header */
	struct tmfs_in_header h;

	/** True if the data for the last argument is in req->pages */
	unsigned argpages:1;

	/** Number of arguments */
	unsigned numargs;

	/** Array of arguments */
	struct tmfs_in_arg args[3];
};

/** One output argument of a request */
struct tmfs_arg {
	unsigned size;
	void *value;
};

/** The request output */
struct tmfs_out {
	/** Header returned from userspace */
	struct tmfs_out_header h;

	/*
	 * The following bitfields are not changed during the request
	 * processing
	 */

	/** Last argument is variable length (can be shorter than
	    arg->size) */
	unsigned argvar:1;

	/** Last argument is a list of pages to copy data to */
	unsigned argpages:1;

	/** Zero partially or not copied pages */
	unsigned page_zeroing:1;

	/** Pages may be replaced with new ones */
	unsigned page_replace:1;

	/** Number or arguments */
	unsigned numargs;

	/** Array of arguments */
	struct tmfs_arg args[2];
};

/** TMFS page descriptor */
struct tmfs_page_desc {
	unsigned int length;
	unsigned int offset;
};

struct tmfs_args {
	struct {
		struct {
			uint32_t opcode;
			uint64_t nodeid;
		} h;
		unsigned numargs;
		struct tmfs_in_arg args[3];

	} in;
	struct {
		unsigned argvar:1;
		unsigned numargs;
		struct tmfs_arg args[2];
	} out;
};

#define TMFS_ARGS(args) struct tmfs_args args = {}

/** The request IO state (for asynchronous processing) */
struct tmfs_io_priv {
	struct kref refcnt;
	int async;
	spinlock_t lock;
	unsigned reqs;
	ssize_t bytes;
	size_t size;
	__u64 offset;
	bool write;
	bool should_dirty;
	int err;
	struct kiocb *iocb;
	struct completion *done;
	bool blocking;
};

#define TMFS_IO_PRIV_SYNC(i) \
{					\
	.refcnt = KREF_INIT(1),		\
	.async = 0,			\
	.iocb = i,			\
}

/**
 * Request flags
 *
 * FR_ISREPLY:		set if the request has reply
 * FR_FORCE:		force sending of the request even if interrupted
 * FR_BACKGROUND:	request is sent in the background
 * FR_WAITING:		request is counted as "waiting"
 * FR_ABORTED:		the request was aborted
 * FR_INTERRUPTED:	the request has been interrupted
 * FR_LOCKED:		data is being copied to/from the request
 * FR_PENDING:		request is not yet in userspace
 * FR_SENT:		request is in userspace, waiting for an answer
 * FR_FINISHED:		request is finished
 * FR_PRIVATE:		request is on private list
 */
enum tmfs_req_flag {
	FR_ISREPLY,
	FR_FORCE,
	FR_BACKGROUND,
	FR_WAITING,
	FR_ABORTED,
	FR_INTERRUPTED,
	FR_LOCKED,
	FR_PENDING,
	FR_SENT,
	FR_FINISHED,
	FR_PRIVATE,
};

/**
 * A request to the client
 *
 * .waitq.lock protects the following fields:
 *   - FR_ABORTED
 *   - FR_LOCKED (may also be modified under fc->lock, tested under both)
 */
struct tmfs_req {
	/** This can be on either pending processing or io lists in
	    tmfs_conn */
	struct list_head list;

	/** Entry on the interrupts list  */
	struct list_head intr_entry;

	/** refcount */
	refcount_t count;

	/** Unique ID for the interrupt request */
	u64 intr_unique;

	/* Request flags, updated with test/set/clear_bit() */
	unsigned long flags;

	/** The request input */
	struct tmfs_in in;

	/** The request output */
	struct tmfs_out out;

	/** Used to wake up the task waiting for completion of request*/
	wait_queue_head_t waitq;

	/** Data for asynchronous requests */
	union {
		struct {
			struct tmfs_release_in in;
			struct inode *inode;
		} release;
		struct tmfs_init_in init_in;
		struct tmfs_init_out init_out;
		struct tmcd_init_in tmcd_init_in;
		struct {
			struct tmfs_read_in in;
			u64 attr_ver;
		} read;
		struct {
			struct tmfs_write_in in;
			struct tmfs_write_out out;
			struct tmfs_req *next;
		} write;
		struct tmfs_notify_retrieve_in retrieve_in;
	} misc;

	/** page vector */
	struct page **pages;

	/** page-descriptor vector */
	struct tmfs_page_desc *page_descs;

	/** size of the 'pages' array */
	unsigned max_pages;

	/** inline page vector */
	struct page *inline_pages[TMFS_REQ_INLINE_PAGES];

	/** inline page-descriptor vector */
	struct tmfs_page_desc inline_page_descs[TMFS_REQ_INLINE_PAGES];

	/** number of pages in vector */
	unsigned num_pages;

	/** File used in the request (or NULL) */
	struct tmfs_file *ff;

	/** Inode used in the request or NULL */
	struct inode *inode;

	/** AIO control block */
	struct tmfs_io_priv *io;

	/** Link on fi->writepages */
	struct list_head writepages_entry;

	/** Request completion callback */
	void (*end)(struct tmfs_conn *, struct tmfs_req *);

	/** Request is stolen from tmfs_file->reserved_req */
	struct file *stolen_file;
};

struct tmfs_iqueue {
	/** Connection established */
	unsigned connected;

	/** Readers of the connection are waiting on this */
	wait_queue_head_t waitq;

	/** The next unique request id */
	u64 reqctr;

	/** The list of pending requests */
	struct list_head pending;

	/** Pending interrupts */
	struct list_head interrupts;

	/** Queue of pending forgets */
	struct tmfs_forget_link forget_list_head;
	struct tmfs_forget_link *forget_list_tail;

	/** Batching of FORGET requests (positive indicates FORGET batch) */
	int forget_batch;

	/** O_ASYNC requests */
	struct fasync_struct *fasync;
};

struct tmfs_pqueue {
	/** Connection established */
	unsigned connected;

	/** Lock protecting accessess to  members of this structure */
	spinlock_t lock;

	/** The list of requests being processed */
	struct list_head processing;

	/** The list of requests under I/O */
	struct list_head io;
};

/**
 * Fuse device instance
 */
struct tmfs_dev {
	/** Fuse connection for this device */
	struct tmfs_conn *fc;

	/** Processing queue */
	struct tmfs_pqueue pq;

	/** list entry on fc->devices */
	struct list_head entry;
};

/**
 * A Fuse connection.
 *
 * This structure is created, when the filesystem is mounted, and is
 * destroyed, when the client device is closed and the filesystem is
 * unmounted.
 */
struct tmfs_conn {
	/** Lock protecting accessess to  members of this structure */
	spinlock_t lock;

	/** Refcount */
	refcount_t count;

	/** Number of tmfs_dev's */
	atomic_t dev_count;

	struct rcu_head rcu;

	/** The user id for this mount */
	kuid_t user_id;

	/** The group id for this mount */
	kgid_t group_id;

	/** The pid namespace for this mount */
	struct pid_namespace *pid_ns;

	/** Maximum read size */
	unsigned max_read;

	/** Maximum write size */
	unsigned max_write;

	/** Input queue */
	struct tmfs_iqueue iq;

	/** The next unique kernel file handle */
	u64 khctr;

	/** rbtree of tmfs_files waiting for poll events indexed by ph */
	struct rb_root polled_files;

	/** Maximum number of outstanding background requests */
	unsigned max_background;

	/** Number of background requests at which congestion starts */
	unsigned congestion_threshold;

	/** Number of requests currently in the background */
	unsigned num_background;

	/** Number of background requests currently queued for userspace */
	unsigned active_background;

	/** The list of background requests set aside for later queuing */
	struct list_head bg_queue;

	/** Flag indicating that INIT reply has been received. Allocating
	 * any tmfs request will be suspended until the flag is set */
	int initialized;

	/** Flag indicating if connection is blocked.  This will be
	    the case before the INIT reply is received, and if there
	    are too many outstading backgrounds requests */
	int blocked;

	/** waitq for blocked connection */
	wait_queue_head_t blocked_waitq;

	/** waitq for reserved requests */
	wait_queue_head_t reserved_req_waitq;

	/** Connection established, cleared on umount, connection
	    abort and device release */
	unsigned connected;

	/** Connection failed (version mismatch).  Cannot race with
	    setting other bitfields since it is only set once in INIT
	    reply, before any other request, and never cleared */
	unsigned conn_error:1;

	/** Connection successful.  Only set in INIT */
	unsigned conn_init:1;

	/** Do readpages asynchronously?  Only set in INIT */
	unsigned async_read:1;

	/** Do not send separate SETATTR request before open(O_TRUNC)  */
	unsigned atomic_o_trunc:1;

	/** Filesystem supports NFS exporting.  Only set in INIT */
	unsigned export_support:1;

	/** write-back cache policy (default is write-through) */
	unsigned writeback_cache:1;

	/** allow parallel lookups and readdir (default is serialized) */
	unsigned parallel_dirops:1;

	/** handle fs handles killing suid/sgid/cap on write/chown/trunc */
	unsigned handle_killpriv:1;

	/*
	 * The following bitfields are only for optimization purposes
	 * and hence races in setting them will not cause malfunction
	 */

	/** Is open/release not implemented by fs? */
	unsigned no_open:1;

	/** Is fsync not implemented by fs? */
	unsigned no_fsync:1;

	/** Is fsyncdir not implemented by fs? */
	unsigned no_fsyncdir:1;

	/** Is flush not implemented by fs? */
	unsigned no_flush:1;

	/** Is setxattr not implemented by fs? */
	unsigned no_setxattr:1;

	/** Is getxattr not implemented by fs? */
	unsigned no_getxattr:1;

	/** Is listxattr not implemented by fs? */
	unsigned no_listxattr:1;

	/** Is removexattr not implemented by fs? */
	unsigned no_removexattr:1;

	/** Are posix file locking primitives not implemented by fs? */
	unsigned no_lock:1;

	/** Is access not implemented by fs? */
	unsigned no_access:1;

	/** Is create not implemented by fs? */
	unsigned no_create:1;

	/** Is interrupt not implemented by fs? */
	unsigned no_interrupt:1;

	/** Is bmap not implemented by fs? */
	unsigned no_bmap:1;

	/** Is poll not implemented by fs? */
	unsigned no_poll:1;

	/** Do multi-page cached writes */
	unsigned big_writes:1;

	/** Don't apply umask to creation modes */
	unsigned dont_mask:1;

	/** Are BSD file locking primitives not implemented by fs? */
	unsigned no_flock:1;

	/** Is fallocate not implemented by fs? */
	unsigned no_fallocate:1;

	/** Is rename with flags implemented by fs? */
	unsigned no_rename2:1;

	/** Use enhanced/automatic page cache invalidation. */
	unsigned auto_inval_data:1;

	/** Does the filesystem support readdirplus? */
	unsigned do_readdirplus:1;

	/** Does the filesystem want adaptive readdirplus? */
	unsigned readdirplus_auto:1;

	/** Does the filesystem support asynchronous direct-IO submission? */
	unsigned async_dio:1;

	/** Is lseek not implemented by fs? */
	unsigned no_lseek:1;

	/** Does the filesystem support posix acls? */
	unsigned posix_acl:1;

	/** Check permissions based on the file mode or not? */
	unsigned default_permissions:1;

	/** Allow other than the mounter user to access the filesystem ? */
	unsigned allow_other:1;

	/** The number of requests waiting for completion */
	atomic_t num_waiting;

	/** Negotiated minor version */
	unsigned minor;

	/** Entry on the tmfs_conn_list */
	struct list_head entry;

	/** Device ID from super block */
	dev_t dev;

	/** Dentries in the control filesystem */
	struct dentry *ctl_dentry[TMFS_CTL_NUM_DENTRIES];

	/** number of dentries used in the above array */
	int ctl_ndents;

	/** Key for lock owner ID scrambling */
	u32 scramble_key[4];

	/** Reserved request for the DESTROY message */
	struct tmfs_req *destroy_req;

	/** Version counter for attribute changes */
	u64 attr_version;

	/** Called on final put */
	void (*release)(struct tmfs_conn *);

	/** Super block for this connection. */
	struct super_block *sb;

	/** Read/write semaphore to hold when accessing sb. */
	struct rw_semaphore killsb;

	/** List of device instances belonging to this connection */
	struct list_head devices;
};

static inline struct tmfs_conn *get_tmfs_conn_super(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct tmfs_conn *get_tmfs_conn(struct inode *inode)
{
	return get_tmfs_conn_super(inode->i_sb);
}

static inline struct tmfs_inode *get_tmfs_inode(struct inode *inode)
{
	return container_of(inode, struct tmfs_inode, inode);
}

static inline u64 get_node_id(struct inode *inode)
{
	return get_tmfs_inode(inode)->nodeid;
}

/** Device operations */
extern const struct file_operations tmfs_dev_operations;

extern const struct dentry_operations tmfs_dentry_operations;
extern const struct dentry_operations tmfs_root_dentry_operations;

/**
 * Inode to nodeid comparison.
 */
int tmfs_inode_eq(struct inode *inode, void *_nodeidp);

/**
 * Get a filled in inode
 */
struct inode *tmfs_iget(struct super_block *sb, u64 nodeid,
			int generation, struct tmfs_attr *attr,
			u64 attr_valid, u64 attr_version);

int tmfs_lookup_name(struct super_block *sb, u64 nodeid, const struct qstr *name,
		     struct tmfs_entry_out *outarg, struct inode **inode);

/**
 * Send FORGET command
 */
void tmfs_queue_forget(struct tmfs_conn *fc, struct tmfs_forget_link *forget,
		       u64 nodeid, u64 nlookup);

struct tmfs_forget_link *tmfs_alloc_forget(void);

/* Used by READDIRPLUS */
void tmfs_force_forget(struct file *file, u64 nodeid);

/**
 * Initialize READ or READDIR request
 */
void tmfs_read_fill(struct tmfs_req *req, struct file *file,
		    loff_t pos, size_t count, int opcode);

/**
 * Send OPEN or OPENDIR request
 */
int tmfs_open_common(struct inode *inode, struct file *file, bool isdir);

struct tmfs_file *tmfs_file_alloc(struct tmfs_conn *fc);
void tmfs_file_free(struct tmfs_file *ff);
void tmfs_finish_open(struct inode *inode, struct file *file);

void tmfs_sync_release(struct tmfs_file *ff, int flags);

/**
 * Send RELEASE or RELEASEDIR request
 */
void tmfs_release_common(struct file *file, int opcode);

/**
 * Send FSYNC or FSYNCDIR request
 */
int tmfs_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int isdir);

/**
 * Notify poll wakeup
 */
int tmfs_notify_poll_wakeup(struct tmfs_conn *fc,
			    struct tmfs_notify_poll_wakeup_out *outarg);

/**
 * Initialize file operations on a regular file
 */
void tmfs_init_file_inode(struct inode *inode);

/**
 * Initialize inode operations on regular files and special files
 */
void tmfs_init_common(struct inode *inode);

/**
 * Initialize inode and file operations on a directory
 */
void tmfs_init_dir(struct inode *inode);

/**
 * Initialize inode operations on a symlink
 */
void tmfs_init_symlink(struct inode *inode);

/**
 * Change attributes of an inode
 */
void tmfs_change_attributes(struct inode *inode, struct tmfs_attr *attr,
			    u64 attr_valid, u64 attr_version);

void tmfs_change_attributes_common(struct inode *inode, struct tmfs_attr *attr,
				   u64 attr_valid);

/**
 * Initialize the client device
 */
int tmfs_dev_init(void);

/**
 * Cleanup the client device
 */
void tmfs_dev_cleanup(void);

int tmfs_ctl_init(void);
void __exit tmfs_ctl_cleanup(void);

/**
 * Allocate a request
 */
struct tmfs_req *tmfs_request_alloc(unsigned npages);

struct tmfs_req *tmfs_request_alloc_nofs(unsigned npages);

/**
 * Free a request
 */
void tmfs_request_free(struct tmfs_req *req);

/**
 * Get a request, may fail with -ENOMEM,
 * caller should specify # elements in req->pages[] explicitly
 */
struct tmfs_req *tmfs_get_req(struct tmfs_conn *fc, unsigned npages);
struct tmfs_req *tmfs_get_req_for_background(struct tmfs_conn *fc,
					     unsigned npages);

/*
 * Increment reference count on request
 */
void __tmfs_get_request(struct tmfs_req *req);

/**
 * Gets a requests for a file operation, always succeeds
 */
struct tmfs_req *tmfs_get_req_nofail_nopages(struct tmfs_conn *fc,
					     struct file *file);

/**
 * Decrement reference count of a request.  If count goes to zero free
 * the request.
 */
void tmfs_put_request(struct tmfs_conn *fc, struct tmfs_req *req);

/**
 * Send a request (synchronous)
 */
void tmfs_request_send(struct tmfs_conn *fc, struct tmfs_req *req);

/**
 * Simple request sending that does request allocation and freeing
 */
ssize_t tmfs_simple_request(struct tmfs_conn *fc, struct tmfs_args *args);

/**
 * Send a request in the background
 */
void tmfs_request_send_background(struct tmfs_conn *fc, struct tmfs_req *req);

void tmfs_request_send_background_locked(struct tmfs_conn *fc,
					 struct tmfs_req *req);

/* Abort all requests */
void tmfs_abort_conn(struct tmfs_conn *fc);

/**
 * Invalidate inode attributes
 */
void tmfs_invalidate_attr(struct inode *inode);

void tmfs_invalidate_entry_cache(struct dentry *entry);

void tmfs_invalidate_atime(struct inode *inode);

/**
 * Acquire reference to tmfs_conn
 */
struct tmfs_conn *tmfs_conn_get(struct tmfs_conn *fc);

/**
 * Initialize tmfs_conn
 */
void tmfs_conn_init(struct tmfs_conn *fc);

/**
 * Release reference to tmfs_conn
 */
void tmfs_conn_put(struct tmfs_conn *fc);

struct tmfs_dev *tmfs_dev_alloc(struct tmfs_conn *fc);
void tmfs_dev_free(struct tmfs_dev *fud);

/**
 * Add connection to control filesystem
 */
int tmfs_ctl_add_conn(struct tmfs_conn *fc);

/**
 * Remove connection from control filesystem
 */
void tmfs_ctl_remove_conn(struct tmfs_conn *fc);

/**
 * Is file type valid?
 */
int tmfs_valid_type(int m);

/**
 * Is current process allowed to perform filesystem operation?
 */
int tmfs_allow_current_process(struct tmfs_conn *fc);

u64 tmfs_lock_owner_id(struct tmfs_conn *fc, fl_owner_t id);

void tmfs_update_ctime(struct inode *inode);

int tmfs_update_attributes(struct inode *inode, struct file *file);

void tmfs_flush_writepages(struct inode *inode);

void tmfs_set_nowrite(struct inode *inode);
void tmfs_release_nowrite(struct inode *inode);

u64 tmfs_get_attr_version(struct tmfs_conn *fc);

/**
 * File-system tells the kernel to invalidate cache for the given node id.
 */
int tmfs_reverse_inval_inode(struct super_block *sb, u64 nodeid,
			     loff_t offset, loff_t len);

/**
 * File-system tells the kernel to invalidate parent attributes and
 * the dentry matching parent/name.
 *
 * If the child_nodeid is non-zero and:
 *    - matches the inode number for the dentry matching parent/name,
 *    - is not a mount point
 *    - is a file or oan empty directory
 * then the dentry is unhashed (d_delete()).
 */
int tmfs_reverse_inval_entry(struct super_block *sb, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name);

int tmfs_do_open(struct tmfs_conn *fc, u64 nodeid, struct file *file,
		 bool isdir);

/**
 * tmfs_direct_io() flags
 */

/** If set, it is WRITE; otherwise - READ */
#define TMFS_DIO_WRITE (1 << 0)

/** TMCD pass tmfs_direct_io() a file which f_mapping->host is not from TMFS */
#define TMFS_DIO_TMCD  (1 << 1)

ssize_t tmfs_direct_io(struct tmfs_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags);
long tmfs_do_ioctl(struct file *file, unsigned int cmd, unsigned long arg,
		   unsigned int flags);
long tmfs_ioctl_common(struct file *file, unsigned int cmd,
		       unsigned long arg, unsigned int flags);
unsigned tmfs_file_poll(struct file *file, poll_table *wait);
int tmfs_dev_release(struct inode *inode, struct file *file);

bool tmfs_write_update_size(struct inode *inode, loff_t pos);

int tmfs_flush_times(struct inode *inode, struct tmfs_file *ff);
int tmfs_write_inode(struct inode *inode, struct writeback_control *wbc);

int tmfs_do_setattr(struct dentry *dentry, struct iattr *attr,
		    struct file *file);

void tmfs_set_initialized(struct tmfs_conn *fc);

void tmfs_unlock_inode(struct inode *inode);
void tmfs_lock_inode(struct inode *inode);

int tmfs_setxattr(struct inode *inode, const char *name, const void *value,
		  size_t size, int flags);
ssize_t tmfs_getxattr(struct inode *inode, const char *name, void *value,
		      size_t size);
ssize_t tmfs_listxattr(struct dentry *entry, char *list, size_t size);
int tmfs_removexattr(struct inode *inode, const char *name);
extern const struct xattr_handler *tmfs_xattr_handlers[];
extern const struct xattr_handler *tmfs_acl_xattr_handlers[];

struct posix_acl;
struct posix_acl *tmfs_get_acl(struct inode *inode, int type);
int tmfs_set_acl(struct inode *inode, struct posix_acl *acl, int type);

#endif /* _FS_TMFS_I_H */
