/*
 * TMCD: Character device in Userspace
 *
 * Copyright (C) 2008-2009  SUSE Linux Products GmbH
 * Copyright (C) 2008-2009  Tejun Heo <tj@kernel.org>
 *
 * This file is released under the GPLv2.
 *
 * TMCD enables character devices to be implemented from userland much
 * like TMFS allows filesystems.  On initialization /dev/tmcd is
 * created.  By opening the file and replying to the TMCD_INIT request
 * userland TMCD server can create a character device.  After that the
 * operation is very similar to TMFS.
 *
 * A TMCD instance involves the following objects.
 *
 * tmcd_conn	: contains tmfs_conn and serves as bonding structure
 * channel	: file handle connected to the userland TMCD server
 * cdev		: the implemented character device
 * dev		: generic device for cdev
 *
 * Note that 'channel' is what 'dev' is in TMFS.  As TMCD deals with
 * devices, it's called 'channel' to reduce confusion.
 *
 * channel determines when the character device dies.  When channel is
 * closed, everything begins to destruct.  The tmcd_conn is taken off
 * the lookup table preventing further access from cdev, cdev and
 * generic device are removed and the base reference of tmcd_conn is
 * put.
 *
 * On each open, the matching tmcd_conn is looked up and if found an
 * additional reference is taken which is released when the file is
 * closed.
 */

#include "tmfs.h"
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/magic.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/module.h>
#include <linux/uio.h>

#include "tmfs_i.h"

#define TMCD_CONNTBL_LEN	64

struct tmcd_conn {
	struct list_head	list;	/* linked on tmcd_conntbl */
	struct tmfs_conn	fc;	/* tmfs connection */
	struct cdev		*cdev;	/* associated character device */
	struct device		*dev;	/* device representing @cdev */

	/* init parameters, set once during initialization */
	bool			unrestricted_ioctl;
};

static DEFINE_MUTEX(tmcd_lock);		/* protects registration */
static struct list_head tmcd_conntbl[TMCD_CONNTBL_LEN];
static struct class *tmcd_class;

static struct tmcd_conn *fc_to_cc(struct tmfs_conn *fc)
{
	return container_of(fc, struct tmcd_conn, fc);
}

static struct list_head *tmcd_conntbl_head(dev_t devt)
{
	return &tmcd_conntbl[(MAJOR(devt) + MINOR(devt)) % TMCD_CONNTBL_LEN];
}


/**************************************************************************
 * TMCD frontend operations
 *
 * These are file operations for the character device.
 *
 * On open, TMCD opens a file from the TMFS mnt and stores it to
 * private_data of the open file.  All other ops call TMFS ops on the
 * TMFS file.
 */

static ssize_t tmcd_read_iter(struct kiocb *kiocb, struct iov_iter *to)
{
	struct tmfs_io_priv io = TMFS_IO_PRIV_SYNC(kiocb->ki_filp);
	loff_t pos = 0;

	return tmfs_direct_io(&io, to, &pos, TMFS_DIO_TMCD);
}

static ssize_t tmcd_write_iter(struct kiocb *kiocb, struct iov_iter *from)
{
	struct tmfs_io_priv io = TMFS_IO_PRIV_SYNC(kiocb->ki_filp);
	loff_t pos = 0;
	/*
	 * No locking or generic_write_checks(), the server is
	 * responsible for locking and sanity checks.
	 */
	return tmfs_direct_io(&io, from, &pos,
			      TMFS_DIO_WRITE | TMFS_DIO_TMCD);
}

static int tmcd_open(struct inode *inode, struct file *file)
{
	dev_t devt = inode->i_cdev->dev;
	struct tmcd_conn *cc = NULL, *pos;
	int rc;

	/* look up and get the connection */
	mutex_lock(&tmcd_lock);
	list_for_each_entry(pos, tmcd_conntbl_head(devt), list)
		if (pos->dev->devt == devt) {
			tmfs_conn_get(&pos->fc);
			cc = pos;
			break;
		}
	mutex_unlock(&tmcd_lock);

	/* dead? */
	if (!cc)
		return -ENODEV;

	/*
	 * Generic permission check is already done against the chrdev
	 * file, proceed to open.
	 */
	rc = tmfs_do_open(&cc->fc, 0, file, 0);
	if (rc)
		tmfs_conn_put(&cc->fc);
	return rc;
}

static int tmcd_release(struct inode *inode, struct file *file)
{
	struct tmfs_file *ff = file->private_data;
	struct tmfs_conn *fc = ff->fc;

	tmfs_sync_release(ff, file->f_flags);
	tmfs_conn_put(fc);

	return 0;
}

static long tmcd_file_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct tmfs_file *ff = file->private_data;
	struct tmcd_conn *cc = fc_to_cc(ff->fc);
	unsigned int flags = 0;

	if (cc->unrestricted_ioctl)
		flags |= TMFS_IOCTL_UNRESTRICTED;

	return tmfs_do_ioctl(file, cmd, arg, flags);
}

static long tmcd_file_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct tmfs_file *ff = file->private_data;
	struct tmcd_conn *cc = fc_to_cc(ff->fc);
	unsigned int flags = TMFS_IOCTL_COMPAT;

	if (cc->unrestricted_ioctl)
		flags |= TMFS_IOCTL_UNRESTRICTED;

	return tmfs_do_ioctl(file, cmd, arg, flags);
}

static const struct file_operations tmcd_frontend_fops = {
	.owner			= THIS_MODULE,
	.read_iter		= tmcd_read_iter,
	.write_iter		= tmcd_write_iter,
	.open			= tmcd_open,
	.release		= tmcd_release,
	.unlocked_ioctl		= tmcd_file_ioctl,
	.compat_ioctl		= tmcd_file_compat_ioctl,
	.poll			= tmfs_file_poll,
	.llseek		= noop_llseek,
};


/**************************************************************************
 * TMCD channel initialization and destruction
 */

struct tmcd_devinfo {
	const char		*name;
};

/**
 * tmcd_parse_one - parse one key=value pair
 * @pp: i/o parameter for the current position
 * @end: points to one past the end of the packed string
 * @keyp: out parameter for key
 * @valp: out parameter for value
 *
 * *@pp points to packed strings - "key0=val0\0key1=val1\0" which ends
 * at @end - 1.  This function parses one pair and set *@keyp to the
 * start of the key and *@valp to the start of the value.  Note that
 * the original string is modified such that the key string is
 * terminated with '\0'.  *@pp is updated to point to the next string.
 *
 * RETURNS:
 * 1 on successful parse, 0 on EOF, -errno on failure.
 */
static int tmcd_parse_one(char **pp, char *end, char **keyp, char **valp)
{
	char *p = *pp;
	char *key, *val;

	while (p < end && *p == '\0')
		p++;
	if (p == end)
		return 0;

	if (end[-1] != '\0') {
		printk(KERN_ERR "TMCD: info not properly terminated\n");
		return -EINVAL;
	}

	key = val = p;
	p += strlen(p);

	if (valp) {
		strsep(&val, "=");
		if (!val)
			val = key + strlen(key);
		key = strstrip(key);
		val = strstrip(val);
	} else
		key = strstrip(key);

	if (!strlen(key)) {
		printk(KERN_ERR "TMCD: zero length info key specified\n");
		return -EINVAL;
	}

	*pp = p;
	*keyp = key;
	if (valp)
		*valp = val;

	return 1;
}

/**
 * tmcd_parse_dev_info - parse device info
 * @p: device info string
 * @len: length of device info string
 * @devinfo: out parameter for parsed device info
 *
 * Parse @p to extract device info and store it into @devinfo.  String
 * pointed to by @p is modified by parsing and @devinfo points into
 * them, so @p shouldn't be freed while @devinfo is in use.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int tmcd_parse_devinfo(char *p, size_t len, struct tmcd_devinfo *devinfo)
{
	char *end = p + len;
	char *uninitialized_var(key), *uninitialized_var(val);
	int rc;

	while (true) {
		rc = tmcd_parse_one(&p, end, &key, &val);
		if (rc < 0)
			return rc;
		if (!rc)
			break;
		if (strcmp(key, "DEVNAME") == 0)
			devinfo->name = val;
		else
			printk(KERN_WARNING "TMCD: unknown device info \"%s\"\n",
			       key);
	}

	if (!devinfo->name || !strlen(devinfo->name)) {
		printk(KERN_ERR "TMCD: DEVNAME unspecified\n");
		return -EINVAL;
	}

	return 0;
}

static void tmcd_gendev_release(struct device *dev)
{
	kfree(dev);
}

/**
 * tmcd_process_init_reply - finish initializing TMCD channel
 *
 * This function creates the character device and sets up all the
 * required data structures for it.  Please read the comment at the
 * top of this file for high level overview.
 */
static void tmcd_process_init_reply(struct tmfs_conn *fc, struct tmfs_req *req)
{
	struct tmcd_conn *cc = fc_to_cc(fc), *pos;
	struct tmcd_init_out *arg = req->out.args[0].value;
	struct page *page = req->pages[0];
	struct tmcd_devinfo devinfo = { };
	struct device *dev;
	struct cdev *cdev;
	dev_t devt;
	int rc, i;

	if (req->out.h.error ||
	    arg->major != TMFS_KERNEL_VERSION || arg->minor < 11) {
		goto err;
	}

	fc->minor = arg->minor;
	fc->max_read = max_t(unsigned, arg->max_read, 4096);
	fc->max_write = max_t(unsigned, arg->max_write, 4096);

	/* parse init reply */
	cc->unrestricted_ioctl = arg->flags & TMCD_UNRESTRICTED_IOCTL;

	rc = tmcd_parse_devinfo(page_address(page), req->out.args[1].size,
				&devinfo);
	if (rc)
		goto err;

	/* determine and reserve devt */
	devt = MKDEV(arg->dev_major, arg->dev_minor);
	if (!MAJOR(devt))
		rc = alloc_chrdev_region(&devt, MINOR(devt), 1, devinfo.name);
	else
		rc = register_chrdev_region(devt, 1, devinfo.name);
	if (rc) {
		printk(KERN_ERR "TMCD: failed to register chrdev region\n");
		goto err;
	}

	/* devt determined, create device */
	rc = -ENOMEM;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		goto err_region;

	device_initialize(dev);
	dev_set_uevent_suppress(dev, 1);
	dev->class = tmcd_class;
	dev->devt = devt;
	dev->release = tmcd_gendev_release;
	dev_set_drvdata(dev, cc);
	dev_set_name(dev, "%s", devinfo.name);

	mutex_lock(&tmcd_lock);

	/* make sure the device-name is unique */
	for (i = 0; i < TMCD_CONNTBL_LEN; ++i) {
		list_for_each_entry(pos, &tmcd_conntbl[i], list)
			if (!strcmp(dev_name(pos->dev), dev_name(dev)))
				goto err_unlock;
	}

	rc = device_add(dev);
	if (rc)
		goto err_unlock;

	/* register cdev */
	rc = -ENOMEM;
	cdev = cdev_alloc();
	if (!cdev)
		goto err_unlock;

	cdev->owner = THIS_MODULE;
	cdev->ops = &tmcd_frontend_fops;

	rc = cdev_add(cdev, devt, 1);
	if (rc)
		goto err_cdev;

	cc->dev = dev;
	cc->cdev = cdev;

	/* make the device available */
	list_add(&cc->list, tmcd_conntbl_head(devt));
	mutex_unlock(&tmcd_lock);

	/* announce device availability */
	dev_set_uevent_suppress(dev, 0);
	kobject_uevent(&dev->kobj, KOBJ_ADD);
out:
	kfree(arg);
	__free_page(page);
	return;

err_cdev:
	cdev_del(cdev);
err_unlock:
	mutex_unlock(&tmcd_lock);
	put_device(dev);
err_region:
	unregister_chrdev_region(devt, 1);
err:
	tmfs_abort_conn(fc);
	goto out;
}

static int tmcd_send_init(struct tmcd_conn *cc)
{
	int rc;
	struct tmfs_req *req;
	struct page *page;
	struct tmfs_conn *fc = &cc->fc;
	struct tmcd_init_in *arg;
	void *outarg;

	BUILD_BUG_ON(TMCD_INIT_INFO_MAX > PAGE_SIZE);

	req = tmfs_get_req_for_background(fc, 1);
	if (IS_ERR(req)) {
		rc = PTR_ERR(req);
		goto err;
	}

	rc = -ENOMEM;
	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		goto err_put_req;

	outarg = kzalloc(sizeof(struct tmcd_init_out), GFP_KERNEL);
	if (!outarg)
		goto err_free_page;

	arg = &req->misc.tmcd_init_in;
	arg->major = TMFS_KERNEL_VERSION;
	arg->minor = TMFS_KERNEL_MINOR_VERSION;
	arg->flags |= TMCD_UNRESTRICTED_IOCTL;
	req->in.h.opcode = TMCD_INIT;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct tmcd_init_in);
	req->in.args[0].value = arg;
	req->out.numargs = 2;
	req->out.args[0].size = sizeof(struct tmcd_init_out);
	req->out.args[0].value = outarg;
	req->out.args[1].size = TMCD_INIT_INFO_MAX;
	req->out.argvar = 1;
	req->out.argpages = 1;
	req->pages[0] = page;
	req->page_descs[0].length = req->out.args[1].size;
	req->num_pages = 1;
	req->end = tmcd_process_init_reply;
	tmfs_request_send_background(fc, req);

	return 0;

err_free_page:
	__free_page(page);
err_put_req:
	tmfs_put_request(fc, req);
err:
	return rc;
}

static void tmcd_fc_release(struct tmfs_conn *fc)
{
	struct tmcd_conn *cc = fc_to_cc(fc);
	kfree_rcu(cc, fc.rcu);
}

/**
 * tmcd_channel_open - open method for /dev/tmcd
 * @inode: inode for /dev/tmcd
 * @file: file struct being opened
 *
 * Userland TMCD server can create a TMCD device by opening /dev/tmcd
 * and replying to the initialization request kernel sends.  This
 * function is responsible for handling TMCD device initialization.
 * Because the fd opened by this function is used during
 * initialization, this function only creates tmcd_conn and sends
 * init.  The rest is delegated to a kthread.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int tmcd_channel_open(struct inode *inode, struct file *file)
{
	struct tmfs_dev *fud;
	struct tmcd_conn *cc;
	int rc;

	/* set up tmcd_conn */
	cc = kzalloc(sizeof(*cc), GFP_KERNEL);
	if (!cc)
		return -ENOMEM;

	tmfs_conn_init(&cc->fc);

	fud = tmfs_dev_alloc(&cc->fc);
	if (!fud) {
		kfree(cc);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&cc->list);
	cc->fc.release = tmcd_fc_release;

	cc->fc.initialized = 1;
	rc = tmcd_send_init(cc);
	if (rc) {
		tmfs_dev_free(fud);
		return rc;
	}
	file->private_data = fud;

	return 0;
}

/**
 * tmcd_channel_release - release method for /dev/tmcd
 * @inode: inode for /dev/tmcd
 * @file: file struct being closed
 *
 * Disconnect the channel, deregister TMCD device and initiate
 * destruction by putting the default reference.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int tmcd_channel_release(struct inode *inode, struct file *file)
{
	struct tmfs_dev *fud = file->private_data;
	struct tmcd_conn *cc = fc_to_cc(fud->fc);
	int rc;

	/* remove from the conntbl, no more access from this point on */
	mutex_lock(&tmcd_lock);
	list_del_init(&cc->list);
	mutex_unlock(&tmcd_lock);

	/* remove device */
	if (cc->dev)
		device_unregister(cc->dev);
	if (cc->cdev) {
		unregister_chrdev_region(cc->cdev->dev, 1);
		cdev_del(cc->cdev);
	}
	/* Base reference is now owned by "fud" */
	tmfs_conn_put(&cc->fc);

	rc = tmfs_dev_release(inode, file);	/* puts the base reference */

	return rc;
}

static struct file_operations tmcd_channel_fops; /* initialized during init */


/**************************************************************************
 * Misc stuff and module initializatiion
 *
 * TMCD exports the same set of attributes to sysfs as tmfsctl.
 */

static ssize_t tmcd_class_waiting_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct tmcd_conn *cc = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", atomic_read(&cc->fc.num_waiting));
}
static DEVICE_ATTR(waiting, 0400, tmcd_class_waiting_show, NULL);

static ssize_t tmcd_class_abort_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct tmcd_conn *cc = dev_get_drvdata(dev);

	tmfs_abort_conn(&cc->fc);
	return count;
}
static DEVICE_ATTR(abort, 0200, NULL, tmcd_class_abort_store);

static struct attribute *tmcd_class_dev_attrs[] = {
	&dev_attr_waiting.attr,
	&dev_attr_abort.attr,
	NULL,
};
ATTRIBUTE_GROUPS(tmcd_class_dev);

static struct miscdevice tmcd_miscdev = {
	.minor		= TMCD_MINOR,
	.name		= "tmcd",
	.fops		= &tmcd_channel_fops,
};

MODULE_ALIAS_MISCDEV(TMCD_MINOR);
MODULE_ALIAS("devname:tmcd");

static int __init tmcd_init(void)
{
	int i, rc;

	/* init conntbl */
	for (i = 0; i < TMCD_CONNTBL_LEN; i++)
		INIT_LIST_HEAD(&tmcd_conntbl[i]);

	/* inherit and extend tmfs_dev_operations */
	tmcd_channel_fops		= tmfs_dev_operations;
	tmcd_channel_fops.owner		= THIS_MODULE;
	tmcd_channel_fops.open		= tmcd_channel_open;
	tmcd_channel_fops.release	= tmcd_channel_release;

	tmcd_class = class_create(THIS_MODULE, "tmcd");
	if (IS_ERR(tmcd_class))
		return PTR_ERR(tmcd_class);

	tmcd_class->dev_groups = tmcd_class_dev_groups;

	rc = misc_register(&tmcd_miscdev);
	if (rc) {
		class_destroy(tmcd_class);
		return rc;
	}

	return 0;
}

static void __exit tmcd_exit(void)
{
	misc_deregister(&tmcd_miscdev);
	class_destroy(tmcd_class);
}

module_init(tmcd_init);
module_exit(tmcd_exit);

MODULE_AUTHOR("Tejun Heo <tj@kernel.org>");
MODULE_DESCRIPTION("Character device in Userspace");
MODULE_LICENSE("GPL");
