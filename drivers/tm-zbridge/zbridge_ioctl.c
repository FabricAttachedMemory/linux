 /*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

/*
 * Descriptor table Read/Write ioctl interface
 * mostly copied from http://people.ee.ethz.ch/~arkeller/linux/code/ioctl.c
 */

#include <linux/fs.h>
#include <linux/ioport.h>
#include <linux/miscdevice.h>  /* change this an have a real device type */
#include "zbridge.h"

static int check_bounds(uint64_t offset)
{
	return (offset < 0 || offset > (DESCRIPTORS_PER_TABLE - 1));
}

static long device_ioctl(struct file *filep, unsigned int cmd,
			 unsigned long arg)
{
	int ret;
	void *owner = (void *)0xBEDABEDA;
	struct desc_ioctl_rep ioctl_rep;

	/* Ioctls are not supported on the self-hosted environment. */
	if (zbridge_get_environment() == SELF_HOSTED)
		return -EINVAL;

	switch (cmd) {
	case DESBK_READ_OFF:
		if (copy_from_user(&ioctl_rep, (struct desc_ioctl_rep *)arg,
				sizeof(struct desc_ioctl_rep)))
			return -EINVAL;

		/* TODO dummy checking */
		if (check_bounds(ioctl_rep.offset))
			return -EINVAL;

		ret = desbk_read_slot(ioctl_rep.offset, owner,
			&ioctl_rep.value);
		if (ret != 0)
			return -EFAULT;
		if (copy_to_user((struct desc_ioctl_rep *)arg, &ioctl_rep,
				sizeof(struct desc_ioctl_rep)))
			return -EFAULT;
		break;
	case DESBL_READ_OFF:
		if (copy_from_user(&ioctl_rep, (struct desc_ioctl_rep *)arg,
				sizeof(struct desc_ioctl_rep)))
			return -EFAULT;

		/* TODO dummy checking */
		if (check_bounds(ioctl_rep.offset))
			return -EINVAL;

		ret = desbl_read_slot(ioctl_rep.offset, owner,
			&ioctl_rep.value);
		if (ret != 0)
			return -EFAULT;
		if (copy_to_user((struct desc_ioctl_rep *)arg, &ioctl_rep,
				sizeof(struct desc_ioctl_rep)))
			return -EFAULT;
		break;
	case DESBK_PUT:
		if (copy_from_user(&ioctl_rep, (struct desc_ioctl_rep *)arg,
				sizeof(struct desc_ioctl_rep)))
			return -EFAULT;
		if (check_bounds(ioctl_rep.offset))
			return -EINVAL;

		desbk_get_slot(ioctl_rep.value, owner, &(ioctl_rep.offset),
			&(ioctl_rep.needs_eviction));
		desbk_put_slot(ioctl_rep.offset, ioctl_rep.value, owner);
		if (copy_to_user((struct desc_ioctl_rep *)arg, &ioctl_rep,
				sizeof(struct desc_ioctl_rep)))
			return -EFAULT;
		break;
	case DESBL_PUT:
		if (copy_from_user(&ioctl_rep, (struct desc_ioctl_rep *)arg,
				sizeof(struct desc_ioctl_rep)))
			return -EFAULT;
		if (check_bounds(ioctl_rep.offset))
			return -EINVAL;

		/* TODO dummy checking */
		write_desbl_full(ioctl_rep.offset, ioctl_rep.value);
		if (copy_to_user((struct desc_ioctl_rep *)arg, &ioctl_rep,
				sizeof(struct desc_ioctl_rep)))
			return -EFAULT;
		break;
#ifdef ZAP_IOCTL
	case DESBK_ZAP:
		if (zbridge_get_allow_zap())
			zbridge_zap_desbk();
		break;
	case DESBL_ZAP:
		if (zbridge_get_allow_zap())
			zbridge_zap_desbl();
		break;
#endif /* ZAP_IOCTL */
        case ZB_COMMIT:
		/*
		 * pmem_drain() triggers this ioctl when a change in the
		 * WRITE_COMMIT HSR is found. 
		 */
		PR_VERBOSE3("ZB_COMMIT ioctl\n");
		dump_error_regs();
		zbridge_write_error();
		break;

	default:
		return -ENOTTY;
	}

	return 0;
}

const struct file_operations fops = {
	.unlocked_ioctl = device_ioctl,
};

static struct miscdevice desc_misc = {
	MISC_DYNAMIC_MINOR,
	/* what's the common naming convention for ioctl? */
	"descioctl",
	&fops,
};

int desc_ioctl_init(void)
{
	return misc_register(&desc_misc);
}

void desc_ioctl_exit(void)
{
	misc_deregister(&desc_misc);
}
