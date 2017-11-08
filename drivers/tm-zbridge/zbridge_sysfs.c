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

#include <linux/kobject.h>
#include <linux/module.h>
#include "zbridge.h"

uint64_t cur_book_offset;
uint64_t cur_booklet_offset;

/* helpers */
static ssize_t table_entry_show(enum DESCS desc, uint64_t offset, ssize_t size,
				char *buf)
{
	uint64_t value;

	switch (desc) {
		case BOOK:
			value = read_book_offset_value(offset);
			break;
		case BOOKLET:
			value = read_booklet_offset_value(offset);
			break;
	}

	return scnprintf(buf, size, "%lld, 0x%llx\n", offset, value);
}

static ssize_t table_entry_store(enum DESCS desc, struct kobject *kobj,
				struct kobj_attribute *attr, const char *buf,
				size_t count)
{
	char **args;
	int num, ret;
	uint64_t offset, value;

	args = argv_split(GFP_KERNEL, buf, &num);

	if (!args)
		return -ENOMEM;

	if (strlen(args[0]) != 3)
		return -EINVAL;

	/* TODO refactor this */
	if (num == 2 && !strcmp(args[0], "set")) {
		ret = kstrtou64(args[1], 0, &offset);
		argv_free(args);

		if (ret) {
			/* pr_err("Error converting offset string\n"); */
			return count;
		}

		if (offset < 0 || offset > DESCRIPTORS_PER_TABLE)
			return count; /* proper error? */

		switch (desc) {
			case BOOK:
				cur_book_offset = offset;
				break;
			case BOOKLET:
				cur_booklet_offset = offset;
				break;
		}
		return count;
	} else if (num == 3 && !strcmp(args[0], "put")) {
		ret = kstrtou64(args[1], 0, &offset);
		ret |= kstrtou64(args[2], 0, &value);

		argv_free(args);

		if (ret) {
			/* pr_err("Error converting offset or value string"); */
			return count;
		}

		if (offset < 0 || offset > DESCRIPTORS_PER_TABLE - 1)
			return count; /* proper error? */

		switch (desc) {
			case BOOK:
				write_desbk_full(offset, value);
				break;
			case BOOKLET:
				write_desbl_full(offset, value);
				break;
		}
	} else {
		argv_free(args);
		return count; /* proper error? */
	}

	return count;

}

static ssize_t book_table_store(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buf,
				size_t count)
{
	return table_entry_store(BOOK, kobj, attr, buf, count);
}

static ssize_t booklet_table_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	return table_entry_store(BOOKLET, kobj, attr, buf, count);
}

static ssize_t book_table_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	return table_entry_show(BOOK, cur_book_offset, PAGE_SIZE, buf);
}

static ssize_t booklet_table_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return table_entry_show(BOOKLET, cur_booklet_offset, PAGE_SIZE, buf);
}

static ssize_t book_table_cursor_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	char **args;
	int num, ret;
	uint64_t offset;

	args = argv_split(GFP_KERNEL, buf, &num);

	if (!args) {
		argv_free(args);
		return -ENOMEM;
	}

	if (num != 1) {
		argv_free(args);
		return count; /* proper value? */
	}

	ret = kstrtou64(args[0], 0, &offset);
	argv_free(args);

	if (ret)
		/* pr_err("Error converting offset string"); */
		return count;

	/* Test and refactor this */
	if (offset < 0 || offset > (DESCRIPTORS_PER_TABLE - 1)) {
		/* test this */
		/* invalid offset ignoring */
		return count;
	}
	cur_book_offset = offset;
	return count;
}

static ssize_t book_table_cursor_show(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%lld\n", cur_book_offset);
}

static ssize_t booklet_table_cursor_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	char **args;
	int num, ret;
	uint64_t offset;

	args = argv_split(GFP_KERNEL, buf, &num);

	if (!args) {
		argv_free(args);
		return -ENOMEM;
	}

	if (num != 1) {
		argv_free(args);
		return -1; /* proper value? */
	}

	ret = kstrtou64(args[0], 0, &offset);
	argv_free(args);

	if (ret) {
		/* pr_err("Error converting offset string"); */
		return count;
	}

	/* MAXIMUM_OFFSET? */
	if (offset < 0 || offset > (DESCRIPTORS_PER_TABLE - 1))
		return count;

	cur_booklet_offset = offset;
	return count;
}

static ssize_t booklet_table_cursor_show(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%lld\n", cur_booklet_offset);
}

static struct kobj_attribute book_table_attr = __ATTR(book_table, 0644,
		book_table_show, book_table_store);

static struct kobj_attribute book_table_cursor_attr = __ATTR(book_table_cursor,
		0644, book_table_cursor_show, book_table_cursor_store);

static struct kobj_attribute booklet_table_attr = __ATTR(booklet_table, 0644,
		booklet_table_show, booklet_table_store);

static struct kobj_attribute booklet_table_cursor_attr =
		 __ATTR(booklet_table_cursor, 0644,
			booklet_table_cursor_show, booklet_table_cursor_store);

/* FIXME insert into the proper part of /dev/w/e */
static struct attribute *attrs[] = {
	&book_table_attr.attr,
	&booklet_table_attr.attr,
	&book_table_cursor_attr.attr,
	&booklet_table_cursor_attr.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

struct kobject *desc_sysfs_kobj;

int desc_sysfs_init(void)
{
	desc_sysfs_kobj = kobject_create_and_add("desc", kernel_kobj);

	if (!desc_sysfs_kobj)
		return -ENOMEM;

	return sysfs_create_group(desc_sysfs_kobj, &attr_group);
}

void desc_sysfs_exit(void)
{
	sysfs_remove_group(desc_sysfs_kobj, &attr_group);
	kobject_put(desc_sysfs_kobj);
}

/* end sysfs */

