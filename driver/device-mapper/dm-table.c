/*
 * dm-table.c
 *
 * Copyright (C) 2001 Sistina Software
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Changelog
 *
 *     16/08/2001 - First version [Joe Thornber]
 */

#include "dm.h"

/* ceiling(n / size) * size */
static inline ulong round_up(ulong n, ulong size)
{
	ulong r = n % size;
	return n + (r ? (size - r) : 0);
}

/* ceiling(n / size) */
static inline ulong div_up(ulong n, ulong size)
{
	return round_up(n, size) / size;
}

/* similar to ceiling(log_size(n)) */
static uint int_log(ulong n, ulong base)
{
	int result = 0;

	while (n > 1) {
		n = div_up(n, base);
		result++;
	}

	return result;
}

/*
 * return the highest key that you could lookup
 * from the n'th node on level l of the btree.
 */
static offset_t high(struct dm_table *t, int l, int n)
{
	while (1) {
		if (n >= t->counts[l])
			return (offset_t) -1;

		if (l == t->depth - 1)
			return t->index[l][((n + 1) * KEYS_PER_NODE) - 1];

		l++;
		n = (n + 1) * (KEYS_PER_NODE + 1) - 1;
	}

	return -1;
}

/*
 * fills in a level of the btree based on the
 * highs of the level below it.
 */
static int setup_btree_index(int l, struct dm_table *t)
{
	int n, c, cn;

	for (n = 0, cn = 0; n < t->counts[l]; n++) {
		offset_t *k = t->index[l] + (n * KEYS_PER_NODE);

		for (c = 0; c < KEYS_PER_NODE; c++)
			k[c] = high(t, l + 1, cn++);
		cn++;		/* one extra for the child that's
                                   greater than all keys */
	}

	return 0;
}

/*
 * highs, and targets are managed as dynamic
 * arrays during a table load.
 */
static int alloc_targets(struct dm_table *t, int num)
{
	offset_t *n_highs;
	struct target *n_targets;
	int n = t->num_targets;

	if (!(n_highs = vmalloc(sizeof(*n_highs) * num)))
		return -ENOMEM;

	if (!(n_targets = vmalloc(sizeof(*n_targets) * num))) {
		vfree(n_highs);
		return -ENOMEM;
	}

	if (n) {
		memcpy(n_highs, t->highs, sizeof(*n_highs) * n);
		memcpy(n_targets, t->targets, sizeof(*n_targets) * n);
	}

	vfree(t->highs);
	vfree(t->targets);

	t->num_allocated = num;
	t->highs = n_highs;
	t->targets = n_targets;

	return 0;
}

struct dm_table *dm_table_create(void)
{
	struct dm_table *t = kmalloc(sizeof(struct dm_table), GFP_NOIO);

	if (!t)
		return 0;

	memset(t, 0, sizeof(*t));

	/* allocate a single nodes worth of targets to
	   begin with */
	if (t && alloc_targets(t, KEYS_PER_NODE)) {
		kfree(t);
		t = 0;
	}

	return t;
}

void dm_table_destroy(struct dm_table *t)
{
	int i;

	if (!t)
		return;

	/* free the indexes */
	for (i = 0; i < t->depth - 1; i++) {
		vfree(t->index[i]);
		t->index[i] = 0;
	}
	vfree(t->highs);

	/* free the targets */
	for (i = 0; i < t->num_targets; i++) {
		struct target *tgt = &t->targets[i];
		tgt->type->dtr(t, tgt->private);
	}
	vfree(t->targets);

	/* free the device list */
	if (t->devices) {
		struct dev_list *d, *n;

		WARN("there are still devices present, someone isn't "
		     "calling dm_table_remove_device");

		for (d = t->devices; d; d = n) {
			n = d->next;
			kfree(d);
		}
	}

	kfree(t);
}

/*
 * checks to see if we need to extend highs or targets
 */
static inline int check_space(struct dm_table *t)
{
	if (t->num_targets >= t->num_allocated)
		return alloc_targets(t, t->num_allocated * 2);

	return 0;
}

/*
 * adds a target to the map
 */
int dm_table_add_target(struct dm_table *t, offset_t high,
			struct target_type *type, void *private)
{
	int r, n;

	if ((r = check_space(t)))
		return r;

	n = t->num_targets++;
	t->highs[n] = high;
	t->targets[n].type = type;
	t->targets[n].private = private;

	return 0;
}

/*
 * convert a device path to a kdev_t.
 */
int dm_table_lookup_device(const char *path, kdev_t *d)
{
	int r;
	struct nameidata nd;
	struct inode *inode;

	if (!path_init(path, LOOKUP_FOLLOW, &nd))
		return 0;

	if ((r = path_walk(path, &nd)))
		goto bad;

	inode = nd.dentry->d_inode;
	if (!inode) {
		r = -ENOENT;
		goto bad;
	}

	if (!S_ISBLK(inode->i_mode)) {
		r = -EINVAL;
		goto bad;
	}

	*d = inode->i_bdev->bd_dev;

 bad:
	path_release(&nd);
	return r;
}

/*
 * see if we've already got a device in the list.
 */
static struct dev_list **find_device(struct dev_list **d, kdev_t dev)
{
	while (*d) {
		if ((*d)->dev == dev)
			break;

		d = &(*d)->next;
	}

	return d;
}

/*
 * add a device to the list, or just increment the
 * usage count if it's already present.
 */
int dm_table_add_device(struct dm_table *t, kdev_t dev)
{
	struct dev_list *d;

	d = *find_device(&t->devices, dev);
	if (!d) {
		d = kmalloc(sizeof(*d), GFP_KERNEL);
		if (!d)
			return -ENOMEM;

		d->dev = dev;
		atomic_set(&d->count, 0);
		d->next = t->devices;
		t->devices = d;
	}
	atomic_inc(&d->count);

	return 0;
}

/*
 * decrement a devices use count and remove it if
 * neccessary.
 */
void dm_table_remove_device(struct dm_table *t, kdev_t dev)
{
	struct dev_list **d = find_device(&t->devices, dev);

	if (!*d) {
		WARN("asked to remove a device that isn't present");
		return;
	}

	if (atomic_dec_and_test(&(*d)->count)) {
		struct dev_list *node = *d;
		*d = (*d)->next;
		kfree(node);
	}
}

/*
 * builds the btree to index the map
 */
int dm_table_complete(struct dm_table *t)
{
	int i, leaf_nodes;

	/* how many indexes will the btree have ? */
	leaf_nodes = div_up(t->num_targets, KEYS_PER_NODE);
	t->depth = 1 + int_log(leaf_nodes, KEYS_PER_NODE + 1);

	/* leaf layer has already been set up */
	t->counts[t->depth - 1] = leaf_nodes;
	t->index[t->depth - 1] = t->highs;

	/* set up internal nodes, bottom-up */
	for (i = t->depth - 2; i >= 0; i--) {
		t->counts[i] = div_up(t->counts[i + 1], KEYS_PER_NODE + 1);
		t->index[i] = vmalloc(NODE_SIZE * t->counts[i]);
		setup_btree_index(i, t);
	}

	return 0;
}


EXPORT_SYMBOL(dm_table_add_device);
