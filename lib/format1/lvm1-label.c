/*
 * Copyright (C) 2002-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "lib.h"
#include "lvm1-label.h"
#include "disk-rep.h"
#include "label.h"
#include "metadata.h"
#include "xlate.h"
#include "format1.h"

#include <sys/stat.h>
#include <fcntl.h>

static void _not_supported(const char *op)
{
	log_error("The '%s' operation is not supported for the lvm1 labeller.",
		  op);
}

static int _lvm1_can_handle(struct labeller *l __attribute__((unused)), void *buf, uint64_t sector)
{
	struct pv_disk *pvd = (struct pv_disk *) buf;
	uint32_t version;

	/* LVM1 label must always be in first sector */
	if (sector)
		return 0;

	version = xlate16(pvd->version);

	if (pvd->id[0] == 'H' && pvd->id[1] == 'M' &&
	    (version == 1 || version == 2))
		return 1;

	return 0;
}

static int _lvm1_write(struct label *label __attribute__((unused)), void *buf __attribute__((unused)))
{
	_not_supported("write");
	return 0;
}

static int _lvm1_read(struct labeller *l, struct device *dev, void *buf, unsigned ioflags,
		      lvm_callback_fn_t read_label_callback_fn, void *read_label_callback_context)
{
	struct pv_disk *pvd = (struct pv_disk *) buf;
	struct vg_disk vgd;
	struct lvmcache_info *info;
	struct label *label = NULL;
	const char *vgid = FMT_LVM1_ORPHAN_VG_NAME;
	const char *vgname = FMT_LVM1_ORPHAN_VG_NAME;
	unsigned exported = 0;
	int r = 0;

	munge_pvd(dev, pvd);

	if (*pvd->vg_name) {
		if (!read_vgd(dev, &vgd, pvd))
			return_0;
		vgid = (char *) vgd.vg_uuid;
		vgname = (char *) pvd->vg_name;
		exported = pvd->pv_status & VG_EXPORTED;
	}

	if (!(info = lvmcache_add(l, (char *)pvd->pv_uuid, dev, vgname, vgid,
				  exported)))
		goto_out;

	label = lvmcache_get_label(info);

	lvmcache_set_device_size(info, ((uint64_t)xlate32(pvd->pv_size)) << SECTOR_SHIFT);
	lvmcache_set_ext_version(info, 0);
	lvmcache_set_ext_flags(info, 0);
	lvmcache_del_mdas(info);
	lvmcache_del_bas(info);
	lvmcache_make_valid(info);

	r = 1;

out:
	if (read_label_callback_fn)
		read_label_callback_fn(!r, 0, read_label_callback_context, label);

	return r;
}

static int _lvm1_initialise_label(struct labeller *l __attribute__((unused)), struct label *label)
{
	strcpy(label->type, "LVM1");

	return 1;
}

static void _lvm1_destroy_label(struct labeller *l __attribute__((unused)), struct label *label __attribute__((unused)))
{
}

static void _lvm1_destroy(struct labeller *l)
{
	dm_free(l);
}

struct label_ops _lvm1_ops = {
	.can_handle = _lvm1_can_handle,
	.write = _lvm1_write,
	.read = _lvm1_read,
	.initialise_label = _lvm1_initialise_label,
	.destroy_label = _lvm1_destroy_label,
	.destroy = _lvm1_destroy,
};

struct labeller *lvm1_labeller_create(struct format_type *fmt)
{
	struct labeller *l;

	if (!(l = dm_malloc(sizeof(*l)))) {
		log_error("Couldn't allocate labeller object.");
		return NULL;
	}

	l->ops = &_lvm1_ops;
	l->fmt = fmt;

	return l;
}
