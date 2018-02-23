/*
 * Copyright (C) 2002-2004 Sistina Software, Inc. All rights reserved.  
 * Copyright (C) 2004-2007 Red Hat, Inc. All rights reserved.
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

#ifndef _LVM_LABEL_H
#define _LVM_LABEL_H

#include "lib/uuid/uuid.h"
#include "lib/device/device.h"
#include "lib/device/bcache.h"
#include "lib/commands/toolcontext.h"

#define LABEL_ID "LABELONE"
#define LABEL_SIZE SECTOR_SIZE	/* Think very carefully before changing this */
#define LABEL_SCAN_SECTORS 4L
#define LABEL_SCAN_SIZE (LABEL_SCAN_SECTORS << SECTOR_SHIFT)

struct labeller;

/* On disk - 32 bytes */
struct label_header {
	int8_t id[8];		/* LABELONE */
	uint64_t sector_xl;	/* Sector number of this label */
	uint32_t crc_xl;	/* From next field to end of sector */
	uint32_t offset_xl;	/* Offset from start of struct to contents */
	int8_t type[8];		/* LVM2 001 */
} __attribute__ ((packed));

/* In core */
struct label {
	char type[8];
	uint64_t sector;
	struct labeller *labeller;
	struct device *dev;
	void *info;
};

struct labeller;

struct label_ops {
	/*
	 * Is the device labelled with this format ?
	 */
	int (*can_handle) (struct labeller * l, void *buf, uint64_t sector);

	/*
	 * Write a label to a volume.
	 */
	int (*write) (struct label * label, void *buf);

	/*
	 * Read a label from a volume.
	 */
	int (*read) (struct labeller * l, struct device * dev,
		     void *label_buf, struct label ** label);

	/*
	 * Populate label_type etc.
	 */
	int (*initialise_label) (struct labeller * l, struct label * label);

	/*
	 * Destroy a previously read label.
	 */
	void (*destroy_label) (struct labeller * l, struct label * label);

	/*
	 * Destructor.
	 */
	void (*destroy) (struct labeller * l);
};

struct labeller {
	struct label_ops *ops;
	const struct format_type *fmt;
};

int label_init(void);
void label_exit(void);

int label_register_handler(struct labeller *handler);

struct labeller *label_get_handler(const char *name);

int label_remove(struct device *dev);
int label_write(struct device *dev, struct label *label);
struct label *label_create(struct labeller *labeller);
void label_destroy(struct label *label);

extern struct bcache *scan_bcache;

int label_scan(struct cmd_context *cmd);
int label_scan_devs(struct cmd_context *cmd, struct dm_list *devs);
int label_scan_devs_excl(struct dm_list *devs);
void label_scan_invalidate(struct device *dev);
void label_scan_invalidate_lv(struct cmd_context *cmd, struct logical_volume *lv);
void label_scan_destroy(struct cmd_context *cmd);
int label_read(struct device *dev, struct label **labelp, uint64_t unused_sector);
int label_read_sector(struct device *dev, struct label **labelp, uint64_t scan_sector);
void label_scan_confirm(struct device *dev);
int label_scan_setup_bcache(void);
int label_scan_open(struct device *dev);

#endif
