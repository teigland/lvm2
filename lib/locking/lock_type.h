/*
 * Copyright (C) 2013 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 */

#ifndef _LOCK_TYPE_H
#define _LOCK_TYPE_H

#define LOCK_TYPE_NONE    0
#define LOCK_TYPE_UNUSED  1 /* may be used later */
#define LOCK_TYPE_CLVM    2
#define LOCK_TYPE_DLM     3
#define LOCK_TYPE_SANLOCK 4

/* The name of the internal lv created to hold sanlock locks. */
#define SANLOCK_LV_NAME "lvmlock"

#ifdef LVMLOCKD_SUPPORT

/*
 * Convert names to numbers e.g. "none" to LOCK_TYPE_NONE.
 * This is done in places where it's easier to work with
 * numbers rather than strings.
 */
int lock_type_to_num(const char *lock_type);

int vg_init_lock_args(struct cmd_context *cmd, struct volume_group *vg);

int vg_free_lock_args_before(struct cmd_context *cmd, struct volume_group *vg);
void vg_free_lock_args_final(struct cmd_context *cmd, struct volume_group *vg);

int lv_init_lock_args(struct cmd_context *cmd,
		      struct volume_group *vg, const char *lv_name,
		      const char *lock_type, const char **lock_args);

int lv_free_lock_args(struct cmd_context *cmd,
		      struct volume_group *vg, const char *lv_name,
		      const char *lock_type, const char *lock_args);

#else /* LVMLOCKD_SUPPORT */

#define lock_type_to_num(lock_type) (0)
#define vg_init_lock_args(cmd, vg) (1)
#define vg_free_lock_args_before(cmd, vg) (1)
#define vg_free_lock_args_final(cmd, vg) do { } while (0)
#define lv_init_lock_args(cmd, vg, lv_name, lock_type, lock_args) (1)
#define lv_free_lock_args(cmd, vg, lv_name, lock_type, lock_args) do { } while (0)

#endif /* LVMLOCKD_SUPPORT */

#endif
