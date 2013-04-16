/*
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 */

#ifndef _LVMLOCKD_H
#define _LVMLOCKD_H

#include "config-util.h"
#include "daemon-client.h"

struct cmd_context;
struct dm_config_tree;

#ifdef LVMLOCKD_SUPPORT

void lvmlockd_init(struct cmd_context *);
void lvmlockd_set_active(int);
void lvmlockd_set_socket(const char *);
int lvmlockd_active(void);
void lvmlockd_disconnect(void);
void lvmlockd_connect_or_warn(void);

void lvmlockd_config_set_host_id(const struct dm_config_value *val);
void lvmlockd_config_free(void);

/*
 * gl lock
 * - serializes changes to global non-vg metadata among nodes:
 *   orphan pv's and vg names
 * - invalidates global/orphan metadata cache after it has
 *   been changed by another node
 *
 * vg lock
 * - serializes changes to vg metdata among nodes
 * - invalidates vg metadata cache after vg has been changed by another node
 *
 * lv lock
 * - tracks activation of an lv among nodes:
 *   allows a node to activate an lv exclusively or non-exclusively
 *   allows a node to check if another node has the lv activated
 *
 * The vg metadata read from lvmetad is only known to be up to date if
 * the vg lock is acquired before the read.
 */

int dlock_gl(struct cmd_context *cmd, const char *def_mode, uint32_t flags);
int dlock_vg(struct cmd_context *cmd, const char *vg_name,
	     const char *def_mode, uint32_t flags);
int dlock_lv(struct cmd_context *cmd, struct logical_volume *lv,
	     const char *def_mode, uint32_t flags);

/*
 * tell lvmlockd to update the vg lock's version when it's released
 *
 * this is called in vg_commit after the updated vg metadata
 * is sent to lvmetad (lvmetad_vg_update).
 */

int dlock_vg_update(struct volume_group *vg);

int dlock_init_vg_sanlock(struct cmd_context *cmd, struct volume_group *vg);
int dlock_init_vg_dlm(struct cmd_context *cmd, struct volume_group *vg);
int dlock_free_vg_sanlock(const char *vg_name, const char *lock_type);
int dlock_start_vg(struct cmd_context *cmd, struct volume_group *vg);
int dlock_stop_vg(struct cmd_context *cmd, struct volume_group *vg);
int dlock_init_lv_sanlock(struct cmd_context *cmd, struct volume_group *vg,
			  char *lv_name, char **lock_args_ret);
int dlock_free_lv_sanlock(struct cmd_context *cmd, struct volume_group *vg,
			  const char *lv_name, const char *lv_lock_args);

#else /* LVMLOCKD_SUPPORT */

#define lvmlockd_init(cmd)					do { } while (0)
#define lvmlockd_set_active(int)				do { } while (0)
#define lvmlockd_set_socket(path)				do { } while (0)
#define lvmlockd_active()					(0)
#define lvmlockd_warning()					do { } while (0)
#define lvmlockd_disconnect()					do { } while (0)
#define lvmlockd_config_free()					do { } while (0)
#define dlock_vg_update(vg)					do { } while (0)

#endif

#endif
