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

int dlock_gl(const char *mode);

int dlock_vg(const char *vg_name, const char *mode);
int dlock_vg_persistent(const char *vg_name, const char *mode);

int dlock_lv_name(const char *vg_name, const char *lv_name, const char *lock_args,
                  const char *mode, const char *opts);
int dlock_lv(struct logical_volume *lv, const char *mode);
int dlock_lv_persistent(struct logical_volume *lv, const char *mode);

/* short for dlock_gl+dlock_vg */
int dlock_gl_vg(const char *vg_name, const char *gl_mode, const char *vg_mode);


/*
 * tell lvmlockd to update the vg lock's version when it's released
 *
 * this is called in vg_commit after the updated vg metadata
 * is sent to lvmetad (lvmetad_vg_update).
 */

int dlock_vg_update(struct volume_group *vg);

/*
 * init/free both disk areas and locking
 */

int dlock_init_vg(struct cmd_context *cmd, struct volume_group *vg);
int dlock_undo_vg(struct cmd_context *cmd, struct volume_group *vg);
int dlock_free_vg(char *vg_name, const char *lock_type);

int dlock_init_lv(struct cmd_context *cmd, struct volume_group *vg, void *lp);
int dlock_free_lv(struct volume_group *vg, const char *lv_name,
		  const char *lock_type, const char *lock_args);

/*
 * Start/join lockspaces.
 */

int dlock_start_vg(struct cmd_context *cmd, struct volume_group *vg);

#else /* LVMLOCKD_SUPPORT */

#define lvmlockd_init(cmd)					do { } while (0)
#define lvmlockd_set_active(int)				do { } while (0)
#define lvmlockd_set_socket(path)				do { } while (0)
#define lvmlockd_active()					(0)
#define lvmlockd_warning()					do { } while (0)
#define lvmlockd_disconnect()					do { } while (0)
#define lvmlockd_config_free()					do { } while (0)
#define dlock_gl(mode)						do { } while (0)
#define dlock_vg(vg_name, mode)					do { } while (0)
#define dlock_vg_persistent(vg_name, mode)			do { } while (0)
#define dlock_lv_name(vg_name, lv_name, lock_args, mode, opts)	do { } while (0)
#define dlock_lv(lv, mode)					do { } while (0)
#define dlock_lv_persistent(lv, mode)				do { } while (0)
#define dlock_gl_vg(vg_name, gl_mode, vg_mode)			do { } while (0)
#define dlock_vg_update(vg)					do { } while (0)
#define dlock_init_vg(cmd, vg) 					do { } while (0)
#define dlock_undo_vg(cmd, vg)					do { } while (0)
#define dlock_free_vg(vg_name, lock_type)			do { } while (0)
#define dlock_init_lv(vg, lp)					do { } while (0)
#define dlock_free_lv(vg, lv_name, lock_type, lock_args) 	do { } while (0)
#define dlock_start_vg(cmd, vg)					do { } while (0)

#endif

#endif
