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

/* daemon management */

void lvmlockd_init(struct cmd_context *);
void lvmlockd_set_active(int);
void lvmlockd_set_socket(const char *);
void lvmlockd_disconnect(void);
void lvmlockd_connect_or_warn(void);

/*
 * dlock_vg_update:
 * Tell lvmlockd to update the vg lock's version when it's released.
 * This is called in vg_commit after the updated vg metadata
 * is sent to lvmetad (lvmetad_vg_update).
 */

int dlock_vg_update(struct volume_group *vg);

int dlock_init_vg_sanlock(struct cmd_context *cmd, struct volume_group *vg);
int dlock_init_vg_dlm(struct cmd_context *cmd, struct volume_group *vg);

int dlock_free_vg_sanlock(struct cmd_context *cmd, struct volume_group *vg);
int dlock_free_vg_dlm(struct cmd_context *cmd, struct volume_group *vg);

int dlock_init_lv_sanlock(struct cmd_context *cmd,
                          struct volume_group *vg, const char *lv_name,
                          const char *lock_type, const char **lock_args_ret);

int dlock_free_lv_sanlock(struct cmd_context *cmd,
                          struct volume_group *vg, const char *lv_name,
                          const char *lock_type, const char *lock_args);

int dlock_start_vg(struct cmd_context *cmd, struct volume_group *vg,
		   const char *cmd_mode);
int dlock_stop_vg(struct cmd_context *cmd, struct volume_group *vg);

int dlock_type(const char *lock_type);

int dlock_general(struct cmd_context *cmd,
                  const char *cmd_name,
                  const char *id,
                  const char *vg_name,
                  const char *vg_lock_type,
                  const char *vg_lock_args,
                  const char *lv_name,
                  const char *lv_lock_args,
                  const char *mode,
                  const char *opts);

#else /* LVMLOCKD_SUPPORT */

#define lvmlockd_init(cmd)							do { } while (0)
#define lvmlockd_set_active(int)						do { } while (0)
#define lvmlockd_set_socket(str)						do { } while (0)
#define lvmlockd_disconnect()							do { } while (0)
#define lvmlockd_connect_or_warn()						do { } while (0)

#define dlock_vg_update(vg)							do { } while (0)
#define dlock_init_vg_sanlock(cmd, vg)						do { } while (0)
#define dlock_init_vg_dlm(cmd, vg)						do { } while (0)
#define dlock_free_vg_sanlock(cmd, vg)						do { } while (0)
#define dlock_free_vg_dlm(cmd, vg)						do { } while (0)
#define dlock_init_lv_sanlock(cmd, vg, lv_name, lock_type, lock_args_ret)	do { } while (0)
#define dlock_free_lv_sanlock(cmd, vg, lv_name, lock_type, lock_args)		do { } while (0)
#define dlock_start_vg(cmd, vg, cmd_mode)					(1)
#define dlock_stop_vg(cmd, vg)							(1)
#define dlock_type(lock_type)							(0)
#define dlock_general(cmd, cmd_name, id, vg_name, vg_lock_type, vg_lock_args, lv_name, lv_lock_args, mode, opts) (1)

#endif /* LVMLOCKD_SUPPORT */

#endif
