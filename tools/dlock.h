/*
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 */

#ifndef _DLOCK_H
#define _DLOCK_H

#define DL_GL_MODE_NOARG        0x00000001
#define DL_GL_MODE_NODEF        0x00000002
#define DL_GL_MODE_NOCMD        0x00000004
#define DL_GL_RENEW_CACHE       0x00000008

#define DL_VG_MODE_NOARG        0x00000001
#define DL_VG_MODE_NODEF        0x00000002
#define DL_VG_MODE_NOCMD        0x00000004
#define DL_VG_PERSISTENT        0x00000008

#define DL_LV_MODE_NOARG        0x00000001
#define DL_LV_MODE_NOCMD        0x00000002
#define DL_LV_PERSISTENT        0x00000004

#ifdef LVMLOCKD_SUPPORT

int dlock_gl(struct cmd_context *cmd, const char *def_mode, uint32_t flags);
int dlock_gl_create(struct cmd_context *cmd, const char *def_mode, uint32_t flags,
		    const char *lock_type);
int dlock_vg(struct cmd_context *cmd, const char *vg_name,
             const char *def_mode, uint32_t flags);
int dlock_lv(struct cmd_context *cmd, struct logical_volume *lv,
             const char *def_mode, uint32_t flags);

int dlock_gl_vg(struct cmd_context *cmd, const char *vg_name,
                const char *def_gl_mode, const char *def_vg_mode,
                uint32_t flags);

int dlock_lv_name(struct cmd_context *cmd, struct volume_group *vg,
                  const char *lv_name, const char *lock_args,
                  const char *def_mode, uint32_t flags);

#else /* LVMLOCKD_SUPPORT */

#define dlock_gl(cmd, def_mode, flags) (1)
#define dlock_gl_create(cmd, def_mode, flags, lock_type) (1)
#define dlock_vg(cmd, vg_name, def_mode, flags) (1)
#define dlock_lv(cmd, lv, def_mode, flags) (1)
#define dlock_gl_vg(cmd, vg_name, def_gl_mode, def_vg_mode, flags) (1)
#define dlock_lv_name(cmd, vg, lv_name, lock_args, def_mode flags) (1)

#endif /* LVMLOCKD_SUPPORT */

#endif
