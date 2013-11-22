/*
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 */

#include "tools.h"
#include "metadata.h"
#include "lvmetad.h"
#include "lvmlockd.h"
#include "lock_type.h"
#include "lvmcache.h"
#include "lvmlockd-client.h"

#if 0
static int mode_num(const char *m)
{
	if (!strcmp(mode, "na"))
		return -2;
	if (!strcmp(mode, "un"))
		return -1;
	if (!strcmp(mode, "nl"))
		return 0;
	if (!strcmp(mode, "sh"))
		return 1;
	if (!strcmp(mode, "ex"))
		return 2;
	return -3;
}

/* same rules as strcmp */
static int mode_compare(const char *m1, const char *m2)
{
	int n1 = mode_num(m1);
	int n2 = mode_num(m2);

	if (n1 < n2)
		return -1;
	if (n1 == n2)
		return 0;
	if (n1 > n2)
		return 1;
}
#endif

/*
 * When the gl is requested, it may not be strictly required,
 * so when the gl is not available, we may be able to continue
 * without it.
 *
 * Reasons that would lessen the necessity of locking gl:
 * no vgs exist (or are seen) that have lock_type dlm|sanlock
 * the vg being operated on by the command does not have lock_type dlm|sanlock
 * the gl lock mode is sh
 *
 * If gl is being locked in the course of locking a vg with a
 * lock_type dlm|sanlock, then we should fail if the gl cannot be locked.
 *
 * If gl is being locked in the course of locking a vg (or vgs), none
 * of which have a sanlock|dlm lock_type, then we could probably go
 * on without it, especially if the mode is sh.
 *
 * So, it may be helpful at some point for this function to know the
 * lock_type of the vg for which it is being used.
 *
 * Where should the "relaxing" decision be made?  Here or in lvmlockd?
 *
 *
 * Have have lvmlockd/dlock_general return three results:
 * success, fail, and skipped for cases where we believe it's
 * ok to continue without acquiring gl.
 *
 * e.g. no vg with gl enabled has been seen, and lock-gl mode is enable,
 * then we should allow dlock_gl to be skipped.
 */

/*
 * Mode is selected by:
 * 1. arg_str_value value from command line
 * 2. def_mode function arg
 * 3. look up a default mode for cmd
 *
 * MODE_NOARG: don't try to get mode from arg_str
 * MODE_NODEF: don't try to get mode from def_mode
 * MODE_NOCMD: don't try to get mode from cmd
 */

int dlock_gl(struct cmd_context *cmd, const char *def_mode, uint32_t flags)
{
	const char *mode = NULL;

	log_debug("dlock_gl %s", command_name(cmd));

	if (!(flags & DL_GL_MODE_NOARG)) {
		mode = arg_str_value(cmd, lockgl_ARG, NULL);
#if 0
		if (mode && def_mode &&
		    (mode_compare(mode, def_mode) < 0) &&
		    !find_config_tree_int(cmd, global_allow_unsafe_lock_modes_CFG)) {
			log_error("Disallowed lock-gl mode \"%s\"", mode);
			return 0;
		}
#endif
	}

	if (!mode && !(flags & DL_GL_MODE_NODEF))
		mode = def_mode;

	/*
	if (!mode && !(flags & DL_GL_MODE_NOCMD))
		mode = if needed, default determined like dlock_vg
	*/

	if (!mode) {
		log_error("lock-gl mode unknown");
		return 0;
	}

	if (!dlock_general(cmd, command_name(cmd), "lock_gl",
			   NULL, NULL, NULL, NULL, NULL, mode, NULL)) {
		/* TODO: select some cases to cause command to fail */
		/* return 0; */
	}

	if (flags & DL_GL_RENEW_CACHE)
		lvmetad_validate_dlock_global(cmd);

	return 1;
}

/*
 * process_each_vg will
 *   dlock_vg(cmd, vgname, NULL, 0);
 *   vg_read()
 *   process vg
 *   dlock_vg(cmd, vgname, "un");
 *
 * This is an exception to the rule of not using an explicit unlock.
 * Here we know that we are at the top level.  process_each_vg
 * could be considered a sequence of separate commands, each on
 * a different vg, and the unlock is consistent with the end of
 * the command.  Once a vg is processed in the process_each loop,
 * we know that that we are completely done with that vg.
 *
 * Without the explicit unlock, single commands that need to
 * query all vgs (fairly common), would end up holding all vg
 * locks at the end.
 */

/*
 * process_each_{vg,lv} will call dlock_vg(cmd, vg_name, NULL, 0);
 * to get mode from arg_str or looking up default by cmd.
 */

int dlock_vg(struct cmd_context *cmd, const char *vg_name,
	     const char *def_mode, uint32_t flags)
{
	const char *mode = NULL;
	const char *opts = NULL;

	log_debug("dlock_vg %s %s", command_name(cmd), vg_name);

	if (!(flags & DL_VG_MODE_NOARG)) {
		mode = arg_str_value(cmd, lockvg_ARG, NULL);
#if 0
		if (mode && def_mode &&
		    (mode_compare(mode, def_mode) < 0) &&
		    !find_config_tree_int(cmd, global_allow_unsafe_lock_modes_CFG)) {
			log_error("Disallowed lock-vg mode \"%s\"", mode);
			return 0;
		}
#endif
	}

	if (!mode && !(flags & DL_VG_MODE_NODEF))
		mode = def_mode;

	if (!mode && !(flags & DL_VG_MODE_NOCMD)) {
		/*
		 * Default mode is needed, but was not provided
		 * in the function args.  This happens when dlock_vg
		 * is called from a process_each function that handles
		 * different commands.  Commands that only
		 * read/check/report/display the vg have DLOCK_VG_SH
		 * set in commands.h.  All other commands modify the vg.
		 */
		if (cmd->command->flags & DLOCK_VG_SH)
			mode = "sh";
		else
			mode = "ex";
	}

	if (!mode) {
		log_error("lock-vg mode unknown");
		return 0;
	}

	/* For vgchange --lock-vg start|stop */
	if (!strcmp(mode, "start") || !strcmp(mode, "stop"))
		return 1;

	if (flags & DL_VG_PERSISTENT)
		opts = "persistent";

	return dlock_general(cmd, command_name(cmd), "lock_vg",
			     vg_name, NULL, NULL, NULL, NULL, mode, opts);
}

int dlock_lv_name(struct cmd_context *cmd, struct volume_group *vg,
		  const char *lv_name, const char *lock_args,
		  const char *def_mode, uint32_t flags)
{
	const char *mode = NULL;
	const char *opts = NULL;

	log_debug("dlock_lv %s %s/%s", command_name(cmd), vg->name, lv_name);

	mode = arg_str_value(cmd, locklv_ARG, NULL);
#if 0
	if (mode && def_mode &&
	    (mode_compare(mode, def_mode) < 0) &&
	    !find_config_tree_int(cmd, global_allow_unsafe_lock_modes_CFG)) {
		log_error("Disallowed lock-lv mode \"%s\"", mode);
		return 0;
	}
#endif
	if (!mode)
		mode = def_mode;

	if (!mode) {
		log_error("lock-lv mode unknown");
		return 0;
	}

	if (flags & DL_LV_PERSISTENT)
		opts = "persistent";

	return dlock_general(cmd, command_name(cmd), "lock_lv",
			     vg->name, vg->lock_type, vg->lock_args,
			     lv_name, lock_args, mode, opts);
}

int dlock_lv(struct cmd_context *cmd, struct logical_volume *lv,
	     const char *def_mode, uint32_t flags)
{
	return dlock_lv_name(cmd, lv->vg, lv->name, lv->lock_args, def_mode, flags);
}

/* shortcut for common pattern of dlock_gl+dlock_vg */

int dlock_gl_vg(struct cmd_context *cmd, const char *vg_name,
		const char *def_gl_mode, const char *def_vg_mode,
		uint32_t flags)
{
	if (!dlock_gl(cmd, def_gl_mode, flags))
		return 0;

	if (!dlock_vg(cmd, vg_name, def_vg_mode, flags)) {
		dlock_gl(cmd, "un", DL_GL_MODE_NOARG);
		return 0;
	}

	return 1;
}

