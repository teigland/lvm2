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
 * Mode is selected by:
 * 1. arg_str_value value from command line
 * 2. def_mode function arg
 * 3. look up a default mode for cmd
 *
 * MODE_NOARG: don't try to get mode from arg_str
 * MODE_NODEF: don't try to get mode from def_mode
 * MODE_NOCMD: don't try to get mode from cmd
 */

/*
 * dlock_gl_create() is used by vgcreate to acquire and/or create the
 * global lock.  vgcreate will have a lock_type for the new vg which
 * dlock_gl_create() can provide in the lock-gl call.
 *
 * dlock_gl() and dlock_gl_create() differ in the specific cases where
 * ENOLS (no lockspace found) is overriden.  In the vgcreate case, the
 * override cases are related to sanlock bootstrap, and the lock_type of
 * the vg being created is needed.
 *
 * - vgcreate of the first dlock-type vg calls dlock_gl_create()
 *   to acquire the global lock.
 *
 * - vgcreate/dlock_gl_create passes gl lock request to lvmlockd,
 *   along with lock_type of the new vg.
 *
 * - lvmlockd finds no global lockspace/lock.
 *
 * - if the lock_type from vgcreate is dlm, lvmlockd creates the
 *   dlm global lockspace, and queues the global lock request
 *   for vgcreate.  dlock_gl_create returns sucess with the gl held.
 *
 * - if the lock_type from vgcreate is sanlock, lvmlockd returns -ENOLS
 *   with NO_GL_LS.  dlock_gl_create sees this and the "enable" lock-gl
 *   mode and returns success without the global lock.  vgcreate calls
 *   vg_init_lock_args() which initializes/enables a global lock on the
 *   new vg's internal sanlock lv.  Future dlock_gl/dlock_gl_create calls
 *   will acquire this newly create global lock.
 */

int dlock_gl_create(struct cmd_context *cmd, const char *def_mode, uint32_t flags,
		    const char *vg_lock_type)
{
	const char *mode = NULL;
	uint32_t result_flags;
	int result;
	int ret;

	log_debug("dlock_gl_create %s lock_type %s", command_name(cmd), vg_lock_type);

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

	if (!mode) {
		log_error("lock-gl mode unknown");
		return 0;
	}

	ret = dlock_general(cmd, command_name(cmd), "lock_gl",
			    NULL, vg_lock_type, NULL, NULL, NULL, mode, NULL,
			    &result, &result_flags);

	if (!ret && (arg_count(cmd, sysinit_ARG) || arg_count(cmd, ignorelockingfailure_ARG))) {
		log_debug("Skip distributed locking for %s",
			  arg_count(cmd, sysinit_ARG) ? "sysinit" : "ignorelockingfailure");
		return 1;
	}

	/*
	 * error without any result from lvmlockd.
	 */
	if (!ret)
		return 0; /* failure */

	/*
	 * result and result_flags were returned from lvmlockd.
	 * in lvmlockd, result 0 is success, and error is < 0.
	 * Some ENOLS (no lockspace) errors are overriden.
	 */

	if (result == -ENOLS) {

		/*
		 * This is the explicit sanlock bootstrap condition for
		 * proceeding without the global lock.  When creating the first
		 * sanlock vg, there is no gl because the gl will exist in the
		 * vg being created.  The "enable" option makes explicit that
		 * this is the case: vgcreate --lock-type sanlock --lock-gl enable
		 *
		 * - LD_RF_NO_GL_LS: lvmlockd has not seen a global lock
		 * - mode is enable: the command line indicates this is
		 *   the special case that enables a new global lock in
		 *   the vg being created.
		 */

		if ((result_flags & LD_RF_NO_GL_LS) &&
		    !strcmp(vg_lock_type, "sanlock") &&
		    !strcmp(mode, "enable")) {
			log_debug("Enabling sanlock global lock");
			lvmetad_validate_dlock_global(cmd, 1);
			return 1; /* success */
		}

		/*
		 * This is an implicit sanlock bootstrap condition for
		 * proceeding without the global lock.  The command line does
		 * not indicate explicitly that this is a bootstrap situation
		 * (via "enable"), but it seems likely to be because lvmlockd
		 * has seen no dlock-type vgs.  It is possible that a global
		 * lock does exist in a vg that has not yet been seen.  If that
		 * vg appears after this creates a new vg with a new enabled
		 * gl, then there will be two enabled global locks, and one
		 * will need to be disabled.  (We could instead return an error
		 * here and insist with an error message that the --lock-gl
		 * enable option be used.)
		 */

		if ((result_flags & LD_RF_NO_GL_LS) &&
		    (result_flags & LD_RF_NO_LOCKSPACES) &&
		    !strcmp(vg_lock_type, "sanlock")) {
			log_print_unless_silent("Enabling sanlock global lock");
			lvmetad_validate_dlock_global(cmd, 1);
			return 1; /* success */
		}

		/*
		 * Allow non-dlock-type vgs to be created even when the global
		 * lock is not available.  Once created, these vgs will not be
		 * protected by locks anyway, so allowing the creation without
		 * a lock is a fairly small relaxing of normal locking.
		 */

		if ((result_flags & LD_RF_NO_GL_LS) &&
		    (!strcmp(vg_lock_type, "none") || !strcmp(vg_lock_type, "local"))) {
			log_print_unless_silent("Enabling sanlock global lock");
			lvmetad_validate_dlock_global(cmd, 1);
			return 1; /* success */
		}

		return 0; /* failure */
	}

	if (result < 0)
		return 0; /* failure */

	if (flags & DL_GL_RENEW_CACHE)
		lvmetad_validate_dlock_global(cmd, 0);

	return 1; /* success */
}

int dlock_gl(struct cmd_context *cmd, const char *def_mode, uint32_t flags)
{
	const char *mode = NULL;
	uint32_t result_flags;
	int result;
	int ret;

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

	if (!mode) {
		log_error("lock-gl mode unknown");
		return 0;
	}

	ret = dlock_general(cmd, command_name(cmd), "lock_gl",
			    NULL, NULL, NULL, NULL, NULL, mode, NULL,
			    &result, &result_flags);

	if (!ret && (arg_count(cmd, sysinit_ARG) || arg_count(cmd, ignorelockingfailure_ARG))) {
		log_debug("Skip distributed locking for %s",
			  arg_count(cmd, sysinit_ARG) ? "sysinit" : "ignorelockingfailure");
		return 1;
	}

	/*
	 * error without any result from lvmlockd.
	 */
	if (!ret)
		return 0; /* failure */

	/*
	 * result and result_flags were returned from lvmlockd.
	 * in lvmlockd, result 0 is success, and error is < 0.
	 * Some ENOLS (no lockspace) errors are overriden.
	 */

	if (result == -ENOLS) {
		/*
		 * This is a general condition for allowing the command to
		 * proceed without a shared global lock when the global lock is
		 * not found.  This should not be a persistent condition.  The
		 * vg containing the global lock should reappear to the system,
		 * or the global lock should be enabled in another vg.
		 */

		if (strcmp(mode, "sh"))
			return 0;

		if ((result_flags & LD_RF_NO_GL_LS) ||
		    (result_flags & LD_RF_NO_LOCKSPACES)) {
			log_warn("Skipping shared global lock, not found");
			lvmetad_validate_dlock_global(cmd, 1);
			return 1; /* success */
		}

		return 0; /* failure */
	}

	if (result < 0)
		return 0; /* failure */

	if (flags & DL_GL_RENEW_CACHE)
		lvmetad_validate_dlock_global(cmd, 0);

	return 1; /* success */
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
	uint32_t result_flags;
	int result;
	int ret;

	/* Only real vgs have locks; orphans are covered by global lock. */
	if (!is_real_vg(vg_name))
		return 1;

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
		if (cmd->command->flags & DLOCK_VG_NA)
			return 1;

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

	/* For vgchange --lock-vg start|stop, vgchange --lock-start */
	if (!strcmp(mode, "start") || !strcmp(mode, "stop"))
		return 1;

	if (flags & DL_VG_PERSISTENT)
		opts = "persistent";

	ret = dlock_general(cmd, command_name(cmd), "lock_vg",
			    vg_name, NULL, NULL, NULL, NULL, mode, opts,
			    &result, &result_flags);

	if (!ret && (arg_count(cmd, sysinit_ARG) || arg_count(cmd, ignorelockingfailure_ARG))) {
		log_debug("Skip distributed locking for %s",
			  arg_count(cmd, sysinit_ARG) ? "sysinit" : "ignorelockingfailure");
		return 1;
	}

	if (!ret)
		return 0; /* failure */

	if (result < 0) {

		/* depending on result_flags, we might ignore
		   the error result */

		return 0; /* failure */
	}

	return 1; /* success */
}

int dlock_lv_name(struct cmd_context *cmd, struct volume_group *vg,
		  const char *lv_name, const char *lock_args,
		  const char *def_mode, uint32_t flags)
{
	const char *mode = NULL;
	const char *opts = NULL;
	uint32_t result_flags;
	int result;
	int ret;

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

	ret = dlock_general(cmd, command_name(cmd), "lock_lv",
			    vg->name, vg->lock_type, vg->lock_args,
			    lv_name, lock_args, mode, opts,
			    &result, &result_flags);

	if (!ret && (arg_count(cmd, sysinit_ARG) || arg_count(cmd, ignorelockingfailure_ARG))) {
		log_debug("Skip distributed locking for %s",
			  arg_count(cmd, sysinit_ARG) ? "sysinit" : "ignorelockingfailure");
		return 1;
	}

	if (!ret)
		return 0;

	if (result < 0)
		return 0;

	return 1;
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

