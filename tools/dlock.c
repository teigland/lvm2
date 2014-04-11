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
#include "lvmcache.h"
#include "lvmlockd-client.h"

static int mode_num(const char *mode)
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
	return -2;
}

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
		if (mode && def_mode && strcmp(mode, "enable") &&
		    (mode_compare(mode, def_mode) < 0) &&
		    !find_config_tree_bool(cmd, global_allow_unsafe_lock_modes_CFG, NULL)) {
			log_error("Disallowed unsafe lock-gl mode \"%s\"", mode);
			return 0;
		}
	}

	if (!mode && !(flags & DL_GL_MODE_NODEF))
		mode = def_mode;

	if (!mode) {
		log_error("lock-gl mode unknown");
		return 0;
	}

	ret = dlock_general(cmd, command_name(cmd), "lock_gl",
			    NULL, vg_lock_type, NULL, NULL, NULL, mode, "update_names",
			    &result, &result_flags);

	if (!ret) {
		/* no result from lvmlockd */
		log_error("Locking failed for global lock");
		return 0;
	}

	/*
	 * result and result_flags were returned from lvmlockd.
	 * in lvmlockd, result 0 is success, and error is < 0.
	 * Some ENOLS (no lockspace) errors are overriden.
	 */

	if (result == -ENOLS) {

		if (!strcmp(mode, "un"))
			return 1;

		/*
		 * This is the explicit sanlock bootstrap condition for
		 * proceding without the global lock.  When creating the first
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
			return 1;
		}

		/*
		 * This is an implicit sanlock bootstrap condition for
		 * proceding without the global lock.  The command line does
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
			return 1;
		}

		/*
		 * Allow non-dlock-type vgs to be created even when the global
		 * lock is not available.  Once created, these vgs will not be
		 * protected by locks anyway, so allowing the creation without
		 * a lock is a fairly small relaxing of normal locking.
		 */

		if ((result_flags & LD_RF_NO_GL_LS) &&
		    (!strcmp(vg_lock_type, "none"))) {
			lvmetad_validate_dlock_global(cmd, 1);
			return 1;
		}

		log_error("Global lock %s error %d", mode, result);
		return 0;
	}

	if (result < 0) {
		log_error("Global lock %s error %d", mode, result);
		return 0;
	}

	if (flags & DL_GL_RENEW_CACHE)
		lvmetad_validate_dlock_global(cmd, 0);

	return 1;
}

int dlock_gl(struct cmd_context *cmd, const char *def_mode, uint32_t flags)
{
	const char *mode = NULL;
	const char *opts = NULL;
	uint32_t result_flags;
	int result;
	int ret;

	if (!(flags & DL_GL_MODE_NOARG)) {
		mode = arg_str_value(cmd, lockgl_ARG, NULL);
		if (mode && def_mode &&
		    (mode_compare(mode, def_mode) < 0) &&
		    !find_config_tree_bool(cmd, global_allow_unsafe_lock_modes_CFG, NULL)) {
			log_error("Disallowed unsafe lock-gl mode \"%s\"", mode);
			return 0;
		}
	}

	if (!mode && !(flags & DL_GL_MODE_NODEF))
		mode = def_mode;

	if (!mode) {
		/* should not happen */
		log_error("dlock_gl %s no mode", command_name(cmd));
		return 0;
	}

	if (flags & DL_GL_UPDATE_NAMES)
		opts = "update_names";

	log_debug("dlock_gl %s %s", command_name(cmd), mode);

	ret = dlock_general(cmd, command_name(cmd), "lock_gl",
			    NULL, NULL, NULL, NULL, NULL, mode, opts,
			    &result, &result_flags);
	if (!ret) {
		/* no result from lvmlockd */

		if (arg_count(cmd, sysinit_ARG) || arg_count(cmd, ignorelockingfailure_ARG)) {
			log_debug("Ignore failed locking for global lock: option %s",
				  arg_count(cmd, sysinit_ARG) ? "sysinit" : "ignorelockingfailure");
			return 1;
		}

		if (!strcmp(mode, "un") || !strcmp(mode, "sh")) {
			log_warn("Ignore failed locking for global lock: mode %s", mode);
			return 1;
		}

		log_error("Locking failed for global lock");
		return 0;
	}

	/*
	 * result and result_flags were returned from lvmlockd.
	 * in lvmlockd, result 0 is success, and error is < 0.
	 */

	if (result == -ENOLS || result == -ESTARTING) {

		if (!strcmp(mode, "un"))
			return 1;

		/*
		 * This is a general condition for allowing the command to
		 * procede without a shared global lock when the global lock is
		 * not found or ready.  This should not be a persistent condition.
		 * The vg containing the global lock should reappear to the system,
		 * or the global lock should be enabled in another vg, or the
		 * the lockspace with the gl should finish starting.
		 */

		if (strcmp(mode, "sh")) {
			log_error("Global lock %s error %d", mode, result);
			return 0;
		}

		if (result == -ESTARTING) {
			log_warn("Skipping global lock: lockspace is starting");
			/* invalidate lvmetad cache to force reading from disk */
			lvmetad_validate_dlock_global(cmd, 1);
			return 1;
		}

		if ((result_flags & LD_RF_NO_GL_LS) ||
		    (result_flags & LD_RF_NO_LOCKSPACES)) {
			log_warn("Skipping global lock: not found");
			/* invalidate lvmetad cache to force reading from disk */
			lvmetad_validate_dlock_global(cmd, 1);
			return 1;
		}

		log_error("Global lock %s error %d", mode, result);
		return 0;
	}

	if (result < 0) {
		log_error("Global lock %s error %d", mode, result);
		return 0;
	}

	if (flags & DL_GL_RENEW_CACHE)
		lvmetad_validate_dlock_global(cmd, 0);

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
	uint32_t result_flags;
	int result;
	int ret;

	/*
	 * Only real vgs have locks; orphans are covered by global lock.
	 */
	if (!is_real_vg(vg_name))
		return 1;

	/*
	 * DLOCK_VG_NA is used in special cases to disable the vg lock.
	 */
	if (cmd->command->flags & DLOCK_VG_NA)
		return 1;

	/*
	 * DL_VG_MODE_NOARG disables getting the mode from --lock-vg arg.
	 */
	if (!(flags & DL_VG_MODE_NOARG)) {
		mode = arg_str_value(cmd, lockvg_ARG, NULL);
		if (mode && def_mode &&
		    (mode_compare(mode, def_mode) < 0) &&
		    !find_config_tree_bool(cmd, global_allow_unsafe_lock_modes_CFG, NULL)) {
			log_error("Disallowed unsafe lock-vg mode \"%s\"", mode);
			return 0;
		}
	}

	/*
	 * DL_VG_MODE_NODEF disables getting the mode from def_mode.
	 */
	if (!mode && !(flags & DL_VG_MODE_NODEF))
		mode = def_mode;

	/*
	 * DL_VG_MODE_NOCMD disables getting the mode from command flags.
	 */
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
		log_error("dlock_vg %s no mode %s", command_name(cmd), vg_name);
		return 0;
	}

	log_debug("dlock_vg %s %s %s", command_name(cmd), mode, vg_name);

	ret = dlock_general(cmd, command_name(cmd), "lock_vg",
			    vg_name, NULL, NULL, NULL, NULL, mode, opts,
			    &result, &result_flags);
	if (!ret) {
		/* no result from lvmlockd */

		if (arg_count(cmd, sysinit_ARG) || arg_count(cmd, ignorelockingfailure_ARG)) {
			log_debug("Ignore failed locking for VG %s: option %s", vg_name,
				  arg_count(cmd, sysinit_ARG) ? "sysinit" : "ignorelockingfailure");
			return 1;
		}

		if (!strcmp(mode, "un") || !strcmp(mode, "sh")) {
			log_warn("Ignore failed locking for VG %s: mode %s", vg_name, mode);
			return 1;
		}

		log_error("Locking failed for VG %s", vg_name);
		return 0;
	}

	if (result == -ELOCALVG) {
		/* the vg is local and does not need a dlock */
		return 1;
	}

	if (result == -EOTHERVG) {
		/* the vg is local and owned by another system */
		log_warn("Skipping VG %s: owned by other system id", vg_name);
		return 0;
	}

	if (result == -ENOLS || result == -ESTARTING) {

		if (!strcmp(mode, "un"))
			return 1;

		if (strcmp(mode, "sh")) {
			log_error("VG lock %s error %d: %s", mode, result, vg_name);
			return 0;
		}

		/* TODO: Should we try to invalidate the cached vg in lvmetad
		   to force reading it from disk, like we do with gl above? */

		if (result == -ESTARTING) {
			log_warn("Skipping lock for VG %s: lockspace is starting", vg_name);
			return 1;
		}

		if (result == -ENOLS) {
			log_warn("Skipping lock for VG %s: not found", vg_name);
			return 1;
		}

		log_error("VG lock %s error %d: %s", mode, result, vg_name);
		return 0;
	}

	if (result < 0) {
		log_error("VG lock %s error %d: %s", mode, result, vg_name);
		return 0;
	}

	return 1;
}

/*
 * The dlock for a vg is acquired before the vg is read, i.e.
 *
 * dlock_vg(vg_name);
 * vg = vg_read(vg_name);
 * dlock_vg_verify(vg);
 *
 * The dlock_vg_verify() step verifies that the vg properties
 * returned from the read are in fact consistent with the locking
 * that was done.
 *
 * The intention is that this step should not need to go back to
 * lvmlockd for anything.  If something wants to go back to lvmlockd,
 * then we should reconsider the locking design of whatever that is
 * to try to avoid it.
 *
 * NB. This verify function will also be used when lvmlockd/dlock is
 * not enabled or used.  Even when lvmlockd/dlock are not used, we
 * should report an error if we find that the vg's system_id does not
 * match our own.
 *
 * TODO:
 * . Verify that lock_type/lock_args from vg match what lvmlockd
 *   used to acquire the vg lock before the vg was read.  I don't
 *   really expect this to be needed in general, but it may be
 *   useful for things like changing a vg's lock_type, so it's
 *   something we can do without until a more specific need for it
 *   appears.
 *
 *   This would require that lvmlockd returns the lock_type/lock_args
 *   that is used in the reply to the dlock_vg, and that we save
 *   that info so that we can check it matches here, e.g.
 *
 *   dlock_vg(cmd, vg_name, mode, flags, &result);
 *   vg_read();
 *   dlock_vg_verify(cmd, vg, result);
 *
 *   dlock_vg would set result to indicate if the vg is local or
 *   which lock_type_num it used.
 *
 *   dlock_vg_verify() would verify the vg is local or that vg->lock_type
 *   matches the lock_type_num that was used.
 */

int dlock_vg_verify(struct cmd_context *cmd, struct volume_group *vg)
{
	int use_lvmlockd;

	/*
	 * These first two exceptions are the same as dlock_vg.
	 */

	if (!is_real_vg(vg->name))
		return 1;

	if (cmd->command->flags & DLOCK_VG_NA)
		return 1;

	if (vg->system_id && vg->system_id[0] &&
	    cmd->hostname && cmd->hostname[0] &&
	    strcmp(vg->system_id, cmd->hostname)) {
		log_error("Skip VG %s with system id \"%s\" from system id \"%s\"",
			  vg->name, vg->system_id, cmd->hostname);
		goto fail;
	}

	use_lvmlockd = find_config_tree_bool(cmd, global_use_lvmlockd_CFG, NULL);

	if (vg_is_clustered(vg) && use_lvmlockd) {
		log_error("Skip VG %s that uses clvmd while use_lvmlockd=1", vg->name);
		goto fail;
	}

	if (dlock_type(vg->lock_type) && !use_lvmlockd) {
		log_error("Skip VG %s that uses lvmlockd while use_lvmlockd=0", vg->name);
		goto fail;
	}

	return 1;
fail:
	return 0;
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

	if (!dlock_type(vg->lock_type))
		return 1;

	mode = arg_str_value(cmd, locklv_ARG, NULL);
	if (mode && def_mode &&
	    (mode_compare(mode, def_mode) < 0) &&
	    !find_config_tree_bool(cmd, global_allow_unsafe_lock_modes_CFG, NULL)) {
		log_error("Disallowed lock-lv mode \"%s\"", mode);
		return 0;
	}

	if (!mode)
		mode = def_mode;

	if (!mode) {
		log_error("dlock_lv %s no mode %s/%s", command_name(cmd), vg->name, lv_name);
		return 0;
	}

	if (!strcmp(mode, "sh") && (flags & DL_LV_MODE_NO_SH)) {
		log_error("Shared activation not compatible with LV type: %s/%s",
			  vg->name, lv_name);
		return 0;
	}

	log_debug("dlock_lv %s %s %s/%s", command_name(cmd), mode, vg->name, lv_name);

	if (flags & DL_LV_PERSISTENT)
		opts = "persistent";

	ret = dlock_general(cmd, command_name(cmd), "lock_lv",
			    vg->name, vg->lock_type, vg->lock_args,
			    lv_name, lock_args, mode, opts,
			    &result, &result_flags);
	if (!ret) {
		/* no result from lvmlockd */
		log_error("Locking failed for LV %s/%s", vg->name, lv_name);
		return 0;
	}

	/* The lv was not active/locked. */
	if (result == -ENOENT && !strcmp(mode, "un"))
		return 1;

	if (result == -EALREADY)
		return 1;

	if (result == -EAGAIN) {
		log_error("LV locked by other host: %s/%s", vg->name, lv_name);
		return 0;
	}

	if (result < 0) {
		log_error("LV lock %s error %d: %s/%s", mode, result, vg->name, lv_name);
		return 0;
	}

	return 1;
}

/*
 * LV type cannot be safely active concurrently on multiple hosts,
 * so shared mode activation is not allowed.
 */
static int lv_ex_required(struct logical_volume *lv)
{
	if (lv_is_external_origin(lv) ||
	    lv_is_thin_type(lv) ||
	    lv_is_mirror_type(lv) ||
	    lv_is_raid_type(lv) ||
	    lv_is_cache_type(lv))
		return 1;
	return 0;
}

int dlock_lv(struct cmd_context *cmd, struct logical_volume *lv,
	     const char *def_mode, uint32_t flags)
{
	if (lv_ex_required(lv))
		flags |= DL_LV_MODE_NO_SH;

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

int dlock_type_to_num(const char *lock_type)
{
	if (!lock_type)
		return LOCK_TYPE_NONE;
	if (!strcmp(lock_type, "none"))
		return LOCK_TYPE_NONE;
	if (!strcmp(lock_type, "clvm"))
		return LOCK_TYPE_CLVM;
	if (!strcmp(lock_type, "dlm"))
		return LOCK_TYPE_DLM;
	if (!strcmp(lock_type, "sanlock"))
		return LOCK_TYPE_SANLOCK;
	return -1;
}

/* vgcreate */

int dlock_init_vg_lock_args(struct cmd_context *cmd, struct volume_group *vg)
{
	const char *gl_mode = arg_str_value(cmd, lockgl_ARG, NULL);
	const char *vg_mode = arg_str_value(cmd, lockvg_ARG, NULL);

	switch (dlock_type_to_num(vg->lock_type)) {
	case LOCK_TYPE_NONE:
	case LOCK_TYPE_CLVM:
		return 1;
	case LOCK_TYPE_DLM:
		return dlock_init_vg_dlm(cmd, vg, gl_mode, vg_mode);
	case LOCK_TYPE_SANLOCK:
		return dlock_init_vg_sanlock(cmd, vg, gl_mode, vg_mode);
	default:
		log_error("Unknown lock_type.");
		return 0;
	}
}

/* vgremove (_before called before vg_remove(), _final called after vg_remove() */

int dlock_free_vg_lock_args_before(struct cmd_context *cmd, struct volume_group *vg)
{
	const char *mode = arg_str_value(cmd, lockvg_ARG, NULL);

	/*
	 * --lock-vg na implies that this should be skipped also.
	 * TODO: should there be an explicit option to control this?
	 */
	if (mode && !strcmp(mode, "na"))
		return 1;

	switch (dlock_type_to_num(vg->lock_type)) {
	case LOCK_TYPE_NONE:
	case LOCK_TYPE_CLVM:
	case LOCK_TYPE_DLM:
		return 1;
	case LOCK_TYPE_SANLOCK:
		/* returning an error will prevent vg_remove() */
		return dlock_free_vg_sanlock(cmd, vg);
	default:
		log_error("Unknown lock_type.");
		return 0;
	}
}

void dlock_free_vg_lock_args_final(struct cmd_context *cmd, struct volume_group *vg)
{
	const char *mode = arg_str_value(cmd, lockvg_ARG, NULL);

	/*
	 * --lock-vg na implies that this should be skipped also.
	 * TODO: should there be an explicit option to control this?
	 */
	if (mode && !strcmp(mode, "na"))
		return;

	switch (dlock_type_to_num(vg->lock_type)) {
	case LOCK_TYPE_NONE:
		dlock_free_vg_local(cmd, vg);
		break;
	case LOCK_TYPE_CLVM:
	case LOCK_TYPE_SANLOCK:
		break;
	case LOCK_TYPE_DLM:
		dlock_free_vg_dlm(cmd, vg);
		break;
	default:
		log_error("Unknown lock_type.");
	}
}

/* lvcreate */

int dlock_init_lv_lock_args(struct cmd_context *cmd,
		      struct volume_group *vg, const char *lv_name,
		      const char *lock_type, const char **lock_args)
{
	int vg_lock_num = dlock_type_to_num(vg->lock_type);
	int lv_lock_num = dlock_type_to_num(lock_type);

	if (lv_lock_num != LOCK_TYPE_NONE && lv_lock_num != vg_lock_num) {
		log_error("lv lock_type %s not compatible with vg lock_type %s",
			  lock_type, vg->lock_type);
		return 0;
	}

	switch (lv_lock_num) {
	case LOCK_TYPE_NONE:
	case LOCK_TYPE_CLVM:
	case LOCK_TYPE_DLM:
		return 1;
	case LOCK_TYPE_SANLOCK:
		return dlock_init_lv_sanlock(cmd, vg, lv_name, lock_type, lock_args);
	default:
		log_error("Unknown lock_type %s.", lock_type);
		return 0;
	}
}

/* lvremove */

int dlock_free_lv_lock_args(struct cmd_context *cmd,
		      struct volume_group *vg, const char *lv_name,
		      const char *lock_type, const char *lock_args)
{
	const char *mode = arg_str_value(cmd, locklv_ARG, NULL);

	/*
	 * --lock-lv na implies that this should be skipped also.
	 * TODO: should there be an explicit option to control this?
	 */
	if (mode && !strcmp(mode, "na"))
		return 1;

	switch (dlock_type_to_num(lock_type)) {
	case LOCK_TYPE_NONE:
	case LOCK_TYPE_CLVM:
	case LOCK_TYPE_DLM:
		return 1;
	case LOCK_TYPE_SANLOCK:
		return dlock_free_lv_sanlock(cmd, vg, lv_name, lock_type, lock_args);
	default:
		log_error("Unknown lock_type %s.", lock_type);
		return 0;
	}
}

