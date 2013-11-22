/*
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 */

#include "lib.h"
#include "toolcontext.h"
#include "metadata.h"
#include "lvmetad.h"
#include "lvmlockd.h"
#include "lock_type.h"
#include "lvmcache.h"
#include "lvmlockd-client.h"

static daemon_handle _lvmlockd;
static int _lvmlockd_active;
static int _lvmlockd_connected;

static const char *_lvmlockd_socket = NULL;
static struct cmd_context *_lvmlockd_cmd = NULL;

void lvmlockd_disconnect(void)
{
	if (_lvmlockd_connected)
		daemon_close(_lvmlockd);
	_lvmlockd_connected = 0;
	_lvmlockd_cmd = NULL;
}

void lvmlockd_init(struct cmd_context *cmd)
{
	if (!_lvmlockd_active && !access(LVMLOCKD_PIDFILE, F_OK))
		log_warn("WARNING: lvmlockd is running but disabled.");
	if (!_lvmlockd_active)
		return;
	_lvmlockd_cmd = cmd;
}

static void _lvmlockd_connect(void)
{
	if (!_lvmlockd_active || !_lvmlockd_socket || _lvmlockd_connected)
		return;

	_lvmlockd = lvmlockd_open(_lvmlockd_socket);

	if (_lvmlockd.socket_fd >= 0 && !_lvmlockd.error) {
		log_debug("Successfully connected to lvmlockd on fd %d.",
			  _lvmlockd.socket_fd);
		_lvmlockd_connected = 1;
	}
}

void lvmlockd_connect_or_warn(void)
{
	if (!_lvmlockd_active || _lvmlockd_connected)
		return;

	_lvmlockd_connect();

	if (!_lvmlockd_connected) {
		log_warn("WARNING: Failed to connect to lvmlockd: %s. No distributed locks available.",
			 strerror(_lvmlockd.error));
	}
}

/*
 * in command setup:
 *
 * 1. if use_lvmlockd is set in config,
 *    lvmlockd_set_active() sets _lvmlockd_active = 1
 *
 * 2. lvmlockd_init() sees _lvmlockd_active, and sets _lvmlockd_cmd
 *
 * 3. lvmlockd_connect_or_warn()/_lvmlockd_connect() see _lvmlockd_active,
 *    create connection and if successful set _lvmlockd_connected = 1
 *
 * in command processing:
 *
 * 1. dlock function calls lvmlockd_connected() which returns
 *    _lvmlockd_connected
 *
 * 2. if lvmlockd_connected() returns 0, dlock function fails
 */

static int lvmlockd_connected(void)
{
	if (_lvmlockd_connected)
		return 1;

	log_error("Error: lvmlockd connection does not exist.");
	return 0;
}

void lvmlockd_set_active(int active)
{
	_lvmlockd_active = active;
}

void lvmlockd_set_socket(const char *sock)
{
	_lvmlockd_socket = sock;
}

static daemon_reply _lvmlockd_send(const char *id, ...)
{
	va_list ap;
	daemon_reply repl;
	daemon_request req;

	req = daemon_request_make(id);

	va_start(ap, id);
	daemon_request_extend_v(req, ap);
	va_end(ap);

	repl = daemon_send(_lvmlockd, req);

	daemon_request_destroy(req);

	return repl;
}

/*
 * Helper; evaluate the reply from lvmlockd, check for errors, print diagnostics
 * and return a summary success/failure exit code.
 */
static int _lvmlockd_handle_reply(daemon_reply reply, const char *action, const char *object)
{
	const char *result_str;
	int result;

	if (reply.error) {
		log_error("Request to %s %s%sin lvmlockd gave response %s.",
			  action, object, *object ? " " : "", strerror(reply.error));
		return 0;
	}

	if (!strcmp(daemon_reply_str(reply, "response", ""), "OK")) {
		result_str = daemon_reply_str(reply, "result", NULL);
		if (!result_str) {
			log_error("no result");
			return 0;
		}

		result = atoi(result_str);

		/* in lvm "1" is good, "0" is error, which is opposite
		   to the rest of the world, so reverse it here for lvm. */

		if (!result)
			return 1;

		/* TODO: handle different kinds of locking errors */

		return 0;
	}

	log_error("Request to %s %s%sin lvmlockd gave response %s. Reason: %s",
		  action, object, *object ? " " : "", 
		  daemon_reply_str(reply, "response", "<missing>"),
		  daemon_reply_str(reply, "reason", "<missing>"));

	return 0;
}

/*
 * Check if a lock_type uses lvmlockd.
 * If not (none, local, clvm), return 0.
 * If so, (dlm sanlock), return LOCK_TYPE_
 */

int dlock_type(const char *lock_type)
{
	if (!lock_type)
		return 0;

	if (!strcmp(lock_type, "dlm"))
		return LOCK_TYPE_DLM;
	if (!strcmp(lock_type, "sanlock"))
		return LOCK_TYPE_SANLOCK;

	return 0;
}

static int dlock_general(struct cmd_context *cmd,
			 const char *cmd_name,
			 const char *id,
			 const char *vg_name,
			 const char *vg_lock_type,
			 const char *vg_lock_args,
			 const char *lv_name,
			 const char *lv_lock_args,
			 const char *mode,
			 const char *opts)
{
	daemon_reply reply;
	int result;
	int pid = getpid();

	if (vg_lock_type && !dlock_type(vg_lock_type))
		return 1;

	if (!strcmp(mode, "na"))
		return 1;

	if (!_lvmlockd_active)
		return 0;
	if (!lvmlockd_connected())
		return 1;

	if (!opts)
		opts = "none";

	/* cmd and pid are passed for informational and debugging purposes */

	if (vg_name && lv_name) {
		reply = _lvmlockd_send(id,
					"cmd = %s", cmd_name,
					"pid = %d", pid,
					"mode = %s", mode,
					"opts = %s", opts,
					"vg_name = %s", vg_name,
					"lv_name = %s", lv_name,
					"vg_lock_type = %s", vg_lock_type ?: "none",
					"vg_lock_args = %s", vg_lock_args ?: "none",
					"lv_lock_args = %s", lv_lock_args ?: "none",
					NULL);

		result = _lvmlockd_handle_reply(reply, id, lv_name);

	} else if (vg_name) {
		reply = _lvmlockd_send(id,
					"cmd = %s", cmd_name,
					"pid = %d", pid,
					"mode = %s", mode,
					"opts = %s", opts,
					"vg_name = %s", vg_name,
					"vg_lock_type = %s", vg_lock_type ?: "none",
					"vg_lock_args = %s", vg_lock_args ?: "none",
					NULL);

		result = _lvmlockd_handle_reply(reply, id, vg_name);

	} else {
		reply = _lvmlockd_send(id,
					"cmd = %s", cmd_name,
					"pid = %d", pid,
					"mode = %s", mode,
					"opts = %s", opts,
					NULL);

		result = _lvmlockd_handle_reply(reply, id, NULL);
	}

	daemon_reply_destroy(reply);

	return result;
}

/*
 * Called after a vg_write to indicate that the version number
 * of the vg lock should be incremented to invalidate the vg
 * cache on other hosts.
 */

int dlock_vg_update(struct volume_group *vg)
{
	daemon_reply reply;
	int result;

	if (!dlock_type(vg->lock_type))
		return 1;

	if (!_lvmlockd_active)
		return 0;
	if (!lvmlockd_connected())
		return 1;

	reply = _lvmlockd_send("vg_update",
				"vg_name = %s", vg->name,
				"version = %u", vg->seqno,
				NULL);

	result = _lvmlockd_handle_reply(reply, "vg_update", vg->name);

	daemon_reply_destroy(reply);

	return result;
}

static struct logical_volume *find_sanlock_lv(struct volume_group *vg,
					      const char *lv_name)
{
	struct lv_list *lvl;

	dm_list_iterate_items(lvl, &vg->lvs) {
		if (!strcmp(lvl->lv->name, lv_name))
			return lvl->lv;
	}
	return NULL;
}

/*
 * Eventually we may create a separate lvmlocks lv on multiple pvs.
 * They will not be mirrored, but will be independent lvs, and
 * sanlock will use all of them.  sanlock will be able to continue locking as
 * long as the majority of them are still available.
 */

static int create_sanlock_lv(struct cmd_context *cmd, struct volume_group *vg,
			      const char *lv_name)
{
	struct lvcreate_params lp;
	struct logical_volume *lv;

	memset(&lp, 0, sizeof(struct lvcreate_params));
	lp.zero = 1;
	lp.activate = CHANGE_ALY;
	lp.vg_name = dm_pool_strdup(cmd->mem, vg->name);
	lp.lv_name = dm_pool_strdup(cmd->mem, lv_name);
	lp.read_ahead = DM_READ_AHEAD_NONE;
	lp.stripes = 1;
	lp.extents = 1073741824 / vg->extent_size;  /* -L 1G */

	/* TODO: configurable default size */

	lv = lv_create_single(vg, &lp);
	if (!lv) {
		log_error("Failed to create sanlock lv %s in vg %s", lv_name, vg->name);
		return 0;
	}

	lv_set_hidden(lv);
	return 1;
}

static int remove_sanlock_lv(struct cmd_context *cmd, struct volume_group *vg)
{
	struct logical_volume *lv;
	const char *lv_name = vg->lock_args;

	lv = find_sanlock_lv(vg, lv_name);
	if (!lv) {
		log_error("Failed to find sanlock lv %s in vg %s", lv_name, vg->name);
		return 0;
	}

	if (!lv_remove(lv)) {
		log_error("Failed to remove sanlock lv %s/%s", vg->name, lv_name);
		return 0;
	}

	return 1;
}

static int activate_sanlock_lv(struct cmd_context *cmd, struct volume_group *vg)
{
	struct logical_volume *lv;
	const char *lv_name = vg->lock_args;

	lv = find_sanlock_lv(vg, lv_name);
	if (!lv) {
		log_error("Failed to find sanlock lv %s in vg %s", lv_name, vg->name);
		return 0;
	}

	if (!activate_lv(cmd, lv)) {
		log_error("Failed to activate sanlock lv %s/%s", vg->name, lv_name);
		return 0;
	}

	return 1;
}

static int deactivate_sanlock_lv(struct cmd_context *cmd, struct volume_group *vg)
{
	struct logical_volume *lv;
	const char *lv_name = vg->lock_args;

	lv = find_sanlock_lv(vg, lv_name);
	if (!lv) {
		log_error("Failed to find sanlock lv %s in vg %s", lv_name, vg->name);
		return 0;
	}

	if (!deactivate_lv(cmd, lv)) {
		log_error("Failed to deactivate sanlock lv %s/%s", vg->name, lv_name);
		return 0;
	}

	return 1;
}

int dlock_init_vg_sanlock(struct cmd_context *cmd, struct volume_group *vg)
{
	daemon_reply reply;
	const char *lv_name = SANLOCK_LV_NAME;
	const char *lock_args;
	int result;

	if (!_lvmlockd_active)
		return 0;
	if (!lvmlockd_connected())
		return 1;

	lock_args = dm_pool_strdup(cmd->mem, lv_name);
	if (!lock_args) {
		log_error("Cannot allocate lock_args.");
		return 0;
	}

	if (!create_sanlock_lv(cmd, vg, lv_name)) {
		log_error("Failed to create internal lv.");
		return 0;
	}

	reply = _lvmlockd_send("init_vg",
				"cmd = %s", cmd->command->name,
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"vg_lock_type = %s", "sanlock",
				"vg_lock_args = %s", lv_name,
				NULL);

	result = _lvmlockd_handle_reply(reply, "init_vg", vg->name);
	if (!result) {
		log_error("lvmlockd init_vg error.");
		remove_sanlock_lv(cmd, vg);
	}

	daemon_reply_destroy(reply);

	/* TODO: prefix lock_args string with some version id here,
	   or it might be done in lvmlockd. */

	vg->lock_args = lock_args;
	return result;
}

int dlock_init_vg_dlm(struct cmd_context *cmd, struct volume_group *vg)
{
	daemon_reply reply;
	const char *reply_str;
	const char *lock_args = NULL;
	int result;

	if (!_lvmlockd_active)
		return 0;
	if (!lvmlockd_connected())
		return 1;

	reply = _lvmlockd_send("init_vg",
				"cmd = %s", cmd->command->name,
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"vg_lock_type = %s", "dlm",
				NULL);

	result = _lvmlockd_handle_reply(reply, "init_vg", vg->name);
	if (!result) {
		log_error("lvmlockd init_vg error.");
		goto out;
	}

	reply_str = daemon_reply_str(reply, "lock_args", NULL);
	if (!reply_str) {
		log_error("missing lock_args");
		result = 0;
		goto out;
	}

	/* the cluster name is returned to save in lock_args */

	lock_args = dm_pool_strdup(cmd->mem, reply_str);
	if (!lock_args) {
		log_error("lock_args allocation failed");
		result = 0;
	}
out:
	daemon_reply_destroy(reply);

	vg->lock_args = lock_args;
	return result;
}

/*
 * vgremove for sanlock:
 *
 * lv remove any existing lv's:
 * lock each lv ex, unlock rename and erase each
 * (To simplify things initially, perhaps just fail if all
 * lvs have not yet been removed.)
 *
 * lock vg ex, unlock rename to "vg_remove"
 *
 * find out if any other hosts are joined to the lockspace,
 * i.e. have it started.  They need to stop the vg before we
 * can remove and erase the sanlock lv.  Possible solution:
 * use a variation of sanlock_request() where we set all bits
 * in our delta lease causing all other hosts to go and
 * examine vglk, which they will see has been renamed to
 * vg_remove, which means they should stop the vg.
 *
 * when no one is using the sanlock lv, then lvremove it.
 *
 * continue with the real vgremove.
 */

/*
 * vgremove
 *
 * dlm:
 *
 * dlock_gl ex
 * dlock_vg ex
 * for each lv,
 *   dlock_lv ex, else fail
 *   if lv is active, deactivate, else fail
 *   dlock_lv un
 * vg_free_lock_args_before:
 *   nothing
 * vg_remove() on disk
 * vg_free_lock_args_final:
 *   dlock_vg un
 *   dlock_gl un
 *   leave dlm lockspace
 *   (notify other nodes to leave the lockspace?)
 *
 * sanlock:
 *
 * dlock_gl ex
 * dlock_vg ex
 * for each lv,
 *   dlock_lv ex, else fail
 *   if lv is active, deactivate, else fail
 *   dlock_lv un
 * vg_free_lock_args_before:
 *   dlock_vg un-rename
 *   dlock_gl un-rename
 *   check if other hosts are in lockspace
 *   notify other hosts to leave the lockspace
 *   wait for other hosts to leave the lockspace
 *   (perhaps just tell remote nodes to vgrefresh, they will see
 *   the renamed vg lock and understand that means to leave)
 *   leave the sanlock lockspace
 *   reinitialize the lockspace (host_id leases) (kills other members)
 *   lvremove internal sanlock lv
 * vg_remove() on disk
 * vg_free_lock_args_final:
 *   nothing
 */

/* called before vg_remove on disk */
int dlock_free_vg_sanlock(struct cmd_context *cmd, struct volume_group *vg)
{
	daemon_reply reply;

	if (!_lvmlockd_active)
		return 0;
	if (!lvmlockd_connected())
		return 1;

	/*
	 * lvmlockd could combine these steps in a "free_vg" command:
	 * dlock_vg unlock-rename, dlock_gl unlock-rename,
	 * check for other hosts in lockspace, notify them to leave,
	 * wait for all to be gone, leave the lockspace.
	 *
	 * Or, we could do it as separate steps from here:
	 * dlock_vg();
	 * dlock_gl();
	 * dlock_remote();
	 * dlock_stop_vg();
	 */

	reply = _lvmlockd_send("free_vg",
				"cmd = %s", cmd->command->name,
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"vg_lock_type = %s", vg->lock_type,
				"vg_lock_args = %s", vg->lock_type,
				NULL);

	/* TODO: return error if this failed */

	daemon_reply_destroy(reply);

	deactivate_sanlock_lv(cmd, vg);

	remove_sanlock_lv(cmd, vg);

	return 1;
}

/* called after vg_remove on disk */
int dlock_free_vg_dlm(struct cmd_context *cmd, struct volume_group *vg)
{
	dlock_vg(cmd, vg->name, "un", 0);

	dlock_gl(cmd, "un", 0);

	/* TODO: use a "refresh lock" callback to notify others
	   to check the vg, find it gone, and leave the lockspace? */

	dlock_stop_vg(cmd, vg);

	return 1;
}

/*
 * Starting a vg involves:
 * 1. reading the vg without a lock
 * 2. getting the lock_type/lock_args from the vg
 * 3. doing start_vg in lvmlockd for the lock_type 
 *    this means joining the lockspace
 *
 * The vg read in step 1 should not be used for anything
 * other than getting the lock_type/lock_args/uuid necessary
 * for starting the lockspace.  To use the vg for anything
 * else would require dlock_vg() and then rereading the
 * vg to ensure a valid copy is used.
 */

int dlock_start_vg(struct cmd_context *cmd, struct volume_group *vg,
		   const char *cmd_mode)
{
	char uuid[64] __attribute__((aligned(8)));
	const char *cmd_mode;
	daemon_reply reply;
	int host_id = 0;
	int result;

	if (!dlock_type(vg->lock_type))
		return 1;

	if (!_lvmlockd_active)
		return 0;
	if (!lvmlockd_connected())
		return 1;

	if (cmd_mode && !strcmp(cmd_mode, "na"))
		return 1;

	if (!strcmp(vg->lock_type, "sanlock")) {
		host_id = find_config_tree_int(cmd, global_lvmlockd_sanlock_host_id_CFG, NULL);
		if (host_id < 1 || host_id > 2000) {
			log_error("Invalid sanlock host_id.");
			return 0;
		}

		if (!activate_sanlock_lv(cmd, vg))
			return 0;
	}

	if (!id_write_format(&vg->id, uuid, sizeof(uuid)))
		strcpy(uuid, "none");

	reply = _lvmlockd_send("start_vg",
				"cmd = %s", cmd->command->name,
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"vg_lock_type = %s", vg->lock_type,
				"vg_lock_args = %s", vg->lock_args,
				"vg_uuid = %s", uuid,
				"host_id = %d", host_id,
				NULL);

	result = _lvmlockd_handle_reply(reply, "start_vg", vg->name);

	daemon_reply_destroy(reply);

	return result;
}

int dlock_stop_vg(struct cmd_context *cmd, struct volume_group *vg)
{
	daemon_reply reply;
	int result;

	if (!dlock_type(vg->lock_type))
		return 1;

	if (!_lvmlockd_active)
		return 0;
	if (!lvmlockd_connected())
		return 1;

	reply = _lvmlockd_send("stop_vg",
				"cmd = %s", cmd->command->name,
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				NULL);

	result = _lvmlockd_handle_reply(reply, "stop_vg", vg->name);
	if (!result) {
		log_error("lvmlockd stop_vg error.");
		goto out;
	}

	if (!strcmp(vg->lock_type, "sanlock")) {
		deactivate_sanlock_lv(cmd, vg);
	}
out:
	daemon_reply_destroy(reply);

	return result;
}

/*
 * For lvcreate, sanlock needs to allocate/initialize a lease area
 * on the internal leases lv to use for the lock for the new lv.
 */

int dlock_init_lv_sanlock(struct cmd_context *cmd,
			  struct volume_group *vg, const char *lv_name,
			  const char *lock_type, const char **lock_args_ret)
{
	daemon_reply reply;
	char *lock_args = NULL;
	const char *reply_str;
	int result;

	if (!_lvmlockd_active)
		return 0;
	if (!lvmlockd_connected())
		return 1;

	reply = _lvmlockd_send("init_lv",
				"cmd = %s", cmd->command->name,
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"lv_name = %s", lv_name,
				"vg_lock_type = %s", vg->lock_type,
				"vg_lock_args = %s", vg->lock_args,
				"lv_lock_type = %s", lock_type,
				NULL);

	result = _lvmlockd_handle_reply(reply, "init_lv", vg->name);

	reply_str = daemon_reply_str(reply, "lock_args", NULL);
	if (!reply_str) {
		log_error("lock_args not returned");
		result = 0;
		goto out;
	}

	lock_args = dm_pool_strdup(cmd->mem, reply_str);
	if (!lock_args) {
		log_error("lock_args allocation failed");
		result = 0;
	}
 out:
	daemon_reply_destroy(reply);

	*lock_args_ret = lock_args;
	return result;
}

/*
 * After lvremove has removed the lv, this is called to let
 * sanlock clear the lease area it had used for the lv.
 */

int dlock_free_lv_sanlock(struct cmd_context *cmd,
			  struct volume_group *vg, const char *lv_name,
			  const char *lock_type, const char *lock_args)
{
	daemon_reply reply;
	int result;

	if (!_lvmlockd_active)
		return 0;
	if (!lvmlockd_connected())
		return 1;

	reply = _lvmlockd_send("free_lv",
				"cmd = %s", cmd->command->name,
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"lv_name = %s", lv_name,
				"vg_lock_type = %s", vg->lock_type,
				"vg_lock_args = %s", vg->lock_args,
				"lv_lock_type = %s", lock_type,
				"lv_lock_args = %s", lock_args,
				NULL);

	result = _lvmlockd_handle_reply(reply, "init_lv", vg->name);

	daemon_reply_destroy(reply);

	return result;
}

#if 0
int dlock_rename_vg(struct volume_group *vg, const char *vg_name)
{
	/* Perhaps require a dlock_type vg to be converted to a
	 * local vg before being renamed, then converted back to
	 * its original type? */

	/*
	 * In lvmlockd, roughly:
	 *
	 * dlock vg ex
	 * dlock vg un (unlock destroy vglk)
	 *
	 * check/fail if any other nodes hold any lv locks
	 * check/fail if any local non-persisent lv locks exist
	 * unlock any local persistent lv locks
	 *
	 * sanlock:
	 * rem_lockspace(vg->name);
	 * sanlock_init(ls_vg_name);
	 * sanlock_init(res_vglk);
	 * add_lockspace(vg_name);
	 * dlm:
	 * release_lockspace
	 * new_lockspace
	 *
	 * dlock vg ex
	 * reacquire any local persistent lv locks
	 */
}
#endif

