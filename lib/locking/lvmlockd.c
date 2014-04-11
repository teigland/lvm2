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
#include "segtype.h"
#include "lvmetad.h"
#include "lvmlockd.h"
#include "lvmcache.h"
#include "lvmlockd-client.h"

static daemon_handle _lvmlockd;
static int _lvmlockd_active;
static int _lvmlockd_connected;

static const char *_lvmlockd_socket = NULL;
static struct cmd_context *_lvmlockd_cmd = NULL;

/* The name of the internal lv created to hold sanlock locks. */
#define SANLOCK_LV_NAME "lvmlock"

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
		log_warn("lvmlockd is not running.");
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
		log_warn("Failed to connect to lvmlockd: %s.",
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

static daemon_reply _lvmlockd_send(const char *req_name, ...)
{
	va_list ap;
	daemon_reply repl;
	daemon_request req;

	req = daemon_request_make(req_name);

	va_start(ap, req_name);
	daemon_request_extend_v(req, ap);
	va_end(ap);

	repl = daemon_send(_lvmlockd, req);

	daemon_request_destroy(req);

	return repl;
}

static void result_str_to_flags(const char *str, uint32_t *flags)
{
	if (strstr(str, "NO_LOCKSPACES"))
		*flags |= LD_RF_NO_LOCKSPACES;

	if (strstr(str, "NO_GL_LS"))
		*flags |= LD_RF_NO_GL_LS;

	if (strstr(str, "LOCAL_LS"))
		*flags |= LD_RF_LOCAL_LS;
}

/*
 * evaluate the reply from lvmlockd, check for errors, extract
 * the result and result_flags returned by lvmlockd.
 * 0 failure (no result/result_flags set)
 * 1 success (result/result_flags set)
 */

static int _lvmlockd_result(daemon_reply reply, int *result, uint32_t *result_flags)
{
	int reply_result;
	const char *reply_flags;
	const char *lock_type;

	if (reply.error) {
		log_error("lvmlockd_result reply error %d", reply.error);
		return 0;
	}

	if (strcmp(daemon_reply_str(reply, "response", ""), "OK")) {
		log_error("lvmlockd_result bad response");
		return 0;
	}

	/* FIXME: using -1000 is dumb */

	reply_result = daemon_reply_int(reply, "op_result", -1000);
	if (reply_result == -1000) {
		log_error("lvmlockd_result no op_result");
		return 0;
	}

	/* The lock_type that lvmlockd used for locking. */
	lock_type = daemon_reply_str(reply, "lock_type", "none");

	*result = reply_result;

	if (!result_flags)
		goto out;

	reply_flags = daemon_reply_str(reply, "result_flags", NULL);
	if (reply_flags)
		result_str_to_flags(reply_flags, result_flags);

 out:
	log_debug("lvmlockd_result %d %s lm %s", reply_result, reply_flags, lock_type);
	return 1;
}

/*
 * Check if a lock_type uses lvmlockd.
 * If not (none, clvm), return 0.
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

/*
 * result/result_flags are values returned from lvmlockd.
 *
 * return 0 (failure)
 * return 1 (result/result_flags indicate success/failure)
 *
 * return 1 result 0   (success)
 * return 1 result < 0 (failure)
 *
 * caller may ignore result < 0 failure depending on
 * result_flags and the specific command/mode.
 *
 * When this function returns 0 (failure), no result/result_flags
 * were obtained from lvmlockd.
 *
 * When this function returns 1 (success), result/result_flags may
 * have been obtained from lvmlockd.  This lvmlockd result may
 * indicate a locking failure.
 */

int dlock_general(struct cmd_context *cmd,
		  const char *cmd_name,
		  const char *req_name,
		  const char *vg_name,
		  const char *vg_lock_type,
		  const char *vg_lock_args,
		  const char *lv_name,
		  const char *lv_lock_args,
		  const char *mode,
		  const char *opts,
		  int *result,
		  uint32_t *result_flags)
{
	daemon_reply reply;
	int pid = getpid();

	*result = 0;
	*result_flags = 0;

	if (vg_lock_type && !dlock_type(vg_lock_type))
		return 1;

	if (!strcmp(mode, "na"))
		return 1;

	if (!_lvmlockd_active)
		return 1;
	if (!lvmlockd_connected())
		return 0;

	if (!opts)
		opts = "none";

	/* cmd and pid are passed for informational and debugging purposes */

	if (vg_name && lv_name) {
		reply = _lvmlockd_send(req_name,
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

		if (!_lvmlockd_result(reply, result, result_flags))
			goto fail;

		log_debug("dlock %s %s vg %s lv %s result %d %x",
			  req_name, mode, vg_name, lv_name, *result, *result_flags);

	} else if (vg_name) {
		reply = _lvmlockd_send(req_name,
					"cmd = %s", cmd_name,
					"pid = %d", pid,
					"mode = %s", mode,
					"opts = %s", opts,
					"vg_name = %s", vg_name,
					"vg_lock_type = %s", vg_lock_type ?: "none",
					"vg_lock_args = %s", vg_lock_args ?: "none",
					NULL);

		if (!_lvmlockd_result(reply, result, result_flags))
			goto fail;

		log_debug("dlock %s %s vg %s result %d %x",
			  req_name, mode, vg_name, *result, *result_flags);

	} else {
		reply = _lvmlockd_send(req_name,
					"cmd = %s", cmd_name,
					"pid = %d", pid,
					"mode = %s", mode,
					"opts = %s", opts,
					"vg_lock_type = %s", vg_lock_type ?: "none",
					NULL);

		if (!_lvmlockd_result(reply, result, result_flags))
			goto fail;

		log_debug("dlock %s %s result %d %x",
			  req_name, mode, *result, *result_flags);
	}

	daemon_reply_destroy(reply);

	/* result/result_flags have lvmlockd result */
	return 1;

 fail:
	/* no result was obtained from lvmlockd */

	log_error("dlock %s %s failed no lvmlockd result", req_name, mode);

	daemon_reply_destroy(reply);
	return 0;
}

/*
 * Called after a vg_write to indicate that the version number
 * of the vg lock should be incremented (set to the new vg seqno)
 * to invalidate the vg cache on other hosts.
 */

int dlock_vg_update(struct volume_group *vg)
{
	daemon_reply reply;
	int result;
	int ret;

	if (!dlock_type(vg->lock_type))
		return 1;

	if (!_lvmlockd_active)
		return 1;
	if (!lvmlockd_connected())
		return 0;

	log_debug("dlock update %s %u", vg->name, vg->seqno);

	reply = _lvmlockd_send("vg_update",
				"vg_name = %s", vg->name,
				"version = %d", (int64_t)vg->seqno,
				NULL);

	if (!_lvmlockd_result(reply, &result, NULL)) {
		ret = 0;
	} else {
		ret = (result < 0) ? 0 : 1;
	}

	daemon_reply_destroy(reply);
	return ret;
}

static struct logical_volume *find_sanlock_lv(struct volume_group *vg,
					      const char *lock_lv_name)
{
	struct lv_list *lvl;

	dm_list_iterate_items(lvl, &vg->lvs) {
		if (!strcmp(lvl->lv->name, lock_lv_name))
			return lvl->lv;
	}
	return NULL;
}

/*
 * Eventually we may create a separate lvmlocks lv on multiple pvs.
 * They will not be mirrored, but will be independent lvs, and
 * sanlock will use all of them.  sanlock will be able to continue locking as
 * long as the majority of them are still available.
 *
 * TODO: create an lvmlock_spare lv on another pv so that recovery from
 * the loss of lvmlock lv is simpler.
 */

static int create_sanlock_lv(struct cmd_context *cmd, struct volume_group *vg,
			      const char *lock_lv_name)
{
	struct logical_volume *lv;
	struct lvcreate_params lp = {
		.activate = CHANGE_ALY,
		.alloc = ALLOC_INHERIT,
		.extents = LVMLOCKD_SANLOCK_LV_SIZE / (vg->extent_size * SECTOR_SIZE),
		.major = -1,
		.minor = -1,
		.permission = LVM_READ | LVM_WRITE,
		.pvh = &vg->pvs,
		.read_ahead = DM_READ_AHEAD_NONE,
		.stripes = 1,
		.vg_name = vg->name,
		.lv_name = dm_pool_strdup(cmd->mem, lock_lv_name),
		.zero = 1,
	};

	dm_list_init(&lp.tags);

	if (!(lp.segtype = get_segtype_from_string(vg->cmd, "striped")))
		return_0;

	lv = lv_create_single(vg, &lp);
	if (!lv) {
		log_error("Failed to create sanlock lv %s in vg %s", lock_lv_name, vg->name);
		return 0;
	}

	lv_set_hidden(lv);
	return 1;
}

/*
 * vg_lock_args format for sanlock is
 * version_string:undefined:lock_lv_name
 *
 * vg_lock_args format for dlm is
 * version_string:undefined:cluster_name
 *
 * lv_lock_args format for sanlock is
 * version_string:undefined:offset
 *
 * lv_lock_args is not used for dlm
 *
 * undefined may contain ":"
 */

static const char *vg_lock_args_to_lv(const char *vg_lock_args)
{
	const char *args = vg_lock_args;
	const char *colon, *last = NULL;

	while (1) {
		if (!args || (*args == '\0'))
			break;
		colon = strstr(args, ":");
		if (!colon)
			break;
		last = colon;
		args = colon + 1;
	}

	if (last)
		return last + 1;
	else
		return NULL;
}

static int remove_sanlock_lv(struct cmd_context *cmd, struct volume_group *vg,
			     const char *lock_lv_name)
{
	struct logical_volume *lv;

	lv = find_sanlock_lv(vg, lock_lv_name);
	if (!lv) {
		log_error("Failed to find sanlock lv %s in vg %s", lock_lv_name, vg->name);
		return 0;
	}

	if (!lv_remove(lv)) {
		log_error("Failed to remove sanlock lv %s/%s", vg->name, lock_lv_name);
		return 0;
	}

	return 1;
}

static int activate_sanlock_lv(struct cmd_context *cmd, struct volume_group *vg)
{
	struct logical_volume *lv;
	const char *lock_lv_name = vg_lock_args_to_lv(vg->lock_args);

	lv = find_sanlock_lv(vg, lock_lv_name);
	if (!lv) {
		log_error("Failed to find sanlock lv %s in vg %s", lock_lv_name, vg->name);
		return 0;
	}

	if (!activate_lv(cmd, lv)) {
		log_error("Failed to activate sanlock lv %s/%s", vg->name, lock_lv_name);
		return 0;
	}

	return 1;
}

static int deactivate_sanlock_lv(struct cmd_context *cmd, struct volume_group *vg)
{
	struct logical_volume *lv;
	const char *lock_lv_name = vg_lock_args_to_lv(vg->lock_args);

	lv = find_sanlock_lv(vg, lock_lv_name);
	if (!lv) {
		log_error("Failed to find sanlock lv %s in vg %s", lock_lv_name, vg->name);
		return 0;
	}

	if (!deactivate_lv(cmd, lv)) {
		log_error("Failed to deactivate sanlock lv %s/%s", vg->name, lock_lv_name);
		return 0;
	}

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
	daemon_reply reply;
	const char *lock_type;
	int host_id = 0;
	int result;
	int ret;

	memset(uuid, 0, sizeof(uuid));

	/* We may want to ignore non-dlock vgs here and
	   inform lvmlockd of local vgs another way, or
	   have it discover local vgs itself. */

	/*
	if (!dlock_type(vg->lock_type))
		return 1;
	*/

	if (!_lvmlockd_active)
		return 1;
	if (!lvmlockd_connected())
		return 0;

	if (cmd_mode && !strcmp(cmd_mode, "na"))
		return 1;

	log_debug("dlock_start_vg %s lock_type %s", vg->name,
		  vg->lock_type ? vg->lock_type : "empty");

	if (vg->lock_type && !strcmp(vg->lock_type, "sanlock")) {
		host_id = find_config_tree_int(cmd, global_lvmlockd_sanlock_host_id_CFG, NULL);
		if (host_id < 1 || host_id > 2000) {
			log_error("Invalid sanlock host_id.");
			return 0;
		}

		/*
		 * This is a crucial difference between starting
		 * sanlock vs dlm vgs: the internal sanlock lv
		 * needs to be activated before lvmlockd does the
		 * start because sanlock needs to use the lv.
		 */

		if (!activate_sanlock_lv(cmd, vg))
			return 0;
	}

	id_write_format(&vg->id, uuid, sizeof(uuid));

	if (!dlock_type(vg->lock_type)) {
		char *sysid = NULL;

		if (vg->system_id && (strlen(vg->system_id) > 0))
			sysid = vg->system_id;

		reply = _lvmlockd_send("add_local",
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"vg_uuid = %s", uuid[0] ? uuid : "none",
				"vg_sysid = %s", sysid ?: "none",
				NULL);

		lock_type = "local";
	} else {
		reply = _lvmlockd_send("start_vg",
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"vg_lock_type = %s", vg->lock_type,
				"vg_lock_args = %s", vg->lock_args,
				"vg_uuid = %s", uuid[0] ? uuid : "none",
				"host_id = %d", (int64_t)host_id,
				"version = %d", (int64_t)vg->seqno,
				NULL);

		lock_type = vg->lock_type;
	}

	if (!_lvmlockd_result(reply, &result, NULL)) {
		result = -1;
		ret = 0;
	} else {
		ret = (result < 0) ? 0 : 1;
	}

	if (result == -EEXIST) {
		ret = 1;
		goto out;
	}

	if (!ret)
		log_error("Locking start %s VG %s %d", lock_type, vg->name, result);
	else
		log_debug("dlock_start_vg %s done", vg->name);

out:
	daemon_reply_destroy(reply);

	return ret;
}

int dlock_stop_vg(struct cmd_context *cmd, struct volume_group *vg)
{
	daemon_reply reply;
	int result;
	int ret;

	if (!dlock_type(vg->lock_type))
		return 1;

	if (!_lvmlockd_active)
		return 1;
	if (!lvmlockd_connected())
		return 0;

	log_debug("dlock_stop_vg %s lock_type %s", vg->name,
		  vg->lock_type ? vg->lock_type : "empty");

	reply = _lvmlockd_send("stop_vg",
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				NULL);

	if (!_lvmlockd_result(reply, &result, NULL)) {
		ret = 0;
	} else {
		ret = (result < 0) ? 0 : 1;
	}

	if (!ret) {
		log_error("Locking stop %s VG %s %d", vg->lock_type, vg->name, result);
		goto out;
	}

	if (!strcmp(vg->lock_type, "sanlock")) {
		log_debug("dlock_stop_vg deactivate sanlock lv");
		deactivate_sanlock_lv(cmd, vg);
	}
out:
	daemon_reply_destroy(reply);

	return ret;
}

/*
 * vgcreate does:
 * dlock_init_vg();
 * vg_create
 * dlock_vg_update();
 * dlock_start_vg();
 */

int dlock_init_vg_sanlock(struct cmd_context *cmd, struct volume_group *vg)
{
	daemon_reply reply;
	const char *reply_str;
	const char *vg_lock_args = NULL;
	const char *lock_lv_name = SANLOCK_LV_NAME;
	int result;
	int ret;

	log_debug("dlock_init_vg_sanlock %s", vg->name);

	if (!_lvmlockd_active)
		return 1;
	if (!lvmlockd_connected())
		return 0;

	if (!create_sanlock_lv(cmd, vg, lock_lv_name)) {
		log_error("Failed to create internal lv.");
		return 0;
	}

	/*
	 * N.B. this passes the lock_lv_name as vg_lock_args
	 * even though it is only part of the final args string
	 * which will be returned from lvmlockd.
	 */

	reply = _lvmlockd_send("init_vg",
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"vg_lock_type = %s", "sanlock",
				"vg_lock_args = %s", lock_lv_name,
				NULL);

	if (!_lvmlockd_result(reply, &result, NULL)) {
		ret = 0;
	} else {
		ret = (result < 0) ? 0 : 1;
	}

	if (!ret) {
		log_error("dlock_init_vg_sanlock lvmlockd result %d", result);
		remove_sanlock_lv(cmd, vg, lock_lv_name);
		goto out;
	}

	reply_str = daemon_reply_str(reply, "vg_lock_args", NULL);
	if (!reply_str) {
		log_error("vg_lock_args not returned");
		ret = 0;
		goto out;
	}

	vg_lock_args = dm_pool_strdup(cmd->mem, reply_str);
	if (!vg_lock_args) {
		log_error("vg_lock_args allocation failed");
		ret = 0;
        }
 out:
	daemon_reply_destroy(reply);

	vg->lock_args = vg_lock_args;
	return ret;
}

int dlock_init_vg_dlm(struct cmd_context *cmd, struct volume_group *vg)
{
	daemon_reply reply;
	const char *reply_str;
	const char *vg_lock_args = NULL;
	int result;
	int ret;

	log_debug("dlock_init_vg_dlm %s", vg->name);

	if (!_lvmlockd_active)
		return 1;
	if (!lvmlockd_connected())
		return 0;

	reply = _lvmlockd_send("init_vg",
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"vg_lock_type = %s", "dlm",
				NULL);

	if (!_lvmlockd_result(reply, &result, NULL)) {
		ret = 0;
	} else {
		ret = (result < 0) ? 0 : 1;
	}

	if (!ret) {
		log_error("dlock_init_vg_dlm lvmlockd result %d", result);
		goto out;
	}

	reply_str = daemon_reply_str(reply, "vg_lock_args", NULL);
	if (!reply_str) {
		log_error("vg_lock_args not returned");
		ret = 0;
		goto out;
	}

	vg_lock_args = dm_pool_strdup(cmd->mem, reply_str);
	if (!vg_lock_args) {
		log_error("vg_lock_args allocation failed");
		ret = 0;
	}
 out:
	daemon_reply_destroy(reply);

	vg->lock_args = vg_lock_args;
	return ret;
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
	char *lv_lock_args = NULL;
	const char *reply_str;
	int result;
	int ret;

	log_debug("dlock_init_lv_sanlock %s/%s", vg->name, lv_name);

	if (!_lvmlockd_active)
		return 1;
	if (!lvmlockd_connected())
		return 0;

	reply = _lvmlockd_send("init_lv",
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"lv_name = %s", lv_name,
				"vg_lock_type = %s", vg->lock_type,
				"vg_lock_args = %s", vg->lock_args,
				NULL);

	if (!_lvmlockd_result(reply, &result, NULL)) {
		ret = 0;
	} else {
		ret = (result < 0) ? 0 : 1;
	}

	if (!ret) {
		log_error("dlock_init_lv_sanlock lvmlockd result %d", result);
		goto out;
	}

	reply_str = daemon_reply_str(reply, "lv_lock_args", NULL);
	if (!reply_str) {
		log_error("lv_lock_args not returned");
		ret = 0;
		goto out;
	}

	lv_lock_args = dm_pool_strdup(cmd->mem, reply_str);
	if (!lv_lock_args) {
		log_error("lv_lock_args allocation failed");
		ret = 0;
	}
 out:
	daemon_reply_destroy(reply);

	*lock_args_ret = lv_lock_args;
	return ret;
}

/*
 * vgremove for sanlock:
 * Any other hosts are joined to the lockspace need to stop
 * the vg before we can remove and erase the sanlock lv.
 * lvmlockd queries for other live hosts in the lockspace,
 * and can use a sanlock host message to tell them to leave.
 * We could wait for some timeout for all other hosts to leave
 * and then fail the vgremove if they haven't.
 */

/* called before vg_remove on disk */
int dlock_free_vg_sanlock(struct cmd_context *cmd, struct volume_group *vg)
{
	daemon_reply reply;
	int result;
	int ret;

	/* Unlocking the vg lock here preempts the dlock_vg("un") in
	   toollib.c which will occur after the lockspace is stopped. */

	log_debug("dlock_free_vg_sanlock for vgremove %s", vg->name);

	if (!_lvmlockd_active)
		return 1;
	if (!lvmlockd_connected())
		return 0;

	reply = _lvmlockd_send("free_vg",
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"vg_lock_type = %s", vg->lock_type,
				"vg_lock_args = %s", vg->lock_args,
				NULL);

	if (!_lvmlockd_result(reply, &result, NULL)) {
		ret = 0;
	} else {
		ret = (result < 0) ? 0 : 1;
	}

	if (result == -EBUSY) {
		log_error("Lockspace not stopped on other hosts");
		goto out;
	}

	if (!ret) {
		log_error("dlock_free_vg_sanlock lvmlockd result %d", result);
		goto out;
	}

	deactivate_sanlock_lv(cmd, vg);

	remove_sanlock_lv(cmd, vg, vg_lock_args_to_lv(vg->lock_args));
 out:
	daemon_reply_destroy(reply);

	return ret;
}

/* called after vg_remove on disk */
int dlock_free_vg_dlm(struct cmd_context *cmd, struct volume_group *vg)
{
	uint32_t result_flags;
	int result;
	int ret;

	/* Unlocking the vg lock here preempts the dlock_vg("un") in
	   toollib.c which will occur after the lockspace is stopped. */

	log_debug("dlock_free_vg_dlm un for vgremove %s", vg->name);

	/* dlock_vg(cmd, vg->name, "un", 0); */

	ret = dlock_general(cmd, "vgremove", "lock_vg", vg->name,
			    NULL, NULL, NULL, NULL, "un", NULL,
			    &result, &result_flags);

	if (!ret || result < 0) {
		log_error("dlock_free_vg_dlm lvmlockd result %d", result);
		return 0;
	}

	dlock_stop_vg(cmd, vg);

	return 1;
}

#if 0
/* called after vg_remove on disk */
/* we want this to remove lvmlockd's cache of the local vg name, but it only
   works on the host doing the vgremove. */
int dlock_free_vg_local(struct cmd_context *cmd, struct volume_group *vg)
{
	uint32_t result_flags;
	int result;
	int ret;

	log_debug("dlock_free_vg_local for vgremove %s", vg->name);

	reply = _lvmlockd_send("free_vg",
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"vg_lock_type = %s", "none",
				NULL);

	if (!ret || result < 0) {
		log_error("dlock_free_vg_local lvmlockd result %d", result);
		return 0;
	}

	return 1;
}
#endif

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
	int ret;

	log_debug("dlock_free_lv_sanlock for lvremove %s/%s",
		  vg->name, lv_name);

	if (!_lvmlockd_active)
		return 1;
	if (!lvmlockd_connected())
		return 0;

	reply = _lvmlockd_send("free_lv",
				"pid = %d", getpid(),
				"vg_name = %s", vg->name,
				"lv_name = %s", lv_name,
				"vg_lock_type = %s", vg->lock_type,
				"vg_lock_args = %s", vg->lock_args,
				"lv_lock_args = %s", lock_args,
				NULL);

	if (!_lvmlockd_result(reply, &result, NULL)) {
		ret = 0;
	} else {
		ret = (result < 0) ? 0 : 1;
	}
	
	if (!ret) {
		log_error("dlock_free_lv_sanlock lvmlockd result %d", result);
	}

	daemon_reply_destroy(reply);

	return ret;
}

/* For now, we will not allow vg rename of a dlock_type vg. */

#if 0
int dlock_rename_vg(struct volume_group *vg, const char *vg_name)
{
	/*
	 * The difficulty is that the lockspace/lock names and paths
	 * are based on the vg name, which means that the existing
	 * lockspace/locks must be released, like vgremove, and new
	 * lockspace/locks must be acquired like vgcreate.
	 *
	 * In lvmlockd we basically want to do a vgremove+vgcreate.
	 */
}
#endif

