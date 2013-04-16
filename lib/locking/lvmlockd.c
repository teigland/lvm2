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
#include "device.h"
#include "lvmlockd.h"
#include "lvmcache.h"
#include "lvmlockd-client.h"
#include "filter.h"
#include "assert.h"
#include "crc.h"

/*
 * Copy of lib/cache/lvmetad.c as much as possible.
 */

static daemon_handle _lvmlockd;
static int _lvmlockd_use = 0;
static int _lvmlockd_connected = 0;

static char *_lvmlockd_host_id = NULL;
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
	if (!_lvmlockd_use && !access(LVMLOCKD_PIDFILE, F_OK))
		log_warn("WARNING: lvmlockd is running but disabled.");
	_lvmlockd_cmd = cmd;
}

static void _lvmlockd_connect(void)
{
	if (!_lvmlockd_use || ! _lvmlockd_socket || !_lvmlockd_connected)
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
	if (!_lvmlockd_use)
		return;

	if (!_lvmlockd_connected)
		_lvmlockd_connect();

	if (_lvmlockd.socket_fd < 0 || _lvmlockd.error)
		log_warn("WARNING: Failed to connect to lvmlockd: %s. No distributed locking.",
			 strerror(_lvmlockd.error));
}

int lvmlockd_active(void)
{
	if (!_lvmlockd_use)
		return 0;

	if (!_lvmlockd_connected)
		_lvmlockd_connect();

	if (_lvmlockd.socket_fd < 0 || _lvmlockd.error)
		log_warn("WARNING: Failed to connect to lvmlockd: %s. No distributed locking.",
			 strerror(_lvmlockd.error));

	return _lvmlockd_connected;
}

void lvmlockd_set_active(int active)
{
	_lvmlockd_use = active;
}

void lvmlockd_config_set_host_id(const struct dm_config_value *val)
{
	dm_asprintf(&_lvmlockd_host_id, "%s", val->v.str);
}

void lvmlockd_config_free(void)
{
	dm_free(_lvmlockd_host_id);
	_lvmlockd_host_id = NULL;
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
	char *result_str;
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

static int _dlock_general(const char *id,
			  const char *vg_name,
			  const char *lv_name,
			  const char *lv_lock_args,
			  const char *mode,
			  const char *opts)
{
	daemon_reply reply;
	int result;

	if (!strcmp(mode, "na"))
		return 1;

	if (!lvmlockd_active() || test_mode())
		return 1; /* fake it */

	if (!opts)
		opts = "none";

	if (vg_name && lv_name) {
		reply = _lvmlockd_send(id,
					"mode = %s", mode,
					"opts = %s", opts,
					"vg_name = %s", vg_name,
					"lv_name = %s", lv_name,
					"lock_args = %s", lv_lock_args ?: "none",
					NULL);

		result = _lvmlockd_handle_reply(reply, id, lv_name);

	} else if (vg_name) {
		reply = _lvmlockd_send(id,
					"mode = %s", mode,
					"opts = %s", opts,
					"vg_name = %s", vg_name,
					NULL);

		result = _lvmlockd_handle_reply(reply, id, vg_name);

	} else {
		reply = _lvmlockd_send(id,
					"mode = %s", mode,
					"opts = %s", opts,
					NULL);

		result = _lvmlockd_handle_reply(reply, id, NULL);
	}

	daemon_reply_destroy(reply);

	return result;
}

int dlock_gl(const char *mode)
{
	return _dlock_general("lock_gl", NULL, NULL, NULL, mode, NULL);
}

int dlock_vg(const char *vg_name, const char *mode)
{
	return _dlock_general("lock_vg", vg_name, NULL, NULL, mode, NULL);
}

int dlock_vg_persistent(const char *vg_name, const char *mode)
{
	return _dlock_general("lock_vg", vg_name, NULL, NULL, mode, "persistent");
}

int dlock_lv_name(const char *vg_name, const char *lv_name, const char *lock_args,
		  const char *mode, const char *opts)
{
	return _dlock_general("lock_lv", vg_name, lv_name, lock_args, mode, opts);
}

int dlock_lv(struct logical_volume *lv, const char *mode)
{
	return _dlock_general("lock_lv", lv->vg->name, lv->name, lv->lock_args,
			      mode, NULL);
}

int dlock_lv_persistent(struct logical_volume *lv, const char *mode)
{
	return _dlock_general("lock_lv", lv->vg->name, lv->name, lv->lock_args,
			      mode, "persistent");
}

/* shortcut for common pattern of dlock_gl+dlock_vg */

int dlock_gl_vg(const char *vg_name, const char *gl_mode, const char *vg_mode)
{
	if (!dlock_gl(gl_mode))
		return 0;

	if (!dlock_vg(vg_name, vg_mode)) {
		dlock_gl("un");
		return 0;
	}

	return 1;
}

int dlock_vg_update(struct volume_group *vg)
{
	daemon_reply reply;
	int result;

	if (!vg->lock_type || !strcmp(vg->lock_type, "none"))
		return 1;

	if (!lvmlockd_active() || test_mode())
		return 1; /* fake it */

	reply = _lvmlockd_send("vg_update",
				"vg_name = %s", vg->name,
				"version = %u", vg->seqno,
				NULL);

	result = _lvmlockd_handle_reply(reply, "vg_update", vg->name);

	daemon_reply_destroy(reply);

	return result;
}

static int _dlock_init_vg(const char *vg_name, const char *lock_type,
			  const char *lvmlocks_name)
{
	daemon_reply reply;
	int result;

	if (!lvmlockd_active() || test_mode())
		return 1; /* fake it */

	reply = _lvmlockd_send("init_vg",
				"vg_name = %s", vg_name,
				"lock_type = %s", lock_type,
				"lock_args = %s", lvmlocks_name ?: "none",
				NULL);

	result = _lvmlockd_handle_reply(reply, "init_vg", vg_name);

	daemon_reply_destroy(reply);

	return result;
}

static int _dlock_init_lv(struct cmd_context *cmd,
			  const char *vg_name, const char *lv_name,
			  const char *lock_type, const char **lock_args)
{
	daemon_reply reply;
	const char *reply_str, *new_str;
	int result;

	*lock_args = NULL;

	if (!lvmlockd_active() || test_mode())
		return 1; /* fake it */

	reply = _lvmlockd_send("init_lv",
				"vg_name = %s", vg_name,
				"lv_name = %s", lv_name,
				"lock_type = %s", lock_type,
				NULL);

	result = _lvmlockd_handle_reply(reply, "init_lv", vg_name);

	reply_str = daemon_reply_str(reply, "lock_args", NULL);
	if (!reply_str)
		goto out;

	new_str = dm_pool_strdup(cmd->mem, reply_str);
	if (!new_str) {
		log_error("lock_args allocation failed");
		result = 0;
		goto out;
	}

	*lock_args = new_str;
 out:
	daemon_reply_destroy(reply);

	return result;
}

/*
 * lvmlockd for sanlock will:
 * unlock_destroy vglk (destroy so it can't be acquired by someone)
 * if other nodes are still in the lockspace, somehow tell them
 * to quit, wait for all to quit (or fail here with an error)
 * rem_lockspace (do we need some sort of destructive remove here?)
 * (sanlock has now closed lvmlocks lv)
 *
 * for dlm:
 * unlock vglk
 * release_lockspace(ls_vgname);
 */

static int _dlock_free_vg(const char *vg_name, const char *lock_type)
{
	daemon_reply reply;
	int result;

	if (!lvmlockd_active() || test_mode())
		return 1; /* fake it */

	reply = _lvmlockd_send("free_vg",
				"vg_name = %s", vg_name,
				"lock_type = %s", lock_type,
				NULL);

	result = _lvmlockd_handle_reply(reply, "free_vg", vg_name);

	daemon_reply_destroy(reply);

	return result;
}

/*
 * Eventually we may create a separate lvmlocks lv on multiple pvs.
 * They will not be mirrored, but will be independent lvs, and
 * sanlock will use all of them.  sanlock will be able to continue locking as
 * long as the majority of them are still available.
 */

/*
 * TODO: more formal method for using the magic name "lvmlocks"?
 * Make it variable?  If so, the name would need to be a part of
 * lock_args for both vg and lv metadata.
 *
 * TODO: configurable lvmlocks lv size?
 */

static int create_lvmlocks_lv(struct cmd_context *cmd, struct volume_group *vg,
			      const char *lv_name)
{
	struct lvcreate_params lp;

	memset(&lp, 0, sizeof(struct lvcreate_params));
	lp.zero = 1;
	lp.activate = CHANGE_ALY;
	lp.vg_name = dm_pool_strdup(cmd->mem, vg->name);
	lp.lv_name = dm_pool_strdup(cmd->mem, lv_name);
	lp.read_ahead = DM_READ_AHEAD_NONE;
	lp.stripes = 1;
	lp.extents = 1073741824 / vg->extent_size;  /* -L 1G */

	if (!lv_create_single(vg, &lp))
		return 0;
	return 1;
}

static int remove_lvmlocks_lv(struct cmd_context *cmd, struct volume_group *vg,
			      const char *lv_name)
{
	if (!lv_name)
		return 1;

	/* TODO: lvremove */
	return 1;
}

#if 0
int dlock_init_gl(struct cmd_context *cmd)
{
}
#endif

/*
 * TODO: more formal method of handling the known lock_type names?
 * i.e. "sanlock" and "dlm"  They can't be completed hidden within
 * lvmlockd because the init function (within the command context)
 * needs to do lock-type-specific things, i.e. creating lvmlocks.
 */

#define LOCKS_LV_NAME "lvmlocks"

int dlock_init_vg(struct cmd_context *cmd, struct volume_group *vg)
{
	const char *lvmlocks_name = NULL;

	if (!vg->lock_type || !strcmp(vg->lock_type, "none"))
		return 1;

	/* create internal lv for lock manager to store lock state */

	if (!strcmp(vg->lock_type, "sanlock")) {
		lvmlocks_name = LOCKS_LV_NAME;
		if (!create_lvmlocks_lv(cmd, vg, lvmlocks_name))
			return 0;
	}

	/* lvmlockd creates/starts the lockspace and lock */

	if (!_dlock_init_vg(vg->name, vg->lock_type, lvmlocks_name)) {
		/* is this remove needed if we just
		   back out the entire vg creation? */
		remove_lvmlocks_lv(cmd, vg, lvmlocks_name);
		return 0;
	}

	return 1;
}

/* undo anything so the vg an be freed */
int dlock_undo_vg(struct cmd_context *cmd, struct volume_group *vg)
{
	if (vg->lock_type && strcmp(vg->lock_type, "sanlock")) {
		_dlock_free_vg(vg->name, vg->lock_type);
		remove_lvmlocks_lv(cmd, vg, "lvmlocks");
	}
	return 1;
}

/* the vg has been freed */
int dlock_free_vg(char *vg_name, const char *lock_type)
{
	if (lock_type && strcmp(lock_type, "dlm"))
		_dlock_free_vg(vg_name, lock_type);
	return 1;
}

#if 0
int dlock_rename_vg(struct volume_group *vg, const char *vg_name)
{
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

/*
 * If the name "lvmlocks" is constant, then lvmlockd can just
 * assume that the lv for locks is named that, and lock_args
 * for sanlock can just include the offset on that lv.  If
 * it's not constant, then the name, e.g. "lvmlocks", needs
 * to be kept in lock_args along with the offset.
 */

/* FIXME: don't use void */
int dlock_init_lv(struct cmd_context *cmd, struct volume_group *vg, void *data)
{
	struct lvcreate_params *lp = data;
	const char *lock_args = NULL;

	if (!lp->lock_type) {
		if (!vg->lock_type || !strcmp(vg->lock_type, "none"))
			return 1;

		lp->lock_type = dm_pool_strdup(cmd->mem, vg->lock_type);
		if (!lp->lock_type) {
			log_error("lock_type allocation failed");
			return 0;
		}
	}

	/* lvmlockd creates/starts the lockspace and lock */

	/* sanlock finds an empty lease area on lvmlocks lv
	   and returns the offset which we need to save in lock_args */

	if (!_dlock_init_lv(cmd, vg->name, lp->lv_name, lp->lock_type, &lock_args)) {
		return 0;
	}

	lp->lock_args = lock_args;

	return 1;
}

static int _dlock_free_lv(const char *vg_name, const char *lv_name,
			  const char *lock_type, const char *lock_args)
{
	return 1;
}

int dlock_free_lv(struct volume_group *vg, const char *lv_name,
		  const char *lock_type, const char *lock_args)
{
	if (!lock_type || !strcmp(lock_type, "none"))
		return 1;

	/* sanlock will clear the lease area used for this lv's lease */

	return _dlock_free_lv(vg->name, lv_name, lock_type, lock_args);
}

int dlock_start_vg(struct cmd_context *cmd, struct volume_group *vg)
{
	char uuid[64] __attribute__((aligned(8)));
	daemon_reply reply;
	int result;

	if (!vg->lock_type || !strcmp(vg->lock_type, "none"))
		return 1;

	if (!lvmlockd_active() || test_mode())
		return 1; /* fake it */

	if (!id_write_format(&vg->id, uuid, sizeof(uuid)))
		strcpy(uuid, "none");

	reply = _lvmlockd_send("start_vg",
				"vg_name = %s", vg->name,
				"lock_type = %s", vg->lock_type,
				"lock_args = %s", vg->lock_args,
				"vg_uuid = %s", uuid,
				"host_id = %s", _lvmlockd_host_id ?: "none",
				NULL);

	result = _lvmlockd_handle_reply(reply, "start_vg", vg->name);

	daemon_reply_destroy(reply);

	return result;
}

int dlock_stop_vg(struct cmd_context *cmd, struct volume_group *vg)
{
	daemon_reply reply;
	int result;

	if (!vg->lock_type || !strcmp(vg->lock_type, "none"))
		return 1;

	if (!lvmlockd_active() || test_mode())
		return 1; /* fake it */

	reply = _lvmlockd_send("stop_vg",
				"vg_name = %s", vg->name,
				NULL);

	result = _lvmlockd_handle_reply(reply, "stop_vg", vg->name);

	daemon_reply_destroy(reply);

	return result;
}

