/*
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 */

/*
 * init_vg vg_name lm_type lm_args
 *
 * Create/initialize a new clustered vg, or clusterize an existing vg.
 * For sanlock, lm_args is the path to the leases lv, which vgcreate
 * automatically creates in the new vg prior to calling lvmlockd.
 * lvmlockd needs to initialize sanlock leases on the leases lv.
 * For dlm, lvmlockd returns the cluster name, which becomes lm_args.
 *
 * vgcreate --lock-type lm_type vg_name devs
 * vgchange --lock-type lm_type vg_name devs
 *
 * Test:
 * lvmlock --lock-init lm_type --lock-args lm_args --vg vg_name
 *
 * vgcreate foo devs
 * lvcreate -L1G -n leases foo
 * lvmlock --lock-init sanlock --lock-args /dev/foo/leases --lock-gl enable --vg foo
 *
 * start_vg foo                  [lvmlock --lock-vg start --vg foo --lock-type sanlock --lock-args /dev/foo/leases --host-id 1]
 * lock_gl (gl from foo is used) [lvmlock --lock-gl ex]
 * vgcreate bar devs
 * lvcreate -L1G -n leases bar
 * lvmlock --lock-init sanlock --lock-args /dev/bar/leases --vg bar
 * unlock_gl
 * start_vg bar
 *
 * (foo is the first vg created, so the gl is enabled in foo;
 * bar is the second vg created, so the gl is disabled in bar.)
 *
 * ----
 *
 * init_lv vg_name lv_name lm_type
 *
 * Create/initialize a new lv in a clustered vg.
 * lvmlockd needs to initialize sanlock disk areas; it is no-op for dlm.
 * The lm_type is generally inherited from the vg.
 * For sanlock, the path to the leases lv is inherited from the vg lm_args.
 * For sanlock, the result of init_lv includes a new offset where the lv
 * lease exists (on the leases lv).  The offset must be passed as lm_args
 * when acquiring the lv lease.
 *
 * lvcreate -n lv_name vg_name
 *
 * (equivalent: lvcreate --lock-type lm_type -n lv_name vg_name)
 *
 * Test:
 * lvmlock --lock-init lm_type --vg vg_name --lv lv_name
 *
 * init_vg foo
 * start_vg foo
 * lock_vg foo
 * lvcreate -n lvx foo
 * lvmlock --lock-init sanlock --vg foo --lv lvx
 * 5242880
 * unlock_vg foo
 *
 * lock_lv foo/lvx   [lvmlock --lock-lv ex --vg foo --lv lvx --lock-args 5242880 --persistent]
 * unlock_lv foo/lvx [lvmlock --lock-lv un --vg foo --lv lvx --persistent]
 *
 * TODO:
 * Create a non-clustered lv in a clustered vg:
 * lvcreate --lock-type none -n lv_name vg_name
 * Later clusterize the non-clustered lv within the clustered vg:
 * lvchange --lock-type lm_type -n lv_name vg_name
 *
 * ----
 *
 * TODO: remove vg or lv, the inverse of init_vg, init_lv
 *
 * free_vg: vgremove
 * free_lv: lvremove
 *
 * Test:
 * lvmlock --lock-del --vg vg_name
 * lvmlock --lock-del --vg vg_name --lv lv_name --lock-args lm_args
 *
 * ----
 *
 * start_vg vg_name lm_type lm_args host_id [vg_uuid]
 *
 * Start (join) the vg lockspace so it can be used for locking by
 * other commands.  lm_type must match what was used in init_vg.
 * For sanlock, lm_args must match what was used in init_vg.
 * For dlm, lm_args must be the cluster name that was found in init_vg.
 *
 * vgchange --lock-vg start vg_name
 * vgchange --lock-start               (scan and start all)
 *
 * The vgchange command reads the lm_type/lm_args from
 * the vg metadata, and the host_id from /etc/lvm/local_id.conf.
 *
 * The vg uuid is used to identify the vg in lvmetad when
 * the vg cache is invalidated.
 *
 * Test:
 * lvmlock --lock-vg start --vg vg_name --lock-type lm_type
 * 	   [--lock-args lm_args] [--vg-uuid uuid] [--host-id num] [--wait]
 *
 * init_vg foo
 * lvmlock --lock-vg start --vg foo --lock-type sanlock --lock-args /dev/foo/leases --host-id 1
 *
 * lock_vg foo   [lvmlock --lock-vg ex --vg foo]
 *
 * ----
 *
 * stop_vg
 *
 * Stop (leave) the vg lockspace, after which the lockspace cannot be used
 * by other commands.
 *
 * vgchange --lock-vg stop vg_name
 * vgchange --lock-stop               (stop all)
 *
 * Test:
 * lvmlock --lock-vg stop --vg vg_name [--force]
 * lvmlock --lock-stop [--force] [--wait]
 *
 * init_vg foo
 * start_vg foo
 * lvmlock --lock-vg stop --vg foo
 *
 * ----
 *
 * start_gl
 * stop_gl
 *
 * Explicitly start or stop the dlm global lockspace.
 * (Not applicable to sanlock lockspaces where the global
 * lockspace is one of the vg lockspaces.)
 *
 * This is not normaly used; the global lockspace is usually
 * started and stopped automatically by lvmlockd.
 *
 * No lvm client commands do this directly, only lvmlock.
 *
 * lvmlock --lock-gl start --lock-type dlm [--wait]
 * lvmlock --lock-gl stop [--force]
 *
 * ----
 *
 * enable_gl
 * disable_gl
 *
 * enable/disable sanlock gl lock in a vg
 *
 * lvmlock --lock-gl enable|disable --vg vg_name
 *
 * Enabling the gl lock in the first sanlock vg is done
 * automatically by init_vg, but in certain cases no vg
 * may exist with a gl enabled, in which case the gl
 * lock would need to be enabled explicitly in one of
 * the remaining vgs.
 *
 * In other cases, multiple vgs may have a gl enabled,
 * in which case the gl should be disabled in one of them.
 *
 * These special cases could be resolved automatically
 * eventually, but for now resolving them requires the
 * use of lvmlock.
 *
 * ----
 *
 * lock_gl mode opts
 *
 * Lock/unlock global lock.
 * gl lockspace must have already been started.
 *
 * Test:
 * lvmlock --lock-gl mode
 *
 * start_vg foo
 * lvmlock --lock-gl ex
 *
 * ----
 *
 * lock_vg mode opts vg_name
 *
 * Lock/unlock the vg lock.
 * vg lockspace must already have been started.
 *
 * Test:
 * lvmlock --lock-vg mode --vg vg_name
 *
 * start_vg foo
 * lvmlock --lock-vg ex --vg foo
 *
 * ----
 *
 * lock_lv mode opts vg_name lv_name lm_args
 *
 * Lock/unlock an lv lock.
 * vg lockspace must already have been started.
 *
 * lm_args is a string that was returned by init_lv
 * . For dlm, there are no lm_args.
 * . For sanlock, lm_args is an offset, and comes from per-lv lock_args
 *   in vg metadata.
 *
 * Test:
 * lvmlock --lock-lv mode --vg vg_name --lv lv_name --lock-args lm_args
 *
 * start_vg foo
 * init_lv foo lvx
 * lvmlock --lock-lv ex --vg foo --lv lvx --lock-args 5242880 --persistent
 * lvmlock --lock-lv un --vg foo --lv lvx --persistent
 *
 * ----
 *
 * vg_update vg_name version
 *
 * Update version of the vg lock.
 * Can only be done when the vg lock is held ex.
 * Is done when the vg metadata has changed, and is used by
 * other hosts to detect that they should invalidate their
 * cached vg metadata.
 * lvmlockd may wait until the vg lock is unlocked to propagate
 * this to the lock manager.
 *
 * Test:
 * lvmlock --lock-vg ex --vg vg_name --update
 *
 * ----
 *
 * persistent: use a persistent lock that is not owned by the requesting
 * command, and remains after the requesting command exits.  A lock that
 * is acquired with --persistent must also be released with --persistent.
 *
 * lvmlock --lock-vg ex --vg vg_name --persistent
 * lvmlock --lock-vg sh --vg vg_name --persistent
 * lvmlock --lock-vg un --vg vg_name --persistent
 *
 * lvchange -ay always uses persistent locks
 * vgchange --lock-vg ex|sh|un without other command option
 * uses persistent locks
 *
 */

#define _XOPEN_SOURCE 500  /* pthread */
#define _ISOC99_SOURCE

#include "configure.h"
#include "daemon-io.h"
#include "config-util.h"
#include "daemon-server.h"
#include "daemon-log.h"
#include "lvm-version.h"
#include "lvmetad-client.h"

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "linux-list.h"

#define EXTERN
#include "lvmlockd-internal.h"

static const char *lvmlockd_protocol = "lvmlockd";
static const int lvmlockd_protocol_version = 1;
static int daemon_quit;

static daemon_handle lvmetad_handle;
static int lvmetad_connected;

/*
 * Main program polls client connections, adds new clients,
 * adds work for client thread.
 *
 * pollfd_mutex is used for adding vs removing entries,
 * and for resume vs realloc.
 */
#define POLL_FD_UNUSED -1		/* slot if free */
#define POLL_FD_IGNORE -2		/* slot is used but ignore in poll */
#define ADD_POLL_SIZE 16		/* increment slots by this amount */

static pthread_mutex_t pollfd_mutex;
static struct pollfd *pollfd;
static int pollfd_size;
static int pollfd_maxi;
static int listen_pi;
static int listen_fd;
static int restart_pi;
static int restart_fds[2];

/*
 * Each lockspace has its own thread to do locking.
 */
static pthread_mutex_t lockspaces_mutex;
static struct list_head lockspaces;

/*
 * Client thread reads client requests and writes client results.
 */
static pthread_t client_thread;
static pthread_mutex_t client_mutex;
static pthread_cond_t client_cond;
static struct list_head client_list;    /* connected clients */
static struct list_head client_results; /* actions to send back to clients */
static uint32_t client_ids;
static int client_stop;                 /* stop the thread */
static int client_work;                 /* a client on client_list has work to do */

/*
 * Worker thread performs misc non-locking actions, e.g. init/free.
 */
static pthread_t worker_thread;
static pthread_mutex_t worker_mutex;
static pthread_cond_t worker_cond;
static struct list_head worker_list;    /* connected clients */
static int worker_stop;                 /* stop the thread */


static int add_pollfd(int fd)
{
	int i, new_size;

	pthread_mutex_lock(&pollfd_mutex);
	for (i = 0; i < pollfd_size; i++) {
		if (pollfd[i].fd != POLL_FD_UNUSED)
			continue;

		pollfd[i].fd = fd;
		pollfd[i].events = POLLIN;
		pollfd[i].revents = 0;

		if (i > pollfd_maxi)
			pollfd_maxi = i;

		pthread_mutex_unlock(&pollfd_mutex);
		return i;
	}

	new_size = pollfd_size + ADD_POLL_SIZE;

	pollfd = realloc(pollfd, new_size * sizeof(struct pollfd));
	if (!pollfd) {
		log_error("can't alloc new size %d for pollfd", new_size);
		return -ENOMEM;
	}

	for (i = pollfd_size; i < new_size; i++) {
		pollfd[i].fd = POLL_FD_UNUSED;
		pollfd[i].events = 0;
		pollfd[i].revents = 0;
	}

	i = pollfd_size;
	pollfd[i].fd = fd;
	pollfd[i].events = POLLIN;
	pollfd[i].revents = 0;
	pollfd_maxi = i;

	pollfd_size = new_size;

	pthread_mutex_unlock(&pollfd_mutex);
	return i;
}

static void rem_pollfd(int pi)
{
	if (pi < 0) {
		log_error("rem_pollfd %d", pi);
		return;
	}
	pthread_mutex_lock(&pollfd_mutex);
	pollfd[pi].fd = POLL_FD_UNUSED;
	pollfd[pi].events = 0;
	pollfd[pi].revents = 0;
	pthread_mutex_unlock(&pollfd_mutex);
}

/*
 * These are few enough that arrays of function pointers can
 * be avoided.
 */

static int lm_add_lockspace(struct lockspace *ls)
{
	if (ls->lm_type == LD_LM_DLM)
		return lm_add_lockspace_dlm(ls);
	else if (ls->lm_type == LD_LM_SANLOCK)
		return lm_add_lockspace_sanlock(ls);
	return -1;
}

static int lm_rem_lockspace(struct lockspace *ls)
{
	if (ls->lm_type == LD_LM_DLM)
		return lm_rem_lockspace_dlm(ls);
	else if (ls->lm_type == LD_LM_SANLOCK)
		return lm_rem_lockspace_sanlock(ls);
	return -1;
}

static int lm_lock(struct lockspace *ls, struct resource *r,
		   int mode, struct action *act, uint64_t *version)
{
	if (ls->lm_type == LD_LM_DLM)
		return lm_lock_dlm(ls, r, mode, version);
	else if (ls->lm_type == LD_LM_SANLOCK)
		return lm_lock_sanlock(ls, r, mode, act->lm_args, version);
	return -1;
}

static int lm_convert(struct lockspace *ls, struct resource *r,
		      int mode, struct action *act, uint64_t version)
{
	if (ls->lm_type == LD_LM_DLM)
		return lm_convert_dlm(ls, r, mode, version);
	else if (ls->lm_type == LD_LM_SANLOCK)
		return lm_convert_sanlock(ls, r, mode, version);
	return -1;
}

static int lm_unlock(struct lockspace *ls, struct resource *r,
		     struct action *act, uint64_t version)
{
	if (ls->lm_type == LD_LM_DLM)
		return lm_unlock_dlm(ls, r, version);
	else if (ls->lm_type == LD_LM_SANLOCK)
		return lm_unlock_sanlock(ls, r, version);
	return -1;
}

static void add_client_result(struct action *act)
{
	pthread_mutex_lock(&client_mutex);
	list_add_tail(&act->list, &client_results);
	pthread_cond_signal(&client_cond);
	pthread_mutex_unlock(&client_mutex);
}

static struct lock *find_lock_client(struct resource *r, uint32_t client_id)
{
	struct lock *lk;

	list_for_each_entry(lk, &r->locks, list) {
		if (lk->client_id == client_id)
			return lk;
	}
	return NULL;
}

static struct lock *find_lock_persistent(struct resource *r)
{
	struct lock *lk;

	list_for_each_entry(lk, &r->locks, list) {
		if (lk->flags & LD_LF_PERSISTENT)
			return lk;
	}
	return NULL;
}

static struct action *find_action_client(struct resource *r, uint32_t client_id)
{
	struct action *act;

	list_for_each_entry(act, &r->actions, list) {
		if (act->client_id != client_id)
			continue;
		return act;
	}
	return NULL;
}

static int res_lock(struct lockspace *ls, struct resource *r, struct action *act)
{
	struct lock *lk;
	uint64_t version;
	int rv;

	if (r->mode == LD_LK_SH && act->mode == LD_LK_SH)
		goto add_lk;

	rv = lm_lock(ls, r, act->mode, act, &version);
	if (rv < 0)
		return rv;

	/* sanity checks, remove */
	if ((r->mode == LD_LK_SH && act->mode != LD_LK_SH) ||
	    (r->mode == LD_LK_EX) || (r->mode != LD_LK_UN)) {
		log_error("lock contradictory modes");
		return -EINVAL;
	}

	if (!version || version > r->version) {

		/*
		 * New version of the lock: means that another
		 * host has changed data protected by this lock
		 * since the last time we acquired it.  We
		 * should invalidate any local cache of the data
		 * protected by this lock and reread it from disk.
		 *
		 * When version comes back as zero, then the lvb
		 * value is new (uninitialized) or the value has
		 * been lost.  In either case we don't know what
		 * state our cache is, so it should be refreshed.
		 */

		r->version = version;

		/*
		 * TODO: send invalidate to lvmetad here or elsewhere?
		 */

		/*
		 * r is vglk: lvmetad vg_remove, then lvmetad needs
		 * to return a specific ESTALE reply to lvm command
		 * that runs next vg_lookup on it, so the lvm command
		 * can reread the vg and refresh the lvmetad cache.
		 */

		if ((r->type == LD_RT_VG) && lvmetad_connected) {
			daemon_reply reply;
			char *uuid;

			if (!ls->vg_uuid[0] || !strcmp(ls->vg_uuid, "none"))
				uuid = ls->name;
			else
				uuid = ls->vg_uuid;

			reply = daemon_send_simple(lvmetad_handle,
						   "vg_remove",
						   "uuid = %s", uuid,
						   NULL);
			/* TODO: check reply? */
			daemon_reply_destroy(reply);
		}

		if ((r->type == LD_RT_GL) && lvmetad_connected) {
			/*
			 * TODO: probably need a new lvmetad cmd
			 * to invalidate vg_list, pv_list, ...
			 * any calls that could return invalid
			 * data due to gl version change.
			 */
		}
	}

	r->mode = act->mode;

add_lk:
	if (r->mode == LD_LK_SH)
		r->sh_count++;

	/* FIXME: take from list of unused lk structs */
	lk = malloc(sizeof(struct lock));
	if (!lk) {
		/* TODO */
	}

	lk->client_id = act->client_id;
	lk->mode = act->mode;

	if (act->flags & LD_AF_PERSISTENT) {
		lk->flags |= LD_LF_PERSISTENT;
		lk->client_id = 0;
	}

	list_add_tail(&lk->list, &r->locks);

	return 0;
}

static int res_convert(struct lockspace *ls, struct resource *r,
		       struct lock *lk, struct action *act)
{
	int rv;

	if (act->mode == LD_LK_EX && lk->mode == LD_LK_SH && r->sh_count > 1)
		return -EAGAIN;

	rv = lm_convert(ls, r, act->mode, act, lk->version);
	if (rv < 0)
		return rv;

	if (lk->mode == LD_LK_EX && act->mode == LD_LK_SH) {
		r->sh_count = 1;
	} else if (lk->mode == LD_LK_SH && act->mode == LD_LK_EX) {
		r->sh_count = 0;
	} else {
		/* should not be possible */
		log_error("res_convert invalid modes %d %d", lk->mode, act->mode);
		return -1;
	}

	r->mode = act->mode;
	lk->mode = act->mode;

	return 0;
}

static int res_cancel(struct lockspace *ls, struct resource *r,
		      struct action *act)
{
	struct action *cact;

	/*
	 * a client can cancel its own non-persistent lock requests,
	 * when could this happen?
	 *
	 * a client can cancel other client's persistent lock requests,
	 * when could this happen?
	 */

	if (act->flags & LD_AF_PERSISTENT) {
		list_for_each_entry(cact, &r->actions, list) {
			if (!(cact->flags & LD_AF_PERSISTENT))
				continue;
			goto do_cancel;
		}
	} else {
		cact = find_action_client(r, act->client_id);
		if (cact)
			goto do_cancel;
	}

	return -ENOENT;

do_cancel:
	cact->result = -ECANCELED;
	list_del(&cact->list);
	add_client_result(cact);

	return -ECANCELED;
}

/*
 * persistent locks will not be unlocked for OP_CLOSE/act_close
 * because act_close->flags does not have the PERSISTENT flag
 * set, and a persistent lk->client_id is zero, which will not
 * match the client in act_close->client_id.
 */

static int res_unlock(struct lockspace *ls, struct resource *r,
		      struct action *act)
{
	struct lock *lk;
	int rv;

	if (act->flags & LD_AF_PERSISTENT) {
		lk = find_lock_persistent(r);
		if (lk)
			goto do_unlock;
	} else {
		lk = find_lock_client(r, act->client_id);
		if (lk)
			goto do_unlock;
	}

	return -ENOENT;

do_unlock:
	/* send unlock to lm when last sh lock is unlocked */
	if (lk->mode == LD_LK_SH) {
		r->sh_count--;
		if (r->sh_count > 0)
			goto rem_lk;
	}

	rv = lm_unlock(ls, r, act, lk->version);
	if (rv < 0) {
		/* should never happen, retry? */
		log_error("unlock failed");
		return rv;
	}

	if (lk->version > r->version)
		r->version = lk->version;

rem_lk:
	list_del(&lk->list);
	free(lk);

	/*
	 * TODO: if unlock isn't synchronous, and next lock runs into
	 * it, what will the effect be?
	 */

	if (list_empty(&r->locks))
		r->mode = LD_LK_UN;

	return 0;
}

static int res_update(struct lockspace *ls, struct resource *r,
		      struct action *act)
{
	struct lock *lk;

	lk = find_lock_client(r, act->client_id);
	if (!lk)
		return -ENOENT;

	if (r->mode != LD_LK_EX) {
		log_error("update on non-ex lock");
		return -EINVAL;
	}

	/* lk version will be written to lm by unlock */

	/* TODO: try to write it to lm here in some cases?
	 * when a SYNC flag is set for update? */

	if (act->flags & LD_AF_NEXT_VERSION)
		lk->version = r->version + 1;
	else
		lk->version = act->version;

	return 0;
}

/*
 * NB. we can't do this if sanlock is holding any locks on
 * the resource; we'd be rewriting the resource from under
 * sanlock and would confuse or break it badly.  We don't
 * know what another host is doing, so these must be used
 * very carefully.
 */

static int res_able(struct lockspace *ls, struct resource *r,
		    struct action *act)
{
	int rv;

	if (ls->lm_type != LD_LM_SANLOCK) {
		/* TODO: any reason to allow this on dlm? */
		log_error("enable/disable only allowed on sanlock resources");
		return -EINVAL;
	}

	if (r->type != LD_RT_GL) {
		/* TODO: any reason to allow this on vg or lv? */
		log_error("enable/disable only allowed on gl");
		return -EINVAL;
	}

	if (r->mode != LD_LK_UN) {
		log_error("enable/disable only allowed on unlocked resource");
		return -EINVAL;
	}

	if (act->op == LD_OP_ENABLE && gl_lsname_sanlock[0]) {
		log_error("disable gl in %s before enable in %s",
			  gl_lsname_sanlock, ls->name);
		return -EINVAL;
	}

	if ((act->op == LD_OP_DISABLE) && (act->flags & LD_AF_EX_DISABLE)) {
		rv = lm_ex_disable_gl_sanlock(ls);
		goto out;
	}

	rv = lm_able_gl_sanlock(ls, act->op == LD_OP_ENABLE);
 out:
	return rv;
}

/*
 * Go through queued actions, and make lock/unlock calls on the resource
 * based on the actions and the existing lock state.
 *
 * All lock operations sent to the lock manager are non-blocking.
 * This is because sanlock does not support lock queueing.
 * Eventually we could enhance this to take advantage of lock
 * queueing when available (i.e. for the dlm).
 *
 * act_close_list: list of CLOSE actions, identifying clients that have
 * closed/terminated their lvmlockd connection, and whose locks should
 * be released.  Do not remove these actions from act_close_list.
 *
 * retry_out: set to 1 if the lock manager returned EAGAIN for any
 * lock ops, meaning we should call process_resource() again in a short
 * while to retry.
 */

static void process_resource(struct lockspace *ls, struct resource *r,
			     struct list_head *act_close_list,
			     int *retry_out)
{
	struct action *act, *safe, *act_close;
	struct lock *lk;
	int rv;

	/*
	 * handle version updates for ex locks
	 * (new version will be written by unlock)
	 */

	list_for_each_entry_safe(act, safe, &r->actions, list) {
		if (act->op == LD_OP_UPDATE) {
			rv = res_update(ls, r, act);
			act->result = rv;
			list_del(&act->list);
			add_client_result(act);
		}
	}

	/*
	 * handle explicit unlock actions
	 */

	list_for_each_entry_safe(act, safe, &r->actions, list) {
		if (act->op == LD_OP_LOCK && act->mode == LD_LK_UN) {
			rv = res_unlock(ls, r, act);

			if (rv == -ENOENT && (act->flags & LD_AF_UNLOCK_CANCEL))
				rv = res_cancel(ls, r, act);

			/*
			 * possible unlock results:
			 * 0: unlock succeeded
			 * -ECANCELED: cancel succeeded
			 * -ENOENT: nothing to unlock or cancel
			 */

			act->result = rv;
			list_del(&act->list);
			add_client_result(act);
		}
	}

	/*
	 * handle implicit unlocks due to client exit,
	 * also clear any outstanding actions for the client
	 */

	list_for_each_entry(act_close, act_close_list, list) {
		res_unlock(ls, r, act_close);
		res_cancel(ls, r, act_close);
	}

	/*
	 * handle enable/disable
	 */

	list_for_each_entry_safe(act, safe, &r->actions, list) {
		if (act->op == LD_OP_ENABLE || act->op == LD_OP_DISABLE) {
			rv = res_able(ls, r, act);
			act->result = rv;
			list_del(&act->list);
			add_client_result(act);
		}

		/* TODO: if disabled, cancel any queued lock actions */
	}

	/*
	 * transient requests on existing transient locks
	 */

	list_for_each_entry_safe(act, safe, &r->actions, list) {
		if (act->flags & LD_AF_PERSISTENT)
			continue;

		lk = find_lock_client(r, act->client_id);
		if (!lk)
			continue;

		if (lk->mode != act->mode) {
			/* convert below */
			/*
			act->result = -EEXIST;
			list_del(&act->list);
			add_client_result(act);
			*/
			continue;
		} else {
			/* success */
			act->result = -EALREADY;
			list_del(&act->list);
			add_client_result(act);
		}
	}

	/*
	 * persistent requests on existing persistent locks
	 *
	 * persistent locks are not owned by a client, so any
	 * existing with matching mode satisfies a request.
	 * only one persistent lock is kept on a resource.
	 * a single "unowned" persistent lock satisfies
	 * any/multiple client requests for a persistent lock.
	 */

	list_for_each_entry_safe(act, safe, &r->actions, list) {
		if (!(act->flags & LD_AF_PERSISTENT))
			continue;

		lk = find_lock_persistent(r);
		if (!lk)
			continue;

		if (lk->mode != act->mode) {
			/* convert below */
			/*
			act->result = -EEXIST;
			list_del(&act->list);
			add_client_result(act);
			*/
			continue;
		} else {
			/* success */
			act->result = -EALREADY;
			list_del(&act->list);
			add_client_result(act);
		}
	}

	/*
	 * transient requests with existing persistent locks
	 *
	 * Just grant the transient request and do not
	 * keep a record of it.  Assume that the persistent
	 * lock will not go away while the transient lock
	 * is needed.
	 *
	 * TODO: define exactly when this can be used,
	 * because there are a number of cases where it
	 * will not work: updating version number (lv
	 * locks have none), ex locks from multiple
	 * clients will not conflict, explicit un of the
	 * transient lock will fail.
	 * We may want to do this properly by tracking
	 * lock owners/conflicts for T locks under a P lock.
	 *
	 * This would be used when an ex, persistent lv lock
	 * exists from activation, and then something like
	 * lvextend asks for ex lock to change the lv.  The
	 * lv could not be unlocked by deactivation while
	 * the lvextend was running.
	 */

	list_for_each_entry_safe(act, safe, &r->actions, list) {
		if (act->flags & LD_AF_PERSISTENT)
			continue;

		lk = find_lock_persistent(r);
		if (!lk)
			continue;

		if ((lk->mode == LD_LK_EX) ||
		    (lk->mode == LD_LK_SH && act->mode == LD_LK_SH)) {
			act->result = 0;
			list_del(&act->list);
			add_client_result(act);
		} else {
			/* persistent lock is sh, transient request is ex */
			act->result = -EEXIST;
			list_del(&act->list);
			add_client_result(act);
		}
	}

	/*
	 * persistent requests with existing transient locks
	 *
	 * If a client requests a P lock for a T lock it already
	 * holds, we can just change T to P.  Fail if the same
	 * happens for locks from different clients.  Changing
	 * another client's lock from T to P may cause problems
	 * if that client tries to unlock or update version.
	 *
	 * This would be used in a case like vgchange --lock-vg ex vgname
	 * where a transient vg lock was acquired to read the vg,
	 * then the command wants to acquire a persistent lock.
	 * The command could instead unlock, then relock in the mode
	 * it wants, so this case may not be necessary.  Or, lvmlockd
	 * could itself attempt a lock conversion by unlock+relock.
	 */

	list_for_each_entry_safe(act, safe, &r->actions, list) {
		if (!(act->flags & LD_AF_PERSISTENT))
			continue;

		lk = find_lock_client(r, act->client_id);
		if (!lk)
			continue;

		if (lk->mode != act->mode) {
			act->result = -EEXIST;
			list_del(&act->list);
			add_client_result(act);
		} else {
			lk->flags |= LD_LF_PERSISTENT;
			lk->client_id = 0;
			act->result = 0;
			list_del(&act->list);
			add_client_result(act);
		}
	}

	/*
	 * convert mode of existing locks
	 */

	list_for_each_entry_safe(act, safe, &r->actions, list) {
		if (act->flags & LD_AF_PERSISTENT)
			lk = find_lock_persistent(r);
		else
			lk = find_lock_client(r, act->client_id);
		if (!lk)
			continue;

		if (lk->mode == act->mode) {
			/* should never happen, should be found above */
			log_error("convert same mode");
			continue;
		}

		/* convert fails immediately, no EAGAIN retry */
		rv = res_convert(ls, r, lk, act);
		act->result = rv;
		list_del(&act->list);
		add_client_result(act);
	}

	/*
	 * Cases above are all requests addressed by existing locks.
	 * Below handle the rest.  Transient and persistent are
	 * handled the same, except
	 * - if mode of existing lock is incompat with requested,
	 *   leave the act on r->actions
	 * - if r mode is EX, any lock action is blocked, just quit
	 */

	if (r->mode == LD_LK_EX)
		return;

	/*
	 * r mode is SH or UN, pass lock-sh actions to lm
	 */

	list_for_each_entry_safe(act, safe, &r->actions, list) {
		/* grant in order, so break here */
		if (act->op == LD_OP_LOCK && act->mode == LD_LK_EX)
			break;
		if (act->op == LD_OP_LOCK && act->mode == LD_LK_SH) {
			rv = res_lock(ls, r, act);
			if (rv == -EAGAIN && act->retries++ < 3) {
				/* leave act on list */
				*retry_out = 1;
			} else {
				act->result = rv;
				list_del(&act->list);
				add_client_result(act);
			}
		}
	}

	/*
	 * r mode is SH, any ex lock action is blocked, just quit
	 */

	if (r->mode == LD_LK_SH)
		return;

	/*
	 * r mode is UN, pass lock-ex action to lm
	 */

	list_for_each_entry_safe(act, safe, &r->actions, list) {
		if (act->op == LD_OP_LOCK && act->mode == LD_LK_EX) {
			rv = res_lock(ls, r, act);
			if (rv == -EAGAIN && act->retries++ < 3) {
				/* leave act on list */
				*retry_out = 1;
			} else {
				act->result = rv;
				list_del(&act->list);
				add_client_result(act);
			}
			break;
		}
	}
}

#define LOCKS_EXIST 1
#define LOCKS_COUNT 2
#define LOCKS_CLEAR 3

static int for_each_lock(struct lockspace *ls, int locks_do)
{
	struct resource *r, *r_safe;
	struct lock *lk, *lk_safe;
	struct action *act, *act_safe;
	uint64_t version;
	int lk_count = 0;
	int rv;

	list_for_each_entry_safe(r, r_safe, &ls->resources, list) {
		version = 0;
		list_for_each_entry_safe(lk, lk_safe, &r->locks, list) {

			lk_count++;

			if (locks_do == LOCKS_EXIST)
				return 1;

			if (locks_do == LOCKS_COUNT)
				continue;

			if (lk->flags & LD_LF_PERSISTENT)
				log_error("drop %s lock", r->name);
			else
				log_error("drop %s lock from client %d",
					  r->name, lk->client_id);

			if (lk->version > version)
				version = lk->version;
			list_del(&lk->list);
			free(lk);
		}

		if (locks_do == LOCKS_COUNT)
			continue;

		if (r->mode == LD_LK_UN)
			continue;

		rv = lm_unlock(ls, r, NULL, version);
		if (rv < 0) {
			log_error("unlock error %d", rv);
		}

		list_for_each_entry_safe(act, act_safe, &r->actions, list) {
			act->result = -ECANCELED;
			list_del(&act->list);
			add_client_result(act);
		}

		list_del(&r->list);
		free(r);
	}

	return lk_count;
}

/*
 * find and return the resource that is referenced by the action
 * - there is a single gl resource per lockspace
 * - there is a single vg resource per lockspace
 * - there can be many lv resources per lockspace, compare names
 */

static struct resource *find_resource_act(struct lockspace *ls,
					  struct action *act)
{
	struct resource *r;

	list_for_each_entry(r, &ls->resources, list) {
		if (r->type != act->rt)
			continue;

		if (r->type == LD_RT_GL && act->rt == LD_RT_GL)
			return r;

		if (r->type == LD_RT_VG && act->rt == LD_RT_VG)
			return r;

		if (r->type == LD_RT_LV && act->rt == LD_RT_LV &&
		    !strcmp(r->name, act->lv_name))
			return r;
	}

	r = malloc(sizeof(struct resource));
	if (!r)
		return NULL;

	memset(r, 0, sizeof(struct resource));

	r->type = act->rt;

	r->mode = LD_LK_UN;

	if (r->type == LD_RT_GL)
		strncpy(r->name, R_NAME_GL, MAX_NAME);
	else if (r->type == LD_RT_VG)
		strncpy(r->name, R_NAME_VG, MAX_NAME);
	else if (r->type == LD_RT_LV)
		strncpy(r->name, act->lv_name, MAX_NAME);

	INIT_LIST_HEAD(&r->locks);
	INIT_LIST_HEAD(&r->actions);

	list_add_tail(&r->list, &ls->resources);

	return r;
}

/*
 * TODO: we could possibly request the full vg metadata,
 * go through all lv's and prepare lv resources, with
 * lock_args, for any lv with lock_type.
 *
 * We may be able to stipulate certain usage that would
 * make this unnecessary.
 */

#if 0
/* ask lvmetad for lock_type/lock_args for this vg */
static int get_vg_lm_info(struct lockspace *ls)
{
	daemon_reply reply;
	const char *lock_type, *lock_args;
	int rv;

	reply = daemon_send_simple(lvmetad_handle,
				   "vg_lock_info",
				   "name = %s", ls->name);

	lock_type = daemon_reply_str(reply, "lock_type", NULL);
	if (!lock_type) {
		rv = -EINVAL;
		goto out;
	}

	if (strcmp(lock_type, "dlm"))
		ls->lm_type = LD_LM_DLM;
	else if (strcmp(lock_type, "sanlock"))
		ls->lm_type = LD_LM_SANLOCK;
	else {
		rv = -EINVAL;
		goto out;
	}

	lock_args = daemon_reply_str(reply, "lock_args", NULL);
	if (lock_args)
		strncpy(ls->lm_args, lock_args, MAX_ARGS);
	rv = 0;

out:
	daemon_reply_destroy(reply);
	return rv;
}
#endif

/*
 * Process actions queued for this lockspace by
 * client_recv_action / add_lock_action.
 *
 * The lockspace_thread can touch its own ls struct without holding
 * lockspaces_mutex until it sets ls->thread_done, after which it
 * cannot touch ls without holding lockspaces_mutex.
 */

static void *lockspace_thread_main(void *arg_in)
{
	struct lockspace *ls = arg_in;
	struct resource *r;
	struct action *add_act, *act, *safe;
	struct list_head tmp_act;
	struct list_head act_close;
	int error = 0;
	int retry;
	int rv;

	INIT_LIST_HEAD(&act_close);

	if (!ls->lm_type) {
		/*
		 * start_vg did not provide lock_type/lock_args,
		 * so try to get it ourself from lvmetad?
		 * TODO: is this necessary?
		 * error = get_vg_lm_info(ls);
		 */
		return NULL;
	}

	/* first action is client add (which may not exist) */
	pthread_mutex_lock(&ls->mutex);
	add_act = NULL;
	if (!list_empty(&ls->actions)) {
		add_act = list_first_entry(&ls->actions, struct action, list);
		list_del(&add_act->list);
	}
	pthread_mutex_unlock(&ls->mutex);

	if (add_act && !(add_act->flags & LD_AF_WAIT)) {
		/* send partial join result back to client */
		add_act->result = 0;
		pthread_mutex_lock(&client_mutex);
		list_add_tail(&add_act->list, &client_results);
		pthread_cond_signal(&client_cond);
		pthread_mutex_unlock(&client_mutex);
		add_act = NULL;
	}

	/* the lm join can take a while */

	error = lm_add_lockspace(ls);

	if (add_act) {
		/* send synchronous join result back to client */
		add_act->result = error;
		pthread_mutex_lock(&client_mutex);
		list_add_tail(&add_act->list, &client_results);
		pthread_cond_signal(&client_cond);
		pthread_mutex_unlock(&client_mutex);
	}

	pthread_mutex_lock(&ls->mutex);
	if (error) {
		ls->thread_stop = 1;
		ls->create_fail = 1;
	} else {
		ls->create_done = 1;
	}
	pthread_mutex_unlock(&ls->mutex);

	if (error)
		goto out_act;

	while (1) {
		pthread_mutex_lock(&ls->mutex);
		while (!ls->thread_work) {
			if (ls->thread_stop) {
				pthread_mutex_unlock(&ls->mutex);
				goto out_rem;
			}
			pthread_cond_wait(&ls->cond, &ls->mutex);
		}

		/* client thread queues actions on ls->actions, we move
		   ls->actions to r->actions, then process the resources */

		while (1) {
			if (list_empty(&ls->actions)) {
				ls->thread_work = 0;
				break;
			}

			act = list_first_entry(&ls->actions, struct action, list);

			if (act->op == LD_OP_STOP) {
				ls->thread_work = 0;
				break;
			}

			list_del(&act->list);

			/* applies to all resources */
			if (act->op == LD_OP_CLOSE) {
				list_add(&act->list, &act_close);
				continue;
			}

			/*
			 * Find the specific resource this action refers to;
			 * creates resource if not found.
			 */

			r = find_resource_act(ls, act);
			if (!r) {
				act->result = -ENOMEM;
				add_client_result(act);
				continue;
			}

			list_add_tail(&act->list, &r->actions);
		}
		pthread_mutex_unlock(&ls->mutex);

		retry = 0;

		list_for_each_entry(r, &ls->resources, list)
			process_resource(ls, r, &act_close, &retry);

		list_for_each_entry_safe(act, safe, &act_close, list) {
			list_del(&act->list);
			free(act);
		}

		if (retry) {
			ls->thread_work = 1;
			usleep(1000000);
		}
	}

out_rem:

	/*
	 * For sanlock, we need to unlock any existing locks
	 * before removing the lockspace, otherwise the sanlock
	 * daemon will kill us when the lockspace goes away.
	 * For dlm, we leave with force, so all locks will
	 * automatically be dropped when we leave the lockspace,
	 * so unlocking all before leaving could be skipped.
	 *
	 * Blindly dropping all existing locks must only be
	 * allowed in emergency/force situations, otherwise it's
	 * obviously dangerous, since the lock holders are still
	 * operating under the assumption that they hold the lock.
	 */

	rv = for_each_lock(ls, LOCKS_CLEAR);
	if (rv)
		log_error("rem_lockspace cleared %d locks", rv);

	lm_rem_lockspace(ls);

out_act:
	/*
	 * Move remaining actions to results; this will usually (always?)
	 * be only the stop action.
	 */
	INIT_LIST_HEAD(&tmp_act);

	pthread_mutex_lock(&ls->mutex);
	list_for_each_entry_safe(act, safe, &ls->actions, list) {
		if (act->op == LD_OP_STOP)
			act->result = 0;
		else
			act->result = -ENOENT;
		list_del(&act->list);
		list_add_tail(&act->list, &tmp_act);
	}
	pthread_mutex_unlock(&ls->mutex);

	pthread_mutex_lock(&client_mutex);
	list_for_each_entry_safe(act, safe, &tmp_act, list) {
		list_del(&act->list);
		list_add_tail(&act->list, &client_results);
	}
	pthread_cond_signal(&client_cond);
	pthread_mutex_unlock(&client_mutex);

	pthread_mutex_lock(&lockspaces_mutex);
	ls->thread_done = 1;
	pthread_mutex_unlock(&lockspaces_mutex);
	return NULL;
}

int lockspaces_empty(void)
{
	int rv;
	pthread_mutex_lock(&lockspaces_mutex);
	rv = list_empty(&lockspaces);
	pthread_mutex_unlock(&lockspaces_mutex);
	return rv;
}

/* lockspaces_mutex is locked */
static struct lockspace *find_lockspace_name(char *ls_name)
{
	struct lockspace *ls;

	list_for_each_entry(ls, &lockspaces, list) {
		if (!strcmp(ls->name, ls_name))
			return ls;
	}
	return NULL;
}

/* TODO: handle lvm_<vg_name> longer than max lockspace name?  Use vg uuid? */

static int vg_ls_name(char *vg_name, char *ls_name)
{
	if (strlen(vg_name) + 4 > MAX_NAME) {
		log_error("vg name too long %s", vg_name);
		return -1;
	}

	snprintf(ls_name, MAX_NAME, "lvm_%s", vg_name);
	return 0;
}

/*
 * When this function returns an error, the caller needs to deal
 * with act (in the cases where act exists).
 */

static int add_lockspace_thread(char *ls_name, char *vg_uuid,
				int lm_type, char *lm_args,
				uint64_t host_id, struct action *act)
{
	struct lockspace *ls, *ls2;
	int rv;

	log_debug("add_lockspace_thread type %d %s", lm_type, ls_name);

	ls = malloc(sizeof(struct lockspace));
	if (!ls)
		return -ENOMEM;

	memset(ls, 0, sizeof(struct lockspace));

	strncpy(ls->name, ls_name, MAX_NAME);
	ls->lm_type = lm_type;

	if (vg_uuid)
		strncpy(ls->vg_uuid, vg_uuid, 64);

	if (lm_args)
		strncpy(ls->lm_args, lm_args, MAX_ARGS);

	ls->host_id = host_id;
	pthread_mutex_init(&ls->mutex, NULL);
	pthread_cond_init(&ls->cond, NULL);
	INIT_LIST_HEAD(&ls->actions);
	INIT_LIST_HEAD(&ls->resources);

	pthread_mutex_lock(&lockspaces_mutex);
	ls2 = find_lockspace_name(ls->name);
	if (ls2) {
		if (ls2->thread_stop)
			rv = -EAGAIN;
		else
			rv = -EEXIST;
		pthread_mutex_unlock(&lockspaces_mutex);
		free(ls);
		return rv;
	}

	/*
	 * act will be null when this lockspace is added automatically/internally
	 * and not by an explicit client action that wants a result.
	 */
	if (act)
		list_add(&act->list, &ls->actions);

	list_add_tail(&ls->list, &lockspaces);
	pthread_mutex_unlock(&lockspaces_mutex);

	rv = pthread_create(&ls->thread, NULL, lockspace_thread_main, ls);
	if (rv < 0) {
		pthread_mutex_lock(&lockspaces_mutex);
		list_del(&ls->list);
		pthread_mutex_unlock(&lockspaces_mutex);
		free(ls);
		return rv;
	}

	return 0;
}

/*
 * There is no add_sanlock_global_lockspace or
 * rem_sanlock_global_lockspace because with sanlock,
 * the global lockspace is one of the vg lockspaces.
 */

static int add_dlm_global_lockspace(struct action *act)
{
	int rv;

	if (gl_running_dlm)
		return -EEXIST;

	gl_running_dlm = 1;

	/* Keep track of whether we automatically added
	   the global ls, so we know to automatically
	   remove it. */

	if (act)
		gl_auto_dlm = 0;
	else
		gl_auto_dlm = 1;

	/*
	 * There's a short period after which a previous gl lockspace thread
	 * has set gl_running_dlm = 0, but before its ls struct has been
	 * deleted, during which this add_lockspace_thread() can fail with
	 * -EAGAIN.
	 */

	rv = add_lockspace_thread(gl_lsname_dlm, NULL, LD_LM_DLM, NULL, 0, act);

	if (rv < 0) {
		gl_running_dlm = 0;
		gl_auto_dlm = 0;
	}

	return rv;
}

/*
 * If dlm gl lockspace is the only one left, then stop it.
 * This is not used for an explicit rem_lockspace action from
 * the client, only for auto remove.
 */

static int rem_dlm_global_lockspace(void)
{
	struct lockspace *ls, *ls_gl;
	int others = 0;
	int rv = 0;

	pthread_mutex_lock(&lockspaces_mutex);
	list_for_each_entry(ls, &lockspaces, list) {
		if (!strcmp(ls->name, gl_lsname_dlm)) {
			ls_gl = ls;
			continue;
		}
		if (ls->thread_stop)
			continue;
		others++;
		break;
	}

	if (others) {
		rv = -EAGAIN;
		goto out;
	}

	if (!ls_gl) {
		rv = -ENOENT;
		goto out;
	}

	ls = ls_gl;
	pthread_mutex_lock(&ls->mutex);
	if (for_each_lock(ls, LOCKS_EXIST)) {
		rv = -EBUSY;
	} else {
		ls->thread_stop = 1;
		ls->thread_work = 1;
		pthread_cond_signal(&ls->cond);
		rv = 0;
	}
	pthread_mutex_unlock(&ls->mutex);
out:
	pthread_mutex_unlock(&lockspaces_mutex);
	return rv;
}

/*
 * When the first dlm lockspace is added for a vg,
 * automatically add a separate dlm lockspace for the
 * global lock if it hasn't been done explicitly.
 * This is to make the dlm global lockspace work similarly to
 * the sanlock global lockspace, which is "automatic" by
 * nature of being one of the vg lockspaces.
 *
 * For sanlock, a separate lockspace is not used for
 * the global lock, but the gl lock lives in a vg
 * lockspace, (although it's recommended to create a
 * special vg dedicated to holding the gl).
 *
 * N.B. for dlm, if this is an add+WAIT action for a vg
 * lockspace, and this triggered the automatic addition
 * of the global lockspace, then the action may complete
 * for the vg ls add, while the gl ls add is still in
 * progress.  If the caller wants to ensure that the
 * gl ls add is complete, they should explicitly add+WAIT
 * the gl ls.
 *
 * If this function returns and error, the caller
 * will queue the act with that error for the client.
 */

static int add_lockspace(struct action *act, uint64_t host_id)
{
	char ls_name[MAX_NAME+1];
	int rv;

	memset(ls_name, 0, sizeof(ls_name));

	if (act->rt == LD_RT_GL) {
		if (gl_use_dlm) {
			rv = add_dlm_global_lockspace(act);
			return rv;
		} else {
			return -EINVAL;
		}
	}

	if (act->rt == LD_RT_VG) {
		if (gl_use_dlm) {
			rv = add_dlm_global_lockspace(NULL);
			if (rv < 0 && rv != -EEXIST)
				return rv;
		}

		rv = vg_ls_name(act->vg_name, ls_name);
		if (rv < 0) {
			return rv;
		}

		rv = add_lockspace_thread(ls_name, act->vg_uuid,
					  act->lm_type, act->lm_args,
					  host_id, act);

		return rv;
	}

	log_error("add_lockspace bad type %d", act->rt);
	return -1;
}

static int rem_lockspace(struct action *act)
{
	struct lockspace *ls;
	char ls_name[MAX_NAME+1];
	int force = act->flags & LD_AF_FORCE;
	int rt = act->rt;
	int rv;

	memset(ls_name, 0, sizeof(ls_name));

	if (act->rt == LD_RT_GL) {
		if (act->lm_type == LD_LM_DLM) {
			strcpy(ls_name, gl_lsname_dlm);
		} else {
			return -EINVAL;
		}
	}

	if (act->rt == LD_RT_VG) {
		rv = vg_ls_name(act->vg_name, ls_name);
		if (rv < 0)
			return rv;
	}

	/* TODO: if this lockspace contains the gl, and other
	   lockspaces exist, then report error and require force? */

	pthread_mutex_lock(&lockspaces_mutex);
	ls = find_lockspace_name(ls_name);

	if (!ls) {
		pthread_mutex_unlock(&lockspaces_mutex);
		return -ENOENT;
	}

	pthread_mutex_lock(&ls->mutex);
	if (ls->thread_stop) {
		pthread_mutex_unlock(&ls->mutex);
		pthread_mutex_unlock(&lockspaces_mutex);
		return -ESTALE;
	}

	if (!force && for_each_lock(ls, LOCKS_EXIST)) {
		pthread_mutex_unlock(&ls->mutex);
		pthread_mutex_unlock(&lockspaces_mutex);
		return -EBUSY;
	}
	ls->thread_work = 1;
	ls->thread_stop = 1;
	if (act)
		list_add_tail(&act->list, &ls->actions);
	pthread_cond_signal(&ls->cond);
	pthread_mutex_unlock(&ls->mutex);
	pthread_mutex_unlock(&lockspaces_mutex);

	/*
	 * If the dlm global lockspace was automatically added when
	 * the first dlm vg lockspace was added, then reverse that
	 * by automatically removing the dlm global lockspace when
	 * the last dlm vg lockspace is removed.
	 */

	if (rt == LD_RT_VG && gl_use_dlm && gl_auto_dlm)
		rem_dlm_global_lockspace();

	return 0;
}

static void free_lockspaces(int wait)
{
	struct lockspace *ls, *safe;
	int done, stop, busy;

 retry:
	busy = 0;

	pthread_mutex_lock(&lockspaces_mutex);
	list_for_each_entry_safe(ls, safe, &lockspaces, list) {

		pthread_mutex_lock(&ls->mutex);
		done = ls->thread_done;
		stop = ls->thread_stop;

		if (wait && !stop) {
			/* this shouldn't happen */
			log_error("free wait no stop");
			ls->thread_stop = 1;
			ls->thread_work = 1;
		}
		pthread_mutex_unlock(&ls->mutex);

		/*
		 * Once thread_done is set, we know that the lockspace_thread
		 * will not be using/touching the ls struct.  Any other
		 * thread touches the ls struct under lockspaces_mutex.
		 */

		if (done) {
			pthread_join(ls->thread, NULL);
			list_del(&ls->list);

			/* TODO: free anything on actions or resources lists */

			free(ls);
		} else {
			busy++;
		}
	}
	pthread_mutex_unlock(&lockspaces_mutex);

	/* FIXME: this should be better, and limit retries */
	if (wait && busy) {
		sleep(1);
		goto retry;
	}
}

static int stop_lockspaces(int force, int wait)
{
	struct lockspace *ls;
	int done = 0;
	int rv = 0;

	pthread_mutex_lock(&lockspaces_mutex);
	list_for_each_entry(ls, &lockspaces, list) {
		pthread_mutex_lock(&ls->mutex);
		if (!force && for_each_lock(ls, LOCKS_EXIST)) {
			rv = -EBUSY;
		} else {
			ls->thread_work = 1;
			ls->thread_stop = 1;
			pthread_cond_signal(&ls->cond);
		}
		pthread_mutex_unlock(&ls->mutex);
	}
	pthread_mutex_unlock(&lockspaces_mutex);

	if (rv || !wait)
		return rv;

	/* FIXME: this should be better, and limit retries */
	while (!done) {
		pthread_mutex_lock(&lockspaces_mutex);
		if (list_empty(&lockspaces))
			done = 1;
		pthread_mutex_unlock(&lockspaces_mutex);
		if (!done)
			sleep(1);
	}

	return 0;
}

static int init_vg(struct action *act)
{
	char ls_name[MAX_NAME+1];
	int rv = 0;

	memset(ls_name, 0, sizeof(ls_name));

	rv = vg_ls_name(act->vg_name, ls_name);
	if (rv < 0)
		return rv;

	if (act->lm_type == LD_LM_SANLOCK)
		rv = lm_init_vg_sanlock(ls_name, act->flags, act->lm_args);
	else if (act->lm_type == LD_LM_DLM)
		rv = lm_init_vg_dlm(ls_name, act->flags, act->lm_args);
	else
		rv = -EINVAL;

	if (!rv) {
		act->result = 0;
		add_client_result(act);
	}

	return rv;
}

static int init_lv(struct action *act)
{
	struct lockspace *ls;
	char ls_name[MAX_NAME+1];
	char ls_lm_args[MAX_ARGS];
	char res_lm_args[MAX_ARGS];
	int lm_type = 0;
	int rv = 0;

	memset(ls_name, 0, sizeof(ls_name));
	memset(ls_lm_args, 0, MAX_ARGS);
	memset(res_lm_args, 0, MAX_ARGS);

	rv = vg_ls_name(act->vg_name, ls_name);
	if (rv < 0)
		return rv;

	pthread_mutex_lock(&lockspaces_mutex);
	ls = find_lockspace_name(ls_name);
	if (ls) {
		lm_type = ls->lm_type;
		memcpy(ls_lm_args, ls->lm_args, MAX_ARGS);
	}
	pthread_mutex_unlock(&lockspaces_mutex);

	if (!lm_type) {
		log_error("init_lv ls_name %s no ls lm_type", ls_name);
		return -EINVAL;
	}

	if (act->lm_type != lm_type) {
		log_error("init_lv ls_name %s wrong lm_type %d %d",
			  ls_name, act->lm_type, lm_type);
		return -EINVAL;
	}

	if (lm_type == LD_LM_SANLOCK) {
		rv = lm_init_lv_sanlock(ls_name, act->lv_name,
					ls_lm_args, res_lm_args);

		act->result = rv;
		memcpy(act->lm_args, res_lm_args, MAX_ARGS);
		add_client_result(act);
		return 0;

	} else if (act->lm_type == LD_LM_DLM) {
		act->result = 0;
		add_client_result(act);
		return 0;
	}

	return -EINVAL;
}

static void *worker_thread_main(void *arg_in)
{
	struct action *act;
	int rv;

	while (1) {
		pthread_mutex_lock(&worker_mutex);
		while (list_empty(&worker_list)) {
			if (worker_stop) {
				pthread_mutex_unlock(&worker_mutex);
				goto out;
			}
			pthread_cond_wait(&worker_cond, &worker_mutex);
		}

		act = list_first_entry(&worker_list, struct action, list);
		list_del(&act->list);
		pthread_mutex_unlock(&worker_mutex);

		switch (act->op) {
		case LD_OP_INIT:
			if (act->rt == LD_RT_VG)
				rv = init_vg(act);
			else if (act->rt == LD_RT_LV)
				rv = init_lv(act);
			else
				rv = -EINVAL;
			break;

		case LD_OP_STOP_ALL:
			rv = stop_lockspaces((act->flags & LD_AF_FORCE) ? FORCE : NO_FORCE,
					     (act->flags & LD_AF_WAIT)  ? WAIT  : NO_WAIT);
			act->result = rv;
			add_client_result(act);
			break;
		default:
			rv = -EINVAL;
			break;
		};

		if (rv < 0) {
			act->result = rv;
			add_client_result(act);
		}
	}
out:
	return NULL;
}

static int setup_worker_thread(void)
{
	int rv;

	INIT_LIST_HEAD(&worker_list);

	pthread_mutex_init(&worker_mutex, NULL);
	pthread_cond_init(&worker_cond, NULL);

	rv = pthread_create(&worker_thread, NULL, worker_thread_main, NULL);
	if (rv)
		return -1;
	return 0;
}

static void close_worker_thread(void)
{
	pthread_mutex_lock(&worker_mutex);
	worker_stop = 1;
	pthread_cond_signal(&worker_cond);
	pthread_mutex_unlock(&worker_mutex);
	pthread_join(worker_thread, NULL);
}

/* client_mutex is locked */
static struct client *find_client_work(void)
{
	struct client *cl;

	list_for_each_entry(cl, &client_list, list) {
		if (cl->recv || cl->dead)
			return cl;
	}
	return NULL;
}

/* client_mutex is locked */
static struct client *find_client_id(uint32_t id)
{
	struct client *cl;

	list_for_each_entry(cl, &client_list, list) {
		if (cl->id == id)
			return cl;
	}
	return NULL;
}

/* client_mutex is locked */
static struct client *find_client_pi(int pi)
{
	struct client *cl;

	list_for_each_entry(cl, &client_list, list) {
		if (cl->pi == pi)
			return cl;
	}
	return NULL;
}

/*
 * wake up poll() because we have added an fd
 * back into pollfd and poll() needs to be restarted
 * to recognize it.
 */
static void restart_poll(void)
{
	write(restart_fds[1], "w", 1);
}

/* poll will take requests from client again, cl->mutex must be held */
static void client_resume(struct client *cl)
{
	if (cl->dead)
		return;

	if (!cl->poll_ignore || cl->fd == -1 || cl->pi == -1) {
		/* shouldn't happen */
		log_error("client_resume %d bad state ig %d fd %d pi %d",
			  cl->id, cl->poll_ignore, cl->fd, cl->pi);
		return;
	}

	pthread_mutex_lock(&pollfd_mutex);
	if (pollfd[cl->pi].fd != POLL_FD_IGNORE) {
		log_error("client_resume %d pi %d fd %d not IGNORE",
			  cl->id, cl->pi, cl->fd);
	}
	pollfd[cl->pi].fd = cl->fd;
	pollfd[cl->pi].events = POLLIN;
	pthread_mutex_unlock(&pollfd_mutex);

	restart_poll();
}

/* called from client_thread, cl->mutex is held */
static void client_send_result(struct client *cl, struct action *act)
{
	response res;

	if (cl->dead) {
		log_debug("client send %d skip dead", cl->id);
		return;
	}

	/* TODO: possibly send back the number of retries? */

	buffer_init(&res.buffer);

	if (act->op == LD_OP_INIT) {
		char *lm_args;

		if (!act->lm_args[0])
			lm_args = "none";
		else
			lm_args = act->lm_args;

		res = daemon_reply_simple("OK",
					  "op = %d", act->op,
					  "op_result = %d", act->result,
					  "lock_args = %s", lm_args,
					  NULL);
	} else {
		res = daemon_reply_simple("OK",
					  "op = %d", act->op,
					  "op_result = %d", act->result,
					  NULL);
	}
	buffer_write(cl->fd, &res.buffer);
	buffer_destroy(&res.buffer);

	client_resume(cl);
}

/*
 * TODO: optimize common case where a client has only locked
 * a couple of lockspaces.  Keep two lockspace ids in cl->ls_ids
 * and queue OP_CLOSE in only these lockspaces.  If more than two
 * are used, then clear ls_ids and queue for all.
 */

/* called from client_thread */
static void client_purge(uint32_t client_id)
{
	struct lockspace *ls;
	struct action *act;

	pthread_mutex_lock(&lockspaces_mutex);
	list_for_each_entry(ls, &lockspaces, list) {

		/* TODO: take from list of unused action structs */
		act = malloc(sizeof(struct action));
		if (!act) {
			continue;
		}
		memset(act, 0, sizeof(struct action));

		act->op = LD_OP_CLOSE;
		act->client_id = client_id;
		act->flags |= LD_AF_CLIENT_DEAD;

		pthread_mutex_lock(&ls->mutex);
		if (!ls->thread_stop) {
			list_add_tail(&act->list, &ls->actions);
			ls->thread_work = 1;
			pthread_cond_signal(&ls->cond);
		} else {
			free(act);
		}
		pthread_mutex_unlock(&ls->mutex);
	}
	pthread_mutex_unlock(&lockspaces_mutex);
}

static int add_lock_action(struct action *act)
{
	struct lockspace *ls;
	char ls_name[MAX_NAME+1];
	int rv;

	memset(ls_name, 0, sizeof(ls_name));

	/* Determine which lockspace this action is for, and set ls_name. */

	if (act->rt == LD_RT_GL && act->op == LD_OP_ENABLE && gl_use_sanlock) {
		vg_ls_name(act->vg_name, ls_name);

	} else if (act->rt == LD_RT_GL) {
		memset(ls_name, 0, sizeof(ls_name));

		if (gl_use_dlm)
			memcpy(ls_name, gl_lsname_dlm, MAX_NAME);
		else if (gl_use_sanlock)
			memcpy(ls_name, gl_lsname_sanlock, MAX_NAME);

		if (!ls_name[0]) {
			log_error("global lockspace not set");
			return -1;
		}
	} else {
		rv = vg_ls_name(act->vg_name, ls_name);
		if (rv < 0)
			return rv;
	}

	pthread_mutex_lock(&lockspaces_mutex);
	ls = find_lockspace_name(ls_name);

	if (!ls) {
		pthread_mutex_unlock(&lockspaces_mutex);
		/* TODO: should we do an implicit ls start if we get a lock op? */
		log_error("lockspace not found %s", ls_name);
		return -ENOENT;
	}

	pthread_mutex_lock(&ls->mutex);
	if (ls->thread_stop) {
		pthread_mutex_unlock(&ls->mutex);
		pthread_mutex_unlock(&lockspaces_mutex);
		log_error("lockspace is stopping %s", ls_name);
		return -ESTALE;
	}

	list_add_tail(&act->list, &ls->actions);
	ls->thread_work = 1;
	pthread_cond_signal(&ls->cond);
	pthread_mutex_unlock(&ls->mutex);
	pthread_mutex_unlock(&lockspaces_mutex);

	/* lockspace_thread_main / process_resource take it from here */

	return 0;
}

static void add_work_action(struct action *act)
{
	pthread_mutex_lock(&worker_mutex);
	list_add_tail(&act->list, &worker_list);
	pthread_cond_signal(&worker_cond);
	pthread_mutex_unlock(&worker_mutex);
}

static int set_act_op_rt(const char *cmd, struct action *act)
{
	if (!strcmp(cmd, "init_vg")) {
		act->op = LD_OP_INIT;
		act->rt = LD_RT_VG;
		return 0;
	}
	if (!strcmp(cmd, "init_lv")) {
		act->op = LD_OP_INIT;
		act->rt = LD_RT_LV;
		return 0;
	}
	if (!strcmp(cmd, "start_vg")) {
		act->op = LD_OP_START;
		act->rt = LD_RT_VG;
		return 0;
	}
	if (!strcmp(cmd, "stop_vg")) {
		act->op = LD_OP_STOP;
		act->rt = LD_RT_VG;
		return 0;
	}
	if (!strcmp(cmd, "start_gl")) {
		act->op = LD_OP_START;
		act->rt = LD_RT_GL;
		return 0;
	}
	if (!strcmp(cmd, "stop_gl")) {
		act->op = LD_OP_STOP;
		act->rt = LD_RT_GL;
		return 0;
	}
	if (!strcmp(cmd, "stop_all")) {
		act->op = LD_OP_STOP_ALL;
		act->rt = 0;
		return 0;
	}
	if (!strcmp(cmd, "lock_gl")) {
		act->op = LD_OP_LOCK;
		act->rt = LD_RT_GL;
		return 0;
	}
	if (!strcmp(cmd, "lock_vg")) {
		act->op = LD_OP_LOCK;
		act->rt = LD_RT_VG;
		return 0;
	}
	if (!strcmp(cmd, "lock_lv")) {
		act->op = LD_OP_LOCK;
		act->rt = LD_RT_LV;
		return 0;
	}
	if (!strcmp(cmd, "gl_update")) {
		act->op = LD_OP_UPDATE;
		act->rt = LD_RT_GL;
		return 0;
	}
	if (!strcmp(cmd, "vg_update")) {
		act->op = LD_OP_UPDATE;
		act->rt = LD_RT_VG;
		return 0;
	}
	if (!strcmp(cmd, "enable_gl")) {
		act->op = LD_OP_ENABLE;
		act->rt = LD_RT_GL;
		return 0;
	}
	if (!strcmp(cmd, "disable_gl")) {
		act->op = LD_OP_DISABLE;
		act->rt = LD_RT_GL;
		return 0;
	}
	if (!strcmp(cmd, "test")) {
		act->op = LD_OP_TEST;
		act->rt = 0;
		return 0;
	}
	log_error("set_act_op_rt %s unknown", cmd);
	return -1;
}

static int set_act_mode(const char *mode, struct action *act)
{
	if (!strcmp(mode, "un")) {
		act->mode = LD_LK_UN;
		return 0;
	}
	if (!strcmp(mode, "nl")) {
		act->mode = LD_LK_NL;
		return 0;
	}
	if (!strcmp(mode, "sh")) {
		act->mode = LD_LK_SH;
		return 0;
	}
	if (!strcmp(mode, "ex")) {
		act->mode = LD_LK_EX;
		return 0;
	}

	/* TODO: update this comment about exactly what special
	   case(s) this can apply to.  Is it only vgcreate
	   of the first sanlock vg with --lock-gl enable|disable? */

	if (!strcmp(mode, "enable")) {
		act->flags |= LD_AF_ENABLE;
		return 0;
	}
	if (!strcmp(mode, "disable")) {
		act->flags |= LD_AF_DISABLE;
		return 0;
	}

	log_error("set_act_mode %s unknown", mode);
	return -1;
}

static int set_act_opts(const char *opts, struct action *act)
{
	if (strstr(opts, "persistent"))
		act->flags |= LD_AF_PERSISTENT;
	if (strstr(opts, "unlock_cancel"))
		act->flags |= LD_AF_UNLOCK_CANCEL;
	if (strstr(opts, "next_version"))
		act->flags |= LD_AF_NEXT_VERSION;
	if (strstr(opts, "wait"))
		act->flags |= LD_AF_WAIT;
	if (strstr(opts, "force"))
		act->flags |= LD_AF_FORCE;
	if (strstr(opts, "ex_disable"))
		act->flags |= LD_AF_EX_DISABLE;
	return 0;
}

static int set_act_version(const char *version, struct action *act)
{
	act->version = atoll(version);
	return 0;
}

static int set_act_lm_type(const char *lm_type, struct action *act)
{
	if (!strcmp(lm_type, "sanlock")) {
		act->lm_type = LD_LM_SANLOCK;
		return 0;
	}
	if (!strcmp(lm_type, "dlm")) {
		act->lm_type = LD_LM_DLM;
		return 0;
	}
	log_error("set_act_lm_type %s unknown", lm_type);
	return -1;
}

/* called from client_thread, cl->mutex is held */
static void client_recv_action(struct client *cl)
{
	request req;
	response res;
	struct action *act;
	const char *cmd, *str;
	uint64_t host_id = 0;
	int result;
	int rv;

	buffer_init(&req.buffer);

	rv = buffer_read(cl->fd, &req.buffer);
	if (!rv) {
		if (errno == ECONNRESET) {
			log_debug("client recv %d ECONNRESET", cl->id);
			cl->dead = 1;
		} else {
			log_error("client recv %d buffer_read error %d", cl->id, errno);
		}
		buffer_destroy(&req.buffer);
		client_resume(cl);
		return;
	}

	req.cft = dm_config_from_string(req.buffer.mem);
	if (!req.cft) {
		log_error("client recv %d config_from_string error", cl->id);
		buffer_destroy(&req.buffer);
		client_resume(cl);
		return;
	}

	cmd = daemon_request_str(req, "request", NULL);
	if (!cmd) {
		log_error("client recv %d no request string", cl->id);
		dm_config_destroy(req.cft);
		buffer_destroy(&req.buffer);
		client_resume(cl);
		return;
	}

	if (!strcmp(cmd, "hello") || !strcmp(cmd, "quit")) {
		result = 0;
		if (!strcmp(cmd, "quit")) {
			pthread_mutex_lock(&lockspaces_mutex);
		       	if (list_empty(&lockspaces)) {
				daemon_quit = 1;
			} else {
				result = -EBUSY;
			}
			pthread_mutex_unlock(&lockspaces_mutex);
		}

		log_debug("client recv %d %s", cl->id, cmd);

		buffer_init(&res.buffer);
		res = daemon_reply_simple("OK",
					  "result = %d", result,
					  "protocol = %s", lvmlockd_protocol,
					  "version = %d", lvmlockd_protocol_version,
					  NULL);
		buffer_write(cl->fd, &res.buffer);
		buffer_destroy(&res.buffer);

		dm_config_destroy(req.cft);
		buffer_destroy(&req.buffer);

		client_resume(cl);
		return;
	}

	/* TODO: take from list of unused action structs */

	act = malloc(sizeof(struct action));
	if (!act) {
		/* TODO: return an error to the client */
		dm_config_destroy(req.cft);
		buffer_destroy(&req.buffer);
		client_resume(cl);
		return;
	}
	memset(act, 0, sizeof(struct action));

	act->mode = -1;

	act->client_id = cl->id;

	rv = set_act_op_rt(cmd, act);
	if (rv < 0) {
		log_error("client recv %d unknown action %s", cl->id, cmd);
		dm_config_destroy(req.cft);
		buffer_destroy(&req.buffer);
		goto out;
	}

	log_debug("client recv %d %s rt %d op %d", cl->id, cmd, act->rt, act->op);

	str = daemon_request_str(req, "vg_name", NULL);
	if (str)
		strncpy(act->vg_name, str, MAX_NAME);

	str = daemon_request_str(req, "lv_name", NULL);
	if (str)
		strncpy(act->lv_name, str, MAX_NAME);

	str = daemon_request_str(req, "vg_uuid", NULL);
	if (str)
		strncpy(act->vg_uuid, str, 64);

	str = daemon_request_str(req, "mode", NULL);
	if (str)
		set_act_mode(str, act);

	str = daemon_request_str(req, "opts", NULL);
	if (str)
		set_act_opts(str, act);

	str = daemon_request_str(req, "version", NULL);
	if (str)
		set_act_version(str, act);

	str = daemon_request_str(req, "lock_type", NULL);
	if (str)
		set_act_lm_type(str, act);

	str = daemon_request_str(req, "lock_args", NULL);
	if (str)
		strncpy(act->lm_args, str, MAX_ARGS);

	if (act->lm_type == LD_LM_SANLOCK && !host_id) {
		str = daemon_request_str(req, "host_id", NULL);
		if (str)
			host_id = atoll(str);
	}

	if (!gl_type_static) {
		/* TODO: allow gl_type_static and gl_use_ to be
		   set from command line or config file.  This
		   would avoid confusion if clusters exist with
		   both dlm and sanlock vgs. */

		if (!gl_use_dlm && act->lm_type == LD_LM_DLM) {
			gl_use_dlm = 1;
			gl_use_sanlock = 0;
		}
		if (!gl_use_dlm && !gl_use_sanlock &&
		    act->lm_type == LD_LM_SANLOCK) {
			gl_use_sanlock = 1;
		}
	}

	dm_config_destroy(req.cft);
	buffer_destroy(&req.buffer);

	switch (act->op) {
	case LD_OP_START:
		rv = add_lockspace(act, host_id);
		break;
	case LD_OP_STOP:
		rv = rem_lockspace(act);
		break;
	case LD_OP_INIT:
	case LD_OP_FREE:
	case LD_OP_STOP_ALL:
		add_work_action(act);
		rv = 0;
		break;
	case LD_OP_LOCK:
	case LD_OP_UPDATE:
	case LD_OP_ENABLE:
	case LD_OP_DISABLE:
		rv = add_lock_action(act);
		break;
	default:
		rv = -EINVAL;
	};

out:
	if (rv < 0) {
		log_debug("client recv %d add result %d", cl->id, rv);
		act->result = rv;
		add_client_result(act);
	}
}

/*
 * TODO: if both dlm and sanlock global locks exist, dlm is acquired first,
 * then client thread removes it from client_results modifies it to make
 * it a sanlock gl request, and requeues it for processing.  The act
 * will come back to client_results a second time, and this result is
 * sent back to client.
 */

static void *client_thread_main(void *arg_in)
{
	struct client *cl;
	struct action *act;

	while (1) {
		pthread_mutex_lock(&client_mutex);
		while (!client_work && list_empty(&client_results)) {
			if (client_stop) {
				pthread_mutex_unlock(&client_mutex);
				goto out;
			}
			pthread_cond_wait(&client_cond, &client_mutex);
		}

		/*
		 * Send outgoing results back to clients
		 */

		if (!list_empty(&client_results)) {
			act = list_first_entry(&client_results, struct action, list);
			list_del(&act->list);
			cl = find_client_id(act->client_id);
			pthread_mutex_unlock(&client_mutex);

			if (cl) {
				pthread_mutex_lock(&cl->mutex);
				client_send_result(cl, act);
				pthread_mutex_unlock(&cl->mutex);
			} else {
				log_debug("no client for result");
			}
			free(act);
			continue;
		}

		/*
		 * Queue incoming actions for lockspace threads
		 */

		if (client_work) {
			cl = find_client_work();
			if (!cl)
				client_work = 0;
			pthread_mutex_unlock(&client_mutex);

			if (!cl)
				continue;

			pthread_mutex_lock(&cl->mutex);

			if (cl->recv) {
				cl->recv = 0;
				client_recv_action(cl);
			}

			if (cl->dead) {
				log_debug("client rem %d pi %d fd %d ig %d",
					  cl->id, cl->pi, cl->fd, cl->poll_ignore);
				/*
				 * If cl->dead was set in main_loop, then the
				 * fd has already been closed and the pollfd
				 * entry is already unused.
				 * main_loop set dead=1, ignore=0, pi=-1, fd=-1
				 *
				 * if cl->dead was not set in main_loop, but
				 * set in client_recv_action, then the main_loop
				 * should be ignoring this client fd.
				 * main_loop set ignore=1
				 */

				if (cl->poll_ignore) {
					log_debug("client close %d pi %d fd %d",
						  cl->id, cl->pi, cl->fd);
					/* assert cl->pi != -1 */
					/* assert pollfd[pi].fd == FD_IGNORE */
					close(cl->fd);
					rem_pollfd(cl->pi);
					cl->pi = -1;
					cl->fd = -1;
					cl->poll_ignore = 0;
				} else {
					/* main thread should have closed */
					if (cl->pi != -1 || cl->fd != -1) {
						log_error("client %d bad state pi %d fd %d",
							  cl->id, cl->pi, cl->fd);
					}
				}
				pthread_mutex_unlock(&cl->mutex);

				pthread_mutex_lock(&client_mutex);
				list_del(&cl->list);
				pthread_mutex_unlock(&client_mutex);

				client_purge(cl->id);

				free(cl);
			} else {
				pthread_mutex_unlock(&cl->mutex);
			}
		}
		pthread_mutex_unlock(&client_mutex);
	}
out:
	return NULL;
}

static int setup_client_thread(void)
{
	int rv;

	INIT_LIST_HEAD(&client_list);
	INIT_LIST_HEAD(&client_results);

	pthread_mutex_init(&client_mutex, NULL);
	pthread_cond_init(&client_cond, NULL);

	rv = pthread_create(&client_thread, NULL, client_thread_main, NULL);
	if (rv)
		return -1;
	return 0;
}

static void close_client_thread(void)
{
	pthread_mutex_lock(&client_mutex);
	client_stop = 1;
	pthread_cond_signal(&client_cond);
	pthread_mutex_unlock(&client_mutex);
	pthread_join(client_thread, NULL);
}

#if 0
static void setup_listener(void)
{
	struct sockaddr_un addr;
	int rv, fd, ci;

	rv = lvmlockd_socket_address(&addr);
	if (rv < 0)
		return rv;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	unlink(addr.sun_path);
	rv = bind(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (rv < 0)
		goto exit_fail;

	rv = chmod(addr.sun_path, DEFAULT_SOCKET_MODE);
	if (rv < 0)
		goto exit_fail;

	rv = chown(addr.sun_path, com.uid, com.gid);
	if (rv < 0) {
		log_error("could not set socket %s permissions: %s",
			  addr.sun_path, strerror(errno));
		goto exit_fail;
	}

	rv = listen(fd, 5);
	if (rv < 0)
		goto exit_fail;

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	listen_pi = add_pollfd(fd);

	return 0;

exit_fail:
	close(fd);
	return -1;
}
#endif

static void process_listener(int poll_fd)
{
	struct client *cl;
	int fd, pi;

	/* assert poll_fd == listen_fd */

	fd = accept(listen_fd, NULL, NULL);
	if (fd < 0)
		return;

	/* TODO: take from list of unused client structs */

	cl = malloc(sizeof(struct client));
	if (!cl)
		return;
	memset(cl, 0, sizeof(struct client));

	pi = add_pollfd(fd);
	if (pi < 0) {
		log_error("process_listener add_pollfd error %d", pi);
		free(cl);
		return;
	}

	cl->pi = pi;
	cl->fd = fd;

	pthread_mutex_init(&cl->mutex, NULL);

	pthread_mutex_lock(&client_mutex);
	cl->id = ++client_ids;
	list_add_tail(&cl->list, &client_list);
	pthread_mutex_unlock(&client_mutex);

	log_debug("client add %d pi %d fd %d", cl->id, cl->pi, cl->fd);
}

/*
 * main loop polls on pipe[0] so that a thread can
 * restart the poll by writing to pipe[1].
 */
static int setup_restart(void)
{
	if (pipe(restart_fds)) {
		log_error("");
		return -1;
	}

	restart_pi = add_pollfd(restart_fds[0]);
	if (restart_pi < 0)
		return restart_pi;

	return 0;
}

/*
 * thread wrote 'w' to restart_fds[1] to restart poll()
 * after adding an fd back into pollfd.
 */
static void process_restart(int fd)
{
	char wake[1];
	/* assert fd == restart_fds[0] */
	read(restart_fds[0], wake, 1);
}

static int main_loop(daemon_state *ds_arg)
{
	struct client *cl;
	int i, rv, is_recv, is_dead;

	log_debug("main_loop");

	/* TODO: avoid possible vg name collision */
	strcpy(gl_lsname_dlm, "lvm_global");

	INIT_LIST_HEAD(&lockspaces);
	pthread_mutex_init(&lockspaces_mutex, NULL);
	pthread_mutex_init(&pollfd_mutex, NULL);

	listen_fd = ds_arg->socket_fd;
	listen_pi = add_pollfd(listen_fd);

	setup_client_thread();
	setup_worker_thread();
	setup_restart();

	lvmetad_handle = lvmetad_open(NULL);
	if (lvmetad_handle.error || lvmetad_handle.socket_fd < 0)
		log_error("lvmetad_open error %d", lvmetad_handle.error);
	else
		lvmetad_connected = 1;

	while (1) {
		rv = poll(pollfd, pollfd_maxi + 1, -1);
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv < 0) {
			/* log error */
			break;
		}
		if (daemon_quit)
			break;

		for (i = 0; i <= pollfd_maxi; i++) {
			if (pollfd[i].fd < 0)
				continue;

			is_recv = 0;
			is_dead = 0;

			if (pollfd[i].revents & POLLIN)
				is_recv = 1;
			if (pollfd[i].revents & (POLLERR | POLLHUP | POLLNVAL))
				is_dead = 1;

			if (!is_recv && !is_dead)
				continue;

			if (i == listen_pi) {
				process_listener(pollfd[i].fd);
				continue;
			}

			if (i == restart_pi) {
				process_restart(pollfd[i].fd);
				continue;
			}

			log_debug("poll pi %d fd %d revents %x",
				  i, pollfd[i].fd, pollfd[i].revents);

			pthread_mutex_lock(&client_mutex);
			cl = find_client_pi(i);
			if (cl) {
				pthread_mutex_lock(&cl->mutex);

				if (cl->recv) {
					/* should not happen */
					log_error("main client %d already recv", cl->id);

				} else if (cl->dead) {
					/* should not happen */
					log_error("main client %d already dead", cl->id);

				} else if (is_dead) {
					log_debug("main close %d pi %d fd %d",
						  cl->id, i, cl->fd);
					cl->dead = 1;
					cl->pi = -1;
					cl->fd = -1;
					cl->poll_ignore = 0;
					close(pollfd[i].fd);
					pollfd[i].fd = POLL_FD_UNUSED;
					pollfd[i].events = 0;
					pollfd[i].revents = 0;

				} else if (is_recv) {
					cl->recv = 1;
					cl->poll_ignore = 1;
					pollfd[i].fd = POLL_FD_IGNORE;
					pollfd[i].events = 0;
					pollfd[i].revents = 0;
				}

				pthread_mutex_unlock(&cl->mutex);

				client_work = 1;
				pthread_cond_signal(&client_cond);

				/* client_thread will pick up and work on any
				   client with cl->recv or cl->dead set */

			} else {
				/* don't think this can happen */
				log_error("no client for index %d fd %d",
					  i, pollfd[i].fd);
				close(pollfd[i].fd);
				pollfd[i].fd = POLL_FD_UNUSED;
				pollfd[i].events = 0;
				pollfd[i].revents = 0;
			}
			pthread_mutex_unlock(&client_mutex);

			/* TODO?: after set_dead, scan pollfd for last unused
			   slot and reduce pollfd_maxi */
		}

		/* clear any lockspaces that have been removed (or failed to start) */
		/* TODO: have worker thread do this? */
		free_lockspaces(NO_WAIT);
	}

	stop_lockspaces(FORCE, NO_WAIT);
	free_lockspaces(WAIT);
	close_worker_thread();
	close_client_thread();
	daemon_close(lvmetad_handle);
	return 0;
}

static void usage(char *prog, FILE *file)
{
	fprintf(file, "Usage:\n"
		"%s [-V] [-h] [-f] [-l {all|wire|debug}] [-s path]\n\n"
		"   -V       Show version of lvmlockd\n"
		"   -h       Show this help information\n"
		"   -f       Don't fork, run in the foreground\n"
		"   -l       Logging message level (-l {all|wire|debug})\n"
		"   -s       Set path to the socket to listen on\n"
		"            (default %s/lvmlockd.socket)\n",
		prog, DEFAULT_RUN_DIR);
}

int main(int argc, char *argv[])
{
	daemon_state ds;
	signed char opt;

	ds.daemon_main = main_loop;
	ds.daemon_init = NULL;
	ds.daemon_fini = NULL;
	ds.socket_path = getenv("LVM_LVMLOCKD_SOCKET");
	if (!ds.socket_path)
		ds.socket_path = DEFAULT_RUN_DIR "/lvmlockd.socket";
	ds.pidfile = LVMLOCKD_PIDFILE;
	ds.protocol = lvmlockd_protocol;
	ds.protocol_version = lvmlockd_protocol_version;
	ds.name = "lvmlockd";

	// use getopt_long
	while ((opt = getopt(argc, argv, "?fhVl:s:")) != EOF) {
		switch (opt) {
		case 'h':
			usage(argv[0], stdout);
			exit(0);
		case '?':
			usage(argv[0], stderr);
			exit(0);
		case 'f':
			ds.foreground = 1;
			daemon_debug = 1;
			break;
		case 'l':
			/* lockd.log_config = optarg; */
			break;
		case 's':
			ds.socket_path = optarg;
			break;
		case 'V':
			printf("lvmlockd version: " LVM_VERSION "\n");
			exit(1);
		}
	}

	/* runs daemon_main/main_loop */
	daemon_start(ds);

	return 0;
}
