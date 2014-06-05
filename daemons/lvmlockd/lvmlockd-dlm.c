
#define _XOPEN_SOURCE 500  /* pthread */
#define _ISOC99_SOURCE

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <endian.h>
#include <fcntl.h>
#include <byteswap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "daemon-server.h"
#include "daemon-log.h"

#include "lvmlockd-internal.h"

/*
 * Using synchronous _wait dlm apis so do not define _REENTRANT and
 * link with non-threaded version of library, libdlm_lt.
 */
#include "libdlm.h"

struct lm_dlm {
	dlm_lshandle_t *dh;
};

struct rd_dlm {
	struct dlm_lksb lksb;
	struct val_blk *vb;
};

/*
 * lock_args format
 *
 * vg_lock_args format for dlm is
 * vg_version_string:undefined:cluster_name
 *
 * lv_lock_args are not used for dlm
 *
 * version_string is MAJOR.MINOR.PATCH
 * undefined may contain ":"
 */

#define VG_LOCK_ARGS_MAJOR 1
#define VG_LOCK_ARGS_MINOR 0
#define VG_LOCK_ARGS_PATCH 0

static int cluster_name_from_args(char *vg_args, char *clustername)
{
	return last_string_from_args(vg_args, clustername);
}

static int check_args_version(char *vg_args)
{
	unsigned int major = 0;
	int rv;

	rv = version_from_args(vg_args, &major, NULL, NULL);
	if (rv < 0) {
		log_error("check_args_version %s error %d", vg_args, rv);
		return rv;
	}

	if (major > VG_LOCK_ARGS_MAJOR) {
		log_error("check_args_version %s major %d %d", vg_args, major, VG_LOCK_ARGS_MAJOR);
		return -1;
	}

	return 0;
}

/* This will be set after dlm_controld is started. */
#define DLM_CLUSTER_NAME_PATH "/sys/kernel/config/dlm/cluster/cluster_name"

static int read_cluster_name(char *clustername)
{
	char *n;
	int fd;
	int rv;

	if (daemon_test) {
		sprintf(clustername, "%s", "test");
		return 0;
	}

	fd = open(DLM_CLUSTER_NAME_PATH, O_RDONLY);
	if (fd < 0) {
		log_error("read_cluster_name: open error %d, check dlm_controld", fd);
		return fd;
	}

	rv = read(fd, clustername, MAX_ARGS - 1);
	if (rv < 0) {
		log_error("read_cluster_name: cluster name read error %d, check dlm_controld", fd);
		close(fd);
		return rv;
	}

	n = strstr(clustername, "\n");
	if (n)
		*n = '\0';
	close(fd);
	return 0;
}

int lm_init_vg_dlm(char *ls_name, char *vg_name, uint32_t flags, char *vg_args)
{
	char clustername[MAX_ARGS];
	char lock_args_version[MAX_ARGS];
	int rv;

	memset(clustername, 0, sizeof(clustername));
	memset(lock_args_version, 0, sizeof(lock_args_version));

	snprintf(lock_args_version, MAX_ARGS, "%u.%u.%u",
		 VG_LOCK_ARGS_MAJOR, VG_LOCK_ARGS_MINOR, VG_LOCK_ARGS_PATCH);

	rv = read_cluster_name(clustername);
	if (rv < 0)
		return rv;

	if (strlen(clustername) + strlen(lock_args_version) + 2 > MAX_ARGS) {
		log_error("init_vg_dlm args too long");
		return -ENAMETOOLONG;
	}

	snprintf(vg_args, MAX_ARGS, "%s:%s", lock_args_version, clustername);
	rv = 0;

	log_debug("init_vg_dlm done %s vg_args %s", ls_name, vg_args);
	return rv;
}

int lm_add_lockspace_dlm(struct lockspace *ls)
{
	char sys_clustername[MAX_ARGS];
	char arg_clustername[MAX_ARGS];
	struct lm_dlm *lmd;
	int rv;

	memset(sys_clustername, 0, sizeof(sys_clustername));
	memset(arg_clustername, 0, sizeof(arg_clustername));

	if (!ls->vg_args[0]) {
		/* global lockspace has no vg args */
		goto skip_args;
	}

	rv = check_args_version(ls->vg_args);
	if (rv < 0)
		return rv;

	rv = read_cluster_name(sys_clustername);
	if (rv < 0)
		return rv;

	rv = cluster_name_from_args(ls->vg_args, arg_clustername);
	if (rv < 0) {
		log_error("add_lockspace_dlm %s no cluster name from args %s", ls->name, ls->vg_args);
		return rv;
	}

	if (strcmp(sys_clustername, arg_clustername)) {
		log_error("add_lockspace_dlm %s mismatching cluster names sys %s arg %s",
			  ls->name, sys_clustername, arg_clustername);
		return -1;
	}

 skip_args:
	lmd = malloc(sizeof(struct lm_dlm));
	if (!lmd) {
		rv = -ENOMEM;
		goto out;
	}

	if (daemon_test)
		goto data;

	lmd->dh = dlm_new_lockspace(ls->name, 0600, DLM_LSFL_NEWEXCL);
	if (!lmd->dh && errno == EEXIST) {
		lmd->dh = dlm_open_lockspace(ls->name);
	}

	if (!lmd->dh) {
		free(lmd);
		rv = -errno;
		log_error("add_lockspace_dlm new error %d", rv);
		goto out;
	}

 data:
	ls->lm_data = lmd;
	rv = 0;
 out:
	return rv;
}

int lm_rem_lockspace_dlm(struct lockspace *ls, int free_vg)
{
	struct lm_dlm *lmd = ls->lm_data;
	int rv;

	if (daemon_test)
		goto out;

	/*
	 * TODO: if free_vg is set, it means we are doing vgremove,
	 * and we may want to tell any other nodes to leave the lockspace.
	 * This is not really necessary since there should be no harm in
	 * having an unused lockspace sitting around.
	 */

	rv = dlm_release_lockspace(ls->name, lmd->dh, 1);
	if (rv < 0) {
		log_error("rem_lockspace_dlm error %d", rv);
		return rv;
	}
 out:
	free(lmd);
	ls->lm_data = NULL;

	if (!strcmp(ls->name, gl_lsname_dlm)) {
		gl_running_dlm = 0;
		gl_auto_dlm = 0;
	}

	return 0;
}

static int lm_add_resource_dlm(struct lockspace *ls, struct resource *r)
{
	struct lm_dlm *lmd = ls->lm_data;
	struct rd_dlm *rdd;
	uint32_t flags = 0;
	char *buf;
	int rv;

	rdd = malloc(sizeof(struct rd_dlm));
	if (!rdd)
		return -ENOMEM;

	memset(rdd, 0, sizeof(struct rd_dlm));

	if (r->type == LD_RT_GL || r->type == LD_RT_VG) {
		buf = malloc(sizeof(struct val_blk) + DLM_LVB_LEN);
		if (!buf) {
			free(rdd);
			return -ENOMEM;
		}
		memset(buf, 0, sizeof(struct val_blk) + DLM_LVB_LEN);

		rdd->vb = (struct val_blk *)buf;
		rdd->lksb.sb_lvbptr = buf + sizeof(struct val_blk);

		flags |= LKF_VALBLK;
	}

	/* because this is a new NL lock request */
	flags |= LKF_EXPEDITE;

	if (daemon_test)
		return 0;

	rv = dlm_ls_lock_wait(lmd->dh, LKM_NLMODE, &rdd->lksb, flags,
			      r->name, strlen(r->name),
			      0, NULL, NULL, NULL);
	if (rv < 0) {
		log_error("S %s R %s add_resource_dlm lock error %d", ls->name, r->name, rv);
		return rv;
	}
	return 0;
}

int lm_rem_resource_dlm(struct lockspace *ls, struct resource *r)
{
	struct lm_dlm *lmd = ls->lm_data;
	struct rd_dlm *rdd = r->lm_data;
	struct dlm_lksb *lksb;
	int rv;

	if (daemon_test) {
		rv = 0;
		goto out;
	}

	if (!rdd)
		return 0;

	lksb = &rdd->lksb;

	rv = dlm_ls_unlock_wait(lmd->dh, lksb->sb_lkid, 0, lksb);
	if (rv < 0) {
		log_error("S %s R %s rem_resource_dlm unlock error %d", ls->name, r->name, rv);
	}
 out:
	if (rdd->vb)
		free(rdd->vb);
	free(rdd);
	r->lm_data = NULL;
	return rv;
}

static int to_dlm_mode(int ld_mode)
{
	switch (ld_mode) {
	case LD_LK_EX:
		return LKM_EXMODE;
	case LD_LK_SH:
		return LKM_PRMODE;
	};
	return -1;
}

int lm_lock_dlm(struct lockspace *ls, struct resource *r, int ld_mode, uint32_t *r_version)
{
	struct lm_dlm *lmd = ls->lm_data;
	struct rd_dlm *rdd;
	struct dlm_lksb *lksb;
	struct val_blk vb;
	uint32_t flags;
	uint16_t vb_version;
	int mode;
	int rv;

	if (!r->lm_data) {
		rv = lm_add_resource_dlm(ls, r);
		if (rv < 0)
			return rv;
	}

	rdd = r->lm_data;
	lksb = &rdd->lksb;

	flags = LKF_CONVERT | LKF_NOQUEUE;

	if (rdd->vb)
		flags |= LKF_VALBLK;

	mode = to_dlm_mode(ld_mode);
	if (mode < 0) {
		log_error("lock_dlm invalid mode %d", ld_mode);
		return -EINVAL;
	}

	log_debug("S %s R %s lock_dlm", ls->name, r->name);

	if (daemon_test) {
		*r_version = 0;
		return 0;
	}

	rv = dlm_ls_lock_wait(lmd->dh, mode, lksb, flags,
			      r->name, strlen(r->name),
			      0, NULL, NULL, NULL);
	if (rv == -EAGAIN) {
		/* TODO: what case is this? what should be done? */
		log_error("S %s R %s lock_dlm mode %d rv EAGAIN", ls->name, r->name, mode);
		return -EAGAIN;
	}
	if (rv < 0) {
		log_error("S %s R %s lock_dlm error %d", ls->name, r->name, rv);
		return rv;
	}

	if (rdd->vb) {
		if (lksb->sb_flags & DLM_SBF_VALNOTVALID) {
			log_debug("S %s R %s lock_dlm VALNOTVALID", ls->name, r->name);
			memset(rdd->vb, 0, sizeof(struct val_blk));
			*r_version = 0;
			goto out;
		}

		memcpy(&vb, lksb->sb_lvbptr, sizeof(struct val_blk));
		vb_version = le16_to_cpu(vb.version);

		if (vb_version && ((vb_version & 0xFF00) > (VAL_BLK_VERSION & 0xFF00))) {
			log_error("S %s R %s lock_dlm ignore vb_version %x",
				  ls->name, r->name, vb_version);
			*r_version = 0;
			free(rdd->vb);
			rdd->vb = NULL;
			lksb->sb_lvbptr = NULL;
			goto out;
		}

		memcpy(rdd->vb, &vb, sizeof(vb));
		*r_version = le32_to_cpu(vb.r_version);

		log_debug("S %s R %s lock_dlm get r_version %u", ls->name, r->name, *r_version);
	}
out:
	return 0;
}

int lm_convert_dlm(struct lockspace *ls, struct resource *r,
		   int ld_mode, uint32_t r_version)
{
	struct lm_dlm *lmd = ls->lm_data;
	struct rd_dlm *rdd = r->lm_data;
	struct dlm_lksb *lksb = &rdd->lksb;
	uint32_t mode;
	uint32_t flags;
	int rv;

	log_debug("S %s R %s convert_dlm", ls->name, r->name);

	flags = LKF_CONVERT | LKF_NOQUEUE;

	if (rdd->vb && r_version && (r->mode == LD_LK_EX)) {
		if (!rdd->vb->version) {
			/* first time vb has been written */
			rdd->vb->version = cpu_to_le16(VAL_BLK_VERSION);
		}
		rdd->vb->r_version = cpu_to_le32(r_version);
		memcpy(lksb->sb_lvbptr, rdd->vb, sizeof(struct val_blk));

		log_debug("S %s R %s convert_dlm set r_version %u",
			  ls->name, r->name, r_version);

		flags |= LKF_VALBLK;
	}

	mode = to_dlm_mode(ld_mode);

	if (daemon_test)
		return 0;

	rv = dlm_ls_lock_wait(lmd->dh, mode, lksb, flags,
			      r->name, strlen(r->name),
			      0, NULL, NULL, NULL);
	if (rv == -EAGAIN) {
		/* TODO: what case is this? what should be done? */
		log_error("S %s R %s convert_dlm mode %d rv EAGAIN", ls->name, r->name, mode);
		return -EAGAIN;
	}
	if (rv < 0) {
		log_error("S %s R %s convert_dlm error %d", ls->name, r->name, rv);
	}
	return rv;
}

int lm_unlock_dlm(struct lockspace *ls, struct resource *r,
		  uint32_t r_version, uint32_t lmuf_flags)
{
	struct lm_dlm *lmd = ls->lm_data;
	struct rd_dlm *rdd = r->lm_data;
	struct dlm_lksb *lksb = &rdd->lksb;
	uint32_t flags;
	int rv;

	log_debug("S %s R %s unlock_dlm r_version %u flags %x",
		  ls->name, r->name, r_version, lmuf_flags);

	flags = LKF_CONVERT;

	if (rdd->vb && r_version && (r->mode == LD_LK_EX)) {
		if (!rdd->vb->version) {
			/* first time vb has been written */
			rdd->vb->version = cpu_to_le16(VAL_BLK_VERSION);
		}
		rdd->vb->r_version = cpu_to_le32(r_version);
		memcpy(lksb->sb_lvbptr, rdd->vb, sizeof(struct val_blk));

		log_debug("S %s R %s unlock_dlm set r_version %u",
			  ls->name, r->name, r_version);

		flags |= LKF_VALBLK;
	}

	if (daemon_test)
		return 0;

	rv = dlm_ls_lock_wait(lmd->dh, LKM_NLMODE, lksb, flags,
			      r->name, strlen(r->name),
			      0, NULL, NULL, NULL);
	if (rv < 0) {
		log_error("S %s R %s unlock_dlm error %d", ls->name, r->name, rv);
	}

	return rv;
}

