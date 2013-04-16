
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
#include <byteswap.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "linux-list.h"
#include "lvmlockd-internal.h"

/*
 * Using synchronous _wait dlm apis so do not define _REENTRANT and
 * link with non-threaded version of library, libdlm_lt.
 */
#include "libdlm.h"

struct lm_dlm {
	dlm_lshandle_t *dh;
};

/* This will be set after dlm_controld is started. */
#define DLM_CLUSTER_NAME_PATH "/sys/kernel/config/dlm/cluster/cluster_name"

int lm_init_vg_dlm(char *ls_name, char *lm_args)
{
	char buf[MAX_ARGS];
	int fd, rv;

	memset(buf, 0, sizeof(buf));

	fd = open(DLM_CLUSTER_NAME_PATH, O_RDONLY);
	if (fd < 0) {
		log_error("lm_init_vg_dlm: cluster name open error %d, check dlm_controld", fd);
		return fd;
	}

	rv = read(fd, buf, MAX_ARGS - 1);
	if (rv < 0) {
		log_error("lm_init_vg_dlm: cluster name read error %d, check dlm_controld", fd);
		goto out;
	}

	strncpy(lm_args, buf, MAX_ARGS);
	rv = 0;
out:
	close(fd);
	return rv;
}

/* TODO: vb.version */

static void read_lvb(struct resource *r, struct dlm_lksb *lksb, uint64_t *version)
{
	struct val_blk vb;

	if (lksb->sb_flags & DLM_SBF_VALNOTVALID) {
		*version = 0;
		return;
	}

	memcpy(&vb, lksb->sb_lvbptr, sizeof(struct val_blk));

	*version = le64_to_cpu(vb.mdver);
}

static void write_lvb(struct resource *r, struct dlm_lksb *lksb, uint64_t version)
{
	struct val_blk vb;

	memset(&vb, 0, sizeof(vb));

	vb.version = cpu_to_le64(version);

	memcpy(lksb->sb_lvbptr, &vb, sizeof(struct val_blk));
}

int lm_add_lockspace_dlm(struct lockspace *ls)
{
	struct lm_dlm *lmd;
	int rv;

	lmd = malloc(sizeof(struct lm_dlm));
	if (!lmd) {
		rv = -ENOMEM;
		goto out;
	}

	lmd->dh = dlm_new_lockspace(ls->name, 0600, DLM_LSFL_NEWEXCL);
	if (!lmd->dh && errno == EEXIST) {
		lmd->dh = dlm_open_lockspace(ls->name);
	}

	if (!lmd->dh) {
		free(lmd);
		rv = -errno;
		goto out;
	}

	ls->lm_data = lmd;
	rv = 0;
out:
	return rv;
}

int lm_rem_lockspace_dlm(struct lockspace *ls)
{
	struct lm_dlm *lmd = ls->lm_data;
	int rv;

	rv = dlm_release_lockspace(ls->name, lmd->dh, 1);
	if (rv < 0) {
		return rv;
	}

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
	struct dlm_lksb *lksb;
	uint32_t flags = 0;
	char *buf;
	int size, rv;

	/*
	 * for gl and vg locks, r->lm_data is lksb+lvb
	 * for lv locks, r->lm_data is only lksb (lvb not used)
	 */

	size = sizeof(struct dlm_lksb);

	if (r->type == LD_RT_GL || r->type == LD_RT_VG)
		size += DLM_LVB_LEN;

	buf = malloc(size);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, size);

	r->lm_data = buf;

	lksb = r->lm_data;

	if (r->type == LD_RT_GL || r->type == LD_RT_VG) {
		lksb->sb_lvbptr = buf + sizeof(struct dlm_lksb);
		flags |= LKF_VALBLK;
	}

	/* because this is a new NL lock request */
	flags |= LKF_EXPEDITE;

	rv = dlm_ls_lock_wait(lmd->dh, LKM_NLMODE, lksb, flags,
			      r->name, strlen(r->name),
			      0, NULL, NULL, NULL);
	if (rv < 0) {
		return rv;
	}
	return 0;
}

static int lm_rem_resource_dlm(struct lockspace *ls, struct resource *r)
{
	struct lm_dlm *lmd = ls->lm_data;
	struct dlm_lksb *lksb = r->lm_data;
	int rv;

	/* TODO: write lvb? */

	rv = dlm_ls_unlock_wait(lmd->dh, lksb->sb_lkid, 0, lksb);

	free(lksb);
	r->lm_data = NULL;
	return rv;
}

static uint32_t to_dlm_mode(int ld_mode)
{
	switch (ld_mode) {
	case LD_LK_EX:
		return LKM_EXMODE;
	case LD_LK_SH:
		return LKM_PRMODE;
	};
	return -1;
}

/* TODO: use LKF_PERSISTENT for persistent locks? */

int lm_lock_dlm(struct lockspace *ls, struct resource *r, int ld_mode, uint64_t *version)
{
	struct lm_dlm *lmd = ls->lm_data;
	struct dlm_lksb *lksb;
	uint32_t mode;
	uint32_t flags;
	int lvb = (r->type == LD_RT_GL || r->type == LD_RT_VG);
	int rv;

	if (!r->lm_data) {
		rv = lm_add_resource_dlm(ls, r);
		if (rv < 0)
			return rv;
	}

	lksb = r->lm_data;

	flags = LKF_CONVERT | LKF_NOQUEUE;

	if (lvb)
		flags |= LKF_VALBLK;

	mode = to_dlm_mode(ld_mode);

	rv = dlm_ls_lock_wait(lmd->dh, mode, lksb, flags,
			      r->name, strlen(r->name),
			      0, NULL, NULL, NULL);
	if (rv < 0) {
		return rv;
	}

	if (lvb)
		read_lvb(r, lksb, version);

	return 0;
}

int lm_unlock_dlm(struct lockspace *ls, struct resource *r, uint64_t version)
{
	struct lm_dlm *lmd = ls->lm_data;
	struct dlm_lksb *lksb = r->lm_data;
	uint32_t flags;
	int lvb = (r->type == LD_RT_GL || r->type == LD_RT_VG);
	int rv;

	flags = LKF_CONVERT;

	if (lvb && (r->mode == LD_LK_EX)) {
		flags |= LKF_VALBLK;
		write_lvb(r, lksb, version);
	}

	rv = dlm_ls_lock_wait(lmd->dh, LKM_NLMODE, lksb, flags,
			      r->name, strlen(r->name),
			      0, NULL, NULL, NULL);
	if (rv < 0) {
		return rv;
	}
	return 0;
}

