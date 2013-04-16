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
#include <sys/types.h>
#include <sys/socket.h>

#include "linux-list.h"
#include "lvmlockd-internal.h"

#include "sanlock.h"
#include "sanlock_rv.h"
#include "sanlock_admin.h"
#include "sanlock_resource.h"

/*
 * Each lockspace thread has its own sanlock daemon connection.
 * If they shared one, then I think all sanlock ops would be
 * serialized.  I think the sanlock daemon intended one connection
 * per pid, but it probably won't hurt to have multiple.
 * TODO: This should be tested/verified, though.
 */

struct lm_sanlock {
	struct sanlk_lockspace ss;
	int align_size;
	int sock; /* sanlock daemon connection */
};

struct rd_sanlock {
	union {
		struct sanlk_resource rs;
		char buf[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	};
};

struct sanlk_resourced {
	union {
		struct sanlk_resource rs;
		char buf[sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk)];
	};
};

/*
 * offset 0 is lockspace
 * offset align_size * 1 is unused
 * offset align_size * 2 is unused
 * offset align_size * 3 is gl lock
 * offset align_size * 4 is vg lock
 * offset align_size * 5 is first lv lock
 */

#define LS_BEGIN 0
#define GL_LOCK_BEGIN 3
#define VG_LOCK_BEGIN 4
#define LV_LOCK_BEGIN 5

int lm_init_vg_sanlock(char *ls_name, uint32_t flags, char *lm_args)
{
	struct sanlk_lockspace ss;
	struct sanlk_resourced rd;
	struct sanlk_disk disk;
	const char *gl_name;
	int align_size;
	int rv;

	memset(&ss, 0, sizeof(ss));
	memset(&rd, 0, sizeof(rd));
	memset(&disk, 0, sizeof(disk));

	if (!lm_args || !lm_args[0]) {
		log_error("init_vg_sanlock lm_args missing");
		return -EINVAL;
	}

	strncpy(disk.path, lm_args, SANLK_PATH_LEN);

	log_debug("init_vg_sanlock %s %s", ls_name, disk.path);

	align_size = sanlock_align(&disk);
	if (align_size <= 0) {
		log_error("init_vg_sanlock bad align size %d %s",
			   align_size, disk.path);
		return -EINVAL;
	}

	strncpy(ss.name, ls_name, SANLK_NAME_LEN);
	memcpy(ss.host_id_disk.path, disk.path, SANLK_PATH_LEN);
	ss.host_id_disk.offset = LS_BEGIN * align_size;

	rv = sanlock_write_lockspace(&ss, 0, 0, 0);
	if (rv < 0) {
		log_error("init_vg_sanlock write_lockspace error %d %s",
			  rv, ss.host_id_disk.path);
		return rv;
	}
	
	/*
	 * We want to create the global lock in the first sanlock vg.
	 * If other sanlock vgs exist, then one of them must contain
	 * the gl.  If gl_lsname_sanlock is not set, then perhaps
	 * the sanlock vg with the gl has been removed or has not yet
	 * been seen. (Would vgcreate get this far in that case?)
	 * If dlm vgs exist, then we choose to use the dlm gl and
	 * not a sanlock gl.
	 */

	if (flags & LD_AF_ENABLE)
		gl_name = R_NAME_GL;
	else if (flags & LD_AF_DISABLE)
		gl_name = R_NAME_GL_DISABLED;
	else if (!gl_use_sanlock || gl_lsname_sanlock[0] || !lockspaces_empty())
		gl_name = R_NAME_GL_DISABLED;
	else
		gl_name = R_NAME_GL;

	memcpy(rd.rs.lockspace_name, ss.name, SANLK_NAME_LEN);
	strncpy(rd.rs.name, gl_name, SANLK_NAME_LEN);
	memcpy(rd.rs.disks[0].path, disk.path, SANLK_PATH_LEN);
	rd.rs.disks[0].offset = align_size * GL_LOCK_BEGIN;
	rd.rs.num_disks = 1;

	rv = sanlock_write_resource(&rd.rs, 0, 0, 0);
	if (rv < 0) {
		log_error("init_vg_sanlock write_resource gl error %d %s",
			  rv, rd.rs.disks[0].path);
		return rv;
	}

	memcpy(rd.rs.lockspace_name, ss.name, SANLK_NAME_LEN);
	strncpy(rd.rs.name, R_NAME_VG, SANLK_NAME_LEN);
	memcpy(rd.rs.disks[0].path, disk.path, SANLK_PATH_LEN);
	rd.rs.disks[0].offset = align_size * VG_LOCK_BEGIN;
	rd.rs.num_disks = 1;

	rv = sanlock_write_resource(&rd.rs, 0, 0, 0);
	if (rv < 0) {
		log_error("init_vg_sanlock write_resource vg error %d %s",
			  rv, rd.rs.disks[0].path);
		return rv;
	}

	log_debug("init_vg_sanlock %s %s %s", ls_name, gl_name, disk.path);

	if (!strcmp(gl_name, R_NAME_GL))
		strncpy(gl_lsname_sanlock, ls_name, MAX_NAME);

	return 0;
}

/*
 * The offset at which the lv lease is written is passed
 * all the way back to the lvcreate command so that it
 * can be saved in the lv's lock_args in the vg metadata.
 */

int lm_init_lv_sanlock(char *ls_name, char *lv_name,
		       char *ls_lm_args, char *res_lm_args)
{
	struct sanlk_resourced rd;
	uint64_t offset;
	int align_size;
	int lv_count = 0;
	int rv;

	memset(&rd, 0, sizeof(rd));

	strncpy(rd.rs.lockspace_name, ls_name, SANLK_NAME_LEN);
	rd.rs.num_disks = 1;
	strncpy(rd.rs.disks[0].path, ls_lm_args, SANLK_PATH_LEN);

	align_size = sanlock_align(&rd.rs.disks[0]);
	if (align_size <= 0) {
		log_error("sanlock_align error %d", align_size);
		return -EINVAL;
	}

	offset = align_size * LV_LOCK_BEGIN;
	rd.rs.disks[0].offset = offset;

	while (1) {
		rd.rs.disks[0].offset = offset;

		memset(rd.rs.name, 0, SANLK_NAME_LEN);

		rv = sanlock_read_resource(&rd.rs, 0);
		if (!rv) {
			/*
			 * success means we read a valid resource at this
			 * offset, so it's not free. TODO: eventually freed
			 * resources will be be given a special name to
			 * indicate they can be reused, so we'd check for
			 * that name here.
			 */

			if (!strncmp(rd.rs.name, lv_name, SANLK_NAME_LEN)) {
				log_error("init_lv_sanlock resource name %s already exists at %llu",
					  lv_name, (unsigned long long)offset);
				return -EEXIST;
			}

			offset += align_size;

			if (lv_count++ >= MAX_LVS_IN_VG) {
				log_error("init_lv_sanlock too many lvs %d", lv_count);
				rv = -ENOENT;
				break;
			}
			continue;
		}

		/*
		 * We intend to eventually get the LEADER_MAGIC error, which
		 * means that a valid resource was not found at this offset,
		 * which means the slot is free to be used for the new lv.
		 * Any other error is unexpected and results in failure.
		 */

		if (rv != SANLK_LEADER_MAGIC) {
			log_error("init_lv_sanlock read error %d offset %llu",
				  rv, (unsigned long long)offset);
			break;
		}

		log_debug("init_lv_sanlock %s %s use offset %llu",
			  ls_name, lv_name, (unsigned long long)offset);

		strncpy(rd.rs.name, lv_name, SANLK_NAME_LEN);

		rv = sanlock_write_resource(&rd.rs, 0, 0, 0);
		if (!rv)
			sprintf(res_lm_args, "%llu", (unsigned long long)offset);
		else
			log_error("init_lv_sanlock write error %d offset %llu",
				  rv, (unsigned long long)rv);
		break;
	}
	return rv;
}

static int find_lv_offset(struct lockspace *ls, struct resource *r,
			  uint64_t *lm_args_offset)
{
	struct sanlk_resourced rd;
	uint64_t offset;
	int align_size;
	int lv_count = 0;
	int rv;

	memset(&rd, 0, sizeof(rd));

	strncpy(rd.rs.lockspace_name, ls->name, SANLK_NAME_LEN);
	rd.rs.num_disks = 1;
	strncpy(rd.rs.disks[0].path, ls->lm_args, SANLK_PATH_LEN);

	align_size = sanlock_align(&rd.rs.disks[0]);
	if (align_size <= 0) {
		log_error("sanlock_align error %d", align_size);
		return -EINVAL;
	}

	offset = align_size * LV_LOCK_BEGIN;

	while (1) {
		rd.rs.disks[0].offset = offset;

		memset(rd.rs.name, 0, SANLK_NAME_LEN);

		rv = sanlock_read_resource(&rd.rs, 0);
		if (!rv) {
			if (!strncmp(rd.rs.name, r->name, SANLK_NAME_LEN)) {
				log_debug("find_lv_offset found %s %s at %llu",
					  ls->name, r->name, (unsigned long long)offset);

				*lm_args_offset = offset;
				return 0;
			}

			offset += align_size;

			if (lv_count++ >= MAX_LVS_IN_VG) {
				log_error("find_lv_offset too many lvs %d", lv_count);
				rv = -ENOENT;
				break;
			}
			continue;
		}
		if (rv != SANLK_LEADER_MAGIC) {
			log_error("find_lv_offset read error %d offset %llu",
				  rv, (unsigned long long)offset);
			break;
		}

		/*
		 * an empty slot means no more resources, assuming that
		 * there are no gaps, so the lv was not found.
		 */

		log_debug("find_lv_offset %s %s not found", ls->name, r->name);
		rv = -ENOENT;
		break;
	}
	return rv;
}

int lm_ex_disable_gl_sanlock(struct lockspace *ls)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct sanlk_resourced rd1;
	struct sanlk_resourced rd2;
	struct sanlk_resource *rs1;
	struct sanlk_resource *rs2;
	struct sanlk_resource **rs_args;
	int rv;

	rs_args = malloc(2 * sizeof(struct sanlk_resource *));
	if (!rs_args)
		return -ENOMEM;

	rs1 = &rd1.rs;
	rs2 = &rd2.rs;

	memset(&rd1, 0, sizeof(rd1));
	memset(&rd2, 0, sizeof(rd2));

	strncpy(rd1.rs.lockspace_name, ls->name, SANLK_NAME_LEN);
	strncpy(rd1.rs.name, R_NAME_GL, SANLK_NAME_LEN);

	strncpy(rd2.rs.lockspace_name, ls->name, SANLK_NAME_LEN);
	strncpy(rd2.rs.name, R_NAME_GL_DISABLED, SANLK_NAME_LEN);

	rd1.rs.num_disks = 1;
	strncpy(rd1.rs.disks[0].path, lms->ss.host_id_disk.path, SANLK_PATH_LEN);
	rd1.rs.disks[0].offset = lms->align_size * GL_LOCK_BEGIN;

	rv = sanlock_acquire(lms->sock, -1, 0, 1, &rs1, NULL);
	if (rv < 0) {
		goto out;
	}

	rs_args[0] = rs1;
	rs_args[1] = rs2;

	rv = sanlock_release(lms->sock, -1, SANLK_REL_RENAME, 2, rs_args);
	if (rv < 0) {
	}

out:
	free(rs_args);
	return rv;
}

/*
 * enable/disable exist because each vg contains a global lock,
 * but we only want to use the gl from one of them.  The first
 * sanlock vg created, has its gl enabled, and subsequent
 * sanlock vgs have their gl disabled.  If the vg containing the
 * gl is removed, the gl from another sanlock vg needs to be
 * enabled.  Or, if gl in multiple vgs are somehow enabled, we
 * want to be able to disable one of them.
 *
 * Disable works by naming/renaming the gl resource to have a
 * name that is different from the predefined name.
 * When a host attempts to acquire the gl with its standard
 * predefined name, it will fail because the resource's name
 * on disk doesn't match.
 */

int lm_able_gl_sanlock(struct lockspace *ls, int enable)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct sanlk_resourced rd;
	const char *gl_name;
	int rv;

	if (enable)
		gl_name = R_NAME_GL;
	else
		gl_name = R_NAME_GL_DISABLED;

	memset(&rd, 0, sizeof(rd));

	strncpy(rd.rs.lockspace_name, ls->name, SANLK_NAME_LEN);
	strncpy(rd.rs.name, gl_name, SANLK_NAME_LEN);

	rd.rs.num_disks = 1;
	strncpy(rd.rs.disks[0].path, lms->ss.host_id_disk.path, SANLK_PATH_LEN);
	rd.rs.disks[0].offset = lms->align_size * GL_LOCK_BEGIN;

	rv = sanlock_write_resource(&rd.rs, 0, 0, 0);
	if (rv < 0) {
		log_error("able_gl_sanlock %d write_resource gl error %d %s",
			  enable, rv, rd.rs.disks[0].path);
		return rv;
	}

	log_debug("able_gl_sanlock %s %s", ls->name, gl_name);

	if (enable)
		strncpy(gl_lsname_sanlock, ls->name, MAX_NAME);

	if (!enable && !strcmp(gl_lsname_sanlock, ls->name))
		memset(gl_lsname_sanlock, 0, sizeof(gl_lsname_sanlock));

	return 0;
}

static int gl_is_enabled(struct lockspace *ls, struct lm_sanlock *lms)
{
	char strname[SANLK_NAME_LEN + 1];
	struct sanlk_resourced rd;
	uint64_t offset;
	int rv;

	memset(&rd, 0, sizeof(rd));

	strncpy(rd.rs.lockspace_name, ls->name, SANLK_NAME_LEN);

	/* leave rs.name empty, it is what we're checking */

	rd.rs.num_disks = 1;
	strncpy(rd.rs.disks[0].path, lms->ss.host_id_disk.path, SANLK_PATH_LEN);

	offset = lms->align_size * GL_LOCK_BEGIN;
	rd.rs.disks[0].offset = offset;

	rv = sanlock_read_resource(&rd.rs, 0);
	if (rv < 0) {
		log_error("gl_is_enabled read_resource error %d", rv);
		return rv;
	}

	memset(strname, 0, sizeof(strname));
	memcpy(strname, rd.rs.name, SANLK_NAME_LEN);

	if (!strcmp(strname, R_NAME_GL_DISABLED)) {
		return 0;
	}

	if (!strcmp(strname, R_NAME_GL)) {
		return 1;
	}

	log_error("gl_is_enabled invalid gl name %s", strname);
	return -1;
}

/*
 * host A: start_vg/add_lockspace
 * host B: vgremove
 *
 * The global lock cannot always be held around start_vg
 * on host A because the gl is in a vg that may not be
 * started yet, or may be in the vg we are starting.
 *
 * If B removes the vg, destroying the delta leases,
 * while A is a lockspace member, it will cause A's
 * sanlock delta lease renewal to fail, and lockspace
 * recovery.
 *
 * Possible way to mostly avoid problems:
 *
 * hostA: start_vg
 *
 * read vg metadata, lock_type/lock_args
 * read and verify vglk lease name
 * sanlock_add_lockspace reads valid delta lease
 * sanlock_add_lockspace done, A is a member
 * read and verify vglk lease name
 *
 * hostB: vgremove
 *
 * lock gl
 * lock vg ex
 * check sanlock for lockspace members
 * lock lv ex (all)
 * unlock lv ex (all)
 * unlock rename vglk
 * wait for max time that add_lockspace could take
 * check sanlock for lockspace members
 * sanlock_rem_lockspace
 * destroy delta leases
 * unlock gl
 * remove vg
 *
 * hostA will fail in one of the places where it verifies
 * the vglk lease name, or hostA will fail in one of the
 * places where it checks sanlock lockspace members.
 * And both can probably fail, but I suspect it would be
 * very unlikely for both to succeed.
 *
 * (I think a similar situation is start_vg vs changing lock_type
 *  from sanlock to something else.)
 */

int lm_add_lockspace_sanlock(struct lockspace *ls)
{
	struct lm_sanlock *lms;
	char lsname[SANLK_NAME_LEN + 1];
	int rv;

	lms = malloc(sizeof(struct lm_sanlock));
	if (!lms)
		return -ENOMEM;

	memset(lsname, 0, sizeof(lsname));
	strncpy(lsname, ls->name, SANLK_NAME_LEN);

	memcpy(lms->ss.name, lsname, SANLK_NAME_LEN);
	strncpy(lms->ss.host_id_disk.path, ls->lm_args, SANLK_PATH_LEN);
	lms->ss.host_id_disk.offset = 0;
	lms->ss.host_id = ls->host_id;

	lms->sock = sanlock_register();
	if (lms->sock < 0) {
		log_error("add_lockspace_sanlock register error %d", lms->sock);
		free(lms);
		return -1;
	}

	lms->align_size = sanlock_align(&lms->ss.host_id_disk);
	if (lms->align_size <= 0) {
		log_error("add_lockspace_sanlock align error %d", lms->align_size);
		close(lms->sock);
		free(lms);
		return -1;
	}

	rv = gl_is_enabled(ls, lms);
	if (rv < 0) {
		log_error("add_lockspace_sanlock gl_enabled error %d", rv);
		close(lms->sock);
		free(lms);
		return rv;
	}

	if (rv) {
		if (gl_use_dlm) {
			log_error("add_lockspace_sanlock: ignore %s gl for dlm gl",
				  lsname);
		} else if (gl_lsname_sanlock[0] && strcmp(gl_lsname_sanlock, lsname)) {
			log_error("add_lockspace_sanlock: multiple sanlock global locks current %s ignore %s",
				  gl_lsname_sanlock, lsname);
		} else {
			log_debug("add_lockspace_sanlock: use global lock in %s", lsname);
			strncpy(gl_lsname_sanlock, lsname, MAX_NAME);
		}
	}

	rv = sanlock_add_lockspace(&lms->ss, 0);
	if (rv < 0) {
		/* TODO: retry for some errors */
		log_error("add_lockspace_sanlock add_lockspace error %d", rv);
		close(lms->sock);
		free(lms);
		return rv;
	}

	log_debug("add_lockspace_sanlock %s done", lsname);

	ls->lm_data = lms;
	return 0;
}

int lm_rem_lockspace_sanlock(struct lockspace *ls)
{
	struct lm_sanlock *lms = ls->lm_data;
	int rv;

	rv = sanlock_rem_lockspace(&lms->ss, 0);
	if (rv < 0) {
		log_error("rem_lockspace_sanlock error %d", rv);
		return rv;
	}

	/* TODO: correct to assume this is only called by the
	   lockspace thread that did the add and uses the connection? */
	close(lms->sock);

	free(lms);
	ls->lm_data = NULL;
	return 0;
}

/*
 * lm_args is only needed for lv locks; it is the offset that lm_init_lv
 * used above, i.e. the disk offset where the lease for this lv resides.
 * (gl and vg locks exist at fixed, known offsets).
 *
 * If lm_args for lv was not provided, we try a linear search to find
 * the resource with a matching name.
 */

static int lm_add_resource_sanlock(struct lockspace *ls, struct resource *r,
				   char *lm_args)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds;
	uint64_t lm_args_offset;
	int rv;

	if (r->type == LD_RT_LV) {
		if (!strcmp(lm_args, "none")) {
			rv = find_lv_offset(ls, r, &lm_args_offset);
			if (rv < 0)
				return rv;
		} else {
			lm_args_offset = atoll(lm_args);
		}
	}

	rds = malloc(sizeof(struct rd_sanlock));
	if (!rds)
		return -ENOMEM;

	memset(rds, 0, sizeof(struct rd_sanlock));

	strncpy(rds->rs.lockspace_name, ls->name, SANLK_NAME_LEN);
	strncpy(rds->rs.name, r->name, SANLK_NAME_LEN);
	rds->rs.num_disks = 1;
	memcpy(rds->rs.disks[0].path, lms->ss.host_id_disk.path, SANLK_PATH_LEN);

	if (r->type == LD_RT_GL)
		rds->rs.disks[0].offset = GL_LOCK_BEGIN * lms->align_size;
	else if (r->type == LD_RT_VG)
		rds->rs.disks[0].offset = VG_LOCK_BEGIN * lms->align_size;
	else if (r->type == LD_RT_LV)
		rds->rs.disks[0].offset = lm_args_offset;

	log_debug("add_resource_sanlock %s offset %llu", r->name,
		  (unsigned long long)rds->rs.disks[0].offset);

	r->lm_data = rds;
	return 0;
}

static int lm_rem_resource_sanlock(struct lockspace *ls, struct resource *r)
{
	struct rd_sanlock *rds = r->lm_data;

	/* TODO: assert r->mode == UN or unlock if it's not? */

	free(rds);
	r->lm_data = NULL;
	return 0;
}

int lm_lock_sanlock(struct lockspace *ls, struct resource *r,
		    int ld_mode, char *lm_args, uint64_t *version)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds = r->lm_data;
	struct sanlk_resource *rs = &rds->rs;
	uint32_t flags = 0;
	struct val_blk vb;
	int lvb = (r->type == LD_RT_GL || r->type == LD_RT_VG);
	int added = 0;
	int rv;

	if (!r->lm_data) {
		rv = lm_add_resource_sanlock(ls, r, lm_args);
		if (rv < 0)
			return rv;
		rds = r->lm_data;
		rs = &rds->rs;
		added = 1;
	}

	if (ld_mode == LD_LK_SH)
		rs->flags |= SANLK_RES_SHARED;
	else
		rs->flags &= ~SANLK_RES_SHARED;

	log_debug("lock_sanlock %s %s", ls->name, r->name);

	if (lvb)
		flags |= SANLK_ACQUIRE_LVB;

	rv = sanlock_acquire(lms->sock, -1, flags, 1, &rs, NULL);
	if (rv < 0) {
		log_error("lock_sanlock %s %s acquire error %d",
			  ls->name, r->name, rv);

		if (added)
			lm_rem_resource_sanlock(ls, r);

		return rv;
	}

	if (lvb) {
		rv = sanlock_get_lvb(0, rs, (char *)&vb, sizeof(vb));
		if (rv < 0) {
			log_error("lock_sanlock %s %s get_lvb error %d",
				  ls->name, r->name, rv);
			*version = 0;
			return rv;
		}

		*version = le64_to_cpu(vb.mdver);

		log_debug("lock_sanlock get version %llu",
			  (unsigned long long)(*version));
	}

	return rv;
}

int lm_unlock_sanlock(struct lockspace *ls, struct resource *r, uint64_t version)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds = r->lm_data;
	struct sanlk_resource *rs = &rds->rs;
	struct val_blk vb;
	int lvb = (r->type == LD_RT_GL || r->type == LD_RT_VG);
	int rv;

	log_debug("unlock_sanlock %s %s", ls->name, r->name);

	if (lvb && (r->mode == LD_LK_EX)) {
		memset(&vb, 0, sizeof(vb));

		vb.mdver = cpu_to_le64(version);

		log_debug("unlock_sanlock set version %llu",
			  (unsigned long long)version);

		rv = sanlock_set_lvb(0, rs, (char *)&vb, sizeof(vb));
		if (rv < 0) {
			log_error("unlock_sanlock %s %s set_lvb error %d",
				  ls->name, r->name, rv);
		}
	}

	rv = sanlock_release(lms->sock, -1, 0, 1, &rs);
	if (rv < 0) {
		log_error("unlock_sanlock %s %s release error %d",
			  ls->name, r->name, rv);
	}

	return rv;
}

