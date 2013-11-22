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

#include "daemon-server.h"
#include "daemon-log.h"

#include "lvmlockd-internal.h"

#include "sanlock.h"
#include "sanlock_rv.h"
#include "sanlock_admin.h"
#include "sanlock_resource.h"

#define lock_args_version "1.0.0"

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
 * lock_args format
 *
 * vg_lock_args format for sanlock is
 * vg_version_string:undefined:lock_lv_name
 *
 * lv_lock_args format for sanlock is
 * lv_version_string:undefined:offset
 *
 * version_string is MAJOR.MINOR.PATCH
 * undefined may contain ":"
 *
 * If a new version of the lock_args string cannot be
 * handled by an old version of lvmlockd, then the
 * new lock_args string should contain a larger major number.
 */

#define VG_LOCK_ARGS_MAJOR 1
#define VG_LOCK_ARGS_MINOR 0
#define VG_LOCK_ARGS_PATCH 0

#define LV_LOCK_ARGS_MAJOR 1
#define LV_LOCK_ARGS_MINOR 0
#define LV_LOCK_ARGS_PATCH 0

/*
 * offset 0 is lockspace
 * offset align_size * 1 is unused
 * offset align_size * 2 is unused
 * ...
 * offset align_size * 64 is unused
 * offset align_size * 65 is gl lock
 * offset align_size * 66 is vg lock
 * offset align_size * 67 is first lv lock
 * offset align_size * 68 is second lv lock
 * ...
 */

#define LS_BEGIN 0
#define GL_LOCK_BEGIN 65
#define VG_LOCK_BEGIN 66
#define LV_LOCK_BEGIN 67

static int lock_lv_name_from_args(char *vg_args, char *lock_lv_name)
{
	return last_string_from_args(vg_args, lock_lv_name);
}

static int lock_lv_offset_from_args(char *lv_args, uint64_t *lock_lv_offset)
{
	char offset_str[MAX_ARGS];
	int rv;

	memset(offset_str, 0, sizeof(offset_str));

	rv = last_string_from_args(lv_args, offset_str);
	if (rv < 0)
		return rv;

	*lock_lv_offset = strtoull(offset_str, NULL, 10);
	return 0;
}

static int check_args_version(char *args, unsigned int our_major)
{
	unsigned int major = 0;
	int rv;

	rv = version_from_args(args, &major, NULL, NULL);
	if (rv < 0) {
		log_error("check_args_version %s error %d", args, rv);
		return rv;
	}

	if (major > our_major) {
		log_error("check_args_version %s major %u %u", args, major, our_major);
		return -1;
	}

	return 0;
}

/*
 * For init_vg, vgcreate passes the internal lv name as vg_args.
 * This constructs the full/proper vg_args format, containing the
 * version and lv name, and returns the real lock_args in vg_args.
 */

int lm_init_vg_sanlock(char *ls_name, char *vg_name, uint32_t flags, char *vg_args)
{
	struct sanlk_lockspace ss;
	struct sanlk_resourced rd;
	struct sanlk_disk disk;
	char lock_lv_name[MAX_ARGS];
	char lock_args_version[MAX_ARGS];
	const char *gl_name;
	int align_size;
	int rv;

	memset(&ss, 0, sizeof(ss));
	memset(&rd, 0, sizeof(rd));
	memset(&disk, 0, sizeof(disk));
	memset(lock_lv_name, 0, sizeof(lock_lv_name));
	memset(lock_args_version, 0, sizeof(lock_args_version));

	if (!vg_args || !vg_args[0] || !strcmp(vg_args, "none")) {
		log_error("init_vg_sanlock vg_args missing");
		return -EINVAL;
	}

	snprintf(lock_args_version, MAX_ARGS, "%u.%u.%u",
		 VG_LOCK_ARGS_MAJOR, VG_LOCK_ARGS_MINOR, VG_LOCK_ARGS_PATCH);

	/* see comment above about input vg_args being only lock_lv_name */
	snprintf(lock_lv_name, MAX_ARGS, "%s", vg_args);

	if (strlen(lock_lv_name) + strlen(lock_args_version) + 2 > MAX_ARGS)
		return -ENAMETOOLONG;

	snprintf(disk.path, SANLK_PATH_LEN, "/dev/%s/%s", vg_name, lock_lv_name);

	log_debug("init_vg_sanlock %s path %s", ls_name, disk.path);

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

	if (!strcmp(gl_name, R_NAME_GL))
		strncpy(gl_lsname_sanlock, ls_name, MAX_NAME);

	snprintf(vg_args, MAX_ARGS, "%s:%s", lock_args_version, lock_lv_name);

	log_debug("init_vg_sanlock done %s vg_args %s", ls_name, vg_args);

	return 0;
}

/*
 * The offset at which the lv lease is written is passed
 * all the way back to the lvcreate command so that it
 * can be saved in the lv's lock_args in the vg metadata.
 */

int lm_init_lv_sanlock(char *ls_name, char *vg_name, char *lv_name,
		       char *vg_args, char *lv_args)
{
	struct sanlk_resourced rd;
	char lock_lv_name[MAX_ARGS];
	char lock_args_version[MAX_ARGS];
	uint64_t offset;
	int align_size;
	int lv_count = 0;
	int rv;

	memset(&rd, 0, sizeof(rd));
	memset(lock_lv_name, 0, sizeof(lock_lv_name));
	memset(lock_args_version, 0, sizeof(lock_args_version));

	rv = lock_lv_name_from_args(vg_args, lock_lv_name);
	if (rv < 0) {
		log_error("lm_init_lv_sanlock lock_lv_name_from_args error %d %s", rv, vg_args);
		return rv;
	}

	snprintf(lock_args_version, MAX_ARGS, "%u.%u.%u",
		 LV_LOCK_ARGS_MAJOR, LV_LOCK_ARGS_MINOR, LV_LOCK_ARGS_PATCH);

	strncpy(rd.rs.lockspace_name, ls_name, SANLK_NAME_LEN);
	rd.rs.num_disks = 1;
	snprintf(rd.rs.disks[0].path, SANLK_PATH_LEN, "/dev/%s/%s", vg_name, lock_lv_name);

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
		if (!rv) {
			snprintf(lv_args, MAX_ARGS, "%s:%llu",
				 lock_args_version, (unsigned long long)offset);
		} else {
			log_error("init_lv_sanlock write error %d offset %llu",
				  rv, (unsigned long long)rv);
		}
		break;
	}
	return rv;
}

static int find_lv_offset(struct lockspace *ls, struct resource *r,
			  uint64_t *lv_args_offset)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct sanlk_resourced rd;
	uint64_t offset;
	int align_size;
	int lv_count = 0;
	int rv;

	memset(&rd, 0, sizeof(rd));

	strncpy(rd.rs.lockspace_name, ls->name, SANLK_NAME_LEN);
	rd.rs.num_disks = 1;
	memcpy(rds.rs.disks[0].path, lms->ss.host_id_disk.path, SANLK_PATH_LEN);

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

				*lv_args_offset = offset;
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
	struct stat st;
	struct lm_sanlock *lms;
	char lock_lv_name[MAX_ARGS];
	char lsname[SANLK_NAME_LEN + 1];
	char disk_path[SANLK_PATH_LEN];
	int rv;

	memset(disk_path, 0, sizeof(disk_path));
	memset(lock_lv_name, 0, sizeof(lock_lv_name));

	rv = check_args_version(ls->vg_args, VG_LOCK_ARGS_MAJOR);
	if (rv < 0)
		return rv;

	rv = lock_lv_name_from_args(ls->vg_args, lock_lv_name);
	if (rv < 0) {
		log_error("lm_add_lockspace_sanlock lock_lv_name_from_args error %d %s", rv, vg_args);
		return rv;
	}

	snprintf(disk_path, SANLK_PATH_LEN, "/dev/%s/%s",
		 ls->vg_name, lock_lv_name);

	/*
	 * When a vg is started, the internal sanlock lv should be
	 * activated before lvmlockd is asked to add the lockspace.
	 * (sanlock needs to use the lv.)
	 * This is what 'vgchange --lock-vg start' does.
	 * It means that START_ALL/start_lockspaces will fail to
	 * start sanlock vg's if the sanlock lv has not been
	 * activated somehow.
	 *
	 * TODO: can we ask something on the system to activate the
	 * sanlock lv or should we just require that vgchange be used
	 * to start sanlock vgs?  Should lvmlockd have a special thread
	 * dedicated to forking/running lvm commands like this?
	 * Should sanlock lvs be "auto-activated"?
	 */
	rv = stat(disk_path, &st);
	if (rv < 0) {
		log_error("add_lockspace_sanlock stat error %d disk_path %s", errno, disk_path);
		return -1;
	}

	lms = malloc(sizeof(struct lm_sanlock));
	if (!lms)
		return -ENOMEM;

	memset(lsname, 0, sizeof(lsname));
	strncpy(lsname, ls->name, SANLK_NAME_LEN);

	memcpy(lms->ss.name, lsname, SANLK_NAME_LEN);
	lms->ss.host_id_disk.offset = 0;
	lms->ss.host_id = ls->host_id;
	strncpy(lms->ss.host_id_disk.path, disk_path, SANLK_PATH_LEN);

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

static int lm_add_resource_sanlock(struct lockspace *ls, struct resource *r,
				   char *lv_args)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds;
	uint64_t lock_lv_offset;
	int rv;

	if (r->type == LD_RT_LV) {
		if (!lv_args[0] || !strcmp(lv_args, "none")) {
			/* this case shouldn't be needed, lv_args should be provided */
			rv = find_lv_offset(ls, r, &lock_lv_offset);
			if (rv < 0)
				return rv;
		} else {
			rv = check_args_version(lv_args, LV_LOCK_ARGS_MAJOR);
			if (rv < 0)
				return rv;

			rv = lock_lv_offset_from_args(lv_args, &lock_lv_offset);
			if (rv < 0) {
				log_error("lm_add_resource_sanlock bad offset from args");
				return rv;
			}
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
		rds->rs.disks[0].offset = lock_lv_offset;

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
		    int ld_mode, char *lv_args, uint64_t *val)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds = r->lm_data;
	struct sanlk_resource *rs = &rds->rs;
	uint32_t version;
	uint32_t flags = 0;
	struct val_blk vb;
	int lvb = (r->type == LD_RT_GL || r->type == LD_RT_VG);
	int added = 0;
	int rv;

	if (!r->lm_data) {
		rv = lm_add_resource_sanlock(ls, r, lv_args);
		if (rv < 0)
			return rv;
		rds = r->lm_data;
		rs = &rds->rs;
		added = 1;
	}

	if (ld_mode == LD_LK_SH) {
		rs->flags |= SANLK_RES_SHARED;
	} else if (ld_mode == LD_LK_EX) {
		rs->flags &= ~SANLK_RES_SHARED;
	} else {
		log_error("lm_lock_sanlock invalid mode %d", ld_mode);
		return -EINVAL;
	}

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

		version = le32_to_cpu(vb.version);

		/* Larger major version number is not compatible. */
		if ((version & 0xFFFF0000) > (VAL_BLK_VERSION & 0xFFFF0000)) {
			log_error("ignoring incompatible val blk version %x", version);
		} else {
			*val = le64_to_cpu(vb.val);

			log_debug("lock_sanlock get version %llu",
				  (unsigned long long)(*val));
		}
	}

	return rv;
}

int lm_convert_sanlock(struct lockspace *ls, struct resource *r,
		       int ld_mode, uint64_t val)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds = r->lm_data;
	struct sanlk_resource *rs = &rds->rs;
	struct val_blk vb;
	uint32_t flags = 0;
	int lvb = (r->type == LD_RT_GL || r->type == LD_RT_VG);
	int rv;

	log_debug("convert_sanlock %s %s", ls->name, r->name);

	if (lvb && (r->mode == LD_LK_EX)) {
		memset(&vb, 0, sizeof(vb));

		vb.version = cpu_to_le32(VAL_BLK_VERSION);
		vb.val = cpu_to_le64(val);

		log_debug("convert_sanlock set version %llu",
			  (unsigned long long)version);

		rv = sanlock_set_lvb(0, rs, (char *)&vb, sizeof(vb));
		if (rv < 0) {
			log_error("convert_sanlock %s %s set_lvb error %d",
				  ls->name, r->name, rv);
		}
	}

	if (ld_mode == LD_LK_SH)
		rs->flags |= SANLK_RES_SHARED;
	else
		rs->flags &= ~SANLK_RES_SHARED;

	rv = sanlock_convert(lms->sock, -1, flags, &rs);
	if (rv == -EAGAIN)
		return -EAGAIN;
	if (rv < 0) {
		log_error("convert_sanlock %s %s convert error %d",
			  ls->name, r->name, rv);
	}

	return rv;
}

int lm_unlock_sanlock(struct lockspace *ls, struct resource *r, uint64_t val)
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

		vb.version = cpu_to_le32(VAL_BLK_VERSION);
		vb.val = cpu_to_le64(val);

		log_debug("unlock_sanlock set val %llu", (unsigned long long)val);

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

