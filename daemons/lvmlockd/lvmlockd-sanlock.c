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
#include "lvmlockd-client.h"

#include "sanlock.h"
#include "sanlock_rv.h"
#include "sanlock_admin.h"
#include "sanlock_resource.h"

/*
 * If access to the pv containing the vg's leases is lost, sanlock cannot renew
 * the leases we have acquired for locked LVs.  This means that we could soon
 * loose the lease to another host which could activate our LV exclusively.  We
 * do not want to get to the point of two hosts having the same LV active
 * exclusively (it obviously violates the purpose of LV locks.)
 *
 * The default method of preventing this problem is for lvmlockd to do nothing,
 * which produces a safe but potentially inconvenient result.  Doing nothing
 * leads to our LV leases not being released, which leads to sanlock using the
 * local watchdog to reset us before another host can acquire our lock.  It
 * would often be preferrable to avoid the abrupt hard reset from the watchdog.
 *
 * There are other options to avoid being reset by our watchdog.  If we can
 * quickly stop using the LVs in question and release the locks for them, then
 * we could avoid a reset (there's a certain grace period of about 40 seconds
 * in which we can attempt this.)  To do this, we can tell sanlock to run a
 * specific program when it has lost access to our leases.  We could use this
 * program to:
 *
 * 1. Deactivate all lvs in the effected vg.  If all the leases are
 * deactivated, then our LV locks would be released and sanlock would no longer
 * use the watchdog to reset us.  If file systems are mounted on the active
 * lvs, then deactivating them would fail, so this option would be of limited
 * usefulness.
 *
 * 2. Option 1 could be extended to kill pids using the fs on the lv, unmount
 * the fs, and deactivate the lv.  This is probably out of scope for lvm
 * directly, and would likely need the help of another system service.
 *
 * 3. Use dmsetup suspend to block access to lvs in the effected vg.  If this
 * was successful, the local host could no longer write to the lvs, we could
 * safely release the LV locks, and sanlock would no longer reset us.  At this
 * point, with suspended lvs, the host would be in a fairly hobbled state, and
 * would almost certainly need a manual, forcible reset.
 *
 * 4. Option 3 could be extended to monitor the lost storage, and if it is
 * reconnected, the leases could be reacquired, and the suspended lvs resumed
 * (reacquiring leases will fail if another host has acquired them since they
 * were released.)  This complexity of this option, combined with the fact that
 * the error conditions are often not as simple as storage being lost and then
 * later connecting, will result in this option being too unreliable.
 *
 * TODO: add a config option that we could use to select a different behavior
 * than the default.  Then implement one of the simpler options as a proof of
 * concept, which could be extended if needed.
 */

/*
 * Each lockspace thread has its own sanlock daemon connection.
 * If they shared one, sanlock acquire/release calls would be
 * serialized.  Some aspects of sanlock expect a single connection
 * from each pid: signals due to a sanlock_request, and
 * acquire/release/convert/inquire.  The later can probably be
 * addressed with a flag to indicate that the pid field should be
 * interpretted as 'ci' (which the caller would need to figure
 * out somehow.)
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
	struct val_blk *vb;
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
 * vgcreate
 *
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
	const char *gl_name = NULL;
	uint64_t offset;
	int align_size;
	int i, rv;

	memset(&ss, 0, sizeof(ss));
	memset(&rd, 0, sizeof(rd));
	memset(&disk, 0, sizeof(disk));
	memset(lock_lv_name, 0, sizeof(lock_lv_name));
	memset(lock_args_version, 0, sizeof(lock_args_version));

	if (!vg_args || !vg_args[0] || !strcmp(vg_args, "none")) {
		log_error("S %s init_vg_san vg_args missing", ls_name);
		return -EINVAL;
	}

	snprintf(lock_args_version, MAX_ARGS, "%u.%u.%u",
		 VG_LOCK_ARGS_MAJOR, VG_LOCK_ARGS_MINOR, VG_LOCK_ARGS_PATCH);

	/* see comment above about input vg_args being only lock_lv_name */
	snprintf(lock_lv_name, MAX_ARGS, "%s", vg_args);

	if (strlen(lock_lv_name) + strlen(lock_args_version) + 2 > MAX_ARGS)
		return -ENAMETOOLONG;

	snprintf(disk.path, SANLK_PATH_LEN, "/dev/mapper/%s-%s", vg_name, lock_lv_name);

	log_debug("S %s init_vg_san path %s", ls_name, disk.path);

	if (daemon_test) {
		if (!gl_lsname_sanlock[0])
			strncpy(gl_lsname_sanlock, ls_name, MAX_NAME);
		goto out;
	}

	align_size = sanlock_align(&disk);
	if (align_size <= 0) {
		log_error("S %s init_vg_san bad align size %d %s",
			  ls_name, align_size, disk.path);
		return -EINVAL;
	}

	strncpy(ss.name, ls_name, SANLK_NAME_LEN);
	memcpy(ss.host_id_disk.path, disk.path, SANLK_PATH_LEN);
	ss.host_id_disk.offset = LS_BEGIN * align_size;

	rv = sanlock_write_lockspace(&ss, 0, 0, 0);
	if (rv < 0) {
		log_error("S %s init_vg_san write_lockspace error %d %s",
			  ls_name, rv, ss.host_id_disk.path);
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
		log_error("S %s init_vg_san write_resource gl error %d %s",
			  ls_name, rv, rd.rs.disks[0].path);
		return rv;
	}

	memcpy(rd.rs.lockspace_name, ss.name, SANLK_NAME_LEN);
	strncpy(rd.rs.name, R_NAME_VG, SANLK_NAME_LEN);
	memcpy(rd.rs.disks[0].path, disk.path, SANLK_PATH_LEN);
	rd.rs.disks[0].offset = align_size * VG_LOCK_BEGIN;
	rd.rs.num_disks = 1;

	rv = sanlock_write_resource(&rd.rs, 0, 0, 0);
	if (rv < 0) {
		log_error("S %s init_vg_san write_resource vg error %d %s",
			  ls_name, rv, rd.rs.disks[0].path);
		return rv;
	}

	if (!strcmp(gl_name, R_NAME_GL))
		strncpy(gl_lsname_sanlock, ls_name, MAX_NAME);
 out:
	snprintf(vg_args, MAX_ARGS, "%s:%s", lock_args_version, lock_lv_name);

	log_debug("S %s init_vg_san done vg_args %s", ls_name, vg_args);

	/*
	 * Go through all lv resource slots and initialize them with the
	 * correct lockspace name but a special resource name that indicates
	 * it is unused.
	 */

	memset(&rd, 0, sizeof(rd));
	rd.rs.num_disks = 1;
	memcpy(rd.rs.disks[0].path, disk.path, SANLK_PATH_LEN);
	strncpy(rd.rs.lockspace_name, ls_name, SANLK_NAME_LEN);
	strcpy(rd.rs.name, "#unused");

	offset = align_size * LV_LOCK_BEGIN;

	log_debug("S %s init_vg_san clearing lv lease areas", ls_name);

	for (i = 0; i < LVMLOCKD_SANLOCK_MAX_LVS_IN_VG; i++) {
		rd.rs.disks[0].offset = offset;

		rv = sanlock_write_resource(&rd.rs, 0, 0, 0);
		if (rv) {
			log_error("clear lv resource area %llu error %d",
				  (unsigned long long)offset, rv);
			break;
		}
		offset += align_size;
	}

	return 0;
}

/*
 * lvcreate
 *
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
		log_error("S %s init_lv_san lock_lv_name_from_args error %d %s",
			  ls_name, rv, vg_args);
		return rv;
	}

	snprintf(lock_args_version, MAX_ARGS, "%u.%u.%u",
		 LV_LOCK_ARGS_MAJOR, LV_LOCK_ARGS_MINOR, LV_LOCK_ARGS_PATCH);

	strncpy(rd.rs.lockspace_name, ls_name, SANLK_NAME_LEN);
	rd.rs.num_disks = 1;
	snprintf(rd.rs.disks[0].path, SANLK_PATH_LEN, "/dev/mapper/%s-%s", vg_name, lock_lv_name);

	align_size = sanlock_align(&rd.rs.disks[0]);
	if (align_size <= 0) {
		log_error("S %s init_lv_san align error %d", ls_name, align_size);
		return -EINVAL;
	}

	offset = align_size * LV_LOCK_BEGIN;
	rd.rs.disks[0].offset = offset;

	if (daemon_test) {
		snprintf(lv_args, MAX_ARGS, "%s:%llu",
			 lock_args_version, (unsigned long long)1111);
		return 0;
	}

	while (1) {
		rd.rs.disks[0].offset = offset;

		memset(rd.rs.name, 0, SANLK_NAME_LEN);

		rv = sanlock_read_resource(&rd.rs, 0);
		if (rv) {
			log_error("S %s init_lv_san read error %d offset %llu",
				  ls_name, rv, (unsigned long long)offset);
			break;
		}

		if (!strncmp(rd.rs.name, lv_name, SANLK_NAME_LEN)) {
			log_error("S %s init_lv_san resource name %s already exists at %llu",
				  ls_name, lv_name, (unsigned long long)offset);
			return -EEXIST;
		}

		if (!strcmp(rd.rs.name, "#unused")) {
			log_debug("S %s init_lv_san %s found unused area at %llu",
				  ls_name, lv_name, (unsigned long long)offset);

			strncpy(rd.rs.name, lv_name, SANLK_NAME_LEN);

			rv = sanlock_write_resource(&rd.rs, 0, 0, 0);
			if (!rv) {
				snprintf(lv_args, MAX_ARGS, "%s:%llu",
				         lock_args_version, (unsigned long long)offset);
			} else {
				log_error("S %s init_lv_san write error %d offset %llu",
					  ls_name, rv, (unsigned long long)rv);
			}
			break;
		}

		offset += align_size;

		if (lv_count++ >= LVMLOCKD_SANLOCK_MAX_LVS_IN_VG) {
			log_error("S %s init_lv_san too many lvs %d", ls_name, lv_count);
			rv = -ENOENT;
			break;
		}
	}

	return rv;
}

/* lvremove */
int lm_free_lv_sanlock(struct lockspace *ls, struct resource *r)
{
	struct rd_sanlock *rds = r->lm_data;
	struct sanlk_resource *rs = &rds->rs;
	int rv;

	log_debug("S %s R %s free_lv_san", ls->name, r->name);

	if (daemon_test)
		return 0;

	strcpy(rs->name, "#unused");

	rv = sanlock_write_resource(rs, 0, 0, 0);
	if (rv < 0) {
		log_error("S %s R %s free_lv_san write error %d",
			  ls->name, r->name, rv);
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
		log_error("S %s able_gl %d write_resource gl error %d %s",
			  ls->name, enable, rv, rd.rs.disks[0].path);
		return rv;
	}

	log_debug("S %s able_gl %s", ls->name, gl_name);

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

int lm_gl_is_enabled(struct lockspace *ls)
{
	return gl_is_enabled(ls, ls->lm_data);
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
		log_error("S %s add_lockspace_san lock_lv_name_from_args error %d %s",
			  ls->name, rv, ls->vg_args);
		return rv;
	}

	snprintf(disk_path, SANLK_PATH_LEN, "/dev/mapper/%s-%s",
		 ls->vg_name, lock_lv_name);

	/*
	 * When a vg is started, the internal sanlock lv should be
	 * activated before lvmlockd is asked to add the lockspace.
	 * (sanlock needs to use the lv.)
	 *
	 * TODO: can we ask something on the system to activate the
	 * sanlock lv or should we just require that vgchange be used
	 * to start sanlock vgs?
	 * Should sanlock lvs be "auto-activated"?
	 */

	/* FIXME: remove this, device is not always ready for us here */
	sleep(1);

	rv = stat(disk_path, &st);
	if (rv < 0) {
		log_error("S %s add_lockspace_san stat error %d disk_path %s",
			  ls->name, errno, disk_path);
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

	if (daemon_test) {
		if (!gl_lsname_sanlock[0]) {
			log_debug("S %s add_lockspace_san use global lock in", lsname);
			strncpy(gl_lsname_sanlock, lsname, MAX_NAME);
		}
		goto out;
	}

	lms->sock = sanlock_register();
	if (lms->sock < 0) {
		log_error("S %s add_lockspace_san register error %d", lsname, lms->sock);
		free(lms);
		return -1;
	}

	rv = sanlock_restrict(lms->sock, SANLK_RESTRICT_SIGKILL);
	if (rv < 0) {
		log_error("S %s restrict error %d", lsname, rv);
	}

	lms->align_size = sanlock_align(&lms->ss.host_id_disk);
	if (lms->align_size <= 0) {
		log_error("S %s add_lockspace_san align error %d", lsname, lms->align_size);
		close(lms->sock);
		free(lms);
		return -1;
	}

	rv = gl_is_enabled(ls, lms);
	if (rv < 0) {
		log_error("S %s add_lockspace_san gl_enabled error %d", lsname, rv);
		close(lms->sock);
		free(lms);
		return rv;
	}

	if (rv) {
		if (gl_use_dlm) {
			log_error("S %s add_lockspace_san gl_use_dlm is set", lsname);
		} else if (gl_lsname_sanlock[0] && strcmp(gl_lsname_sanlock, lsname)) {
			log_error("S %s add_lockspace_san multiple sanlock global locks current %s",
				  lsname, gl_lsname_sanlock);
		} else {
			log_debug("S %s add_lockspace_san use global lock", lsname);
			strncpy(gl_lsname_sanlock, lsname, MAX_NAME);
		}
	}

	rv = sanlock_add_lockspace(&lms->ss, 0);
	if (rv < 0) {
		/* TODO: retry for some errors */
		log_error("S %s add_lockspace_san add_lockspace error %d", lsname, rv);
		close(lms->sock);
		free(lms);
		return rv;
	}
out:
	log_debug("S %s add_lockspace_san done", lsname);

	ls->lm_data = lms;
	return 0;
}

int lm_rem_lockspace_sanlock(struct lockspace *ls, int free_vg)
{
	struct lm_sanlock *lms = ls->lm_data;
	int rv;

	if (daemon_test)
		goto out;

	rv = sanlock_rem_lockspace(&lms->ss, 0);
	if (rv < 0) {
		log_error("S %s rem_lockspace_san error %d", ls->name, rv);
		return rv;
	}

	if (free_vg) {
		/*
		 * Destroy sanlock lockspace (delta leases).  Forces failure for any
		 * other host that is still using or attempts to use this lockspace.
		 * This shouldn't be generally necessary, but there may some races
		 * between nodes starting and removing a vg which this could help.
		 */
		strncpy(lms->ss.name, "#unused", SANLK_NAME_LEN);

		rv = sanlock_write_lockspace(&lms->ss, 0, 0, 0);
		if (rv < 0) {
			log_error("S %s rem_lockspace free_vg write_lockspace error %d %s",
				  ls->name, rv, lms->ss.host_id_disk.path);
		}
	}
out:
	close(lms->sock);

	free(lms);
	ls->lm_data = NULL;

	/* TODO: should we only clear gl_lsname when doing free_vg? */

	if (!strcmp(ls->name, gl_lsname_sanlock))
		memset(gl_lsname_sanlock, 0, sizeof(gl_lsname_sanlock));

	return 0;
}

#if 0
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
	memcpy(rd.rs.disks[0].path, lms->ss.host_id_disk.path, SANLK_PATH_LEN);

	align_size = sanlock_align(&rd.rs.disks[0]);
	if (align_size <= 0) {
		log_error("find_lv_offset align error %d", align_size);
		return -EINVAL;
	}

	offset = align_size * LV_LOCK_BEGIN;

	while (1) {
		rd.rs.disks[0].offset = offset;

		memset(rd.rs.name, 0, SANLK_NAME_LEN);

		rv = sanlock_read_resource(&rd.rs, 0);
		if (!rv) {
			if (!strncmp(rd.rs.name, r->name, SANLK_NAME_LEN)) {
				log_debug("S %s R %s find_lv_offset found at %llu",
					  ls->name, r->name, (unsigned long long)offset);

				*lv_args_offset = offset;
				return 0;
			}

			offset += align_size;

			if (lv_count++ >= LVMLOCKD_SANLOCK_MAX_LVS_IN_VG) {
				log_error("S %s R %s find_lv_offset too many lvs %d",
					  ls->name, r->name, lv_count);
				rv = -ENOENT;
				break;
			}
			continue;
		}
		if (rv != SANLK_LEADER_MAGIC) {
			log_error("S %s R %s find_lv_offset read error %d offset %llu",
				  ls->name, r->name, rv, (unsigned long long)offset);
			break;
		}

		/*
		 * an empty slot means no more resources, assuming that
		 * there are no gaps, so the lv was not found.
		 */

		log_debug("S %s R %s find_lv_offset not found", ls->name, r->name);
		rv = -ENOENT;
		break;
	}
	return rv;
}
#endif

static int lm_add_resource_sanlock(struct lockspace *ls, struct resource *r,
				   char *lv_args)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds;

#if 0
	uint64_t lock_lv_offset;
	int rv;
	/* This case shouldn't be needed, lv_args should always be provided AFAICS. */
	if ((r->type == LD_RT_LV) && (!lv_args[0] || !strcmp(lv_args, "none"))) {
		rv = find_lv_offset(ls, r, &lock_lv_offset);
		if (rv < 0)
			return rv;
	}
#endif

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

	/* LD_RT_LV offset is set in each lm_lock call from lv_args. */

	if (r->type == LD_RT_GL || r->type == LD_RT_VG) {
		rds->vb = malloc(sizeof(struct val_blk));
		if (!rds->vb) {
			free(rds);
			return -ENOMEM;
		}
		memset(rds->vb, 0, sizeof(struct val_blk));
	}

	r->lm_data = rds;
	return 0;
}

int lm_rem_resource_sanlock(struct lockspace *ls, struct resource *r)
{
	struct rd_sanlock *rds = r->lm_data;

	/* TODO: assert r->mode == UN or unlock if it's not? */

	if (!rds)
		return 0;
	if (rds->vb)
		free(rds->vb);
	free(rds);
	r->lm_data = NULL;
	return 0;
}

int lm_lock_sanlock(struct lockspace *ls, struct resource *r, int ld_mode, char *lv_args,
		    uint32_t *r_version, uint32_t *n_version, int *retry)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds;
	struct sanlk_resource *rs;
	uint64_t lock_lv_offset;
	uint32_t flags = 0;
	struct val_blk vb;
	uint16_t vb_version;
	int added = 0;
	int rv;

	if (!r->lm_data) {
		rv = lm_add_resource_sanlock(ls, r, lv_args);
		if (rv < 0)
			return rv;
		added = 1;
	}

	rds = r->lm_data;
	rs = &rds->rs;

	if (r->type == LD_RT_LV) {
		/* The lv may have been removed and recreated with a new lease
		   offset so we need to get the offset from lv_args each time
		   instead of reusing the value. */

		rv = check_args_version(lv_args, LV_LOCK_ARGS_MAJOR);
		if (rv < 0) {
			log_error("S %s R %s lock_san wrong lv_args version %s",
				  ls->name, r->name, lv_args);
			return rv;
		}

		rv = lock_lv_offset_from_args(lv_args, &lock_lv_offset);
		if (rv < 0) {
			log_error("S %s R %s lock_san lv_offset_from_args error %d %s",
				  ls->name, r->name, rv, lv_args);
			return rv;
		}

		if (!added && (rds->rs.disks[0].offset != lock_lv_offset)) {
			log_debug("S %s R %s lock_san offset old %llu new %llu",
				  ls->name, r->name,
				  (unsigned long long)rds->rs.disks[0].offset,
				  (unsigned long long)lock_lv_offset);
		}

		rds->rs.disks[0].offset = lock_lv_offset;
	}

	if (ld_mode == LD_LK_SH) {
		rs->flags |= SANLK_RES_SHARED;
	} else if (ld_mode == LD_LK_EX) {
		rs->flags &= ~SANLK_RES_SHARED;
	} else {
		log_error("lock_san invalid mode %d", ld_mode);
		return -EINVAL;
	}

	log_debug("S %s R %s lock_san", ls->name, r->name);

	if (daemon_test) {
		*r_version = 0;
		*n_version = 0;
		return 0;
	}

	if (rds->vb)
		flags |= SANLK_ACQUIRE_LVB;

	rv = sanlock_acquire(lms->sock, -1, flags, 1, &rs, NULL);

	if (rv == -EAGAIN) {
		/*
		 * It appears that sanlock_acquire returns EAGAIN when we request
		 * a shared lock but the lock is held ex by another host.
		 * There's no point in retrying this case, just return an error.
		 *
		 * TODO: verify the sanlock behavior here.
		 */
		log_debug("S %s R %s lock_san acquire mode %d rv EAGAIN", ls->name, r->name, ld_mode);
		*retry = 0;
		return -EAGAIN;
	}

	if (rv == SANLK_ACQUIRE_IDLIVE || rv == SANLK_ACQUIRE_OWNED || rv == SANLK_ACQUIRE_OTHER) {
		/*
		 * The lock is held by another host.  These failures can
		 * happen while multiple hosts are concurrently acquiring
		 * shared locks.  We want to retry a couple times in this
		 * case because we'll probably get the sh lock.
		 *
		 * I believe these are also the errors when requesting an
		 * ex lock that another host holds ex.  We want to report
		 * something like: "lock is held by another host" in this case.
		 * Retry is pointless here.
		 *
		 * We can't distinguish between the two cases above,
		 * so if requesting a sh lock, retry a couple times,
		 * otherwise don't.
		 *
		 * TODO: verify sanlock behavior here.
		 */
		log_debug("S %s R %s lock_san acquire mode %d rv %d", ls->name, r->name, ld_mode, rv);
		*retry = (ld_mode == LD_LK_SH) ? 1 : 0;
		return -EAGAIN;
	}

	if (rv < 0) {
		log_error("S %s R %s lock_san acquire error %d",
			  ls->name, r->name, rv);

		if (added) {
			lm_rem_resource_sanlock(ls, r);
			return rv;
		}

		/* if the gl has been disabled, remove and free the gl resource */
		if ((rv == SANLK_LEADER_RESOURCE) && (r->type == LD_RT_GL)) {
			if (!lm_gl_is_enabled(ls)) {
				log_error("S %s R %s lock_san gl has been disabled",
					  ls->name, r->name);
				if (!strcmp(gl_lsname_sanlock, ls->name))
					memset(gl_lsname_sanlock, 0, sizeof(gl_lsname_sanlock));
				return -EUNATCH;
			}
		}

		return rv;
	}

	if (rds->vb) {
		rv = sanlock_get_lvb(0, rs, (char *)&vb, sizeof(vb));
		if (rv < 0) {
			log_error("S %s R %s lock_san get_lvb error %d", ls->name, r->name, rv);
			*r_version = 0;
			*n_version = 0;
			goto out;
		}

		vb_version = le16_to_cpu(vb.version);

		if (vb_version && ((vb_version & 0xFF00) > (VAL_BLK_VERSION & 0xFF00))) {
			log_error("S %s R %s lock_san ignore vb_version %x",
				  ls->name, r->name, vb_version);
			*r_version = 0;
			free(rds->vb);
			rds->vb = NULL;
			goto out;
		}

		*r_version = le32_to_cpu(vb.r_version);
		*n_version = le32_to_cpu(vb.n_version);
		memcpy(rds->vb, &vb, sizeof(vb)); /* rds->vb saved as le */

		log_debug("S %s R %s lock_san get r_version %u n_version %u",
			  ls->name, r->name, *r_version, *n_version);
	}
out:
	return rv;
}

int lm_convert_sanlock(struct lockspace *ls, struct resource *r,
		       int ld_mode, uint32_t r_version)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds = r->lm_data;
	struct sanlk_resource *rs = &rds->rs;
	struct val_blk vb;
	uint32_t flags = 0;
	int rv;

	log_debug("S %s R %s convert_san", ls->name, r->name);

	if (daemon_test)
		goto rs_flag;

	if (rds->vb && r_version && (r->mode == LD_LK_EX)) {
		if (!rds->vb->version) {
			/* first time vb has been written */
			rds->vb->version = cpu_to_le16(VAL_BLK_VERSION);
		}
		if (r_version)
			rds->vb->r_version = cpu_to_le32(r_version);
		memcpy(&vb, rds->vb, sizeof(vb));

		log_debug("S %s R %s convert_san set r_version %u",
			  ls->name, r->name, r_version);

		rv = sanlock_set_lvb(0, rs, (char *)&vb, sizeof(vb));
		if (rv < 0) {
			log_error("S %s R %s convert_san set_lvb error %d",
				  ls->name, r->name, rv);
		}
	}

 rs_flag:
	if (ld_mode == LD_LK_SH)
		rs->flags |= SANLK_RES_SHARED;
	else
		rs->flags &= ~SANLK_RES_SHARED;

	if (daemon_test)
		return 0;

	rv = sanlock_convert(lms->sock, -1, flags, rs);
	if (rv == -EAGAIN) {
		/* TODO: what case is this? what should be done? */
		log_error("S %s R %s convert_san EAGAIN", ls->name, r->name);
		return -EAGAIN;
	}
	if (rv < 0) {
		log_error("S %s R %s convert_san convert error %d", ls->name, r->name, rv);
	}

	return rv;
}

static int release_rename(struct lockspace *ls, struct resource *r)
{
	struct rd_sanlock rd1;
	struct rd_sanlock rd2;
	struct sanlk_resource *res1;
	struct sanlk_resource *res2;
	struct sanlk_resource **res_args;
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds = r->lm_data;
	int rv;

	log_debug("S %s R %s release rename", ls->name, r->name);

	res_args = malloc(2 * sizeof(struct sanlk_resource *));
	if (!res_args)
		return -ENOMEM;

	memcpy(&rd1, rds, sizeof(struct rd_sanlock));
	memcpy(&rd2, rds, sizeof(struct rd_sanlock));

	res1 = (struct sanlk_resource *)&rd1;
	res2 = (struct sanlk_resource *)&rd2;

	strcpy(res2->name, "invalid_removed");

	res_args[0] = res1;
	res_args[1] = res2;

	rv = sanlock_release(lms->sock, -1, SANLK_REL_RENAME, 2, res_args);
	if (rv < 0) {
		log_error("S %s R %s unlock_san release rename error %d", ls->name, r->name, rv);
	}

	free(res_args);

	return rv;
}

/*
 * rds->vb is stored in le
 * 
 * r_version is r->version
 *
 * for GL locks lvmlockd just increments this value
 * each time the global lock is released from ex.
 *
 * for VG locks it is the seqno from the vg metadata.
 *
 * n_version is r->names_version
 *
 * n_version is only used in gl locks.
 * lvmlockd increments this value each time
 * the global lock is released from ex by a
 * command that changes the list of vgs.
 */

int lm_unlock_sanlock(struct lockspace *ls, struct resource *r,
		      uint32_t r_version, uint32_t n_version, uint32_t lmu_flags)
{
	struct lm_sanlock *lms = ls->lm_data;
	struct rd_sanlock *rds = r->lm_data;
	struct sanlk_resource *rs = &rds->rs;
	struct val_blk vb;
	int rv;

	log_debug("S %s R %s unlock_san r_version %u flags %x",
		  ls->name, r->name, r_version, lmu_flags);

	if (daemon_test)
		return 0;

	if (rds->vb && r_version && (r->mode == LD_LK_EX)) {
		if (!rds->vb->version) {
			/* first time vb has been written */
			rds->vb->version = cpu_to_le16(VAL_BLK_VERSION);
		}
		if (r_version)
			rds->vb->r_version = cpu_to_le32(r_version);
		if (n_version)
			rds->vb->n_version = cpu_to_le32(n_version);
		memcpy(&vb, rds->vb, sizeof(vb));

		log_debug("S %s R %s unlock_san set r_version %u n_version %u",
			  ls->name, r->name, r_version, n_version);

		rv = sanlock_set_lvb(0, rs, (char *)&vb, sizeof(vb));
		if (rv < 0) {
			log_error("S %s R %s unlock_san set_lvb error %d",
				  ls->name, r->name, rv);
		}
	}

	/*
	 * For vgremove (FREE_VG) we unlock-rename the vg and gl locks
	 * so they cannot be reacquired.
	 */
	if ((lmu_flags & LMUF_FREE_VG) &&
	    (r->type == LD_RT_GL || r->type == LD_RT_VG)) {
		return release_rename(ls, r);
	}

	rv = sanlock_release(lms->sock, -1, 0, 1, &rs);
	if (rv < 0) {
		log_error("S %s R %s unlock_san release error %d", ls->name, r->name, rv);
	}

	return rv;
}

int lm_hosts_sanlock(struct lockspace *ls, int notify)
{
	struct sanlk_host *hss = NULL;
	struct sanlk_host *hs;
	uint32_t state;
	int hss_count = 0;
	int found_self = 0;
	int found_others = 0;
	int i, rv;

	rv = sanlock_get_hosts(ls->name, 0, &hss, &hss_count, 0);
	if (rv < 0) {
		log_error("S %s hosts_san get_hosts error %d", ls->name, rv);
		return 0;
	}

	if (!hss || !hss_count) {
		log_error("S %s hosts_san zero hosts", ls->name);
		return 0;
	}

	hs = hss;

	for (i = 0; i < hss_count; i++) {
		log_debug("S %s hosts_san host_id %llu gen %llu flags %x",
			  ls->name,
			  (unsigned long long)hs->host_id,
			  (unsigned long long)hs->generation,
			  hs->flags);

		if (hs->host_id == ls->host_id) {
			found_self = 1;
			continue;
		}

		state = hs->flags & SANLK_HOST_MASK;
		if (state == SANLK_HOST_LIVE)
			found_others++;
		hs++;
	}
	free(hss);

	if (found_others && notify) {
#if 0
		struct sanlk_host_event he;
		memset(&he, 0, sizeof(he));
		hm.host_id = 1;
		hm.generation = 0;
		hm.event = EVENT_VGSTOP;
		sanlock_set_event(ls->name, &he, SANLK_SETEV_ALL_HOSTS);
#endif
		/*
		 * We'll need to retry for a while before all the hosts see
		 * this event and stop the vg.
		 * We'll need to register for events from the lockspace
		 * and add the registered fd to our poll set.
		 */
	}

	if (!found_self) {
		log_error("S %s hosts_san self not found others %d", ls->name, found_others);
		return 0;
	}

	return found_others;
}

