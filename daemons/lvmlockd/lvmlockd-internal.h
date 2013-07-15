/*
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 */


#ifndef _LVM_LVMLOCKD_INTERNAL_H
#define _LVM_LVMLOCKD_INTERNAL_H

/* TODO: figure out real restraints/requirements for these */
#define MAX_NAME 64
#define MAX_ARGS 64

/* TODO: get this from somewhere else? is this a good number? */
#define MAX_LVS_IN_VG 128

#define R_NAME_GL_DISABLED "_gl_lock_disabled"
#define R_NAME_GL          "gl_lock"
#define R_NAME_VG          "vg_lock"

/* lock manager types */
enum {
	LD_LM_DLM = 1,
	LD_LM_SANLOCK,
};

/* operation types */
enum {
	LD_OP_TEST = 1,
	LD_OP_INIT,
	LD_OP_FREE,
	LD_OP_START,
	LD_OP_STOP,
	LD_OP_STOP_ALL,
	LD_OP_LOCK,
	LD_OP_UPDATE,
	LD_OP_CLOSE,
	LD_OP_ENABLE,
	LD_OP_DISABLE,
};

/* resource types */
enum {
	LD_RT_GL = 1,
	LD_RT_VG,
	LD_RT_LV,
};

/* lock modes, more restrictive must be larger value */
enum {
	LD_LK_UN = 0,
	LD_LK_NL = 1,
	LD_LK_SH = 2,
	LD_LK_EX = 3,
};

struct client {
	struct list_head list;
	pthread_mutex_t mutex;
	int pid;
	int fd;
	int pi;
	uint32_t id;
	unsigned int recv : 1;
	unsigned int dead : 1;
	unsigned int poll_ignore : 1;
	char name[MAX_NAME];
};

#define LD_AF_PERSISTENT    0x00000001
#define LD_AF_CLIENT_DEAD   0x00000002
#define LD_AF_UNLOCK_CANCEL 0x00000004
#define LD_AF_NEXT_VERSION  0x00000008
#define LD_AF_WAIT          0x00000010
#define LD_AF_FORCE         0x00000020
#define LD_AF_EX_DISABLE    0x00000040

struct action {
	struct list_head list;
	uint32_t client_id;
	uint32_t flags;			/* LD_AF_ */
	uint64_t version;
	int8_t op;			/* operation type LD_OP_ */
	int8_t rt;			/* resource type LD_RT_ */
	int8_t mode;			/* lock mode LD_LK_ */
	int8_t lm_type;			/* lock manager: LM_DLM, LM_SANLOCK */
	int retries;
	int result;
	char vg_uuid[64];
	char vg_name[MAX_NAME+1];
	char lv_name[MAX_NAME+1];
	char lm_args[MAX_ARGS];		/* lock manager specific args */
};

struct resource {
	struct list_head list;		/* lockspace.resources */
	char name[MAX_NAME+1];		/* vg name or lv name */
	int8_t type;			/* resource type LD_RT_ */
	int8_t mode;
	unsigned int sh_count;		/* number of sh locks on locks list */
	uint64_t version;
	struct list_head locks;
	struct list_head actions;
	void *lm_data;
};

#define LD_LF_PERSISTENT 0x00000001

struct lock {
	struct list_head list;		/* resource.locks */
	int8_t mode;			/* lock mode LD_LK_ */
	uint64_t version;
	uint32_t flags;			/* LD_LF_ */
	uint32_t client_id; /* may be 0 for persistent or internal locks */
};

struct lockspace {
	struct list_head list;		/* lockspaces */
	char name[MAX_NAME+1];
	char vg_uuid[64];

	int8_t lm_type;			/* lock manager: LM_DLM, LM_SANLOCK */
	char lm_args[MAX_ARGS];		/* lock manager specific args */
	void *lm_data;
	uint64_t host_id;

	pthread_t thread;		/* makes synchronous lock requests */
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	unsigned int create_fail : 1;
	unsigned int create_done : 1;
	unsigned int thread_work : 1;
	unsigned int thread_stop : 1;
	unsigned int thread_done : 1;

	struct list_head actions;	/* new client actions */
	struct list_head resources;	/* resource/lock state for gl/vg/lv */
};

struct val_blk {
	uint32_t version;
	uint32_t flags;
	uint64_t mdver;
};

int lockspaces_empty(void);

int lm_add_lockspace_dlm(struct lockspace *ls);
int lm_rem_lockspace_dlm(struct lockspace *ls);
int lm_lock_dlm(struct lockspace *ls, struct resource *r, int ld_mode, uint64_t *version);
int lm_unlock_dlm(struct lockspace *ls, struct resource *r, uint64_t version);

int lm_init_vg_sanlock(char *ls_name, char *lm_args);
int lm_init_lv_sanlock(char *ls_name, char *lv_name, char *ls_lm_args, char *res_lm_args);
int lm_add_lockspace_sanlock(struct lockspace *ls);
int lm_rem_lockspace_sanlock(struct lockspace *ls);
int lm_lock_sanlock(struct lockspace *ls, struct resource *r, int ld_mode,
		    char *lm_args, uint64_t *version);
int lm_unlock_sanlock(struct lockspace *ls, struct resource *r, uint64_t version);
int lm_able_gl_sanlock(struct lockspace *ls, int enable);

/* TODO: logging */

#define log_debug(fmt, args...) \
do { \
        if (daemon_debug) \
                printf("D " fmt "\n", ##args); \
} while (0)

#define log_error(fmt, args...) \
do { \
        if (daemon_debug) \
                printf("E " fmt "\n", ##args); \
} while (0)

#if __BYTE_ORDER == __BIG_ENDIAN
#define le16_to_cpu(x) (bswap_16((x)))
#define le32_to_cpu(x) (bswap_32((x)))
#define le64_to_cpu(x) (bswap_64((x)))
#define cpu_to_le16(x) (bswap_16((x)))
#define cpu_to_le32(x) (bswap_32((x)))
#define cpu_to_le64(x) (bswap_64((x)))
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#endif

/* to improve readability */
#define WAIT     1
#define NO_WAIT  0
#define FORCE    1
#define NO_FORCE 0

/*
 * global variables
 */

#ifndef EXTERN
#define EXTERN extern
#else
#undef EXTERN
#define EXTERN
#endif

EXTERN int daemon_debug;

/*
 * gl_type_static and gl_use_ are set by command line or config file
 * to specify whether the global lock comes from dlm or sanlock.
 * Without a static setting, lvmlockd will figure out where the
 * global lock should be (but it could get mixed up in cases where
 * both sanlock and dlm vgs exist.)
 *
 * gl_use_dlm means that the gl should come from lockspace gl_lsname_dlm
 * gl_use_sanlock means that the gl should come from lockspace gl_lsname_sanlock
 *
 * gl_use_dlm has precedence over gl_use_sanlock, so if a node sees both
 * dlm and sanlock vgs, it will use the dlm gl.
 *
 * gl_use_ is set when the first evidence of that lm_type is seen
 * in any command.
 *
 * gl_lsname_sanlock is set when the first vg is seen in which an
 * enabled gl is exists, or when init_vg creates a vg with gl enabled,
 * or when enable_gl is used.
 *
 * gl_lsname_sanlock is cleared when free_vg deletes a vg with gl enabled
 * or when disable_gl matches.
 */

EXTERN int gl_type_static;
EXTERN int gl_use_dlm;
EXTERN int gl_use_sanlock;

EXTERN char gl_lsname_dlm[MAX_NAME+1];
EXTERN char gl_lsname_sanlock[MAX_NAME+1];

EXTERN int gl_running_dlm;
EXTERN int gl_auto_dlm;

#endif
