/*
 * Copyright (C) 2013 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 */

int lock_type_to_num(char *lock_type)
{
	if (!lock_type)
		return LOCK_TYPE_NONE;
	if (!strcmp(lock_type, "none"))
		return LOCK_TYPE_NONE;
	if (!strcmp(lock_type, "local"))
		return LOCK_TYPE_LOCK;
	if (!strcmp(lock_type, "clvm"))
		return LOCK_TYPE_CLVM;
	if (!strcmp(lock_type, "dlm"))
		return LOCK_TYPE_DLM;
	if (!strcmp(lock_type, "sanlock"))
		return LOCK_TYPE_SANLOCK;
	return -1;
}

/* vgcreate */

static int vg_init_lock_args(struct cmd_context *cmd, struct volume_group *vg)
{
	switch (lock_type_to_num(vg->lock_type)) {
	case LOCK_TYPE_NONE:
	case LOCK_TYPE_CLVM:
		return 1;
	case LOCK_TYPE_LOCAL:
		if (!cmd->local_id)
			return 1;
		if (!(vg->lock_type = dm_pool_strdup(cmd->libmem, cmd->local_id) {
			log_error("Failed to allocate local_id.");
			return 0;
		}
		return 1;
	case LOCK_TYPE_DLM:
		return dlock_init_vg_dlm(cmd, vg);
	case LOCK_TYPE_SANLOCK:
		return dlock_init_vg_sanlock(cmd, vg);
	default:
		log_error("Unknown lock_type.");
		return 0;
	}
}

/* lvcreate */

static int lv_init_lock_args(struct cmd_context *cmd, struct volume_group *vg,
			     char *lv_name, char **lock_args)
{
	switch (lock_type_to_num(vg->lock_type)) {
	case LOCK_TYPE_NONE:
	case LOCK_TYPE_CLVM:
	case LOCK_TYPE_LOCAL:
	case LOCK_TYPE_DLM:
		return 1;
	case LOCK_TYPE_SANLOCK:
		return dlock_init_lv_sanlock(cmd, vg, lv_name, lock_args);
	default:
		log_error("Unknown lock_type.");
		return 0;
	}
}

/* lvremove */

static int lv_free_lock_args(struct cmd_context *cmd, struct volume_group *vg,
			     char *lv_name, char *lv_lock_args)
{
	switch (lock_type_to_num(vg->lock_type)) {
	case LOCK_TYPE_NONE:
	case LOCK_TYPE_CLVM:
	case LOCK_TYPE_LOCAL:
	case LOCK_TYPE_DLM:
		return 1;
	case LOCK_TYPE_SANLOCK:
		return dlock_free_lv_sanlock(cmd, vg, lv_name, lv_lock_args);
	default:
		log_error("Unknown lock_type.");
		return 0;
	}
}

