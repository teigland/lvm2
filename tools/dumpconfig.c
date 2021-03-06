/*
 * Copyright (C) 2003-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2007 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "tools.h"

static int _get_vsn(struct cmd_context *cmd, unsigned int *major,
		    unsigned int *minor, unsigned int *patchlevel)
{
	const char *atversion = arg_str_value(cmd, atversion_ARG, NULL);

	if (!atversion)
		atversion = LVM_VERSION;

	if (sscanf(atversion, "%u.%u.%u", major, minor, patchlevel) != 3) {
		log_error("Incorrect version format.");
		return 0;
	}

	return 1;
}

static struct cft_check_handle *_get_cft_check_handle(struct cmd_context *cmd)
{
	struct cft_check_handle *handle = cmd->cft_check_handle;

	if (!handle) {
		if (!(handle = dm_pool_zalloc(cmd->libmem, sizeof(*cmd->cft_check_handle)))) {
			log_error("Configuration check handle allocation failed.");
			return NULL;
		}
		handle->cft = cmd->cft;
		cmd->cft_check_handle = handle;
	}

	return handle;
}

int dumpconfig(struct cmd_context *cmd, int argc, char **argv)
{
	const char *file = arg_str_value(cmd, file_ARG, NULL);
	const char *type = arg_str_value(cmd, configtype_ARG, "current");
	unsigned int major, minor, patchlevel;
	struct config_def_tree_spec tree_spec = {0};
	struct dm_config_tree *cft = cmd->cft;
	struct cft_check_handle *cft_check_handle;
	int r = ECMD_PROCESSED;

	if (arg_count(cmd, configtype_ARG) && arg_count(cmd, validate_ARG)) {
		log_error("Only one of --type and --validate permitted.");
		return EINVALID_CMD_LINE;
	}

	if (arg_count(cmd, atversion_ARG) && !arg_count(cmd, configtype_ARG)) {
		log_error("--atversion requires --type");
		return EINVALID_CMD_LINE;
	}

	if (arg_count(cmd, ignoreadvanced_ARG))
		tree_spec.ignoreadvanced = 1;

	if (arg_count(cmd, ignoreunsupported_ARG))
		tree_spec.ignoreunsupported = 1;

	if (arg_count(cmd, validate_ARG)) {
		if (!(cft_check_handle = _get_cft_check_handle(cmd)))
			return ECMD_FAILED;

		cft_check_handle->force_check = 1;
		cft_check_handle->skip_if_checked = 1;
		cft_check_handle->suppress_messages = 0;

		if (config_def_check(cmd, cft_check_handle)) {
			log_print("LVM configuration valid.");
			return ECMD_PROCESSED;
		} else {
			log_error("LVM configuration invalid.");
			return ECMD_FAILED;
		}
	}

	if (!strcmp(type, "current")) {
		if (arg_count(cmd, atversion_ARG)) {
			log_error("--atversion has no effect with --type current");
			return EINVALID_CMD_LINE;
		}
		tree_spec.type = CFG_DEF_TREE_CURRENT;

		if (!(cft_check_handle = _get_cft_check_handle(cmd)))
			return ECMD_FAILED;

		cft_check_handle->force_check = 1;
		cft_check_handle->skip_if_checked = 1;
		cft_check_handle->suppress_messages = 1;

		config_def_check(cmd, cft_check_handle);
	}

	else if (!strcmp(type, "default"))
		tree_spec.type = CFG_DEF_TREE_DEFAULT;
	else if (!strcmp(type, "missing"))
		tree_spec.type = CFG_DEF_TREE_MISSING;
	else if (!strcmp(type, "new"))
		tree_spec.type = CFG_DEF_TREE_NEW;
	else {
		log_error("Incorrect type of configuration specified. "
			  "Expected one of: current, default, missing, new.");
		return EINVALID_CMD_LINE;
	}

	if ((tree_spec.ignoreadvanced || tree_spec.ignoreunsupported) &&
	    (tree_spec.type == CFG_DEF_TREE_CURRENT)) {
		log_error("--ignoreadvanced and --ignoreunsupported has no effect with --type current");
		return EINVALID_CMD_LINE;
	}

	if (tree_spec.type != CFG_DEF_TREE_CURRENT) {
		if (!_get_vsn(cmd, &major, &minor, &patchlevel))
			return EINVALID_CMD_LINE;
		tree_spec.version = vsn(major, minor, patchlevel);
		cft = config_def_create_tree(&tree_spec);
	}

	if (!config_write(cft, arg_count(cmd, withcomments_ARG),
			  arg_count(cmd, withversions_ARG),
			  file, argc, argv)) {
		stack;
		r = ECMD_FAILED;
	}

	/* cmd->cft (the "current" tree) is destroyed with cmd context destroy! */
	if (tree_spec.type != CFG_DEF_TREE_CURRENT && cft)
		dm_pool_destroy(cft->mem);

	return r;
}
