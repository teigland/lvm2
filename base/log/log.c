/*
 * Copyright (C) 2018 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "log.h"

#include "base/memory/container_of.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

//----------------------------------------------------------------

static struct logger *_global_log = NULL;

struct logger *swap_log(struct logger *l)
{
	struct logger *old = _global_log;
	_global_log = l;
	return old;
}

static struct logger *get_log()
{
	if (!_global_log)
		swap_log(create_file_logger(stderr));

	return _global_log;
}

void log_set_level(enum log_level l)
{
	struct logger *lg = get_log();
	lg->set_level(lg, l);
}

void log_msg(enum log_level lvl,
	 const char *file, unsigned line,
	 const char *fmt, ...)
{
	va_list ap;
	struct logger *lg = get_log();

	va_start(ap, fmt);
	lg->log(lg, lvl, file, line, fmt, ap);
	va_end(ap);
}

//----------------------------------------------------------------

struct file_log {
	FILE *f;
	enum log_level lvl;
	struct logger l;
};

void fl_destroy(struct logger *lg)
{
	struct file_log *fl = container_of(lg, struct file_log, l);
	free(fl);
}

void fl_set_level(struct logger *lg, enum log_level l)
{
	struct file_log *fl = container_of(lg, struct file_log, l);
	fl->lvl = l;
}

void fl_log(struct logger *lg,
	    enum log_level lvl, const char *file,
	    unsigned line, const char *fmt, va_list ap)
{
	struct file_log *fl = container_of(lg, struct file_log, l);
	if (lvl >= fl->lvl) {
		// FIXME: add a timestamp
		fprintf(fl->f, "%s(%u): ", file, line);
		vfprintf(fl->f, fmt, ap);
		fprintf(fl->f, "\n");
	}
}

struct logger *create_file_logger(FILE *f)
{
	struct file_log *fl = malloc(sizeof(*fl));

	if (!fl) {
		fprintf(stderr, "couldn't allocate file logger\n");
		return NULL;
	}

	fl->f = f;
	fl->lvl = _LOG_INFO;
	fl->l.destroy = fl_destroy;
	fl->l.set_level = fl_set_level;
	fl->l.log = fl_log;

	return &fl->l;
}

//----------------------------------------------------------------

