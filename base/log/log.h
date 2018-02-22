/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
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
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef BASE_LOG_LOG_H
#define BASE_LOG_LOG_H

#include <stdarg.h>
#include <stdio.h>

//----------------------------------------------------------------

enum log_level {
	_LOG_FATAL,
	_LOG_ERR,
	_LOG_WARN,
	_LOG_NOTICE,
	_LOG_INFO,
	_LOG_DEBUG,
};

struct logger {
	void (*destroy)(struct logger *lg);
	void (*set_level)(struct logger *lg, enum log_level l);
	void (*log)(struct logger *lg,
		    enum log_level lvl, const char *file,
		    unsigned line, const char *fmt, va_list ap);
};

// The default logger writes to stderr
struct logger *swap_log(struct logger *l);
void log_set_level(enum log_level l);
void log_msg(enum log_level,
	     const char *file, unsigned line,
	     const char *fmt, ...)
	__attribute__((format (printf, 4, 5)));

struct logger *create_file_logger(FILE *f);

#define log_fatal(msg...) log_msg(_LOG_FATAL, __FILE__, __LINE__, msg)
#define log_error(msg...) log_msg(_LOG_ERR, __FILE__, __LINE__, msg)
#define log_err(msg...) log_msg(_LOG_ERR, __FILE__, __LINE__, msg)
#define log_warn(msg...) log_msg(_LOG_WARN, __FILE__, __LINE__, msg)
#define log_notice(msg...) log_msg(_LOG_NOTICE, __FILE__, __LINE__, msg)
#define log_info(msg...) log_msg(_LOG_INFO, __FILE__, __LINE__, msg)
#define log_debug(msg...) log_msg(_LOG_DEBUG, __FILE__, __LINE__, msg)

// FIXME: I hate these, but keeping for now because so heavily used.
#define INTERNAL_ERROR "Internal error: "
#define stack log_debug("<backtrace>")  /* Backtrace on error */
#define return_0        do { stack; return 0; } while (0)
#define return_NULL     do { stack; return NULL; } while (0)
#define return_EINVALID_CMD_LINE \
                        do { stack; return EINVALID_CMD_LINE; } while (0)
#define return_ECMD_FAILED do { stack; return ECMD_FAILED; } while (0)
#define goto_out        do { stack; goto out; } while (0)
#define goto_bad        do { stack; goto bad; } while (0)

#endif
