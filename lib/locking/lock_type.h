/*
 * Copyright (C) 2013 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 */

#define LOCK_TYPE_NONE    0
#define LOCK_TYPE_LOCAL   1
#define LOCK_TYPE_CLVM    2
#define LOCK_TYPE_DLM     3
#define LOCK_TYPE_SANLOCK 4

/* The name of the internal lv created to hold sanlock locks. */
#define SANLOCK_LV_NAME "lvmlock"

/*
 * Convert names to numbers e.g. "none" to LOCK_TYPE_NONE.
 * This is done in places where it's easier to work with
 * numbers rather than strings.
 */
int lock_type_to_num(char *lock_type);

