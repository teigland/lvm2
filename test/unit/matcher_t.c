/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2010 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "units.h"
#include "libdevmapper.h"

#include "matcher_data.h"

static struct dm_pool *mem = NULL;

int regex_init(void) {
	mem = dm_pool_create("bitset test", 1024);
	return mem == NULL;
}

int regex_fini(void) {
	dm_pool_destroy(mem);
	return 0;
}

static struct dm_regex *make_scanner(const char **rx)
{
	struct dm_regex *scanner;
	int nrx = 0;
	for (; rx[nrx]; ++nrx);

	scanner = dm_regex_create(mem, rx, nrx);
	CU_ASSERT_FATAL(scanner != NULL);
	return scanner;
}

static void test_fingerprints(void) {
	struct dm_regex *scanner;

	scanner = make_scanner(dev_patterns);
	CU_ASSERT_EQUAL(dm_regex_fingerprint(scanner), 0x7f556c09);

	scanner = make_scanner(random_patterns);
	CU_ASSERT_EQUAL(dm_regex_fingerprint(scanner), 0x9f11076c);
}

static void test_matching(void) {
	struct dm_regex *scanner;
	int i;

	scanner = make_scanner(dev_patterns);
	for (i = 0; devices[i].str; ++i)
		CU_ASSERT_EQUAL(dm_regex_match(scanner, devices[i].str), devices[i].expected - 1);

	scanner = make_scanner(nonprint_patterns);
	for (i = 0; nonprint[i].str; ++i)
		CU_ASSERT_EQUAL(dm_regex_match(scanner, nonprint[i].str), nonprint[i].expected - 1);
}

CU_TestInfo regex_list[] = {
	{ (char*)"fingerprints", test_fingerprints },
	{ (char*)"matching", test_matching },
	CU_TEST_INFO_NULL
};
