#ifndef TEST_UNIT_FRAMEWORK_H
#define TEST_UNIT_FRAMEWORK_H

#include <stdbool.h>
#include <stdint.h>

#include "libdevmapper.h"

//-----------------------------------------------------------------

struct test_details {
	struct dm_list list;

	const char *path;
	const char *desc;
	void (*fn)(void *);
	void *(*fixture_init)(void);
	void (*fixture_exit)(void *);
};

struct test_suite {
	const char *path;
	struct dm_list tests;
};

struct test_suite *test_suite_create(const char *path);
void test_suite_destroy(struct test_suite *ts);
bool register_test(struct test_suite *ts,
		   const char *path, const char *desc,
		   void (*fn)(void *),
		   void *(*fix_init)(void),
		   void (*fix_exit)(void *));
void run_tests(struct test_suite *ts);

void test_fail(const char *fmt, ...)
	__attribute__((noreturn, format (printf, 1, 2)));

#define T_ASSERT(e) do {if (!(e)) {test_fail("assertion failed: '%s'", # e);} } while(0)

//-----------------------------------------------------------------

#endif
