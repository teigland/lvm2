#include "framework.h"

#include <setjmp.h>

/*----------------------------------------------------------------
 * Assertions
 *--------------------------------------------------------------*/

static jmp_buf _test_k;
#define TEST_FAILED 1

void test_fail(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	longjmp(_test_k, TEST_FAILED);
}

struct test_suite *test_suite_create(const char *path)
{
	struct test_suite *ts = malloc(sizeof(*ts));
	if (ts) {
		ts->path = path;
		dm_list_init(&ts->tests);
	}

	return ts;
}

void test_suite_destroy(struct test_suite *ts)
{
	struct test_details *td, *tmp;

	dm_list_iterate_items_safe (td, tmp, &ts->tests) {
		dm_list_del(&td->list);
		free(td);
	}

	free(ts);
}

bool register_test(struct test_suite *ts,
		   const char *path, const char *desc,
		   void (*fn)(void *),
		   void *(*fix_init)(void),
		   void (*fix_exit)(void *))
{
	struct test_details *t = malloc(sizeof(*t));
	if (!t) {
		fprintf(stderr, "out of memory\n");
		return false;
	}

	t->path = path;
	t->desc = desc;
	t->fn = fn;
	t->fixture_init = fix_init;
	t->fixture_exit = fix_exit;
	dm_list_add(&ts->tests, &t->list);

	return true;
}

void run_tests(struct test_suite *ts)
{
	// We have to declare these as volatile because of the setjmp()
	volatile unsigned passed = 0, total = 0;
	volatile struct test_details *t = NULL;

	dm_list_iterate_items (t, &ts->tests) {
		void *fixture;
		fprintf(stderr, "[RUN    ] %s\n", t->path);

		total++;
		if (setjmp(_test_k))
			fprintf(stderr, "[   FAIL] %s\n", t->path);
		else {
			if (t->fixture_init)
				fixture = t->fixture_init();
			else
				fixture = NULL;

			t->fn(fixture);

			if (t->fixture_exit)
				t->fixture_exit(fixture);

			passed++;
			fprintf(stderr, "[     OK] %s\n", t->path);
		}
	}

	fprintf(stderr, "\n%u/%u tests passed\n", passed, total);
}

//-----------------------------------------------------------------
