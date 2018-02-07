#include "units.h"

#include <stdio.h>
#include <stdlib.h>

//-----------------------------------------------------------------

int main(int argc, char **argv)
{
	struct test_suite *ts = bcache_tests();
	run_tests(ts);
	test_suite_destroy(ts);

	return 0;
}

//-----------------------------------------------------------------
