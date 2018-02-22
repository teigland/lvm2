#ifndef BASE_MEMORY_ZALLOC_H
#define BASE_MEMORY_ZALLOC_H

#include <stdlib.h>
#include <string.h>

//----------------------------------------------------------------

static inline void *zalloc(size_t len)
{
	void *ptr = malloc(len);
	if (ptr)
		memset(ptr, 0, len);
	return ptr;
}

//----------------------------------------------------------------

#endif
