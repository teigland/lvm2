/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.  
 * Copyright (C) 2004-2011 Red Hat, Inc. All rights reserved.
 *
 * This file is part of the device-mapper userspace tools.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "base/memory/pool.h"

#include "base/data-struct/list.h"
#include "base/log/log.h"
#include "base/memory/zalloc.h"

// FIXME: for PRIsize_t, remove
#include "lib/misc/util.h"

#include <sys/mman.h>
#include <stddef.h>

static DM_LIST_INIT(_dm_pools);
void dm_pools_check_leaks(void);

struct chunk {
	char *begin, *end;
	struct chunk *prev;
} __attribute__((aligned(8)));

struct dm_pool {
	struct dm_list list;
	struct chunk *chunk, *spare_chunk;	/* spare_chunk is a one entry free
						   list to stop 'bobbling' */
	const char *name;
	size_t chunk_size;
	size_t object_len;
	unsigned object_alignment;
	int locked;
	long crc;
};

static void _align_chunk(struct chunk *c, unsigned alignment);
static struct chunk *_new_chunk(struct dm_pool *p, size_t s);
static void _free_chunk(struct chunk *c);

/* by default things come out aligned for doubles */
#define DEFAULT_ALIGNMENT __alignof__ (double)

struct dm_pool *dm_pool_create(const char *name, size_t chunk_hint)
{
	size_t new_size = 1024;
	struct dm_pool *p = zalloc(sizeof(*p));

	if (!p) {
		log_error("Couldn't create memory pool %s (size %"
			  PRIsize_t ")", name, sizeof(*p));
		return 0;
	}

	p->name = name;
	/* round chunk_hint up to the next power of 2 */
	p->chunk_size = chunk_hint + sizeof(struct chunk);
	while (new_size < p->chunk_size)
		new_size <<= 1;
	p->chunk_size = new_size;
	dm_list_add(&_dm_pools, &p->list);
	return p;
}

void dm_pool_destroy(struct dm_pool *p)
{
	struct chunk *c, *pr;
	_free_chunk(p->spare_chunk);
	c = p->chunk;
	while (c) {
		pr = c->prev;
		_free_chunk(c);
		c = pr;
	}

	dm_list_del(&p->list);
	free(p);
}

void *dm_pool_alloc(struct dm_pool *p, size_t s)
{
	return dm_pool_alloc_aligned(p, s, DEFAULT_ALIGNMENT);
}

void *dm_pool_alloc_aligned(struct dm_pool *p, size_t s, unsigned alignment)
{
	struct chunk *c = p->chunk;
	void *r;

	/* realign begin */
	if (c)
		_align_chunk(c, alignment);

	/* have we got room ? */
	if (!c || (c->begin > c->end) || ((c->end - c->begin) < (int) s)) {
		/* allocate new chunk */
		size_t needed = s + alignment + sizeof(struct chunk);
		c = _new_chunk(p, (needed > p->chunk_size) ?
			       needed : p->chunk_size);

		if (!c)
			return_NULL;

		_align_chunk(c, alignment);
	}

	r = c->begin;
	c->begin += s;

#ifdef VALGRIND_POOL
	VALGRIND_MAKE_MEM_UNDEFINED(r, s);
#endif

	return r;
}

void dm_pool_empty(struct dm_pool *p)
{
	struct chunk *c;

	for (c = p->chunk; c && c->prev; c = c->prev)
		;

	if (c)
		dm_pool_free(p, (char *) (c + 1));
}

void dm_pool_free(struct dm_pool *p, void *ptr)
{
	struct chunk *c = p->chunk;

	while (c) {
		if (((char *) c < (char *) ptr) &&
		    ((char *) c->end > (char *) ptr)) {
			c->begin = ptr;
#ifdef VALGRIND_POOL
			VALGRIND_MAKE_MEM_NOACCESS(c->begin, c->end - c->begin);
#endif
			break;
		}

		if (p->spare_chunk)
			_free_chunk(p->spare_chunk);

		c->begin = (char *) (c + 1);
#ifdef VALGRIND_POOL
                VALGRIND_MAKE_MEM_NOACCESS(c->begin, c->end - c->begin);
#endif

		p->spare_chunk = c;
		c = c->prev;
	}

	if (!c)
		log_error(INTERNAL_ERROR "pool_free asked to free pointer "
			  "not in pool");
	else
		p->chunk = c;
}

int dm_pool_begin_object(struct dm_pool *p, size_t hint)
{
	struct chunk *c = p->chunk;
	const size_t align = DEFAULT_ALIGNMENT;

	p->object_len = 0;
	p->object_alignment = align;

	if (c)
		_align_chunk(c, align);

	if (!c || (c->begin > c->end) || ((c->end - c->begin) < (int) hint)) {
		/* allocate a new chunk */
		c = _new_chunk(p,
			       hint > (p->chunk_size - sizeof(struct chunk)) ?
			       hint + sizeof(struct chunk) + align :
			       p->chunk_size);

		if (!c)
			return 0;

		_align_chunk(c, align);
	}

	return 1;
}

int dm_pool_grow_object(struct dm_pool *p, const void *extra, size_t delta)
{
	struct chunk *c = p->chunk, *nc;

	if (!delta)
		delta = strlen(extra);

	if ((c->end - (c->begin + p->object_len)) < (int) delta) {
		/* move into a new chunk */
		if (p->object_len + delta > (p->chunk_size / 2))
			nc = _new_chunk(p, (p->object_len + delta) * 2);
		else
			nc = _new_chunk(p, p->chunk_size);

		if (!nc)
			return 0;

		_align_chunk(p->chunk, p->object_alignment);

#ifdef VALGRIND_POOL
		VALGRIND_MAKE_MEM_UNDEFINED(p->chunk->begin, p->object_len);
#endif

		memcpy(p->chunk->begin, c->begin, p->object_len);

#ifdef VALGRIND_POOL
		VALGRIND_MAKE_MEM_NOACCESS(c->begin, p->object_len);
#endif

		c = p->chunk;
	}

#ifdef VALGRIND_POOL
	VALGRIND_MAKE_MEM_UNDEFINED(p->chunk->begin + p->object_len, delta);
#endif

	memcpy(c->begin + p->object_len, extra, delta);
	p->object_len += delta;
	return 1;
}

void *dm_pool_end_object(struct dm_pool *p)
{
	struct chunk *c = p->chunk;
	void *r = c->begin;
	c->begin += p->object_len;
	p->object_len = 0u;
	p->object_alignment = DEFAULT_ALIGNMENT;
	return r;
}

void dm_pool_abandon_object(struct dm_pool *p)
{
#ifdef VALGRIND_POOL
	VALGRIND_MAKE_MEM_NOACCESS(p->chunk, p->object_len);
#endif
	p->object_len = 0;
	p->object_alignment = DEFAULT_ALIGNMENT;
}

static void _align_chunk(struct chunk *c, unsigned alignment)
{
	c->begin += alignment - ((unsigned long) c->begin & (alignment - 1));
}

static struct chunk *_new_chunk(struct dm_pool *p, size_t s)
{
	struct chunk *c;

	if (p->spare_chunk &&
	    ((p->spare_chunk->end - p->spare_chunk->begin) >= (ptrdiff_t)s)) {
		/* reuse old chunk */
		c = p->spare_chunk;
		p->spare_chunk = 0;
	} else {
		c = malloc(s);
		if (!c) {
			log_error("Out of memory.  Requested %" PRIsize_t
				  " bytes.", s);
			return NULL;
		}

		c->begin = (char *) (c + 1);
		c->end = (char *) c + s;

#ifdef VALGRIND_POOL
		VALGRIND_MAKE_MEM_NOACCESS(c->begin, c->end - c->begin);
#endif
	}

	c->prev = p->chunk;
	p->chunk = c;
	return c;
}

static void _free_chunk(struct chunk *c)
{
#ifdef VALGRIND_POOL
#  ifdef DEBUG_MEM
	if (c)
		VALGRIND_MAKE_MEM_UNDEFINED(c + 1, c->end - (char *) (c + 1));
#  endif
#endif
	free(c);
}

char *dm_pool_strdup(struct dm_pool *p, const char *str)
{
	size_t len = strlen(str) + 1;
	char *ret = dm_pool_alloc(p, len);

	if (ret)
		memcpy(ret, str, len);

	return ret;
}

char *dm_pool_strndup(struct dm_pool *p, const char *str, size_t n)
{
	char *ret = dm_pool_alloc(p, n + 1);

	if (ret) {
		strncpy(ret, str, n);
		ret[n] = '\0';
	}

	return ret;
}

void *dm_pool_zalloc(struct dm_pool *p, size_t s)
{
	void *ptr = dm_pool_alloc(p, s);

	if (ptr)
		memset(ptr, 0, s);

	return ptr;
}

void dm_pools_check_leaks(void)
{
	struct dm_pool *p;

	if (dm_list_empty(&_dm_pools)) {
		return;
	}

	log_error("You have a memory leak (not released memory pool):");
	dm_list_iterate_items(p, &_dm_pools) {
		log_error(" [%p] %s", p, p->name);
	}
	log_error(INTERNAL_ERROR "Unreleased memory pool(s) found.");
}

