#ifndef BASE_MEMORY_POOL_H
#define BASE_MEMORY_POOL_H

#include <stdlib.h>

//----------------------------------------------------------------

/*
 * The pool allocator is useful when you are going to allocate
 * lots of memory, use the memory for a bit, and then free the
 * memory in one go.  A surprising amount of code has this usage
 * profile.
 *
 * You should think of the pool as an infinite, contiguous chunk
 * of memory.  The front of this chunk of memory contains
 * allocated objects, the second half is free.  dm_pool_alloc grabs
 * the next 'size' bytes from the free half, in effect moving it
 * into the allocated half.  This operation is very efficient.
 *
 * dm_pool_free frees the allocated object *and* all objects
 * allocated after it.  It is important to note this semantic
 * difference from malloc/free.  This is also extremely
 * efficient, since a single dm_pool_free can dispose of a large
 * complex object.
 *
 * dm_pool_destroy frees all allocated memory.
 *
 * eg, If you are building a binary tree in your program, and
 * know that you are only ever going to insert into your tree,
 * and not delete (eg, maintaining a symbol table for a
 * compiler).  You can create yourself a pool, allocate the nodes
 * from it, and when the tree becomes redundant call dm_pool_destroy
 * (no nasty iterating through the tree to free nodes).
 *
 * eg, On the other hand if you wanted to repeatedly insert and
 * remove objects into the tree, you would be better off
 * allocating the nodes from a free list; you cannot free a
 * single arbitrary node with pool.
 */

struct dm_pool;

/* constructor and destructor */
struct dm_pool *dm_pool_create(const char *name, size_t chunk_hint)
	__attribute__((__warn_unused_result__));
void dm_pool_destroy(struct dm_pool *p);

/* simple allocation/free routines */
void *dm_pool_alloc(struct dm_pool *p, size_t s)
	__attribute__((__warn_unused_result__));
void *dm_pool_alloc_aligned(struct dm_pool *p, size_t s, unsigned alignment)
	__attribute__((__warn_unused_result__));
void dm_pool_empty(struct dm_pool *p);
void dm_pool_free(struct dm_pool *p, void *ptr);

/*
 * To aid debugging, a pool can be locked. Any modifications made
 * to the content of the pool while it is locked can be detected.
 * Default compilation is using a crc checksum to notice modifications.
 * The pool locking is using the mprotect with the compilation flag
 * DEBUG_ENFORCE_POOL_LOCKING to enforce the memory protection.
 */
/* query pool lock status */
int dm_pool_locked(struct dm_pool *p);
/* mark pool as locked */
int dm_pool_lock(struct dm_pool *p, int crc)
	__attribute__((__warn_unused_result__));
/* mark pool as unlocked */
int dm_pool_unlock(struct dm_pool *p, int crc)
	__attribute__((__warn_unused_result__));

/*
 * Object building routines:
 *
 * These allow you to 'grow' an object, useful for
 * building strings, or filling in dynamic
 * arrays.
 *
 * It's probably best explained with an example:
 *
 * char *build_string(struct dm_pool *mem)
 * {
 *      int i;
 *      char buffer[16];
 *
 *      if (!dm_pool_begin_object(mem, 128))
 *              return NULL;
 *
 *      for (i = 0; i < 50; i++) {
 *              snprintf(buffer, sizeof(buffer), "%d, ", i);
 *              if (!dm_pool_grow_object(mem, buffer, 0))
 *                      goto bad;
 *      }
 *
 *	// add null
 *      if (!dm_pool_grow_object(mem, "\0", 1))
 *              goto bad;
 *
 *      return dm_pool_end_object(mem);
 *
 * bad:
 *
 *      dm_pool_abandon_object(mem);
 *      return NULL;
 *}
 *
 * So start an object by calling dm_pool_begin_object
 * with a guess at the final object size - if in
 * doubt make the guess too small.
 *
 * Then append chunks of data to your object with
 * dm_pool_grow_object.  Finally get your object with
 * a call to dm_pool_end_object.
 *
 * Setting delta to 0 means it will use strlen(extra).
 */
int dm_pool_begin_object(struct dm_pool *p, size_t hint);
int dm_pool_grow_object(struct dm_pool *p, const void *extra, size_t delta);
void *dm_pool_end_object(struct dm_pool *p);
void dm_pool_abandon_object(struct dm_pool *p);

/* utilities */
char *dm_pool_strdup(struct dm_pool *p, const char *str)
	__attribute__((__warn_unused_result__));
char *dm_pool_strndup(struct dm_pool *p, const char *str, size_t n)
	__attribute__((__warn_unused_result__));
void *dm_pool_zalloc(struct dm_pool *p, size_t s)
	__attribute__((__warn_unused_result__));

//----------------------------------------------------------------

#endif
