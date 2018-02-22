#ifndef BASE_MEMORY_CONTAINER_OF_H
#define BASE_MEMORY_CONTAINER_OF_H

//----------------------------------------------------------------

#define container_of(v, t, head) \
    ((t *)((const char *)(v) - (const char *)&((t *) 0)->head))

//----------------------------------------------------------------

#endif
