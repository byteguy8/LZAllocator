// Humble implementation of a buddy allocator

#ifndef _LZALLOCATOR_H_
#define _LZALLOCATOR_H_

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct _lzallocator_header_
{
    char free;
    size_t size;
    struct _lzallocator_header_ *prev;
    struct _lzallocator_header_ *next;
} LZAllocatorHeader;

typedef struct _lzallocator_
{
    size_t bytes;
    struct _lzallocator_header_ *blocks;
} LZAllocator;

#define LZALLOCATOR_HEADER_SIZE (sizeof(struct _lzallocator_header_))
#define LZALLOCATOR_CALC_BLOCK_SIZE(size) (size - LZALLOCATOR_HEADER_SIZE)

// interface
struct _lzallocator_ *lzallocator_create(size_t bytes);
void lzallocator_destroy(struct _lzallocator_ *allocator);

size_t lzallocator_kib(size_t kb_size);
size_t lzallocator_mib(size_t mb_size);
int lzallocator_is_power_of_two(size_t value);
size_t lzallocator_available_space(struct _lzallocator_ *allocator);
int lzallocator_validate_ptr(void *ptr, struct _lzallocator_ *allocator);

struct _lzallocator_header_ *lzallocator_get_header(void *ptr);
void *lzallocator_alloc_from_header(struct _lzallocator_header_ *header);

void lzallocator_join_blocks(struct _lzallocator_ *allocator);
struct _lzallocator_header_ *lzallocator_split_block(struct _lzallocator_header_ *header);

struct _lzallocator_header_ *lzallocator_best_fit(size_t bytes, struct _lzallocator_ *allocator);
struct _lzallocator_header_ *lzallocator_find_by_split(size_t bytes, struct _lzallocator_header_ *header);

void *lzallocator_alloc(size_t bytes, struct _lzallocator_ *allocator, struct _lzallocator_header_ **header_out);
void *lzallocator_calloc(size_t bytes, struct _lzallocator_ *allocator, struct _lzallocator_header_ **header_out);
void lzallocator_dealloc(void *ptr, struct _lzallocator_ *allocator);
void *lzallocator_realloc(size_t bytes, void *ptr, struct _lzallocator_ *allocator, struct _lzallocator_header_ **header_out);

#endif