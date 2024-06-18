// Humble implementation of a buddy allocator

#ifndef _LZALLOCATOR_H_
#define _LZALLOCATOR_H_

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifndef LZALLOCATOR_BLOCK_SIZE
#define LZALLOCATOR_BLOCK_SIZE 4
#endif

typedef struct _lzallocator_header_
{
    char free;
    size_t size;
    struct _lzallocator_header_ *prev;
    struct _lzallocator_header_ *next;
} LZAllocatorHeader;

typedef struct _lzallocator_
{
    size_t asize;
    size_t bsize;
    struct _lzallocator_header_ *blocks;
} LZAllocator;

int lzallocator_is_power_of_two(size_t value)
{
    return (value > 0) & ((value & (value - 1)) == 0);
}

size_t lzallocator_available_space(struct _lzallocator_ *allocator)
{
    size_t space = 0;
    struct _lzallocator_header_ *current = allocator->blocks;

    while (current)
    {
        struct _lzallocator_header_ *next = current->next;

        if (current->free)
            space += current->size;

        current = next;
    }

    return space;
}

void lzallocator_join_blocks(struct _lzallocator_ *allocator)
{
    struct _lzallocator_header_ *current = allocator->blocks;

    while (current)
    {
        struct _lzallocator_header_ *next = current->next;

        if (next && current->free && next->free && lzallocator_is_power_of_two(current->size + next->size))
        {
            if (next->next)
                next->next->prev = current;

            current->next = next->next;
            current->size += next->size;

            continue;
        }

        current = next;
    }
}

struct _lzallocator_header_ *lzallocator_split_block(struct _lzallocator_header_ *header)
{
    if (header->size / 2 < LZALLOCATOR_BLOCK_SIZE)
        return NULL;

    header->size /= 2;

    size_t header_size = sizeof(struct _lzallocator_header_);
    size_t blocks_count = header->size / LZALLOCATOR_BLOCK_SIZE;
    size_t headers_size = header_size * blocks_count;
    size_t total_size = headers_size + header->size;

    unsigned char *area = (unsigned char *)header;
    unsigned char *new_area = area + total_size;

    struct _lzallocator_header_ *next = (struct _lzallocator_header_ *)new_area;

    next->free = 1;
    next->size = header->size;
    next->prev = header;
    next->next = header->next;

    if (header->next)
        header->next->prev = next;

    header->next = next;

    return next;
}

void *lzallocator_alloc_from_header(struct _lzallocator_header_ *header)
{
    assert(header && "header is NULL");
    assert(header->free && "header is not free");

    header->free = 0;

    return (void *)(((unsigned char *)header) + sizeof(struct _lzallocator_header_));
}

struct _lzallocator_header_ *lzallocator_get_header(void *ptr)
{
    return (struct _lzallocator_header_ *)(((unsigned char *)ptr) - sizeof(struct _lzallocator_header_));
}

size_t lzallocator_kib_count(size_t kb_size)
{
    size_t modulo = kb_size % 2;
    size_t padding = 2 - modulo;
    size_t size = modulo == 0 ? kb_size : kb_size + padding;

    return size * 1024 / LZALLOCATOR_BLOCK_SIZE;
}

size_t lzallocator_mib_count(size_t mb_size)
{
    size_t modulo = mb_size % 2;
    size_t padding = 2 - modulo;
    size_t size = modulo == 0 ? mb_size : mb_size + padding;

    return size * (1024 * 1024) / LZALLOCATOR_BLOCK_SIZE;
}

struct _lzallocator_ *lzallocator_create(size_t block_count)
{
    assert(lzallocator_is_power_of_two(LZALLOCATOR_BLOCK_SIZE && "Illegal block size. Not power of two"));
    assert(lzallocator_is_power_of_two(block_count) && "Illegal block count. Not power of two");

    size_t block_size = LZALLOCATOR_BLOCK_SIZE;
    size_t blocks_size = block_size * block_count;

    size_t header_size = sizeof(struct _lzallocator_header_);
    size_t headers_size = header_size * block_count;

    void *area = malloc(headers_size + blocks_size);
    struct _lzallocator_ *allocator = (struct _lzallocator_ *)malloc(sizeof(struct _lzallocator_));

    if (!area || !allocator)
    {
        free(area);
        free(allocator);

        return NULL;
    }

    allocator->asize = headers_size + blocks_size;
    allocator->bsize = blocks_size;
    allocator->blocks = (struct _lzallocator_header_ *)area;

    allocator->blocks->free = 1;
    allocator->blocks->size = blocks_size;
    allocator->blocks->prev = NULL;
    allocator->blocks->next = NULL;

    return allocator;
}

size_t lzallocator_calculate_bytes(size_t size)
{
    size_t bytes = size / LZALLOCATOR_BLOCK_SIZE;

    if (size % LZALLOCATOR_BLOCK_SIZE != 0)
        bytes += 1;

    bytes *= LZALLOCATOR_BLOCK_SIZE;

    return bytes;
}

struct _lzallocator_header_ *lzallocator_best_fit(size_t size, size_t bytes, struct _lzallocator_ *allocator)
{
    size_t last_size = 0;
    struct _lzallocator_header_ *header = NULL;
    struct _lzallocator_header_ *current = allocator->blocks;

    while (current)
    {
        struct _lzallocator_header_ *next = current->next;

        // A block can only be choosen if is free and its size is large enough to
        // contains the requested size. But we need to try the best fit. A very large
        // block would be a waste of (maybe) space and execution time, because it will
        // need to be splitted later. So we check to find the at lest large enough block
        if (current->free && (current->size >= bytes && (current->size < last_size || last_size == 0)))
        {
            header = current;
            last_size = current->size;
            size_t fit = last_size / bytes;

            // if the found block is large enough to
            // contain at least one or two times the
            // requested size, we break. We found the best correct block
            if (fit == 1 && fit < 2)
                break;
        }

        current = next;
    }

    return header;
}

struct _lzallocator_header_ *lzallocator_find_by_split(size_t size, size_t bytes, struct _lzallocator_header_ *header)
{
    assert(header && "header is NULL");

    if (header->free == 0)
        return NULL;
    if (header->size <= LZALLOCATOR_BLOCK_SIZE)
        return NULL;
    if (bytes > header->size)
        return NULL;

    if (bytes == header->size)
        return header;
    if (header->size / 2 < bytes)
        return header;

    do
    {
        lzallocator_split_block(header);
    } while (header->size / 2 >= bytes);

    return header;
}

void *lzallocator_alloc(size_t size, struct _lzallocator_ *allocator, struct _lzallocator_header_ **header_out)
{
    size_t bytes = lzallocator_calculate_bytes(size);

    // If the first block was splitted, we need to check for every block to find the best for the request size
    if (allocator->blocks->next)
    {
        struct _lzallocator_header_ *header = lzallocator_best_fit(size, bytes, allocator);

        if (!header)
            return NULL;

        // If the found block size is bigger enough to contains the requested size twice, then we
        // split the block to give the best block size possible
        if (header->size / 2 >= bytes)
            header = lzallocator_find_by_split(size, bytes, header);

        if (header_out)
            *header_out = header;

        void *ptr = lzallocator_alloc_from_header(header);

        lzallocator_join_blocks(allocator);

        return ptr;
    }

    struct _lzallocator_header_ *header = lzallocator_find_by_split(size, bytes, allocator->blocks);

    if (!header)
        return NULL;

    void *ptr = lzallocator_alloc_from_header(header);

    if (header_out)
        *header_out = header;

    lzallocator_join_blocks(allocator);

    return ptr;
}

void *lzallocator_malloc(size_t size, struct _lzallocator_ *allocator, struct _lzallocator_header_ **header_out)
{
    void *ptr = lzallocator_alloc(size, allocator, header_out);

    if (ptr)
        memset(ptr, 0, size);

    return ptr;
}

int lzallocator_validate_ptr(void *ptr, struct _lzallocator_ *allocator)
{
    unsigned char *block_ptr = (unsigned char *)ptr;

    return (block_ptr < (unsigned char *)allocator->blocks) || (block_ptr > (((unsigned char *)allocator->blocks) + allocator->asize));
}

void lzallocator_dealloc(void *ptr, struct _lzallocator_ *allocator)
{
    if (!ptr || lzallocator_validate_ptr(ptr, allocator))
        return;

    struct _lzallocator_header_ *header = lzallocator_get_header(ptr);

    header->free = 1;

    lzallocator_join_blocks(allocator);
}

void *lzallocator_realloc(size_t size, void *ptr, struct _lzallocator_ *allocator, struct _lzallocator_header_ **header_out)
{
    if (!ptr)
        return lzallocator_alloc(size, allocator, header_out);

    if (lzallocator_validate_ptr(ptr, allocator))
        return NULL;

    void *new_ptr = lzallocator_alloc(size, allocator, header_out);

    if (new_ptr)
    {
        struct _lzallocator_header_ *old_header = lzallocator_get_header(ptr);
        struct _lzallocator_header_ *new_header = lzallocator_get_header(new_ptr);

        size_t min = old_header->size < new_header->size ? old_header->size : new_header->size;

        memcpy(new_ptr, ptr, min);

        lzallocator_dealloc(ptr, allocator);
    }

    return new_ptr;
}

void lzallocator_destroy(struct _lzallocator_ *allocator)
{
    if (!allocator)
        return;

    free(allocator->blocks);
    free(allocator);
}

#endif