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

// implementation
struct _lzallocator_ *lzallocator_create(size_t bytes)
{
    assert(lzallocator_is_power_of_two(bytes) && "Illegal bytes value. Not power of two");

    void *area = malloc(bytes);
    struct _lzallocator_ *allocator = (struct _lzallocator_ *)malloc(sizeof(struct _lzallocator_));

    if (!area || !allocator)
    {
        free(area);
        free(allocator);

        return NULL;
    }

    allocator->bytes = bytes;
    allocator->blocks = (struct _lzallocator_header_ *)area;

    allocator->blocks->free = 1;
    allocator->blocks->size = bytes;
    allocator->blocks->prev = NULL;
    allocator->blocks->next = NULL;

    return allocator;
}

void lzallocator_destroy(struct _lzallocator_ *allocator)
{
    if (!allocator)
        return;

    free(allocator->blocks);
    free(allocator);
}

size_t lzallocator_kib(size_t kb_size)
{
    size_t modulo = kb_size % 2;
    size_t padding = 2 - modulo;
    size_t size = modulo == 0 ? kb_size : kb_size + padding;

    return size * 1024;
}

size_t lzallocator_mib(size_t mb_size)
{
    size_t modulo = mb_size % 2;
    size_t padding = 2 - modulo;
    size_t size = modulo == 0 ? mb_size : mb_size + padding;

    return size * (1024 * 1024);
}

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

int lzallocator_validate_ptr(void *ptr, struct _lzallocator_ *allocator)
{
    unsigned char *block_ptr = (unsigned char *)ptr;

    return (block_ptr < (unsigned char *)allocator->blocks) || (block_ptr > (((unsigned char *)allocator->blocks) + allocator->bytes));
}

struct _lzallocator_header_ *lzallocator_get_header(void *ptr)
{
    return (struct _lzallocator_header_ *)(((unsigned char *)ptr) - LZALLOCATOR_HEADER_SIZE);
}

void *lzallocator_alloc_from_header(struct _lzallocator_header_ *header)
{
    assert(header && "header is NULL");
    assert(header->free && "header is not free");

    header->free = 0;

    return (void *)(((unsigned char *)header) + LZALLOCATOR_HEADER_SIZE);
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
    size_t header_size = sizeof(struct _lzallocator_header_);

    // A block size can be less or equals to the header side.
    // Blocks need to have enough space for headers, which contains
    // information of that block: free, previous o next.
    if (header->size / 2 <= header_size)
        return NULL;

    header->size /= 2;

    unsigned char *area = (unsigned char *)header;
    unsigned char *new_area = area + header->size;

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

struct _lzallocator_header_ *lzallocator_best_fit(size_t bytes, struct _lzallocator_ *allocator)
{
    size_t last_size = 0;
    struct _lzallocator_header_ *header = NULL;
    struct _lzallocator_header_ *current = allocator->blocks;

    while (current)
    {
        struct _lzallocator_header_ *next = current->next;

        if (current->free)
        {
            size_t current_size = LZALLOCATOR_CALC_BLOCK_SIZE(current->size);

            if (bytes == current_size)
                return current;

            if (current_size > bytes && (current_size < last_size || last_size == 0))
            {
                header = current;
                last_size = current_size;

                continue;
            }
        }

        current = next;
    }

    return header;
}

struct _lzallocator_header_ *lzallocator_find_by_split(size_t bytes, struct _lzallocator_header_ *header)
{
    assert(header && "header is NULL");

    size_t block_size = LZALLOCATOR_CALC_BLOCK_SIZE(header->size);

    if (!header->free)
        return NULL;
    if (bytes > block_size)
        return NULL;

    if (bytes == block_size)
        return header;
    if (LZALLOCATOR_CALC_BLOCK_SIZE(header->size / 2) < bytes)
        return header;

    do
    {
        lzallocator_split_block(header);
    } while (LZALLOCATOR_CALC_BLOCK_SIZE(header->size / 2) >= bytes);

    return header;
}

void *lzallocator_alloc(size_t bytes, struct _lzallocator_ *allocator, struct _lzallocator_header_ **header_out)
{
    // If the first block was splitted, we need to check for every block to find the best for the request size
    if (allocator->blocks->next)
    {
        struct _lzallocator_header_ *header = lzallocator_best_fit(bytes, allocator);

        if (!header)
            return NULL;

        // If the found block size is bigger enough to contains the requested size twice, then we
        // split the block to give the best block size possible
        if (header->size / 2 >= bytes)
            header = lzallocator_find_by_split(bytes, header);

        if (header_out)
            *header_out = header;

        void *ptr = lzallocator_alloc_from_header(header);

        lzallocator_join_blocks(allocator);

        return ptr;
    }

    struct _lzallocator_header_ *header = lzallocator_find_by_split(bytes, allocator->blocks);

    if (!header)
        return NULL;

    void *ptr = lzallocator_alloc_from_header(header);

    if (header_out)
        *header_out = header;

    lzallocator_join_blocks(allocator);

    return ptr;
}

void *lzallocator_calloc(size_t bytes, struct _lzallocator_ *allocator, struct _lzallocator_header_ **header_out)
{
    void *ptr = lzallocator_alloc(bytes, allocator, header_out);

    if (ptr)
        memset(ptr, 0, bytes);

    return ptr;
}

void *lzallocator_realloc(size_t bytes, void *ptr, struct _lzallocator_ *allocator, struct _lzallocator_header_ **header_out)
{
    if (!ptr)
        return lzallocator_alloc(bytes, allocator, header_out);

    if (lzallocator_validate_ptr(ptr, allocator))
        return NULL;

    void *new_ptr = lzallocator_alloc(bytes, allocator, header_out);

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

void lzallocator_dealloc(void *ptr, struct _lzallocator_ *allocator)
{
    if (!ptr || lzallocator_validate_ptr(ptr, allocator))
        return;

    struct _lzallocator_header_ *header = lzallocator_get_header(ptr);

    header->free = 1;

    lzallocator_join_blocks(allocator);
}

#endif