#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "mymalloc.h"

typedef struct Block {
  // Is the block allocated or not?
  bool allocated;
  // Size of the block (including meta-data size)
  size_t size;
} Block;

// Word alignment
const size_t kAlignment = sizeof(size_t);
// Size of meta-data per Block
const size_t kBlockMetadataSize = sizeof(Block);
// Minimum allocation size (1 word)
const size_t kMinAllocationSize = kAlignment;
// Maximum allocation size (16 MB)
const size_t kMaxAllocationSize = (16ull << 20) - kBlockMetadataSize;
// Memory size that is mmapped (64 MB)
const size_t kMemorySize = (16ull << 22);

// Starting address of our heap
static Block *start = NULL;

/// Acquire more memory from OS
static Block *acquire_memory() {
  // Acquire one more chunk from OS
  Block *block = mmap(NULL, kMemorySize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  // Initialize block metadata
  block->allocated = false;
  block->size = kMemorySize;
  return block;
}

/// Round up size
inline static size_t round_up(size_t size, size_t alignment) {
  const size_t mask = alignment - 1;
  return (size + mask) & ~mask;
}

/// Get data pointer of a block
inline static void *block_to_data(Block *block) {
  return (void *)(((size_t)block) + kBlockMetadataSize);
}

/// Get the block of a data pointer
inline static Block *data_to_block(void *ptr) {
  return (Block *)(((size_t)ptr) - kBlockMetadataSize);
}

/// Get right neighbour
inline static Block *get_right_block(Block *block) {
  size_t ptr = ((size_t)block) + block->size;
  // Return NULL if we are outside the bounds of our heap
  if (ptr >= ((size_t)start) + kMemorySize) return NULL;
  return (Block *)ptr;
}

/// Check if Block pointed by `block` is in our mmaped memory
static bool in_mmaped_memory(Block *block) {
  size_t block_sz = (size_t)block;
  size_t start_sz = (size_t)start;
  size_t end_sz = start_sz + kMemorySize;
  if (start == NULL)
    // if we haven't mmaped anything then it is not in our memory
    return false;
  if (block_sz < start_sz)
    // if the block is before our start then it is not in our memory
    return false;
  if (block_sz > end_sz)
    // if the block is after our end then it is not in our memory
    return false;
  return true;
}

/// Split a block into two. Both of the blocks will be set as unallocated.
/// Return block with size at least as big as `size`
static Block *split_block(Block *block, size_t size) {
  // We should only split unallocated blocks
  assert(!block->allocated);
  size_t total_size = block->size;

  Block *first = block;
  first->allocated = false;
  first->size = total_size - size - kBlockMetadataSize;

  Block *second = get_right_block(first);
  second->size = total_size - first->size;
  second->allocated = false;
  return second;
}

void *my_malloc(size_t size) {
  if (size == 0 || size > kMaxAllocationSize) return NULL;

  // Round up allocation size
  size = round_up(size + kBlockMetadataSize, kAlignment);

  // Initial allocation?
  if (start == NULL) {
    start = acquire_memory();
  }

  // Find a block in the freelist
  Block *block = NULL;
  for (Block *b = start; b != NULL; b = get_right_block(b)) {
    if (!b->allocated && b->size >= size) {
      block = b;
      break;
    }
  }

  // We failed to find a free block. Return NULL
  if (block == NULL) {
    errno = ENOMEM;
    return NULL;
  }

  // Split block if the block is too large. Our splitting heuristic will split
  // a block if its size >= requested size + 2 * meta-data size + minimum
  // allocation size
  if (block->size >= size + (kBlockMetadataSize << 1) + kMinAllocationSize) {
    Block *second = split_block(block, size);
    Block *first = block;
    first->allocated = false;
    block = second;
  }

  // Mark block as allocated; We don't have to set the size of the block
  // anymore as the `split_block` function will set the size
  block->allocated = true;
  // Zero memory and return
  void *data = block_to_data(block);
  memset(data, 0, size);
  return data;

  return NULL;
}

void my_free(void *ptr) {
  if (ptr == NULL) return;

  // Get block pointer
  Block *block = data_to_block(ptr);

  if (!in_mmaped_memory(block) || !block->allocated) {
    errno = EINVAL;
    fprintf(stderr, "my_free: %s\n", strerror(errno));
    abort();
  }

  // Mark block as free
  block->allocated = false;
}