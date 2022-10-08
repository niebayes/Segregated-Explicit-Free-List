#include "mymalloc.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define STATUS_MASK 1
#define ALLOCATED 1
#define FREE 0

// Memory size that is mmapped (32 MB)
// since the `exact` test explicitly tests if our implementation could
// serve a request of size kMaxAllocationSize = 16 MB, kMemorySize shall
// at least be 32MB.
const size_t kMemorySize = (8ull << 22);
// const size_t kMemorySize = 2048;

typedef struct Meta {
  size_t metadata;
} Meta;
const size_t kHeaderSize = sizeof(Meta);
const size_t kFooterSize = sizeof(Meta);

// block pointer.
typedef struct Block {
  Meta head;
  void *next;
  void *prev;
  // payload.
  // padding.
  // Meta foot;
} Block;
const size_t kBlockPtrSize = sizeof(void *);

/// Round up size
inline static size_t round_up(size_t size, size_t alignment) {
  const size_t mask = alignment - 1;
  return (size + mask) & ~mask;
}

// // Word alignment
// const size_t kAlignment = sizeof(size_t);
// // Minimum allocation size (1 word)
// const size_t kMinAllocationSize = kAlignment;
// // Arena size is 4 MB
// const size_t ARENA_SIZE = (4ull << 20);

// free block content = header + next ptr + prev ptr + padding + footer.
const size_t kFreeBlockSizeWithoutPadding =
    kHeaderSize + 2 * kBlockPtrSize + kFooterSize;
const size_t kFreeBlockSize =
    (kFreeBlockSizeWithoutPadding + (kAlignment - 1)) & (~(kAlignment - 1));

// Maximum allocation size (16 MB)
const size_t kMaxAllocationSize = (16ull << 20) - kFreeBlockSize;

inline static size_t get_size(Meta *meta) { return meta->metadata >> 3; }
inline static void set_size(Meta *meta, const size_t size) {
  // clear the old size.
  meta->metadata &= 7;
  // set size.
  meta->metadata |= (size << 3);
}

inline static size_t get_status(Meta *meta) {
  return meta->metadata & STATUS_MASK;
}
inline static void set_status(Meta *meta, const size_t status) {
  // clear the old status.
  meta->metadata &= ~(1UL);
  // set status.
  meta->metadata |= status;
}

// metadata getters and setters.
inline static Meta *get_header(Block *block) { return (Meta *)block; }
inline static Meta *get_footer(Block *block) {
  const size_t size = get_size(get_header(block));
  return (Meta *)((size_t)block + size - kFooterSize);
}

inline static void *get_next_ptr(Block *block) {
  return *((size_t **)((size_t)block + kHeaderSize));
}
inline static size_t get_next_ptr_addr(Block *block) {
  return (size_t)block + kHeaderSize;
}
inline static void set_next_ptr(Block *block, void *next) {
  size_t addr = get_next_ptr_addr(block);
  *((size_t *)addr) = (size_t)next;
}

inline static void *get_prev_ptr(Block *block) {
  return *((size_t **)((size_t)block + kHeaderSize + kBlockPtrSize));
}
inline static size_t get_prev_ptr_addr(Block *block) {
  return (size_t)block + kHeaderSize + kBlockPtrSize;
}
inline static void set_prev_ptr(Block *block, void *prev) {
  size_t addr = get_prev_ptr_addr(block);
  *((size_t *)addr) = (size_t)prev;
}

inline static size_t get_block_size(Block *block) {
  return get_size(get_header(block));
}
inline static void set_block_size(Block *block, const size_t size) {
  set_size(get_header(block), size);
  set_size(get_footer(block), size);
}

inline static size_t get_block_status(Block *block) {
  return get_status(get_header(block));
}
inline static void set_block_status(Block *block, const size_t status) {
  set_status(get_header(block), status);
  set_status(get_footer(block), status);
}

inline static Block *get_block_from_footer(Meta *foot) {
  const size_t size = get_size(foot);
  return (Block *)((size_t)foot + kFooterSize - size);
}

/// Get data pointer of a block
inline static void *block_to_data(Block *block) {
  return (void *)(((size_t)block) + kHeaderSize);
}

/// Get the block of a data pointer
inline static Block *data_to_block(void *ptr) {
  return (Block *)(((size_t)ptr) - kHeaderSize);
}

typedef struct FreeList {
  // Starting address of our heap
  void *start;
  size_t heap_start;
  size_t heap_end;

  // fenceposts, i.e. dummy blocks at both ends.
  Block *head_fencepost;
  Block *tail_fencepost;
} FreeList;

// SegFreeList[i] keeps track of free blocks of size 8*(i+1).
// note, size is allocation size.
#define N_CLASSES N_LISTS
FreeList SegFreeList[N_CLASSES];

size_t max(size_t a, size_t b) {
  if (a >= b) {
    return a;
  }
  return b;
}

size_t min(size_t a, size_t b) {
  if (a <= b) {
    return a;
  }
  return b;
}

inline static size_t which_list(const size_t bsize) {
  assert(bsize >= kFreeBlockSize);
  // get allocation size.
  const size_t size = round_up(bsize - kFreeBlockSize, kAlignment);
  return min((size / 8) - 1, N_CLASSES - 1);
}

inline static bool class_changed(const size_t old_bsize,
                                 const size_t new_bsize) {
  return which_list(old_bsize) != which_list(new_bsize);
}

/// Acquire more memory from OS
static void *acquire_memory(FreeList *free_list) {
  // Acquire one more chunk from OS
  // one more kAlignment memory to account for alignment.
  free_list->start = mmap(NULL, kMemorySize, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  assert((size_t)free_list->start % kAlignment == 0);
  if (free_list->start == NULL) {
    return NULL;
  }

  // reset memory.
  memset(free_list->start, 0, kMemorySize);

  // round up heap start address.
  // note, some rounding up may be redundant.
  free_list->heap_start = (size_t)free_list->start;
  free_list->heap_end = (size_t)free_list->start + kMemorySize;

  return free_list->start;
}

static Block *get_right_block(Block *block);

static void init_free_list(FreeList *free_list) {
  // set head and tail fenceposts.
  free_list->head_fencepost = (Block *)free_list->heap_start;
  free_list->tail_fencepost = (Block *)(free_list->heap_end - kFreeBlockSize);

  set_block_size(free_list->head_fencepost, kFreeBlockSize);
  set_block_status(free_list->head_fencepost, ALLOCATED);

  set_block_size(free_list->tail_fencepost, kFreeBlockSize);
  set_block_status(free_list->tail_fencepost, ALLOCATED);

  // set the initial free block.
  Block *block = get_right_block(free_list->head_fencepost);
  const size_t free_block_size =
      free_list->heap_end - free_list->heap_start - 2 * kFreeBlockSize;
  set_block_size(block, free_block_size);
  set_block_status(block, FREE);

  // init the free list.
  set_next_ptr(free_list->head_fencepost, (void *)block);
  set_prev_ptr(block, (void *)free_list->head_fencepost);
  set_next_ptr(block, (void *)free_list->tail_fencepost);
  set_prev_ptr(free_list->tail_fencepost, (void *)block);
}

bool initialized = false;

inline static bool init_seg_list() {
  for (int i = 0; i < N_CLASSES; i++) {
    FreeList *free_list = &SegFreeList[i];
    if (acquire_memory(free_list) == NULL) {
      return false;
    }
    init_free_list(free_list);
  }
  initialized = true;
  return true;
}

static bool in_heap(void *ptr) {
  size_t addr = (size_t)ptr;
  for (int i = 0; i < N_CLASSES; i++) {
    FreeList *free_list = &SegFreeList[i];
    if (addr >= free_list->heap_start && addr <= free_list->heap_end) {
      return true;
    }
  }
  return false;
}

/// Get physically adjacent neighbours. Used for coalescing.
inline static Block *get_left_block(Block *block) {
  void *ptr = (void *)((size_t)block - kFooterSize);
  // Return NULL if we are outside the bounds of our heap
  if (!in_heap(ptr)) {
    return NULL;
  }
  return get_block_from_footer((Meta *)ptr);
}

inline static Block *get_right_block(Block *block) {
  const size_t size = get_block_size(block);
  void *ptr = (void *)(((size_t)block) + size);
  // Return NULL if we are outside the bounds of our heap
  if (!in_heap(ptr)) {
    return NULL;
  }
  return (Block *)ptr;
}

// get logically adjacent neighbours. Used for tracing the free list.
inline static Block *get_next_block(Block *block) {
  void *next_ptr = get_next_ptr(block);
  return (Block *)next_ptr;
}

inline static Block *get_prev_block(Block *block) {
  void *prev_ptr = get_prev_ptr(block);
  return (Block *)prev_ptr;
}

// insert the block at the head of the free list.
void free_list_add(FreeList *free_list, Block *block) {
  set_block_status(block, FREE);
  void *old_next = get_next_ptr(free_list->head_fencepost);
  set_next_ptr(free_list->head_fencepost, (void *)block);
  set_prev_ptr(block, free_list->head_fencepost);
  set_next_ptr(block, old_next);
}

void free_list_delete(Block *block) {
  set_block_status(block, ALLOCATED);
  Block *prev_block = get_prev_block(block);
  Block *next_block = get_next_block(block);
  set_next_ptr(prev_block, (void *)next_block);
  set_prev_ptr(next_block, (void *)prev_block);
}

inline static void seg_list_add(Block *block) {
  free_list_add(&SegFreeList[which_list(get_block_size(block))], block);
}

inline static void seg_list_delete(Block *block) { free_list_delete(block); }

void print_free_block(Block *b) {
  Meta *head = get_header(b);
  Meta *foot = get_header(b);

  printf("size: %zu | alloc: %zu\n", get_size(head), get_status(head) & 1);
  printf("prev: %p | curr: %p | next: %p\n", get_prev_ptr(b), (void *)b,
         get_next_ptr(b));
  printf("size: %zu | alloc: %zu\n", get_size(foot), get_status(foot) & 1);
  printf("\n");
}

void print_free_list(FreeList *free_list) {
  for (Block *b = free_list->head_fencepost;
       b != NULL && b <= free_list->tail_fencepost; b = get_next_block(b)) {
    print_free_block(b);
  }
}

void print_seg_list() {
  for (int i = 0; i < N_CLASSES; i++) {
    printf("FreeList[%d] BEGIN\n\n", i);
    print_free_list(&SegFreeList[i]);
    printf("FreeList[%d] END\n\n", i);
  }
}

// coalesce the free block with the physically adjacent left or right or both
// free blocks.
static Block *coalesce(Block *block) {
  Block *left_block = get_left_block(block);
  Block *right_block = get_right_block(block);

  const size_t left_alloc = get_block_status(left_block);
  const size_t right_alloc = get_block_status(right_block);

  size_t size = get_block_size(block);

  if (left_alloc && right_alloc) {
    // Neither the right nor the left blocks are unallocated. In this case,
    // simply insert the block into the appropriate free list
    seg_list_add(block);
    return block;

  } else if (left_alloc && !right_alloc) {
    // Only the right block is unallocated. Then coalesce the current and right
    // blocks together. The newly coalesced block should remain where the right
    // block was in the free list
    size += get_block_size(right_block);

    Block *prev_block = get_prev_block(right_block);
    Block *next_block = get_next_block(right_block);
    seg_list_delete(right_block);

    const size_t old_bsize = get_block_size(block);

    set_block_size(block, size);

    set_next_ptr(prev_block, block);
    set_prev_ptr(block, prev_block);
    set_next_ptr(block, next_block);
    set_prev_ptr(next_block, block);

    if (class_changed(old_bsize, get_block_size(block))) {
      seg_list_delete(block);
      seg_list_add(block);
    }

    return block;

  } else if (!left_alloc && right_alloc) {
    // Only the left block is unallocated. Then coalesce the current and left
    // blocks, and the newly coalesced block should remain where the left block
    // was in the free list.
    size += get_block_size(left_block);

    const size_t old_bsize = get_block_size(left_block);

    set_block_size(left_block, size);

    if (class_changed(old_bsize, get_block_size(left_block))) {
      seg_list_delete(left_block);
      seg_list_add(left_block);
    }

    return left_block;

  } else {
    // Both the right and left blocks are unallocated, and we must coalesce with
    // both neighbors. In this case, the coalesced block should remain where the
    // left block (lower in memory) was in the free list.
    size += get_block_size(left_block) + get_block_size(right_block);
    seg_list_delete(right_block);

    const size_t old_bsize = get_block_size(left_block);

    set_block_size(left_block, size);

    if (class_changed(old_bsize, get_block_size(left_block))) {
      seg_list_delete(left_block);
      seg_list_add(left_block);
    }

    return left_block;
  }
}

static Block *place(Block *block, const size_t bsize) {
  const size_t size = get_block_size(block);

  // Split block if the block is too large. Our splitting heuristic will split
  // a block if its size >= requested size + 2 * free block size + minimum
  // allocation size
  if (size >= bsize + (kFreeBlockSize << 1) + kMinAllocationSize) {
    // If the block is larger than the request size and the remainder is large
    // enough to be allocated on its own, the block is split into two smaller
    // blocks. We could allocate either of the blocks to the user, but for
    // determinism, the user is allocated the block which is higher in memory
    // (the rightmost block).
    const size_t old_bsize = get_block_size(block);

    set_block_size(block, size - bsize);

    Block *new_block = get_right_block(block);
    set_block_size(new_block, bsize);
    set_block_status(new_block, ALLOCATED);

    if (class_changed(old_bsize, get_block_size(block))) {
      seg_list_delete(block);
      seg_list_add(block);
    }

    return new_block;

  } else {
    // If the block is exactly the request size, the block is simply removed
    // from the free list.
    // If the block is larger than the request size, but the
    // remainder is too small to be allocated on its own, the extra memory is
    // included in the memory allocated to the user and the full block is still
    // allocated just as if it had been exactly the right size.
    seg_list_delete(block);
    return block;
  }
}

inline static Block *find_fit(const size_t bsize) {
  for (int i = which_list(bsize); i < N_CLASSES; i++) {
    FreeList *free_list = &SegFreeList[i];
    for (Block *b = get_next_block(free_list->head_fencepost);
         b < free_list->tail_fencepost; b = get_next_block(b)) {
      assert(b != NULL);
      if (get_block_status(b) == FREE && get_block_size(b) >= bsize) {
        return b;
      }
    }
  }
  return NULL;
}

void *my_malloc(size_t size) {
  // do not serve requests over max allocation size.
  if (size == 0 || size > kMaxAllocationSize) {
    return NULL;
  }

  // compute the min block size that could hold this data, and round up the
  // block size.
  const size_t bsize = round_up(size + kFreeBlockSize, kAlignment);

  // Initial allocation?
  if (!initialized) {
    // add the requested memory to the free list and init the allocator.
    if (!init_seg_list()) {
      errno = ENOMEM;
      return NULL;
    }
  }

  // Find a block in the segregated free list using first fit policy.
  Block *block = find_fit(bsize);

  // We failed to find a free block. Return NULL
  if (block == NULL) {
    errno = ENOMEM;
    return NULL;
  }

  // place the data in the block and split the block if necessary.
  block = place(block, bsize);

  // print_seg_list();

  // Zero memory and return
  void *data = block_to_data(block);
  memset(data, 0, size);
  return data;
}

void my_free(void *ptr) {
  if (ptr == NULL) {
    return;
  }

  // Get block pointer
  Block *block = data_to_block(ptr);

  if (!in_heap((void *)block) || get_block_status(block) != ALLOCATED) {
    errno = EINVAL;
    fprintf(stderr, "my_free: %s\n", strerror(errno));
    exit(1);
  }

  // Mark block as free
  set_block_status(block, FREE);

  // insert it back to the free list and coalesce if necessary.
  coalesce(block);
}
