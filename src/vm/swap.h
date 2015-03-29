#ifndef VM_SWAP_H_
#define VM_SWAP_H_

#include "devices/block.h"
#include "threads/vaddr.h"

// swap 
struct block *swap;
// The swap bitmap
struct bitmap *sw_table;
// swap lock
struct lock sw_lock;

#define SEC_NUM  PGSIZE / BLOCK_SECTOR_SIZE

void swap_init(void);
block_sector_t swap_set(void * addr);
void swap_get(block_sector_t index, void * addr);
void release_sector (block_sector_t index);
#endif /* vm/swap.h */
