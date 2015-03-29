#ifndef VM_SWAP_H_
#define VM_SWAP_H_

#include "devices/block.h"
#include "threads/vaddr.h"

/* The swap slots */
struct block *swap;
/* The bitmap represents the usage of the swap */
struct bitmap *sw_table;
/* Lock used to coordinate swap */
struct lock sw_lock;

/* Note: PGSIZE = 4096, BLOCK_SECTOR_SIZE = 512
 * So each page needs 8 swap sectors.
 */
#define SEC_NUM  PGSIZE / BLOCK_SECTOR_SIZE

void swap_init(void);
block_sector_t swap_set(void * addr);
void swap_get(block_sector_t index, void * addr);
void release_sector (block_sector_t index);
#endif /* vm/swap.h */
