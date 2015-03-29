#ifndef VM_SWAP_H_
#define VM_SWAP_H_

#include "devices/block.h"
#include "threads/vaddr.h"

/* The swap slots */
struct block *swap;
/* The bitmap represents the usage of the swap */
struct bitmap *swap_table;
/* Lock used to coordinate swap */
struct lock swap_lock;

/* Note: PGSIZE = 4096, BLOCK_SECTOR_SIZE = 512
 * So each page needs 8 swap sectors.
 */
#define SEC_NUM  PGSIZE / BLOCK_SECTOR_SIZE;

void swap_init(void);
block_sector_t set_swap(void * addr);
void get_swap(block_sector_t sector, void * addr);
void free_sector (block_sector_t sector);
#endif /* vm/swap.h */
