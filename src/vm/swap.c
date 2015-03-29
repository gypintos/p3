#include "vm/swap.h"
#include <bitmap.h>
#include <debug.h>
#include "threads/synch.h"


void
swap_init(void)
{
  swap = block_get_role(BLOCK_SWAP);
  sw_table = bitmap_create(block_size(swap)/ SEC_NUM);
  lock_init(&sw_lock);
}

/* Save a page with the given address in swap */
block_sector_t
swap_set(void * addr)
{
  lock_acquire(&sw_lock);
  // Find a free sector in the swap table
  block_sector_t index = bitmap_scan (sw_table, 0, 1, false);
  //printf("Found sector %d to write page %p", sector, addr);
  if(index == BITMAP_ERROR)
    PANIC("Swap table is full.");

  int i = 0;
  // Write page to swap
  while(i < SEC_NUM){
        block_write (swap, index * SEC_NUM + i, addr + BLOCK_SECTOR_SIZE * i);
        i++;
  }

  // for (i = 0; i< SEC_NUM; i++) {
  //   /* Write block to swap */
  //   block_write (swap, index * SEC_NUM + i, addr + BLOCK_SECTOR_SIZE * i);
  // }

  // Set the index in the swap table to true
  bitmap_set (sw_table, index, true);
  lock_release(&sw_lock);
  return index;
}

/* Get a page from the swap table */
void
swap_get(block_sector_t index, void * addr)
{
  int i = 0;
  while(i < SEC_NUM){
    block_read (swap, index * SEC_NUM + i, addr + BLOCK_SECTOR_SIZE * i);
    i++;
  }
  // for (i = 0; i< SEC_NUM; i++)
  //   block_read (swap, index * SEC_NUM + i, addr + BLOCK_SECTOR_SIZE * i);

  lock_acquire(&sw_lock);
  // Deallocate the given sector in the swap table
  bitmap_set (sw_table, index, false);
  lock_release(&sw_lock);
}

/* Mark swap sector as unused*/
void
release_sector (block_sector_t index)
{
  lock_acquire(&sw_lock);
  // Deallocate the given sector in the swap table
  bitmap_set (sw_table, index, false);
  lock_release(&sw_lock);
}
