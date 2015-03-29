#include "vm/swap.h"
#include <bitmap.h>
#include <debug.h>
#include "threads/synch.h"


void
swap_init(void)
{
  swap = block_get_role(BLOCK_SWAP);
  int size = block_size(swap);
  sw_table = bitmap_create(size/ SEC_NUM);
  lock_init(&sw_lock);
}

block_sector_t
swap_set(void * addr)
{
  lock_acquire(&sw_lock);

  block_sector_t index = bitmap_scan (sw_table, 0, 1, false);
  if(index == BITMAP_ERROR)
    PANIC("it is full now!");

  int i = 0;
  while(i < SEC_NUM){
        block_write (swap, index * SEC_NUM + i, addr + BLOCK_SECTOR_SIZE * i);
        i++;
  }
  bitmap_set (sw_table, index, true);
  lock_release(&sw_lock);
  return index;
}

void
swap_get(block_sector_t index, void * addr)
{
  int i = 0;
  while(i < SEC_NUM){
    block_read (swap, index * SEC_NUM + i, addr + BLOCK_SECTOR_SIZE * i);
    i++;
  }
  lock_acquire(&sw_lock);
  bitmap_set (sw_table, index, false);
  lock_release(&sw_lock);
}

void
release_sector (block_sector_t index)
{
  lock_acquire(&sw_lock);
  bitmap_set (sw_table, index, false);
  lock_release(&sw_lock);
}
