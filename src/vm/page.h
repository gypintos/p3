#ifndef VM_PAGE_H_
#define VM_PAGE_H_

#include <hash.h>
#include <inttypes.h>
#include <list.h>
#include "devices/block.h"
#include "filesys/file.h"
#include "threads/thread.h"


/* To implement sharing, we use a table to map the executable file and
 a list of threads which run that executable. */
struct hash ht_exec_to_threads;
struct lock exec_list_lock;		 /* Lock of the ht_exec_to_threads */

/* ht_exec_to_threads entry */
struct exec_threads {
  struct hash_elem hash_elem;   /* Hash table element */
  char exec_name[16];           /* Executable file name */
  struct list threads;          /* List of threads. */
};

enum page_type {
  STACK,        /* Page contains stack data */
  SEGMENT,      /* Page contains program segment */
  MMAP          /* MMAP */
};

/* Supplemental page table entry */
struct page {
  struct hash_elem hash_elem;/* Hash table element. */
  void *addr;                /* Virtual address. */
  enum page_type type;       /* Page's type. */
  bool writable;             /* Whether page is writable. */
  bool segment_dirty;        /* Segment was written to at least once. */
  bool swapped;              /* Is page swapped */
  void *kaddr;               /* Kernel virtual address of the referred frame */
  block_sector_t sector;     /* Swap address */
  int fd;                    /* File descriptor */
  struct file *file;         /* File that the page was mapped from */
  int offset;                /* Offset in file */
  uint32_t read_bytes;       /* Bytes that reads from file */
  uint32_t zero_bytes;       /* Bytes that must be zeroed */
  bool loaded;               /* Page loaded or not */
};

unsigned hash_fun_exec_name(const struct hash_elem *elem, void *aux UNUSED);
bool cmp_exec_name(const struct hash_elem *a, const struct hash_elem *b,
                  void *aux UNUSED);

struct exec_threads * exec_threads_lookup (char *exec_name);
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_,
                void *aux UNUSED);
struct page * page_lookup (const void *address, struct thread *t);
void add_page_stack (void * addr, bool writable, void * faddr);
void add_page_segment (void * addr, bool writable, off_t of,
                       uint32_t read_bytes, uint32_t zero_bytes);
void add_page_mmap (void * addr, off_t ofs, struct file *file,
                    uint32_t read_bytes, uint32_t zero_bytes);
bool load_page (struct page *p, bool pin);
bool grow_stack (void * addr, bool lock, void *kaddr);
void release_mmap_page (struct page *p);
void evict_mmap_page (struct page *p);
void page_destructor (struct hash_elem *p_, void *aux UNUSED);
void swap_in (struct page *p);
void swap_out (struct page *p, void *k_addr);
void add_exec_threads_entry (struct thread *t);
void remove_exec_threads_entry (struct thread *t);
#endif /* vm/page.h */