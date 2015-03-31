#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "frame.h"


struct hash_iterator frames_iter;  

void fmt_init (void) {
  hash_init(&frames, frame_hash_func, frame_hash_less_func, NULL);
  lock_init(&frames_lock);
  cond_init(&frames_locked);
  lock_init(&ht_exec_to_threads_lock);
}

struct frame *select_fm (void) {
  void *end = clock_point_max;
  if (clock_point != clock_point_init)
    end = clock_point - PGSIZE;

  struct frame *fm;
  for (;clock_point != end; clock_point += PGSIZE){
    if (clock_point >= clock_point_max) clock_point = clock_point_init;
    fm = frame_lookup(clock_point);
    if (!fm){
      continue;
    } else if (fm->locked || fm->pinned){
      if (is_frame_accessed(fm)){
        hash_apply(&fm->thread_to_uaddr, clear_page_accessed);
      }
      continue;
    } else {
      if (is_frame_accessed(fm)){
        hash_apply(&fm->thread_to_uaddr, clear_page_accessed);
      } else {
        return fm;
      }
    }
  }

  fm = NULL;
  while(!fm){
    hash_first(&frames_iter, &frames);
    while(hash_next(&frames_iter)){
      fm = hash_entry(hash_cur(&frames_iter), struct frame, elem);
      if (!fm->locked && !fm->pinned){
        return fm;
      }
    }
    cond_wait(&frames_locked, &frames_lock);  
  }
}

void *fm_allocate (enum palloc_flags flags, bool lock) {
  lock_acquire(&frames_lock);
  void *kaddr = palloc_get_page(PAL_USER | flags);
  struct frame *fm;
  if (kaddr == NULL){
    fm = select_fm();
    fm->pinned = true;
    fm->locked = lock;
    kaddr = fm->k_addr;
    struct hash *ht_thread_uaddr = &fm->thread_to_uaddr;
    hash_first(&fm->ttu_i, ht_thread_uaddr);
    struct t_to_uaddr *thread_uaddr;
    while (hash_next(&fm->ttu_i)){
      thread_uaddr = hash_entry(hash_cur(&fm->ttu_i), struct t_to_uaddr, elem);
      struct page* p = find_page(thread_uaddr->uaddr, thread_uaddr->t);
      p->isLoaded = false;
      pagedir_clear_page(thread_uaddr->t->pagedir, p->vaddr);
      if (p->type == STACK){
        page_to_swap(p);
      } else if (p->type == SEGMENT){
        if (p->writable && (is_frame_dirty(fm) || p->isDirty)){
          p->isDirty = true;
          page_to_swap(p);
        }
      } else {
        write_mmap_page_to_file(p);
      }
    }
    hash_clear(&fm->thread_to_uaddr, t_to_uaddr_destructor_func);
  } else {
    fm = malloc(sizeof(struct frame));
    fm->locked = lock;
    fm->k_addr = kaddr;
    fm->pinned = true;
    hash_init(&fm->thread_to_uaddr, t_to_uaddr_hash_func, t_to_uaddr_hash_less_func, NULL);
    hash_insert(&frames, &fm->elem);
  }

  lock_release(&frames_lock);
  return kaddr;
}

/* Maps given user virtual address of the current thread to the
   frame at the given kernel virtual address */
void assign_page_to_frame (void *kaddr, void *uaddr) { 
  lock_acquire(&frames_lock);
  struct t_to_uaddr *thread_uaddr = malloc(sizeof(struct t_to_uaddr));
  thread_uaddr->t = thread_current();
  thread_uaddr->uaddr = uaddr;
  struct frame *fm = frame_lookup(kaddr);
  hash_insert(&fm->thread_to_uaddr, &thread_uaddr->elem);
  fm->pinned = false;
  cond_signal(&frames_locked, &frames_lock);
  lock_release(&frames_lock);
}

/* If no other threads are using the frame,
   deletes entry from frame table and frees frame and user pool
   address. */
void free_uninstalled_frame (void *addr) {
  lock_acquire(&frames_lock);
  struct frame *fm = frame_lookup(addr);
  fm->pinned = false;
  if(hash_empty(&fm->thread_to_uaddr)){
    palloc_free_page(addr);
    hash_delete(&frames, &fm->elem);
    free(fm);
  }
}

/* If no other threads are using the frame, deletes entry from frame table
   and frees frame and user pool address. */
void free_frame (struct page *p, bool freepdir) 
  p->isLoaded = false;
  struct frame *fm = frame_lookup(p->kaddr);
  struct t_to_uaddr *thread_to_uaddr;
  struct thread *curr = thread_current();
  if(fm){
    thread_to_uaddr = t_to_uaddr_lookup(fm, curr);
    if(thread_to_uaddr){
      hash_delete(&fm->thread_to_uaddr, &thread_to_uaddr->elem);

      if(fm->pinned == NULL && hash_empty(&fm->thread_to_uaddr)){
        if(freepdir){
          pagedir_clear_page(curr->pagedir, thread_to_uaddr->uaddr);
          palloc_free_page(p->kaddr);
        }
        hash_delete(&frames, &fm->elem);
        hash_destroy(&fm->thread_to_uaddr, t_to_uaddr_destructor_func);
        free(fm);
      }else{
        pagedir_clear_page(curr->pagedir, thread_to_uaddr->uaddr);
        free(thread_to_uaddr);
      }
      
    }
  }   
}

/* Returns true if PTE_A flag is set for any of the
   page table entries for this frame */
bool is_frame_accessed (struct frame *f) {
    return ttu_ormap (f, &pagedir_is_accessed);
}

/* Returns true if PTE_D flag is set for any of the
   page table entries for this frame */
bool is_frame_dirty (struct frame *f) {
    return ttu_ormap (f, &pagedir_is_dirty);
}

/* Returns the frame at the given kernel virtual address,
   or a null pointer if no such frame exists. */
struct frame *frame_lookup (void *address)
{
  struct frame fm;
  fm.k_addr = address;
  struct hash_elem *ele = hash_find(&frames, &fm.elem); 
  if(ele){
    return hash_entry(ele, struct frame, elem);
  }else{
    return NULL;
  }
}

/* Returns hash of the frame. */
unsigned frame_hash_func (const struct hash_elem *e, void *aux UNUSED) {
    struct frame *fm = hash_entry(e, struct frame, elem);
    return (uintptr_t)fm->k_addr;
}

/* Returns true if virtual kernel address of frame a is
   less than virtual kernel address of frame b. */

bool
frame_hash_less_func (const struct hash_elem *first, const struct hash_elem *second, void *aux UNUSED)
{
    struct frame *fm_first = hash_entry (first, struct frame, elem);
    struct frame *fm_second = hash_entry (second, struct frame, elem);
    return (uintptr_t)fm_first->k_addr < (uintptr_t)fm_second->k_addr;
}


/* Returns hash of the frame. */
unsigned t_to_uaddr_hash_func (const struct hash_elem *e, void *aux UNUSED) {
  struct t_to_uaddr *thread_to_uaddr = hash_entry(e, struct t_to_uaddr, elem);
  return hash_bytes(thread_to_uaddr->t, sizeof thread_to_uaddr->t);
}

/* Returns true if address of frame a is less than address of frame b. */
bool t_to_uaddr_hash_less_func (const struct hash_elem *first, const struct hash_elem *second, void *aux UNUSED) {
  struct t_to_uaddr *u_first = hash_entry (first, struct t_to_uaddr, elem);
  struct t_to_uaddr *u_second = hash_entry (second, struct t_to_uaddr, elem);
  return u_first->t < u_second->t;
}

/* Frees memory allocated to a frame */
void t_to_uaddr_destructor_func (struct hash_elem *e, void *aux UNUSED) {
  struct t_to_uaddr *thread_to_uaddr = hash_entry (e, struct t_to_uaddr, elem);
  free(thread_to_uaddr);
}

void clear_page_accessed (struct hash_elem *e, void *aux UNUSED) {
  struct t_to_uaddr *thread_to_uaddr = hash_entry (e, struct t_to_uaddr, elem);
  pagedir_set_accessed(thread_to_uaddr->t->pagedir, thread_to_uaddr->uaddr, false); 
}

/* Returns the thread to uddr mapping,
   or a null pointer if no such mapping exists. */
struct t_to_uaddr *t_to_uaddr_lookup (struct frame *f, struct thread *t)
{
  struct t_to_uaddr thread_to_uaddr;
  thread_to_uaddr.t = t;
  struct hash_elem *ele = hash_find(&f->thread_to_uaddr, &thread_to_uaddr.elem);
  if(ele){
    return hash_entry(ele, struct t_to_uaddr, elem);
  }else{
    return NULL;
  }
}

/* Returns true if after applying function to hash table entries
   at least one returns true, false - otherwise */
bool ttu_ormap (struct frame *f, pdir_bool_func pdir_func) {
  hash_first(&f->ttu_i_b, &f->thread_to_uaddr);
  while(hash_next(&f->ttu_i_b)){
    struct t_to_uaddr *thread_to_uaddr = hash_entry(hash_cur(&f->ttu_i_b), struct t_to_uaddr, elem);
    if(pdir_func(thread_to_uaddr->t->pagedir, thread_to_uaddr->uaddr)) return true;
  }
  return false;

}
