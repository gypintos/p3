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

/* Allocates one frame from user pool. If no free frames left - chooses
   frame to evict page from, evicts. Marks frame as locked, if lock is set to true.
   Returns kernel virtual address, if free frame found and eviction was successful,
   panicks kernel otherwise.*/
void *allocate_frame (enum palloc_flags flags, bool lock) {

    lock_acquire(&frames_lock);
    void *addr = palloc_get_page (flags | PAL_USER);

    //
    // lock_acquire(&frames_lock);
    // void *kaddr = palloc_get_page(PAL_USER | flags);
    //

    /*There are free frames in the user pool */
    if (addr != NULL) {

        struct frame *f = malloc (sizeof (struct frame));
        f->k_addr = addr;
        f->pinned = true;
        f->locked = lock;
        hash_init(&f->thread_to_uaddr, t_to_uaddr_hash_func, t_to_uaddr_hash_less_func, NULL);
        hash_insert(&frames, &f->elem);
    }
    else {
        /* Some of the used frames should be freed */
        struct frame *f = select_fm();
        f->locked = lock;
        f->pinned = true;
        addr = f->k_addr;
        struct t_to_uaddr *ttu;
        struct hash *ttus = &f->thread_to_uaddr;
        hash_first(&f->ttu_i, ttus);
        while (hash_next (&f->ttu_i))
        {
          ttu = hash_entry (hash_cur (&f->ttu_i), struct t_to_uaddr, elem);
          struct page *p = find_page(ttu->uaddr, ttu->t);
          /* Invalidate to eliminate reads\writes */
          p->isLoaded = false;
          pagedir_clear_page (ttu->t->pagedir, p->vaddr);
          switch (p->type) {
               case MMAP: {
                  write_mmap_page_to_file (p);
                  break;
              }
              case SEGMENT: {
                  if (p->writable) {
                      /* Segment that is once dirty, is always dirty */
                      if (!p->isDirty) {
                        bool dirty = is_frame_dirty(f);
                        if (dirty) {
                          p->isDirty = dirty;
                        }
                      }
                      if (p->isDirty) {
                          page_to_swap(p);
                      }
                  }
                  break;
              }
              case STACK: {
                  page_to_swap(p);
                  break;
                }
              default: NOT_REACHED ();
            }
        }
        hash_clear(&f->thread_to_uaddr, t_to_uaddr_destructor_func);

    }


    //
    // struct frame *fm;
    // if (kaddr == NULL){
    //   fm = select_fm();
    //   fm->pinned = true;
    //   fm->locked = true;
    //   kaddr = fm->k_addr;
    //   struct hash *ht_thread_uaddr = &fm->thread_to_uaddr;
    //   hash_first(&fm->ttu_i, ht_thread_uaddr);
    //   struct t_to_uaddr *thread_uaddr;
    //   while (hash_next(&fm->ttu_i)){
    //     thread_uaddr = hash_entry(hash_cur(&fm->ttu_i), struct t_to_uaddr, elem);
    //     struct page* p = find_page(thread_uaddr->uaddr, thread_uaddr->t);
    //     p->isLoaded = false;
    //     pagedir_clear_page(thread_uaddr->t->pagedir, p->vaddr);
    //     if (p->type == STACK){
    //       page_to_swap(p);
    //     } else if (p->type == SEGMENT){
    //       if (p->writable && (is_frame_dirty(fm) || p->isDirty)){
    //         p->isDirty = true;
    //         page_to_swap(p);
    //       }
    //     } else {
    //       write_mmap_page_to_file(p);
    //     }
    //   }
    //   hash_clear(&fm->thread_to_uaddr, t_to_uaddr_destructor_func);
    // } else {
    //   fm = malloc(sizeof(struct frame));
    //   fm->locked = lock;
    //   fm->k_addr = kaddr;
    //   fm->pinned = true;
    //   hash_init(&fm->thread_to_uaddr, t_to_uaddr_hash_func, t_to_uaddr_hash_less_func, NULL);
    //   hash_insert(&frames, &fm->elem);
    // }

    // lock_release(&frames_lock);
    // return kaddr;

    //


    lock_release(&frames_lock);
    return addr;
}

/* Maps given user virtual address of the current thread to the
   frame at the given kernel virtual address */
void assign_page_to_frame (void *kaddr, void *uaddr) {
    lock_acquire(&frames_lock);
    struct frame *f = frame_lookup (kaddr);
    struct t_to_uaddr *ttu = malloc(sizeof (struct t_to_uaddr));
    ttu->t = thread_current();
    ttu->uaddr = uaddr;
    hash_insert (&f->thread_to_uaddr, &ttu->elem);
    f->pinned = false;
    cond_signal(&frames_locked, &frames_lock);
    lock_release(&frames_lock);
}

/* If no other threads are using the frame,
   deletes entry from frame table and frees frame and user pool
   address. */
void free_uninstalled_frame (void *addr) {
    lock_acquire(&frames_lock);
    struct frame *f = frame_lookup(addr);
    if (hash_empty (&f->thread_to_uaddr)) {
        palloc_free_page(addr);
        hash_delete(&frames, &f->elem);
        free(f);
    }
    f->pinned = false;
    lock_release(&frames_lock);
}

/* If no other threads are using the frame, deletes entry from frame table
   and frees frame and user pool address. */
void free_frame (struct page *p, bool freepdir) {
    p->isLoaded = false;
    struct frame *f = frame_lookup(p->kaddr);
    if (f != NULL) {
        struct t_to_uaddr *ttu = t_to_uaddr_lookup (f, thread_current());
        if (ttu != NULL) {
            /* Page installed */
            hash_delete(&f->thread_to_uaddr, &ttu->elem);
            if (f->pinned || !hash_empty (&f->thread_to_uaddr)) {
                /* Frame is shared - invalidate */
                pagedir_clear_page(thread_current()->pagedir, ttu->uaddr);
                free(ttu);
            }
            else {
                /* Frame used by this page only - free */
                if (freepdir) {
                    pagedir_clear_page(thread_current()->pagedir, ttu->uaddr);
                    palloc_free_page(p->kaddr);
                }
                hash_delete(&frames, &f->elem);
                hash_destroy(&f->thread_to_uaddr, t_to_uaddr_destructor_func);
                free(f);
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
  struct frame f;
  struct hash_elem *e;

  f.k_addr = address;
  e = hash_find (&frames, &f.elem);
  return e != NULL ? hash_entry (e, struct frame, elem) : NULL;
}

/* Returns hash of the frame. */
unsigned frame_hash_func (const struct hash_elem *e, void *aux UNUSED) {
    struct frame *f = hash_entry(e, struct frame, elem);
    return (uintptr_t)f->k_addr;
}

/* Returns true if virtual kernel address of frame a is
   less than virtual kernel address of frame b. */
bool
frame_hash_less_func (const struct hash_elem *a,
                      const struct hash_elem *b,
                      void *aux UNUSED)
{
    struct frame *f_a = hash_entry (a, struct frame, elem);
    struct frame *f_b = hash_entry (b, struct frame, elem);
    return (uintptr_t)f_a->k_addr < (uintptr_t)f_b->k_addr;
}


/* Returns hash of the frame. */
unsigned t_to_uaddr_hash_func (const struct hash_elem *e, void *aux UNUSED) {
  struct t_to_uaddr *ttu = hash_entry(e, struct t_to_uaddr, elem);
  return hash_bytes(ttu->t, sizeof ttu->t);
}

/* Returns true if address of frame a is less than address of frame b. */
bool t_to_uaddr_hash_less_func (const struct hash_elem *a,
                                const struct hash_elem *b,
                                void *aux UNUSED) {
  struct t_to_uaddr *ttu_a = hash_entry (a, struct t_to_uaddr, elem);
  struct t_to_uaddr *ttu_b = hash_entry (b, struct t_to_uaddr, elem);
  return ttu_a->t < ttu_b->t;
}

/* Frees memory allocated to a frame */
void t_to_uaddr_destructor_func (struct hash_elem *e, void *aux UNUSED) {
  struct t_to_uaddr *ttu = hash_entry (e, struct t_to_uaddr, elem);
  free(ttu);
}

void clear_page_accessed (struct hash_elem *e, void *aux UNUSED) {
  struct t_to_uaddr *ttu = hash_entry (e, struct t_to_uaddr, elem);
  pagedir_set_accessed(ttu->t->pagedir, ttu->uaddr, false);
}

/* Returns the thread to uddr mapping,
   or a null pointer if no such mapping exists. */
struct t_to_uaddr *t_to_uaddr_lookup (struct frame *f, struct thread *t)
{
  struct t_to_uaddr ttu;
  struct hash_elem *e;

  ttu.t = t;
  e = hash_find (&f->thread_to_uaddr, &ttu.elem);
  return e != NULL ? hash_entry (e, struct t_to_uaddr, elem) : NULL;
}

/* Returns true if after applying function to hash table entries
   at least one returns true, false - otherwise */
bool ttu_ormap (struct frame *f, pdir_bool_func pdir_func) {

  hash_first(&f->ttu_i_b, &f->thread_to_uaddr);

  while (hash_next (&f->ttu_i_b))
  {
    struct t_to_uaddr *ttu = hash_entry (hash_cur (&f->ttu_i_b),
                                         struct t_to_uaddr, elem);
    if (pdir_func(ttu->t->pagedir, ttu->uaddr))
        return true;
  }
  return false;
}
