#include "threads/thread.h"
#include "threads/palloc.h"
#include "page.h"
#include "hash.h"

/* Frame table entry */
struct frame
  {
  void *k_addr;         /* Kernel virtual address mapped to frame physical address */
  bool pinned;          /* Is data being read into the frame */
  bool locked;          /* Frame filled for syscall*/
  struct hash thread_to_uaddr;  /* Threads using the frame with user virtual addresses mapped to it */
  struct hash_iterator ttu_i;   /* Iterator over thread_to_uaddr table */
  struct hash_iterator ttu_i_b; /* Iterator over thread_to_uaddr table - bits check*/
  struct hash_elem elem;      /* Frames hash table element */
  };

/* Thread to user virtual address mapping */
struct t_to_uaddr {
  struct thread *t;       /* Pointer to a thread using the frame */
  void *uaddr;          /* User virtual address mapped to the frame in thread t */
  struct hash_elem elem;      /* Hash element of thread_to_uaddr */
  };

void *clock_point;          /* Frame the clock algorithm currently points to */
void *clock_point_init;        /* Initial position of the clock hand */
void *clock_point_max;        /* Maximum position of the clock hand (maximal address of the frames in the user pool */

struct hash frames;        /* Frames table */
struct lock frames_lock;       /* Frame lock */
struct condition frames_locked;  /* Condition to wait on for any frame to unpin\unlock */
  
void *fm_allocate (enum palloc_flags flags, bool lock);
void release_fm (struct page *p, bool freepdir);
void release_unused_fm (void *addr);
void fmt_init (void);
void thread_fm_mapping (void *kaddr, void *uaddr);
struct frame *find_fm (void *address);
bool if_fm_accessed (struct frame *f);
bool if_fm_dirty (struct frame *f);

unsigned frame_hash_func (const struct hash_elem *e, void *aux UNUSED);
bool frame_hash_less_func (const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux UNUSED);
unsigned t_to_uaddr_hash_func (const struct hash_elem *e, void *aux UNUSED);
void clear_page_accessed (struct hash_elem *e, void *aux UNUSED);
bool t_to_uaddr_hash_less_func (const struct hash_elem *a,
                                const struct hash_elem *b,
                                void *aux UNUSED);
void t_to_uaddr_destructor_func (struct hash_elem *e, void *aux UNUSED);
struct t_to_uaddr *t_to_uaddr_lookup (struct frame *f, struct thread *t);
typedef bool pdir_bool_func (uint32_t *pd, const void *upage);
bool ttu_ormap (struct frame *f, pdir_bool_func pdir_func);
struct frame *select_fm(void);
