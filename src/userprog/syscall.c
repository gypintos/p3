#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include <hash.h>
#include <limits.h>
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/exception.h"
#include "vm/frame.h"
#include "vm/page.h"

#define BUFFER_SIZE 300

static void syscall_handler (struct intr_frame *);
struct semaphore sys_sema;

void remove_fds (struct hash_elem *e, void *aux);
void remove_mapids (struct hash_elem *e, void *aux UNUSED);
void remove_child_info (struct hash_elem *e, void *aux UNUSED);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
  sema_init(&sys_sema, 1);
}

void validate_addr (void *addr, void *esp, bool writable) {
    if (!addr || addr >= PHYS_BASE || addr < USER_VADDR_BASE )
        exit(-1);

    lock_acquire(&frames_lock);
    struct page *p = page_lookup(addr, thread_current());
    struct frame *fm = NULL;
    if (p != NULL && p->loaded){
        fm = frame_lookup(p->kaddr);
        fm->locked = true;
    }
    lock_release(&frames_lock);

    if (p != NULL && !p->loaded ) {
        bool load_result = load_page(p, true);
        if (!load_result) exit(-1);
    }

    if (p != NULL ){
        if (writable && !p->writable)
            exit(-1);
    } else if (esp != NULL){
        bool is_valid= false;
        if (addr >= esp - DEFAUTL_STACK_GROUTH &&
            STACK_MAX_SIZE >= PHYS_BASE - pg_round_down(addr)){
            is_valid = grow_stack(addr, true, NULL);
        }
        if (!is_valid)
            exit(-1);
    } else {
        exit(-1);
    }
}

void validate_buf (char* buf_ptr, int size, void* esp, bool writable) {
    validate_addr (buf_ptr, esp, writable);
    int page_cnt= size / PGSIZE;
    int remain= size % PGSIZE;
    int i;
    for (i = 1; i <= page_cnt; i++) {
        validate_addr(buf_ptr+ i * PGSIZE, esp, writable);
    }
    if (remain > 0) {
        validate_addr(buf_ptr+ size, esp, writable);
    }
}


/* Resolves the called function from system call number,
 * validates arguments, passes control to the called function and
 * sets its return value, if any, to eax */
static void
syscall_handler (struct intr_frame *f)
{
 int *syscall = (int *)f->esp;
 validate_addr(syscall, NULL, /* Writeable */ false);
    switch (*syscall) {
        case SYS_HALT: {
            halt();
            break;
        }
        case SYS_WRITE: {
            void *args[3];
            get_args(syscall, 3, args);
            char *buf_ptr = (char *)*(int *)args[1];
            validate_buf (buf_ptr, *(int *)args[2], NULL, /* Writeable */ false);
            f->eax = write (*(int *)args[0], buf_ptr, *(int *)args[2]);
            release_args(syscall, 3, args);
            break;
        }
        case SYS_OPEN: {
            void *args[1];
            get_args(syscall, 1, args);
            char *buf_ptr = (char *)*(int *)args[0];
            validate_addr(buf_ptr, f->esp, /* Writeable */ false);
            f->eax = open (buf_ptr);
            release_args(syscall, 1, args);
            break;
        }
        case SYS_EXIT: {
            void *args[1];
            get_args(syscall, 1, args);
            f->eax = *(int *)args[0];
            exit(*(int *)args[0]);
            break;
        }
        case SYS_EXEC: {
            void *args[1];
            get_args(syscall, 1, args);
            char *buf_ptr = (char *)*(int *)args[0];
            validate_addr(buf_ptr, f->esp, /* Writeable */ false);
            int cid = exec(buf_ptr);
            f->eax = cid;
            release_args(syscall, 1, args);
            break;
        }
        case SYS_WAIT: {
            void *args[1];
            get_args(syscall, 1, args);
            f->eax = wait(*(int *) args[0]);
            release_args(syscall, 1, args);
            break;
        }
        case SYS_CREATE: {
            // File system code checks for name length, so we do not need to.
            void *args[2];
            get_args(syscall, 2, args);
            char *buf_ptr = (char *)*(int *)args[0];
            validate_addr(buf_ptr, f->esp, /* Writeable */ false);
            f->eax = create(buf_ptr, *(int *)args[1]);
            release_args(syscall, 2, args);
            break;
            }
        case SYS_REMOVE: {
            void *args[1];
            get_args(syscall, 1, args);
            char *buf_ptr = (char *)*(int *)args[0];
            validate_addr(buf_ptr, f->esp, /* Writeable */ false);
            f->eax = remove (buf_ptr);
            release_args(syscall, 1, args);
            break;
            }
        case SYS_FILESIZE: {
            void *args[1];
            get_args(syscall, 1, args);
            int file_sz = filesize(*(int *)args[0]);
            if (file_sz == -1) {
                exit (-1);
            }
            else {
                f->eax = file_sz;
            }
            release_args(syscall, 1, args);
            break;
            }
        case SYS_READ: {
            void *args[3];
            get_args(syscall, 3, args);
            char *buf_ptr = (char *)*(int *)args[1];
            validate_buf(buf_ptr, *(unsigned *)args[2], f->esp, true);
            f->eax = read (*(int *)args[0], buf_ptr, *(unsigned *)args[2]);
            release_args(syscall, 3, args);
            break;
        }
        case SYS_SEEK: {
            void *args[2];
            get_args(syscall, 2, args);
            seek (*(int *)args[0], *(unsigned *)args[1]);
            release_args(syscall, 2, args);
            break;
            }
        case SYS_TELL: {
            void *args[1];
            get_args(syscall, 1, args);
            f->eax = tell(*(int *)args[0]);
            release_args(syscall, 1, args);
            break;
            }
        case SYS_CLOSE: {
            void *args[1];
            get_args(syscall, 1, args);
            close (*(int *)args[0]);
            release_args(syscall, 1, args);
            break;
        }
        case SYS_MMAP: {
            void *args[2];
            get_args(syscall, 2, args);
            f->eax = mmap(*(int *)args[0], (char *)*(int *)args[1]);
            release_args(syscall, 2, args);
            break;
        }
        case SYS_MUNMAP: {
            void *args[1];
            get_args(syscall, 1, args);
            munmap((mapid_t)*(int *)args[0]);
            release_args(syscall, 1, args);
            break;
        }
    }

}

void get_args (int *ptr, int count, void **argv) {
    int i;
    for (i = 0; i < count; ++i)
    {
        void *tmp_ptr= (void*) ++ptr;
        validate_addr(tmp_ptr, NULL, NULL);
        argv[i] = tmp_ptr;

    }
}

void release_args (int *ptr, int count, void **argv) {
    int i;
    for (i = 0; i < count; i++){
        void* tmp_ptr = (void*) ++ptr;
        lock_acquire(&frames_lock);
        struct page *p = page_lookup(ptr, thread_current());
        if (p && p->loaded){
            struct frame *fm = frame_lookup(p->kaddr);
            fm->locked = false;
        }
        lock_release(&frame_lock);
        argv[i] = tmp_ptr;
    }
}


void release_buf (const char* buf_ptr, int size) {
    lock_acquire(&frames_lock);
    struct page  *p  = page_lookup(buf_ptr, thread_current());
    struct frame *fm = frame_lookup(p->kaddr);
    fm->locked = false;
    int page_cnt = size/PGSIZE;
    int remain   = size%PGSIZE;
    int i;
    for (i= 1; i <= page_cnt; i++) {
        p = page_lookup(buf_ptr + i * PGSIZE, thread_current());
        fm = frame_lookup(p->kaddr);
        fm->locked = false;
    }
    if (remain > 0) {
        p = page_lookup(buf_ptr + size, thread_current());
        fm = frame_lookup(p->kaddr);
        fm->locked = false;
    }
    cond_signal(&frames_locked, &frames_lock);
    lock_release(&frames_lock);
}

/* Terminates Pintos by calling shutdown_power_off().*/
void halt (void) {
    shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel.
 * Updates status in the children status list of the parent process.
 * Closes all open files. Closes own executable and calls thread_exit(). */
void exit (int status) {
    struct thread *t = thread_current();
    printf ("%s: exit(%d)\n", t->name, status);

    /* Clean up id_addr */
    struct hash *mapids_ptr = &t->mapids;
    hash_destroy(mapids_ptr, remove_mapids);

    /* Clean up files */
    struct hash *fds_ptr = &t->fds;
    hash_destroy(fds_ptr, remove_fds);

    lock_acquire(&exec_list_lock);
    remove_exec_threads_entry(t);
    lock_release(&exec_list_lock);

    /* Close executable */
    lock_acquire(&filesys_lock);
    file_close(t->exe);
    lock_release(&filesys_lock);

    /* Destroy supplementary page table */
    hash_destroy(&t->page_table, page_destructor);

    sema_down(&sys_sema);

    /* Clean up children list and notify them that parent is exiting */
    hash_destroy(&thread_current()->children, remove_child_info);

    if (t->parent != NULL) {
        struct thread *p = t->parent;
        //signal exit status to the parent
        struct child_info *ct = find_child_info(p, thread_current()->tid);
        if (ct != NULL) {
            lock_acquire(&ct->wait_lock);
            ct->exit_code = status;
            ct->state = CHILD_EXITING;
            ct->cthread = NULL;
            cond_signal(&ct->wait_cond, &ct->wait_lock);
            lock_release(&ct->wait_lock);
        }
    }
    sema_up(&sys_sema);
    thread_exit();
}

/* Runs the executable whose name is given in cmd_line,
   passing any given arguments, and returns the new process's
   program id. */
tid_t exec (const char *file_name){
    lock_acquire(&filesys_lock);
    tid_t child = process_execute (file_name);
    lock_release(&filesys_lock);
    return child;
}

/* Waits for a child process pid and returns the child's exit status. */
int wait (tid_t cid) {
    return process_wait(cid);
}

/* Creates a new file called file initially initial_size bytes in size. */
bool create (const char *file_name, unsigned initial_size) {
        lock_acquire(&filesys_lock);
        int fd = filesys_create(file_name, initial_size);
        lock_release(&filesys_lock);
        return fd;
    }

 /* Opens the file called file. Returns a nonnegative integer
   file descriptor or -1 if the file could not be opened.*/
 int open (const char *file_name) {
     struct thread *t = thread_current();

     if (hash_size(&t->fds) == MAX_FILES) {
         return -1;
     }

     lock_acquire(&filesys_lock);
     struct file *file_ptr = filesys_open(file_name);
     lock_release(&filesys_lock);
     if (file_ptr == NULL) {
            return -1;
     }
     struct file_desc *opened_file = malloc(sizeof (struct file_desc));
     opened_file->fptr = file_ptr;
     add_to_fds(t, opened_file);
     return opened_file->fid;
}
/* Allocates new file descriptor id, assigns it to opened_file file_desc
   and adds file_desc to the hash table of the thread pointed to by t.*/
void add_to_fds(struct thread *t, struct file_desc *opened_file) {
     do {
             if (t->fd_seq == USHRT_MAX) {
                 t->fd_seq = 1;
             }
             opened_file->fid = ++t->fd_seq;
         }
     while (hash_insert(&t->fds, &opened_file->elem) != NULL);
}


 /* Deletes the file called file. Returns true if successful, false otherwise. */
 bool remove (const char *file_name) {
        lock_acquire(&filesys_lock);
        bool removed = filesys_remove(file_name);
        lock_release(&filesys_lock);
        return removed;
 }

 /* Returns the size, in bytes, of the file open as fd, -1
    if process does not own file descriptor*/
 int filesize (int fd) {
     struct file *file_ptr = thread_fd_to_file(fd);
     int size = -1;
     if (file_ptr != NULL) {
        lock_acquire(&filesys_lock);
        size = file_length(file_ptr);
        lock_release(&filesys_lock);
     }
     return size;
  }

 /* Returns pointer to a file if it is opened by current thread,
  * null - otherwise. */
 struct file * thread_fd_to_file (int fid) {
    struct file_desc fd;
    struct file_desc *fd_ptr ;
    fd.fid = fid;
    struct hash_elem *e = hash_find(&thread_current()->fds, &fd.elem);
    if (e == NULL) {
        return NULL;
    }
    fd_ptr = hash_entry(e, struct file_desc, elem);
    return fd_ptr->fptr;
 }

/* Reads size bytes from the file open as fd into buffer.
   Returns the number of bytes actually read. */
int read (int fd, void *buffer, unsigned length) {
    if (fd == 1) {
        return -1;
    }
    if (fd == 0) {
        char *b = (char *) buffer;
        int i = 0;
        while (length > 0 || b[i-1] != '\n') {
            b[i] = input_getc();
            i++;
            length--;
        }
        release_buf(buffer, length);
        return i;
    }
    struct file *file_ptr = thread_fd_to_file(fd);

    if (file_ptr != NULL) {
        lock_acquire(&filesys_lock);
        length = file_read(file_ptr, buffer, length);
        lock_release(&filesys_lock);
        release_buf(buffer, length);
        return length;
    }
    return -1;
}

/* Writes contents of the buffer to the given file descriptor. */
int write (int fd, const void *buffer, unsigned length) {

    const char *b = (char *) buffer;
    if (fd == 1) {
        int it = length / BUFFER_SIZE;
        int rem = length % BUFFER_SIZE;
        int k;
        for(k = 0; k < it; k++) {
            putbuf(b + BUFFER_SIZE * k, BUFFER_SIZE);
        }
        if (rem != 0) {
            putbuf(b + BUFFER_SIZE * it, rem);
        }
        release_buf(b, length);
        return length;
    }
    else if (fd == 0) {
        return 0;
    }
    else {
       struct file *file_ptr = thread_fd_to_file(fd);
       if (file_ptr != NULL) {
           lock_acquire(&filesys_lock);
           length = file_write(file_ptr, b, length);
           lock_release(&filesys_lock);
           release_buf(b, length);

           return length;
        }
        return 0;
    }
}

/*Closes a file, if process owns file descriptor.
  Removes file descriptor from the list of the process.*/
void close (int fid) {
    struct file_desc fd;
    fd.fid = fid;
    struct hash *fds_ptr = &thread_current()->fds;
    struct hash_elem *e = hash_delete(fds_ptr, &fd.elem);
    if (e == NULL) {return;}
    struct file_desc *fd_ptr = hash_entry(e, struct file_desc, elem);
    lock_acquire(&filesys_lock);
    file_close(fd_ptr->fptr);
    lock_release(&filesys_lock);
    free(fd_ptr);
}

/* Changes the next byte to be read or written in open file fd
   to position, expressed in bytes from the beginning of the file.*/
void seek (int fd, unsigned position) {
    struct file *file_ptr = thread_fd_to_file(fd);
    if (file_ptr != NULL) {
        lock_acquire(&filesys_lock);
        file_seek(file_ptr, position);
        lock_release(&filesys_lock);
    }
}


/* Returns the position of the next byte to be read or written
 in open file fd, expressed in bytes from the beginning of the file. */
unsigned tell (int fd) {
    struct file *file_ptr = thread_fd_to_file(fd);
    unsigned position = -1;
    if (file_ptr != NULL) {
        lock_acquire(&filesys_lock);
        position = file_tell(file_ptr);
        lock_release(&filesys_lock);
    }
    return position;
}

/* File descriptor destructor */
void remove_fds (struct hash_elem *e, void *aux) {
    struct lock *fd_lock = (struct lock *) aux;
    struct file_desc *fdp = hash_entry (e, struct file_desc, elem);
    lock_acquire(fd_lock);
    file_close(fdp->fptr);
    lock_release(fd_lock);
    free(fdp);
}

/* Mapping  destructor */
void remove_mapids (struct hash_elem *e, void *aux UNUSED) {
    struct id_addr *m = hash_entry (e, struct id_addr, elem);
    munmap_mapping (m, thread_current ());
    free(m);
}

/* child info destructor */
void remove_child_info (struct hash_elem *e, void *aux UNUSED) {
    struct child_info *ct = hash_entry (e, struct child_info, elem);
    if (ct->cthread != NULL) {
        ct->cthread->parent = NULL;
    }
    free(ct);
}

/* Maps the file open as fd into the process's
 virtual address space. The entire file is mapped into
 consecutive virtual pages starting at addr. */
mapid_t mmap (int fd, void *addr) {

    /* console input and output are not mappable */
    if (fd == STDIN_FILENO || fd == STDOUT_FILENO) {
        return MAP_FAILED;
    }

    int size = filesize(fd);
    /* if the file open as fd has a length of zero bytes
     * or if an error occurs in filesize */
    if (size == -1 || size == 0) {
        return MAP_FAILED;
    }

    /* if addr is not page-aligned */
    if (pg_ofs(addr) != 0) {
        return MAP_FAILED;
    }

    /* if addr is 0 */
    if (!addr) {
        return MAP_FAILED;
    }

    int page_num = size / PGSIZE;
    int rem_bytes = size % PGSIZE;
    if (rem_bytes != 0) {
        page_num++;
    }

    struct thread *t = thread_current();

    /* if the range of pages mapped overlaps any existing set of
     * mapped pages */
    void * ckexist_pt = addr;
    int ckexist_cnt;
    for (ckexist_cnt = 0; ckexist_cnt < page_num;
        ckexist_cnt++, ckexist_pt += PGSIZE) {
        if (page_lookup(ckexist_pt, t)) {
            return MAP_FAILED;
        }
    }

    struct file *file_ptr = thread_fd_to_file(fd);
    if (file_ptr == NULL) {
        return MAP_FAILED;
    }

    /* use file_reopen function to obtain a separate and
     * independent reference to the file */
    lock_acquire(&filesys_lock);
    struct file *refile_ptr = file_reopen(file_ptr);
    lock_release(&filesys_lock);
    if (refile_ptr == NULL) {
        return MAP_FAILED;
    }

    /* add to supplemental page table */
    int offset = 0;
    void *naddr = addr;
    while (size > 0) {
        uint32_t read_bytes = size >= PGSIZE? PGSIZE : size;
        uint32_t zero_bytes = PGSIZE - read_bytes;

        add_page_mmap(naddr, offset, refile_ptr,
                        read_bytes, zero_bytes);

        size -= read_bytes;
        offset += read_bytes;
        naddr += PGSIZE;
    }

    /* create new id_addr, add to mapids */
    struct id_addr *m;
    m = (struct id_addr *)malloc(sizeof(struct id_addr));
    m->addr = addr;
    m->pnum = page_num;
    do {
        if (t->mapid_cnt == USHRT_MAX) {
         t->mapid_cnt = 1;
        }
        m->mapid = ++t->mapid_cnt;
     }
    while (hash_insert(&t->mapids, &m->elem) != NULL);

    return m->mapid;
}

/* Unmaps the id_addr designated by id_addr. */
void munmap (mapid_t id_addr) {
    struct id_addr m_;
    struct id_addr *m;
    struct hash_elem *e;
    struct thread *t = thread_current();
    m_.mapid = id_addr;
    e = hash_find(&t->mapids, &m_.elem);
    if (e != NULL) {
        m = hash_entry(e, struct id_addr, elem);
    } else {
        return;
    }

    munmap_mapping(m, t);
}

void munmap_mapping (struct id_addr *m, struct thread *t) {
    void *addr = m->addr;
    int i;
    /* write back to file */
    for (i = 1; i <= m->pnum; i++) {
        struct page *p = page_lookup(addr, t);
        ASSERT((p != NULL) && (p->type == MMAP));
        release_mmap_page(p);
        hash_delete(&t->page_table, &p->hash_elem);
        free(p);
        addr += PGSIZE;
    }

    hash_delete(&t->mapids, &m->elem);
}
