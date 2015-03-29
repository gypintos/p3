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
            f->eax = file_sz;
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
        lock_release(&frames_lock);
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

void halt (void) {
    shutdown_power_off();
}

void exit (int status) {
    struct thread* curr= thread_current();
    printf ("%s: exit(%d)\n", curr->name, status);
    hash_destroy(&curr->mapids, remove_mapids);
    hash_destroy(&curr->fds, remove_fds);

    lock_acquire(&exec_list_lock);
    remove_exec_threads_entry(curr);
    lock_release(&exec_list_lock);

    lock_acquire(&filesys_lock);
    file_close(curr->exe);
    lock_release(&filesys_lock);

    hash_destroy(&curr->page_table, page_destructor);

    sema_down(&sys_sema);
    hash_destroy(&thread_current()->children, remove_child_info);
    if (curr->parent != NULL){
        struct thread *p = curr->parent;
        struct child_info* ci = find_child_info(p, thread_current()->tid);
        if (ci){
            lock_acquire(&ci->wait_lock);
            ci->state = CHILD_EXITING;
            ci->cthread = NULL;
            ci->exit_code = status;
            cond_signal(&ci->wait_cond, &ci->wait_lock);
            lock_release(&ci->wait_lock);
        }
    }
    sema_up(&sys_sema);
    thread_exit();
}

tid_t exec (const char *file_name){
    lock_acquire(&filesys_lock);
    tid_t pid = process_execute(file_name);
    lock_release(&filesys_lock);
    return pid;
}

int wait (tid_t pid) {
    return process_wait(pid);
}

bool create (const char *file_name, unsigned initial_size) {
    if(!file_name) exit(-1);
    lock_acquire(&filesys_lock);
    int result = filesys_create(file_name, initial_size);
    lock_release(&filesys_lock);
    return result;
}

int open (const char *file_name) {
    struct thread* curr = thread_current();
    if (hash_size(&curr->fds) == MAX_OPEN_FILES)
        return -1;
    lock_acquire(&filesys_lock);
    struct file* f_ptr = filesys_open(file_name);
    if (!f_ptr){
        lock_release(&filesys_lock);
        return -1;
    }
    lock_release(&filesys_lock);
    struct file_desc *fd_open = malloc(sizeof(struct file_desc));
    fd_open->fptr = f_ptr;
    insert_fd(curr, fd_open);
    return fd_open->fid; 
}

void insert_fd(struct thread *t, struct file_desc *fd) {
     fd->fid = ++t->fd_seq;
     while(!hash_insert(&t->fds, &fd->elem)){
        ;
     }

}

 bool remove (const char *file_name) {
    lock_acquire(&filesys_lock);
    bool result = filesys_remove(file_name);
    lock_release(&filesys_lock);
    return result;
 }

 int filesize (int fd) {
    lock_acquire(&filesys_lock);
    struct file *fptr = get_file_by_id(fd);
    int fsize = -1;
    if (fptr != NULL) {
        fsize = file_length(fptr);
     }
     lock_release(&filesys_lock);
     return fsize;
  }

 struct file * get_file_by_id (int fid) {
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
    // if (fd == 1) {
    //     return -1;
    // }
    // if (fd == 0) {
    //     char *b = (char *) buffer;
    //     int i = 0;
    //     while (length > 0 || b[i-1] != '\n') {
    //         b[i] = input_getc();
    //         i++;
    //         length--;
    //     }
    //     release_buf(buffer, length);
    //     return i;
    // }
    // struct file *file_ptr = get_file_by_id(fd);

    // if (file_ptr != NULL) {
    //     lock_acquire(&filesys_lock);
    //     length = file_read(file_ptr, buffer, length);
    //     lock_release(&filesys_lock);
    //     release_buf(buffer, length);
    //     return length;
    // }
    // return -1;
//

    if (fd == STDOUT_FILENO){
        return -1;
    } else if (fd == STDIN_FILENO){
        int i;
        char *tmp = (char *) buffer;
        for( i = 0; i < length; i++){
            tmp[i] = input_getc();
        }
        release_buf(buffer, length);
        return length;
    } else {
        lock_acquire(&filesys_lock);
        struct file* fptr = get_file_by_id(fd);
        if (fptr == NULL){
            lock_release(&filesys_lock);
            return -1;
        }
        int result = file_read(fptr, buffer, length);
        lock_release(&filesys_lock);
        return result;
    }

}

int write (int fd, const void *buffer, unsigned length) {
    if (fd == STDIN_FILENO) {
        return 0;
    } else if (fd == STDOUT_FILENO){
        int cnt = length/BUFFER_SIZE;
        int remain = length%BUFFER_SIZE;
        int i;
        for (i = 0; i < cnt; i++){
            putbuf(buffer + i* BUFFER_SIZE, BUFFER_SIZE);
        }
        if (remain > 0){
            putbuf(buffer + cnt * BUFFER_SIZE, remain);
        }
        release_buf(buffer, length);
        return length;
    } else {
        struct file *f_ptr = get_file_by_id(fd);
        if (f_ptr) {
            lock_acquire(&filesys_lock);
            length = file_write(f_ptr, buffer, length);
            lock_release(&filesys_lock);
            release_buf(buffer, length);
            return length;
        };
        return 0;
    }
}


void close (int fid) {
    struct file_desc fd;
    fd.fid = fid;
    struct hash_elem* elem = hash_delete(&thread_current()->fds, &fd.elem);
    if (!elem){
        return;  
    } else {
        struct file_desc* fdp = hash_entry(elem, struct file_desc, elem);
        lock_acquire(&filesys_lock);
        file_close(fdp->fptr);
        lock_release(&filesys_lock);
        free(fdp);
    } 
}

void seek (int fd, unsigned pos) {
    lock_acquire(&filesys_lock);
    struct file *fptr = get_file_by_id(fd);
    if (!fptr){
        lock_release(&filesys_lock);
        return;
    }
    file_seek(fptr, pos);
    lock_release(&filesys_lock);
}

unsigned tell (int fd) {
    lock_acquire(&filesys_lock);
    struct file* fptr = get_file_by_id(fd);
    if (!fptr){
        lock_release(&filesys_lock);
        return -1;
    }
    unsigned pos = file_tell(fptr);
    lock_release(&filesys_lock);
    return pos;
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
    munmap_helper (m, thread_current ());
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

    if (fd == STDIN_FILENO || fd == STDOUT_FILENO || addr == NULL 
        || pg_ofs(addr)) {
        return MAP_FAILED;
    }

    int size = filesize(fd);
    if (size == -1 || size == 0) {
        return MAP_FAILED;
    }




    // /* console input and output are not mappable */
    // if (fd == STDIN_FILENO || fd == STDOUT_FILENO) {
    //     return MAP_FAILED;
    // }

    // int size = filesize(fd);
    //  if the file open as fd has a length of zero bytes
    //  * or if an error occurs in filesize 
    // if (size == -1 || size == 0) {
    //     return MAP_FAILED;
    // }

    // /* if addr is not page-aligned */
    // if (pg_ofs(addr) != 0) {
    //     return MAP_FAILED;
    // }

    // /* if addr is 0 */
    // if (!addr) {
    //     return MAP_FAILED;
    // }




    // int page_num = size / PGSIZE;
    // int rem_bytes = size % PGSIZE;
    // if (rem_bytes != 0) {
    //     page_num++;
    // }


    struct file* fptr = get_file_by_id(fd);
    if(!fptr) {
        return MAP_FAILED;
    }

    int page_cnt= size / PGSIZE;
    int remain= size % PGSIZE;
    if (remain){
        page_cnt++;
    }



    struct thread *curr = thread_current();

    //struct thread *t = thread_current();

    /* if the range of pages mapped overlaps any existing set of
     * mapped pages */


    void *exist_addr = addr;
    int exist_cnt = 0;
    while(exist_cnt < page_cnt) {
        if(page_lookup(exist_addr, curr)){
            return MAP_FAILED;
        }
        exist_addr += PGSIZE;
        exist_cnt++;
    }

    // void * ckexist_pt = addr;
    // int ckexist_cnt;
    // for (ckexist_cnt = 0; ckexist_cnt < page_num;
    //     ckexist_cnt++, ckexist_pt += PGSIZE) {
    //     if (page_lookup(ckexist_pt, t)) {
    //         return MAP_FAILED;
    //     }
    // }

    // struct file *file_ptr = get_file_by_id(fd);
    // if (file_ptr == NULL) {
    //     return MAP_FAILED;
    // }

    /* use file_reopen function to obtain a separate and
     * independent reference to the file */

    lock_acquire(&filesys_lock);
    struct file *re_fptr = file_reopen(fptr);
    lock_release(&filesys_lock);
    if(!re_fptr) return MAP_FAILED;


    // lock_acquire(&filesys_lock);
    // struct file *refile_ptr = file_reopen(file_ptr);
    // lock_release(&filesys_lock);
    // if (refile_ptr == NULL) {
    //     return MAP_FAILED;
    // }

    /* add to supplemental page table */

    int offset = 0;
    void *naddr = addr;
    while(size > 0){
         uint32_t rbytes = 0;
         uint32_t zbytes = 0;
        if(size >= PGSIZE){
            rbytes = PGSIZE;
        } else {
            rbytes = size;
        }
        zbytes = PGSIZE - rbytes;
        add_page_mmap(naddr, offset, re_fptr, rbytes, zbytes);
        size -= rbytes;
        offset += rbytes;
        naddr += PGSIZE;
    }




    // int offset = 0;
    // void *naddr = addr;
    // while (size > 0) {
    //     uint32_t read_bytes = size >= PGSIZE? PGSIZE : size;
    //     uint32_t zero_bytes = PGSIZE - read_bytes;

    //     add_page_mmap(naddr, offset, refile_ptr,
    //                     read_bytes, zero_bytes);

    //     size -= read_bytes;
    //     offset += read_bytes;
    //     naddr += PGSIZE;
    // }

    /* create new id_addr, add to mapids */

    struct id_addr *new_addr;
    new_addr = (struct id_addr *)malloc(sizeof(struct id_addr));
    new_addr->addr = addr;
    new_addr->pnum = page_cnt;

    if(curr->mapid_cnt == USHRT_MAX){
        curr->mapid_cnt = 1;
    }
    curr->mapid_cnt++;
    new_addr->mapid = curr->mapid_cnt;

    while(!hash_insert(&curr->mapids, &new_addr->elem)){
        ;
    }
    return new_addr->mapid;


    // struct id_addr *m;
    // m = (struct id_addr *)malloc(sizeof(struct id_addr));
    // m->addr = addr;
    // m->pnum = page_num;
    // do {
    //     if (t->mapid_cnt == USHRT_MAX) {
    //      t->mapid_cnt = 1;
    //     }
    //     m->mapid = ++t->mapid_cnt;
    //  }
    // while (hash_insert(&t->mapids, &m->elem) != NULL);

    // return m->mapid;
}

/* Unmaps the id_addr designated by id_addr. */
void munmap (mapid_t id) {
    struct thread *curr = thread_current();
    struct id_addr new_addr;
    struct hash_elem *ele = hash_find(&curr->mapids, &new_addr.elem);
    struct id_addr *e_addr;
    if(ele)    e_addr = hash_entry(elem, struct id_addr, elem);
    else    return;

    munmap_helper(e_addr, curr);


    // struct id_addr m_;
    // struct id_addr *m;
    // struct hash_elem *e;
    // struct thread *t = thread_current();
    // m_.mapid = id_addr;
    // e = hash_find(&t->mapids, &m_.elem);
    // if (e != NULL) {
    //     m = hash_entry(e, struct id_addr, elem);
    // } else {
    //     return;
    // }

    // munmap_mapping(m, t);
}

void munmap_helper (struct id_addr *id, struct thread *t) {
    void *addr = id->addr;
    int i = 1;
    while( i <= id->pnum){
        struct page *p = page_lookup(addr, t);
        if(p && p->type == MMAP){
            release_mmap_page(p);
            hash_delete(&t->page_table, &p->hash_elem);
            free(p);
            addr += PGSIZE;
            i++;
        }
    }
    hash_delete(&t->mapids, &id->elem);


    // void *addr = id->addr;
    // int i;
    // /* write back to file */
    // for (i = 1; i <= id->pnum; i++) {
    //     struct page *p = page_lookup(addr, t);
    //     ASSERT((p != NULL) && (p->type == MMAP));
    //     release_mmap_page(p);
    //     hash_delete(&t->page_table, &p->hash_elem);
    //     free(p);
    //     addr += PGSIZE;
    // }

    //hash_delete(&t->mapids, &id->elem);
}
