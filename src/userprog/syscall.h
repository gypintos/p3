#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"

typedef int mapid_t;
struct lock filesys_lock;

void syscall_init (void);
void exit (int status);

int write (int fd, const void *buffer, unsigned length);
tid_t exec (const char *file_name);
int wait (tid_t);
void halt (void);
bool create (const char *file_name, unsigned initial_size);
int open (const char *file_name);
bool remove (const char *file_name);
int filesize (int fd);
struct file * get_file_by_id (int fd);
void insert_fd (struct thread *t, struct file_desc* opened_file);
int read (int fd, void *buffer, unsigned length);
void close (int fd);
void seek (int fd, unsigned position);
unsigned tell (int fd);
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t id_addr);
void munmap_mapping (struct id_addr *m, struct thread *t);

void get_args (int *ptr, int argnum, void **syscall_args_ptr);
void validate_addr (void *addr, void *esp, bool writable);
void validate_buf (char* buff_ptr, int size, void *esp, bool writeable);
void release_buf (const char* buff_ptr, int size);
void release_args (int *ptr, int argnum, void **syscall_args_ptr);

/* Map region identifier. */

/* Failure status code of mmap operation */
#define MAP_FAILED ((mapid_t) -1)

#endif /* userprog/syscall.h */
