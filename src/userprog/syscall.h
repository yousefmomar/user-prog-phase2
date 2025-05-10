#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/interrupt.h"

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

void syscall_init (void);
void syscall_handler (struct intr_frame *);
int syscall_num_args(int syscall_code);
int conv_vaddr_to_physaddr(const void *vaddr);
void load_args(struct intr_frame *f, int *arg, int arg_count);
void verify_ptr(const void*vaddr);
void verify_str_addr(const void*str);
void verify_buffer(void* buffer,int size_buffer);

struct file_descriptor *get_file_descriptor(int fd);
struct file_descriptor *set_file_descriptor(struct file *file);

struct lock file_system_lock;
int sys_write(int fd, const void *buffer, unsigned size);

#endif /* userprog/syscall.h */
