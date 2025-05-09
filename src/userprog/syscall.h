#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

void syscall_init (void);
static void syscall_handler (struct intr_frame *);
static int syscall_num_args(int syscall_code);
static int conv_vaddr_to_physaddr(const void *vaddr);
static void load_args(struct intr_frame *f, int *arg, int arg_count);
static void verify_ptr(const void*vaddr);
static void verify_str_addr(const void*str);
static void verify_buffer(void* buffer,int size_buffer);

#endif /* userprog/syscall.h */
