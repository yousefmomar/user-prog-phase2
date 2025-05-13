#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <syscall-nr.h>
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "process.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/inode.h"

static void *get_validated_addr(const void *vaddr) {
  void *phys_addr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!phys_addr || !is_user_vaddr(vaddr) || vaddr < (void *)0x08048000) {
    exit(-1);
  }
  return phys_addr;
}

static void validate_buffer(void *buffer, unsigned size) {
  char *buf = (char *)buffer;
  for (unsigned i = 0; i < size; i++) {
    get_validated_addr(buf + i);
  }
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_system_lock);
}

int syscall_num_args(int syscall_code)
{
  switch (syscall_code)
  {
  case SYS_HALT:
  case SYS_EXIT:
  case SYS_EXEC:
  case SYS_WAIT:
  case SYS_REMOVE:
  case SYS_OPEN:
  case SYS_FILESIZE:
  case SYS_TELL:
  case SYS_CLOSE:
    return 1;

  case SYS_CREATE:
  case SYS_SEEK:
    return 2;

  case SYS_READ:
  case SYS_WRITE:
    return 3;
  }
}

void halt(void) {
  shutdown_power_off();
}

void exit(int status) {
  struct thread *cur = thread_current();
  if (cur->cp != NULL) {
    cur->cp->exit_status = status;
  }
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

tid_t exec(const char *cmd_line) {
    // Check for NULL pointer
    if (cmd_line == NULL) {
        exit(-1);
    }

    // Basic pointer validation - is it in user space?
    if (!is_user_vaddr(cmd_line)) {
        exit(-1);
    }

    // Make a copy of the command line in kernel memory
    char *cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL) {
        return -1;
    }
    
    // Safely copy string from user space to kernel space
    // We'll validate each character as we copy
    int i;
    for (i = 0; i < PGSIZE - 1; i++) {
        // Get and validate each character's address
        void *ptr = (void *)(cmd_line + i);
        if (!is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
            palloc_free_page(cmd_copy);
            exit(-1);
        }
        
        // Copy the character
        cmd_copy[i] = *(char *)ptr;
        
        // If we've reached the end of the string, break
        if (cmd_copy[i] == '\0') {
            break;
        }
    }
    
    // Ensure null termination in case we hit PGSIZE limit
    cmd_copy[i] = '\0';
  
    // Execute the process
    tid_t tid = process_execute(cmd_copy);
    
    if (tid == TID_ERROR) {
        palloc_free_page(cmd_copy);
        return -1;
    }
    
    // Find the child process using the function you've defined
    struct child_process *cp = find_child_process(thread_current(), tid);
    if (cp == NULL) {
        palloc_free_page(cmd_copy);
        return -1;
    }
    
    // Wait for child to load using the semaphore
    sema_down(&cp->load_sema);
    
    // Free the command line copy
    palloc_free_page(cmd_copy);
    
    // Check if load was successful
    if (!cp->load_success) {
        return -1;
    }
    
    return tid;
}

int wait(tid_t pid) {
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
  if (file == NULL) {
    exit(-1);
  }
  verify_ptr((const void*)file);
  verify_str_addr((const void*)file);
  
  lock_acquire(&file_system_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_system_lock);
  return success;
}

bool remove(const char *file) {
  if (file == NULL) {
    exit(-1);
  }
  verify_ptr((const void*)file);
  verify_str_addr((const void*)file);

  lock_acquire(&file_system_lock);
  bool success = filesys_remove(file);
  lock_release(&file_system_lock);
  return success;
}

int open(const char *file) {
  if (file == NULL) {
    return -1;
  }
  verify_ptr((const void*)file);
  verify_str_addr((const void*)file);

  lock_acquire(&file_system_lock);
  struct file *f = filesys_open(file);
  if (f == NULL) {
    lock_release(&file_system_lock);
    return -1;
  }

  struct file_descriptor *fd = set_file_descriptor(f);
  lock_release(&file_system_lock);

  if (fd == NULL) {
    file_close(f);
    return -1;
  }

  return fd->fd;
}

void close(int fd) {
  struct file_descriptor *fdesc = get_file_descriptor(fd);
  if (fdesc == NULL) {
    return;
  }

  lock_acquire(&file_system_lock);
  file_close(fdesc->file);
  lock_release(&file_system_lock);

  list_remove(&fdesc->elem);
  free(fdesc);
}

int read(int fd, void *buffer, unsigned size) {

  if (buffer == NULL) {
    exit(-1);
  }
  
  // Validate the entire buffer
  verify_buffer((void *)buffer, size);
  

  if (fd == 0) {
    unsigned i;
    for (i = 0; i < size; i++) {
      ((char *)buffer)[i] = input_getc();
    }
    return size;
  } else {
    struct file_descriptor* fdesc = get_file_descriptor(fd);
    if (fdesc == NULL)
        return -1;
    struct file* f = fdesc->file;

    if (f == NULL) {
      return -1;
    }

    lock_acquire(&file_system_lock);
    int bytes_read = file_read(f, buffer, size);
    lock_release(&file_system_lock);

    return bytes_read;
  }
}

int filesize(int fd)
{
  struct file_descriptor* fdesc = get_file_descriptor(fd);
  if (fdesc == NULL)
      return -1;
  struct file* f = fdesc->file;
    
  lock_acquire(&file_system_lock);
  int size = file_length(f);
  lock_release(&file_system_lock);

  return size;
}

void seek(int fd, unsigned position) 
{
  struct file_descriptor* fdesc = get_file_descriptor(fd);
  if (fdesc == NULL)
      return;
  struct file* f = fdesc->file;
  
  if (f == NULL) return;

  lock_acquire(&file_system_lock);
  file_seek(f, position);
  lock_release(&file_system_lock);
}

unsigned tell(int fd) 
{
  struct file_descriptor* fdesc = get_file_descriptor(fd);
  if (fdesc == NULL)
      return -1;
  struct file* f = fdesc->file;
  
  if (f == NULL) return -1;

  lock_acquire(&file_system_lock);
  unsigned pos = file_tell(f);
  lock_release(&file_system_lock);

  return pos;
}

void syscall_handler(struct intr_frame *f)
{
  if (!is_user_vaddr(f->esp) || f->esp >= PHYS_BASE) {
      exit(-1);
  }

  verify_ptr(f->esp);

  int arg[3];
  int esp = conv_vaddr_to_physaddr((const void *)f->esp);
  int syscall_code = *(int *)esp;
  int num_args = syscall_num_args(syscall_code);

  switch(num_args){
    case 1:
      load_args(f,&arg[0],1);
      switch(syscall_code){
        case SYS_HALT:
          halt();
          break;

        case SYS_EXIT:
          exit(arg[0]);
          break;

        case SYS_EXEC:
          f->eax = exec((const char *)arg[0]);
          break;

        case SYS_WAIT:
          f->eax = wait(arg[0]);
          break;

        case SYS_REMOVE:
          f->eax = remove((const char *)arg[0]);
          break;

        case SYS_OPEN:
          f->eax = open((const char *)arg[0]);
          break;

        case SYS_FILESIZE:
          f->eax = filesize(arg[0]);
          break;

        case SYS_TELL:
          f->eax = tell(arg[0]);
          break;

        case SYS_CLOSE:
          close(arg[0]);
          break;
      }
      break;

    case 2:
      load_args(f,arg,2);
      switch(syscall_code){
        case SYS_CREATE:
          f->eax = create((const char *)arg[0], (unsigned)arg[1]);
          break;

        case SYS_SEEK:
          seek(arg[0], (unsigned)arg[1]);
          break;
      }
      break;

    case 3:
      load_args(f,&arg[0],3);
      switch(syscall_code){
        case SYS_READ:
          f->eax = read(arg[0], (void *)arg[1], (unsigned)arg[2]);
          break;

        case SYS_WRITE:
          f->eax = sys_write(arg[0], (const void *)arg[1], (unsigned)arg[2]);
          break;
      }
      break;
  }
}

int conv_vaddr_to_physaddr(const void *vaddr)
{
  verify_ptr(vaddr);

  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (ptr == NULL)
  {
    exit(-1);
  }
  else
  {
    return (int *)ptr;
  }
}

void load_args(struct intr_frame *f, int *arg, int arg_count)
{
  int i = 0;

  while (i < arg_count)
  {
    int *ptr = (int *)f->esp + i + 1;
    verify_ptr((const void *)ptr);
    arg[i++] = *ptr;
  }
}

void verify_ptr(const void *vaddr)
{
  if (vaddr == NULL) {
    exit(-1);
  }

  if (!is_user_vaddr(vaddr) || 
      vaddr < (void *)0x08048000 || 
      vaddr >= PHYS_BASE ||
      pagedir_get_page(thread_current()->pagedir, vaddr) == NULL) {
      exit(-1);
  }
}

void verify_str_addr(const void *str)
{
  char *toCheck = *(char *)conv_vaddr_to_physaddr(str);
  for (toCheck; toCheck != 0; toCheck = *(char *)conv_vaddr_to_physaddr(++str))
    ;
}

void verify_buffer(void *buffer, int size_buffer)
{
  if (buffer == NULL) {
    exit(-1);
  }

  // Check each page the buffer spans
  char *start = (char *)buffer;
  char *end = start + size_buffer;
  
  // Verify first and last byte of buffer
  verify_ptr(start);
  verify_ptr(end - 1);
  
  // If buffer spans multiple pages, verify each page boundary
  char *page = (char *)pg_round_down(start + PGSIZE);
  while (page < end) {
    verify_ptr(page);
    page += PGSIZE;
  }
}

struct file_descriptor *get_file_descriptor(int fd)
{
  struct thread *cur = thread_current();
  struct list_elem *e;

  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
  {
    struct file_descriptor *file_desc = list_entry(e, struct file_descriptor, elem);
    if (file_desc->fd == fd)
    {
      return file_desc;
    }
  }

  return NULL;
}

struct file_descriptor *set_file_descriptor(struct file *file) {
  struct thread *cur = thread_current();
  struct file_descriptor *fd = malloc(sizeof(struct file_descriptor));
  
  if (fd == NULL) {
    return NULL;
  }

  fd->file = file;
  fd->fd = cur->next_fd++;
  list_push_back(&cur->file_list, &fd->elem);
  
  return fd;
}

int sys_write(int fd, const void *buffer, unsigned size)
{
  if (buffer == NULL) {
    exit(-1);
  }
  
  // Validate the entire buffer
  verify_buffer((void *)buffer, size);
  

  struct thread *cur = thread_current();
  struct file *file = NULL;
  int bytes_written = -1;

  switch (fd)
  {
  case STDOUT_FILENO:
  case STDERR_FILENO:
    lock_acquire(&file_system_lock);
    putbuf(buffer, size);
    lock_release(&file_system_lock);
    return size;

  case STDIN_FILENO:
    return -1;
  }

  struct file_descriptor *fdesc = get_file_descriptor(fd);
  if (fdesc == NULL || fdesc->file == NULL)
  {
    return -1;
  }

  file = fdesc->file;

  lock_acquire(&file_system_lock);
  if (!(file->deny_write))
  {
    bytes_written = file_write(file, buffer, size);
  }
  lock_release(&file_system_lock);

  return bytes_written;
}