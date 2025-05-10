#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <syscall-nr.h>
// #include <vaddr.h>//ta2reban 8alat
#include "threads/vaddr.h" //el sa7 maybe ?
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "process.h"
#include "devices/input.h"
#include "devices/shutdown.h"


void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_system_lock);
}
static int syscall_num_args(int syscall_code)
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


void close (int fd)
{
      struct file_descriptor* fdesc = get_file_descriptor(fd);
      if (fdesc == NULL)
          return -1;
      struct file* f = fdesc->file;
  
      lock_acquire(&file_system_lock);
      file_close(f);
      lock_release(&file_system_lock);


      list_remove(&fdesc->elem);
      free(fdesc);
      // thread_current()->file_list[fd] = NULL;

}

bool create (const char *file,unsigned initial_size)
{
  lock_acquire(&file_system_lock);
  bool successful = filesys_create(file, initial_size); // from filesys.h
  lock_release(&file_system_lock);
  return successful;
}

int read (int fd, void *buffer, unsigned size){
  if (fd == 0) {
    // Read from keyboard
    unsigned i;
    for (i = 0; i < size; i++) {
      ((char *)buffer)[i] = input_getc();
    }
    return size;
  } else {
    // Read from file
    // struct file *f = thread_current()->file_list[fd];
    struct file_descriptor* fdesc = get_file_descriptor(fd);
    if (fdesc == NULL)
        return -1;
    struct file* f = fdesc->file;

    if (f == NULL) {
      return -1; // File not found
    }

    lock_acquire(&file_system_lock);
    int bytes_read = file_read(f, buffer, size);
    lock_release(&file_system_lock);

    return bytes_read;
  }
}

int filesize(int fd)
{
  // struct file *f = thread_current()->file_list[fd];
    struct file_descriptor* fdesc = get_file_descriptor(fd);
    if (fdesc == NULL)
        return -1;
    struct file* f = fdesc->file;
    
 
  lock_acquire(&file_system_lock);
  int size = file_length(f);
  lock_release(&file_system_lock);

  return size;
}

int open(const char *file) 
{
  lock_acquire(&file_system_lock);
  struct file *f = filesys_open(file);  
  lock_release(&file_system_lock);

  if (f == NULL)
      return -1;

    struct file_descriptor *fdesc = set_file_descriptor(f);
    if (fdesc == NULL) {
        file_close(f);
        return -1;
    }

    return fdesc->fd;
}


void seek(int fd, unsigned position) 
{
  // struct file *f = thread_current()->file_list[fd];
  struct file_descriptor* fdesc = get_file_descriptor(fd);
  if (fdesc == NULL)
      return -1;
  struct file* f = fdesc->file;
  
  if (f == NULL) return;

  lock_acquire(&file_system_lock);
  file_seek(f, position);
  lock_release(&file_system_lock);
}

unsigned tell(int fd) 
{
  // struct file *f = thread_current()->file_list[fd];
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
/**
 * @brief implement all 13 syscalls here
 *
 *
 */

void
syscall_handler(struct intr_frame *f UNUSED)
{

  int arg[3];
  int esp = conv_vaddr_to_physaddr((const void *)f->esp);
  int syscall_code = *(int *)esp;
  int num_args = syscall_num_args(syscall_code);

  /* 13 system calls handling*/

  switch(num_args){
    case 1:
      load_args(f,&arg[0],1);
      switch(syscall_code){

        case SYS_CLOSE:
          {
            int file_descriptor= conv_vaddr_to_physaddr((const void*)arg[0]);
            close(file_descriptor);
            break;
          }

        case SYS_FILESIZE:
          {
            int fd=conv_vaddr_to_physaddr((const void*)arg[0]);
            f->eax=filesize(fd);
            break;
          }
          
        case SYS_EXEC:
          {
              // Verify the filename pointer is valid
              verify_ptr((const void*)arg[0]);
              verify_str_addr((const void*)arg[0]);

              // Get physical address of filename
              const char* file_name = (const char*)conv_vaddr_to_physaddr((const void*)arg[0]);
              
              // Execute process and store result in eax
              tid_t tid = process_execute(file_name);

              struct thread *child = thread_get_by_tid(tid);
                  if (child == NULL)
                      f->eax = -1;
                  else {
                      // Wait for child to finish loading
                      sema_down(&child->cp->load_sema);
                      
                      // Check if load was successful
                      if (child->cp->load_success)
                          f->eax = tid;
                      else
                          f->eax = -1;
                  }
                  break;
          }
          
        case SYS_REMOVE:
          {
              // Verify the filename pointer is valid
              verify_ptr((const void*)arg[0]);
              verify_str_addr((const void*)arg[0]);
              
              // Get physical address of filename
              const char* file_name = (const char*)conv_vaddr_to_physaddr((const void*)arg[0]);
              
              // Remove file and store result in eax
              f->eax = filesys_remove(file_name);
              break;
          }
        case SYS_OPEN:
          {
            verify_str_addr((const void*)arg[0]);
            const char* filename = (const char*)arg[0];
            f->eax = open(filename);
            break;
          }
        case SYS_TELL:
          {
            int fd = arg[0];
            f->eax = tell(fd);
            break;
          }
          
      /////////////////==== NEW ===////////////////////
      case SYS_WAIT:
      {
        // Get child process ID from the first argument passed to syscall
        // arg[0] contains the PID of the child process to wait for
        int pid = arg[0];

        // Call process_wait() with the child PID
        // process_wait() will:
        // 1. Block the current process until specified child terminates
        // 2. Return the child's exit status
        // 3. Return -1 if the child was already waited on or if pid is invalid
        // Store the return value in eax register which holds syscall return values
        f->eax = process_wait(pid);
        break;
      }
      case SYS_EXIT:
      {
        // Safely get the exit code argument using existing validation functions
        void *arg_ptr = (void *)(f->esp + 4);
        verify_ptr(arg_ptr); // Validate the pointer before dereferencing

        int exit_code = *(int *)arg_ptr;
        thread_current()->cp->exit_status = exit_code;
        process_exit(); // This function won't return
        break;
      }
      }
      break;

    case 2:
    load_args(f,arg,2);
    switch(syscall_code){

      case SYS_CREATE:
      {
        verify_str_addr((const void*)arg[0]);
        arg[1]= conv_vaddr_to_physaddr((const void*)arg[1]);
        const char* file= (const char*)arg[0];
        unsigned initial_size= arg[1];
        f->eax=create(file,initial_size);
        break;
      }
      case SYS_SEEK:
        {
          int fd = arg[0];
          unsigned position = arg[1];
          seek(fd, position);
          break;
        }
    }
    break;

    case 3:
      load_args(f,&arg[0],3);
      switch(syscall_code){

      case SYS_READ:
      {
        arg[0]=conv_vaddr_to_physaddr((const void*)arg[0]);
        arg[2]=conv_vaddr_to_physaddr((const void*)arg[2]);
        verify_buffer((void*)arg[1],arg[2]);
        int fd= arg[0];
        void* buffer= (void*)arg[1];
        unsigned size= arg[2];
        f->eax=read(fd,buffer,size);
        break;
      }
      case SYS_WRITE:
        {
          /* Get and verify arguments */
          int fd = arg[0];
          void *buffer = (void *)arg[1];
          unsigned size = (unsigned)arg[2];

          verify_buffer(buffer, size); // Validate user buffer

          /* Perform the write */
          f->eax = sys_write(fd, buffer, size);
          break;
        }
 
  }

  printf("system call!\n");
  thread_exit();
}
}
/**
 * @brief convert from virtual address to physical address
 *
 * @param vaddr
 * @return int
 */
static int
conv_vaddr_to_physaddr(const void *vaddr)
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

/**
 * @brief loads arguments from user space to kernel space
 *
 * @param f
 * @param arg
 * @param arg_count
 */
static void load_args(struct intr_frame *f, int *arg, int arg_count)
{
  int i = 0;

  while (i < arg_count)
  {

    int *ptr = (int *)f->esp + i + 1;
    verify_ptr((const void *)ptr);
    arg[i++] = *ptr;
  }
}
/**
 * @brief verify the pointer is valid or not
 * @brief valid means in the user space not entering non-authorrized space aka kernel space
 *
 * @param vaddr
 */
static void verify_ptr(const void *vaddr)
{
  if (vaddr < (void *)0x08048000 || vaddr > (void *)PHYS_BASE)
  {
    exit(-1);
  }
}
/**
 * @brief check te validty of the dtrint pointer for all characters
 *
 * @param str
 */
static void verify_str_addr(const void *str)
{
  char *toCheck = *(char *)conv_vaddr_to_physaddr(str);
  for (toCheck; toCheck != 0; toCheck = *(char *)conv_vaddr_to_physaddr(++str))
    ;
}
/**
 * @brief check te validty of the dtrint pointer for all buffer pointers
 *
 * @param buffer
 * @param size_buffer
 */
static void verify_buffer(void *buffer, int size_buffer)
{

  int i = 0;

  char *temp = (char *)buffer;
  while (i < size_buffer)
  {
    verify_ptr((const void *)temp++);
    i++;
  }
}

struct file_descriptor *get_file_descriptor(int fd)
{
  struct thread *cur = thread_current(); // Get the current thread
  struct list_elem *e;

  // Iterate through the file descriptor list of the current thread
  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
  {
    struct file_descriptor *file_desc = list_entry(e, struct file_descriptor, elem);
    if (file_desc->fd == fd)
    {
      return file_desc; // Return the file descriptor object if found
    }
  }

  return NULL; // Return NULL if the file descriptor was not found
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
  struct thread *cur = thread_current();
  struct file *file = NULL;
  int bytes_written = -1;

  /* Handle standard file descriptors (no lock needed for console) */
  switch (fd)
  {
  case STDOUT_FILENO:
  case STDERR_FILENO:
    lock_acquire(&file_system_lock); // Acquire lock before writing to console
    putbuf(buffer, size);            // Write the buffer to console
    lock_release(&file_system_lock); // Release lock after writing to console
    return size;

  case STDIN_FILENO:
    return -1; // Can't write to stdin
  }

  /* Search for the file descriptor in thread's file_list */
  struct file_descriptor *fdesc = get_file_descriptor(fd);
  if (fdesc == NULL || fdesc->file == NULL)
  {
    return -1; // Invalid file descriptor or file not opened
  }

  file = fdesc->file;

  /* Perform the write with the global file system lock */
  lock_acquire(&file_system_lock); // Acquire the global file system lock
  if (!(file->deny_write))
  {
    bytes_written = file_write(file, buffer, size); // Write to the file
  }
  lock_release(&file_system_lock); // Release the global lock after writing to the file

  return bytes_written; // Return the number of bytes written, or -1 if error
}