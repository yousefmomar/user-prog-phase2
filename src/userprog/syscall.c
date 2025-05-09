#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <vaddr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/file.h"


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
static int syscall_num_args(int syscall_code){
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


/**
 * @brief implement all 13 syscalls here 
 * 
 * 
 */


static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  int arg[3];
  int esp = conv_vaddr_to_physaddr((const void *)f->esp);
  int syscall_code = *(int*)esp;
  int num_args = syscall_num_args(syscall_code);

  /* 13 system calls handling*/


  switch(num_args){
    case 1:
    load_args(f,arg,1);
    switch(syscall_code){
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
    /////////////////==== NEW ===////////////////////
      
    }
    break;
    case 2:
    load_args(f,arg,2);
    switch(syscall_code){

    }
    break;
    case 3:
    load_args(f,arg,3);
    switch(syscall_code){
      case SYS_WRITE: {
        /* Get and verify arguments */
        int fd = arg[0];
        void *buffer = (void *)arg[1];
        unsigned size = (unsigned)arg[2];
        
        verify_buffer(buffer, size);  // Validate user buffer
        
        /* Perform the write */
        f->eax = sys_write(fd, buffer, size);
        break;
    }

    }
    break;
  }


  printf ("system call!\n");
  thread_exit ();
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
    if(ptr==NULL){
      exit(-1);
    } else{
      return (int*)ptr;
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

  while(i<arg_count){

    int* ptr= (int* )f->esp + i +1;
    verify_ptr((const void*)ptr);
    arg[i++]= *ptr;

  }
}
/**
 * @brief verify the pointer is valid or not 
 * @brief valid means in the user space not entering non-authorrized space aka kernel space 
 * 
 * @param vaddr 
 */
static void verify_ptr(const void*vaddr){
  if(vaddr<(void*)0x08048000 || vaddr>(void*)PHYS_BASE){
    exit(-1);
  }
}
/**
 * @brief check te validty of the dtrint pointer for all characters
 * 
 * @param str 
 */
static void verify_str_addr(const void*str)
{
  char *toCheck = *(char*)conv_vaddr_to_physaddr(str);
  for(toCheck; toCheck!=0; toCheck = *(char*)conv_vaddr_to_physaddr(++str));
}
/**
 * @brief check te validty of the dtrint pointer for all buffer pointers
 * 
 * @param buffer 
 * @param size_buffer 
 */
static void verify_buffer(void* buffer,int size_buffer){

  int i=0;

  char* temp= (char*)buffer;
  while(i<size_buffer){
    verify_ptr((const void*)temp++);
    i++;
  }

}


static int
sys_write(int fd, const void *buffer, unsigned size)
{
    struct thread *cur = thread_current();
    int bytes_written = -1;

    /* Handle console output first */
    if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
        putbuf(buffer, size);
        return size;
    }
    if (fd == STDIN_FILENO) return -1;

    /* Find the file descriptor */
    struct list_elem *e;
    for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list);
         e = list_next(e)) {
        struct file_descriptor *fdesc = list_entry(e, struct file_descriptor, elem);
        if (fdesc->fd == fd) {
            /* Perform the write with locking */
            lock_acquire(&file_system_lock);
            bytes_written = file_write(fdesc->file, buffer, size);
            lock_release(&file_system_lock);
            break;
        }
    }

    return bytes_written;
}