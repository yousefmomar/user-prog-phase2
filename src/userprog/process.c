#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

////////// NEW ///////////
#include "threads/synch.h"
///////// NEW ///////////

/* Used for setup_stack */
static void push_stack(int order, void **esp, char *token, char **argv, int argc);

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp, char **save_ptr);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name)
{
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, file_name, PGSIZE);

	/* Parsed file name */
	char *save_ptr;
	file_name = strtok_r((char *)file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page(fn_copy);
	return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *file_name_)
{
	char *file_name = file_name_;
	struct intr_frame if_;
	bool success;

	/* the first token is file name */
	char *save_ptr;
	file_name = strtok_r(file_name, " ", &save_ptr);

	/* Initialize interrupt frame and load executable. */
	memset(&if_, 0, sizeof if_);
	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
	if_.cs = SEL_UCSEG;
	if_.eflags = FLAG_IF | FLAG_MBS;
	success = load(file_name, &if_.eip, &if_.esp, &save_ptr);

	thread_current()->cp->load_success = success;
	sema_up(&thread_current()->cp->load_sema);
	
	/* If load failed, quit. */
	palloc_free_page(file_name);
	if (!success)
		thread_exit();

	/* Start the user process by simulating a return from an
	 interrupt, implemented by intr_exit (in
	 threads/intr-stubs.S).  Because intr_exit takes all of its
	 arguments on the stack in the form of a `struct intr_frame',
	 we just point the stack pointer (%esp) to our stack frame
	 and jump to it. */
	asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
	NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */

/////////////////////////////////////////////
//////////========= NEW ==========///////////
/////////////////////////////////////////////

/* List to keep track of all child processes created by the current process */
static struct list child_list;

/* Initialize the list of child processes
	Called when the process system starts up */
void process_init(void)
{
	list_init(&child_list); // Initialize empty list for child processes
}

/* Search through child_list to find a specific child process by its thread ID
	Returns NULL if child is not found
	Used by process_wait and update_child_exit_status */
static struct child_process *find_child_process(struct thread *parent, tid_t child_tid)
{
    struct list_elem *e;
    for (e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e))
    {
        struct child_process *cp = list_entry(e, struct child_process, elem);
        if (cp->pid == child_tid)
            return cp;
    }
    return NULL;
}


/* Create a new child process entry and add it to child_list
	Called when a new process is created via process_execute
	Initializes synchronization primitives for parent-child coordination */
void add_child_process(tid_t child_tid)
{
	struct child_process *cp = malloc(sizeof(struct child_process));
	if (cp != NULL)
	{
		cp->pid = child_tid;					// Store child's thread ID
		cp->exit_status = -1;					// Initialize exit status to -1
		cp->wait = false;						// No wait yet
		cp->exit = false;						// Child hasn't exited
		sema_init(&cp->load_sema, 0);			// Semaphore for load synchronization
		sema_init(&cp->exit_sema, 0);			// Semaphore for exit synchronization
		list_push_back(&child_list, &cp->elem); // Add to list of children
	}
}



/* Check if a given thread ID represents a child process of the current process
	Returns true if the thread ID belongs to a direct child of the current process,
	false otherwise. */
static bool is_child_process(struct thread *parent, tid_t child_tid)
{
	struct list_elem *e;

	/* Iterate through each element in the child_list */
	for (e = list_begin(&child_list); e != list_end(&child_list); e = list_next(e))
	{
		/* Get the child_process structure from the list element */
		struct child_process *cp = list_entry(e, struct child_process, elem);

		/* Check if this child's process ID matches the one we're looking for */
		if (cp->pid == child_tid)
		{
			return true; /* Found a matching child process */
		}
	}

	/* No matching child process was found */
	return false;
}

/* Wait for a child process to exit and retrieve its exit status
	Returns -1 if:
	- child_tid is not a child of the calling process
	- process_wait was already called for this child
	- child_tid is invalid */
int process_wait(tid_t child_tid)
{
	struct thread *cur = thread_current();
	struct child_process *cp = find_child_process(cur, child_tid);

	// Validate child process
	if (cp == NULL || cp->wait || !is_child_process(cur, child_tid))
		return -1;

	cp->wait = true; // Mark that we're waiting on this child

	// If child hasn't exited yet, wait for it
	if (!cp->exit)
		sema_down(&cp->exit_sema);

	int status = cp->exit_status; // Get child's exit status

	// Cleanup: remove child from list and free its memory
	list_remove(&cp->elem);
	free(cp);

	return status;
}

/////////////////////////////////////////////
//////////========= NEW ==========///////////
/////////////////////////////////////////////

///////////////////start of exit updates/////////////////////////
/* Free the current process's resources. */
void process_exit(void)
{
    struct thread *cur = thread_current();
    uint32_t *pd = cur->pagedir;

    /* Print termination message */
    printf("%s: exit(%d)\n", cur->name, cur->exit_status);

    /* If parent is still alive, notify parent */
    if (cur->parent_tid != TID_ERROR)
    {
        struct thread *parent = get_thread_by_tid(cur->parent_tid);
        if (parent != NULL)
        {
            struct child_process *cp = find_child_process(parent, cur->tid);
            if (cp != NULL)
            {
                cp->exit_status = cur->exit_status;
                cp->exit = true;
                sema_up(&cp->exit_sema); // Notify parent
            }
        }
    }

    /* Close all open files */
    struct list_elem *e;
    while (!list_empty(&cur->file_list))
    {
        e = list_pop_front(&cur->file_list);
        struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
        file_close(fd->file);
        free(fd);
    }

    /* Close running executable */
    if (cur->executable != NULL)
    {
        file_allow_write(cur->executable);
        file_close(cur->executable);
    }

    /* Clean up child_list (free all child_process structs) */
    while (!list_empty(&cur->child_list))
    {
        e = list_pop_front(&cur->child_list);
        struct child_process *cp = list_entry(e, struct child_process, elem);
        free(cp);
    }

    /* Destroy page directory */
    if (pd != NULL)
    {
        cur->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }

    thread_exit(); // Terminate thread
}

/* Update a child process's exit status when it terminates
	Called by process_exit when a child process exits
	Signals waiting parent that child has finished */
void update_child_exit_status(tid_t child_tid, int exit_code)
{
	struct child_process *cp = find_child_process(thread_current(), child_tid);
	if (cp != NULL)
	{
		ASSERT(cp != NULL);
		cp->exit_status = exit_code; // Store exit code
		cp->exit = true;			 // Mark as exited
		sema_up(&cp->exit_sema);	 // Wake up waiting parent if any
	}
	else
	{
		PANIC("No child process found with tid %d", child_tid);
	}
}
////////////////end of exit updates/////////////////////////

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
	struct thread *t = thread_current();

	/* Activate thread's page tables. */
	pagedir_activate(t->pagedir);

	/* Set thread's kernel stack for use in processing
	 interrupts. */
	tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
	unsigned char e_ident[16];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
	Elf32_Word p_type;
	Elf32_Off p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0			/* Ignore. */
#define PT_LOAD 1			/* Loadable segment. */
#define PT_DYNAMIC 2		/* Dynamic linking info. */
#define PT_INTERP 3			/* Name of dynamic loader. */
#define PT_NOTE 4			/* Auxiliary info. */
#define PT_SHLIB 5			/* Reserved. */
#define PT_PHDR 6			/* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* redefined setup_stack to take save_ptr as argument */
static bool setup_stack(void **esp, const char *file_name, char **save_ptr);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes,
						 bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp, char **save_ptr)
{
	struct thread *t = thread_current();
	struct Elf32_Ehdr ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pagedir = pagedir_create();
	if (t->pagedir == NULL)
		goto done;
	process_activate();

	/* Open executable file. */
	file = filesys_open(file_name);
	if (file == NULL)
	{
		printf("load: %s: open failed\n", file_name);
		goto done;
	}
	file_deny_write(file);

	/* Read and verify executable header. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
	{
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Elf32_Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* Ignore this segment. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint32_t file_page = phdr.p_offset & ~PGMASK;
				uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint32_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
					 Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					/* Entirely zero.
					 Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment(file, file_page, (void *)mem_page,
								  read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack(esp, file_name, save_ptr))
		goto done;

	/* Start address. */
	*eip = (void (*)(void))ehdr.e_entry;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close(file);
	return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (Elf32_Off)file_length(file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	 user address space range. */
	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	 address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	 Not only is it a bad idea to map page 0, but if we allowed
	 it then user code that passed a null pointer to system calls
	 could quite likely panic the kernel by way of null pointer
	 assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

		- READ_BYTES bytes at UPAGE must be read from FILE
		  starting at offset OFS.

		- ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Calculate how to fill this page.
		 We will read PAGE_READ_BYTES bytes from FILE
		 and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page(upage, kpage, writable))
		{
			palloc_free_page(kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp, const char *file_name, char **save_ptr)
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage != NULL)
	{
		success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
		if (success)
		{
			*esp = PHYS_BASE;
		}
		else
		{
			palloc_free_page(kpage);
			return success;
		}

		char **argv = malloc(2 * sizeof(char *));

		if (argv != NULL)
		{
			int argc = 0;
			int argv_size = 2;
			char *token = (char *)file_name;

			/* push arguments to stack */
			while (token != NULL)
			{
				*esp -= strlen(token) + 1;
				argv[argc++] = *esp;
				/* resize argv if it exceeds the length */
				if (argc >= argv_size)
				{
					argv = realloc(argv, (argv_size *= 2) * sizeof(char *));
					if (argv == NULL)
					{
						return false;
					}
				}
				memcpy(*esp, token, strlen(token) + 1);
				token = strtok_r(NULL, " ", save_ptr);
			}

			/* align words */
			int size = (size_t)*esp % 4;
			if (size != 0)
			{
				memcpy(*esp -= size, &argv[argc], size);
			}

			/* set the last index of argv to 0 */
			argv[argc] = 0;

			int number_of_arg = argc;
			/* push all argv */
			while (number_of_arg >= 0)
			{
				*esp -= sizeof(char *);
				memcpy(*esp, &argv[number_of_arg--], sizeof(char *));
			}

			/* push argv, argc, and return address in order */
			for (int order = 1; order < 4; order++)
			{
				push_stack(order, esp, token, argv, argc);
			}

			/* free the argv */
			free(argv);
		}
		else
		{
			return false;
		}
		return success;
	}
	else
	{
		return success;
	}
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* Verify that there's not already a page at that virtual
	 address, then map our page there. */
	return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}

/* final argument push for the stack */
static void push_stack(int order, void **esp, char *token, char **argv, int argc)
{
	switch (order)
	{
	case 1:
		/* 1 push argv */
		token = *esp;
		*esp -= sizeof(char **);
		memcpy(*esp, &token, sizeof(char **));
		break;

	case 2:
		/* 2 push argc */
		*esp -= sizeof(int);
		memcpy(*esp, &argc, sizeof(int));
		break;

	case 3:
		/* 3 push return address */
		*esp -= sizeof(void *);
		memcpy(*esp, &argv[argc], sizeof(void *));
		break;
	}
}