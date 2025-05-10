#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit(void);
void process_activate (void);
struct child_process *find_child_process(struct thread *parent, tid_t child_tid);
void update_child_exit_status(tid_t child_tid, int status);


#endif /* userprog/process.h */
