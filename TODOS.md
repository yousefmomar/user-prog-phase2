# System Call Implementation - TODO List

This document tracks progress on implementing 13 system calls and their integration within the `sysCall_handler`.

## 🛠️ TODO

- [X] **Memory Verification**
  - Implement `verify_str`, `verify_ptr`, `conv_addr`, and check for the converted address.

- [ ] **File System Calls**
  - Use functions from `file.h` within a critical section using locks.
  - Add opened files to:
    - The thread’s file list.
    - The list of locks held by the thread.

- [ ] **Process Synchronization**
  - For `wait()` and `exec()`:
    - Use `sema_up()` and `sema_down()` within the `thread` struct to signal process end or wait.
    - Challenge: Implement correct behavior for both parent and child "threads".

- [ ] **Process Exit**
  - On `exit()`, release all locks acquired by the process, especially if it exits while inside any critical section.

- [ ] **exec() Function Enhancements**
  - Ensure correct parent-child relationship:
    - Identify the parent to call `sema_up()` when child process finishes.
    - Track children inside `thread_create()`.

---

✅ Use checkboxes to track your progress as you go!
