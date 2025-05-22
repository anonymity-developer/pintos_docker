#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
struct lock filesys_lock; // [*]2-K: 파일 시스템 락 추가

#endif /* userprog/syscall.h */
