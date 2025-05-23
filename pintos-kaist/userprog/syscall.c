#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
typedef int pid_t;
#include "threads/palloc.h"
#include <string.h>

void syscall_entry(void);
void syscall_handler(struct intr_frame *f);
void sys_halt (void);
void sys_exit (int status);
int sys_write(int fd, const void *buffer, unsigned size);
int sys_exec (const char *cmd_line);
int sys_open(const char *file);
void check_address(void *addr);
pid_t sys_fork(const char *thread_name, struct intr_frame *fff);
static struct file *find_file_by_fd(int fd);

/*
이 파일에서 프로세스 생성과 실행을 관리한다
유저프로세스가 커널 기능에 접근하고 싶을 때, 시스템 콜을 호출하여 커널에게 요청한다

현재는 메세지만 출력하고 프로세스를 종료하는 기능만 있다

시스템 콜에 필요한 나머지 기능을 여기에 구현해야한다
*/

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */


void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
  lock_init(&filesys_lock); // [*]2-K: 락 초기화
}

/* The main system call interface */
// [*]2-K : 기본 함수에 시스템콜 넘버에 따른 분기 추가
void
syscall_handler (struct intr_frame *f UNUSED) {
  // TODO: Your implementation goes here.

  /* rax = 시스템 콜 넘버 */
  int syscall_n = f->R.rax; /* 시스템 콜 넘버 */
  switch (syscall_n)
  {
  case SYS_HALT:
    sys_halt();
    break;
  case SYS_EXIT:
    sys_exit(f->R.rdi);
    break;
  case SYS_WRITE:
    f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
    break;
  case SYS_EXEC:
    if (sys_exec(f->R.rdi) == -1) {
      sys_exit(-1);
      }
    break;
  case SYS_FORK:
    f->R.rax = sys_fork(f->R.rdi, f);
    break;
  case SYS_OPEN:
    f->R.rax = open(f->R.rdi);
    break;
  case SYS_WAIT:
    f->R.rax = sys_wait(f->R.rdi);
  default:
    thread_exit ();
    break;
  }
  // printf ("system call!\n");
}

// [*]2-K : 커널 halt는 프로그램 종료
void sys_halt(void) {
  power_off();
}

// [*]2-K : 커널 exit은 상태값을 받아서 출력 후 종료
void sys_exit(int status) {
  struct thread *cur = thread_current();
  // 정상적으로 종료됐으면 status는 0을 받는다.
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();  // process_exit() → schedule() → _cleanup
}

// [*]2-K : 커널 sys_write
int sys_write(int fd, const void *buffer, unsigned size) {

  check_address(buffer);

  // STDOUT인 경우 콘솔에 출력
  if (fd == 1)
    {
      putbuf(buffer, size);
      return size;
    }

  // TODO: 그 외 fd는 추가 file_write() 구현 필요
  return -1;
}

pid_t sys_fork(const char *thread_name, struct intr_frame *fff){
  check_address(thread_name);
  return process_fork(thread_name, fff);
}
// [*]2-K 커널 exec
int sys_exec(const char *cmd_line) {

  // 1) 유저 영역에서 커널 영역 침범하지 않았는지 확인
  check_address(cmd_line);

  // 2) 커널 영역에 명령어 복사를 위한 공간 확보
  int cmd_line_size = strlen(cmd_line) + 1;
  char *cm_copy = palloc_get_page(PAL_ZERO);  // 커널 메모리 확보
  if (cm_copy == NULL)
  {
    sys_exit(-1);
  }
  strlcpy(cm_copy, cmd_line, cmd_line_size);  // 안전하게 복사해둠
  
  // file 실행이 실패했다면 -1을 리턴한다.
  if (process_exec(cm_copy) == -1)
  {
      return -1;
  }
  // 정상적으로 process_exec 실행되면 아래 부분은 실행되지 않음.
  NOT_REACHED();
  return 0;
}

// [*]2-K 커널 open
int open(const char *file)
{
  check_address(file);
  lock_acquire(&filesys_lock);
  struct file *open_file = filesys_open(file);

  if (open_file == NULL)
  {
      return -1;
  }
  // fd table에 file추가
  int fd = add_file_to_fdt(open_file);

  // fd table 가득 찼을경우
  // if (fd == -1)
  // {
  //     file_close(open_file);
  // }
  lock_release(&filesys_lock);
  return fd;
}

int sys_wait(pid_t pid){
  return process_wait(pid);
}

// [*]2-K 유저 영역에서 커널 영역 침범하지 않았는지 확인
void check_address(void *addr) {
    struct thread *t = thread_current();

    if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(t->pml4, addr) == NULL)
    {
        sys_exit(-1);
    }
}

// [*]2-K: 파일을 현재 프로세스의 fdt에 추가
int
add_file_to_fdt (struct file *file)
{
  struct thread *cur = thread_current ();
  struct file **fdt = cur->fd_table;     /* fd_table 포인터 가져오기 */
  int start = cur->next_fd;
  int fd = start;                         /* fd를 start로 초기화 */

  /* 1) OPEN_LIMIT 범위 안에서 비어 있는 슬롯을 찾는다. */
  while (fd < OPEN_LIMIT && fdt[fd] != NULL)
    fd++;

  /* 2) 빈 슬롯이 없으면 -1 리턴 */
  if (fd >= OPEN_LIMIT)
    return -1;

  /* 3) 빈 슬롯에 파일 저장, next_fd 갱신, fd 반환 */
  fdt[fd] = file;
  cur->next_fd = fd + 1;
  return fd;
}

// [*]2-K: fd 값을 넣으면 해당 file을 반환하는 함수
static struct file *find_file_by_fd(int fd)
{
    struct thread *cur = thread_current();
    if (fd < 0 || fd >= OPEN_LIMIT)
    {
        return NULL;
    }
    return cur->fd_table[fd];
}