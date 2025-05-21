#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void sys_halt (void);
void sys_exit (int status);
int sys_write(int fd, const void *buffer, unsigned size);
int sys_exec (const char *cmd_line);
void check_address(void *addr);

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
  // // 임시 추가
  //  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
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

// [*]2-K 커널 exec
int sys_exec(const char *cmd_line) {

    // 1) 유저 영역에서 커널 영역 침범하지 않았는지 확인
  check_address(cmd_line);

  int pid = process_exec((void*)cmd_line);
  if (pid < 0)
      return -1;

// - 명령줄 인수도 자식 프로세스에 전달합니다.  
// - 성공하면 새로 생성된 자식 프로세스의 PID를 반환합니다.  
// - 프로그램 로드나 스레드 생성에 실패하면 `-1`을 반환합니다.  
// - 이 `exec()`를 호출한 부모 프로세스는, 자식 프로세스가 완전히 생성되고 실행 파일을 모두 로드할 때까지 기다려야 합니다.  
  
  // 성공한 경우, 새 자식 PID를 반환
  return pid;
  // NOT_REACHED();
  // return 0;
}

// [*]2-K 유저 영역에서 커널 영역 침범하지 않았는지 확인
void check_address(void *addr) {
    struct thread *t = thread_current();

    if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(t->pml4, addr) == NULL)
    {
        sys_exit(-1);
    }
}
