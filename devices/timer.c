#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks; // OS 부팅 이후 발생한 타이머 틱 수

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick; // 타이머 틱 당 루프 수, timer_calibrate()에서 초기화

static intr_handler_func timer_interrupt; // 타이머 인터럽트 처리 함수 포인터
static bool too_many_loops (unsigned loops); // 주어진 루프 수가 1 타이머 틱보다 긴지 확인
static void busy_wait (int64_t loops); // 짧은 지연을 위한 busy-wait 루프 실행
static void real_time_sleep (int64_t num, int32_t denom); // 실제 시간 기반으로 sleep

/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
void
timer_init (void) {
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ; // 8254 입력 주파수를 TIMER_FREQ로 나누고 반올림

	outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
						   // Command Word: 카운터 0, LSB 먼저, MSB 다음, 모드 2, 이진수
	outb (0x40, count & 0xff); // 카운터 0에 하위 바이트(LSB) 출력
	outb (0x40, count >> 8);  // 카운터 0에 상위 바이트(MSB) 출력

	intr_register_ext (0x20, timer_interrupt, "8254 Timer"); // 인터럽트 벡터 0x20에 타이머 인터럽트 처리 함수 등록
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON); // 인터럽트 활성화 상태 확인
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	loops_per_tick = 1u << 10; // loops_per_tick 초기값을 2^10으로 설정
	while (!too_many_loops (loops_per_tick << 1)) { // 2배씩 증가시키면서 1 타이머 틱 초과 여부 확인
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	high_bit = loops_per_tick; // 현재까지의 근사값 저장
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1) // 다음 8비트??
		if (!too_many_loops (high_bit | test_bit)) // 현재 값에 test_bit OR 연산 후 1 타이머 틱 초과 여부 확인
			loops_per_tick |= test_bit; // 초과하지 않으면 해당 비트 설정

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ); // 초당 루프 수 출력
}

/* Returns the number of timer ticks since the OS booted. */
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable (); // 인터럽트 비활성화 (원자성 보장)
	int64_t t = ticks; // 현재 ticks 값 복사
	intr_set_level (old_level); // 인터럽트 이전 상태로 복원
	barrier (); // 컴파일러 최적화 방지
	return t; // 복사한 ticks 값 반환
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then; // 현재 ticks에서 then 값을 빼 경과된 ticks 수 반환
}

/* Suspends execution for approximately TICKS timer ticks. */
void
timer_sleep (int64_t ticks) {
	int64_t start = timer_ticks (); // sleep 시작 시점의 ticks 값 저장

	ASSERT (intr_get_level () == INTR_ON); // 인터럽트 활성화 상태 확인
	// while (timer_elapsed (start) < ticks) // 경과된 ticks 수가 목표 ticks 수보다 작으면
	// 	thread_yield (); // 현재 스레드를 양보하여 다른 스레드 실행
	if (timer_elapsed (start) < ticks){ // [*]1-1. 깨어날 시간이 안 됐을 때만 재우기
		thread_sleep(start + ticks);
	}
}

/* Suspends execution for approximately MS milliseconds. */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000); // 밀리초를 기준으로 real_time_sleep 호출
}

/* Suspends execution for approximately US microseconds. */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000); // 마이크로초를 기준으로 real_time_sleep 호출
}

/* Suspends execution for approximately NS nanoseconds. */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000); // 나노초를 기준으로 real_time_sleep 호출
}

/* Prints timer statistics. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ()); // 현재 ticks 수 출력
}

/* Timer interrupt handler. */
static void
timer_interrupt (struct intr_frame *args UNUSED) {
	ticks++; // 전체 ticks 수 증가
	thread_tick (); // 현재 스레드의 tick 증가 및 스케줄링 결정

	 /* code to add:
	check sleep list and the global tick.
	find any threads to wake up,
	move them to the ready list if necessary.
	update the global tick.
	*/

	//[*]1-1. 재운 스레드 깨우는 함수 호출
	if (ticks >= min_wakeup_tick) {
		thread_wakeup();	
	}
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	int64_t start = ticks; // 현재 ticks 값 저장
	while (ticks == start) // ticks 값이 변경될 때까지 대기 (1 타이머 틱 대기)
		barrier (); // 컴파일러 최적화 방지

	/* Run LOOPS loops. */
	start = ticks; // 다시 현재 ticks 값 저장
	busy_wait (loops); // 주어진 루프 수만큼 busy-wait 실행

	/* If the tick count changed, we iterated too long. */
	barrier (); // 컴파일러 최적화 방지
	return start != ticks; // busy-wait 전후의 ticks 값이 다르면 true (너무 오래 기다림) 반환
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0) // 주어진 루프 수만큼 반복
		barrier (); // 컴파일러 최적화 방지 (루프가 최적화되어 사라지는 것 방지)
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom) {
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom; // 목표 시간을 타이머 틱으로 변환 (내림)

	ASSERT (intr_get_level () == INTR_ON); // 인터럽트 활성화 상태 확인
	if (ticks > 0) { // 1 타이머 틱 이상 대기해야 하는 경우
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
		timer_sleep (ticks); // timer_sleep() 사용하여 CPU 양보
	} else { // 1 타이머 틱 미만의 짧은 시간 대기해야 하는 경우
		/* Otherwise, use a busy-wait loop for more accurate
		   sub-tick timing.  We scale the numerator and denominator
		   down by 1000 to avoid the possibility of overflow. */
		ASSERT (denom % 1000 == 0); // 분모가 1000으로 나누어 떨어지는지 확인 (오버플로 방지 목적)
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
		// busy-wait를 사용하여 더 정확한 서브 틱 시간 지연 (오버플로 방지를 위해 분자와 분모를 1000으로 나눔)
	}
}