/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void sema_init(struct semaphore *sema, unsigned value)
{
	ASSERT(sema != NULL);

	sema->value = value;
	list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
// 어떤 자원에 대해서 sema_down은 1->0, 만약 0인 상태면(다른애가 점유 중이면) 현재 스레드는 block되고 기다림
// 자원 획득에 성공했다면 sema를 감소시킴
void sema_down(struct semaphore *sema)
{
	enum intr_level old_level;

	ASSERT(sema != NULL);
	ASSERT(!intr_context());

	old_level = intr_disable();
	while (sema->value == 0)
	{
		// list_push_back (&sema->waiters, &thread_current ()->elem);
		list_insert_ordered(&sema->waiters, &thread_current()->elem, thread_compare_priority, NULL); // [*]1-2-2. 우선순위 넣기
		thread_block();
	}
	sema->value--;
	intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema)
{
	enum intr_level old_level;
	bool success;

	ASSERT(sema != NULL);

	old_level = intr_disable();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level(old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
// 어떤 자원에 대해서 sema_up은 0->1, 자원을 내려놓고 돌아가니 waiters 중에 우선순위 높은 애 뽑아서 ready상태로 만듦
// 지금 ready_list로 간 애가 지금 실행되고 있는 애보다 우선순위가 높으면 cpu 순서 넘겨 받아야함
void sema_up(struct semaphore *sema)
{
	enum intr_level old_level;

	ASSERT(sema != NULL);

	old_level = intr_disable();
	if (!list_empty(&sema->waiters))
	{
		list_sort(&sema->waiters, thread_compare_priority, NULL); //[*]1-2-2. wait 도중 우선순위 변동 주의
		thread_unblock(list_entry(list_pop_front(&sema->waiters), struct thread, elem));
	}
	sema->value++;
	thread_preemption(); // [*]1-2-2. 지금 waiters 나간 애가 우선 순위가 높아서 바로 실행될 수도 있으니 부르기
	intr_set_level(old_level);
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void)
{
	struct semaphore sema[2];
	int i;

	printf("Testing semaphores...");
	sema_init(&sema[0], 0);
	sema_init(&sema[1], 0);
	thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up(&sema[0]);
		sema_down(&sema[1]);
	}
	printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper(void *sema_)
{
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down(&sema[0]);
		sema_up(&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock *lock)
{
	ASSERT(lock != NULL);

	lock->holder = NULL;
	sema_init(&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void lock_acquire(struct lock *lock)
{
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(!lock_held_by_current_thread(lock)); // 현재 스레드가 이 락을 이미 가지고 있다면 금지

	// [*]1-2-3. 만약 락을 요청했는데 나보다 우선순위 낮은 애가 보유 중이라면, sema down 전에 우선순위 넘겨 줌
	// 어떤 락을 기다리는 지 thread에 넣고, lock의 donation 리스트에 우선순위 맞춰서 넣고, 본인의 우선순위 부여
	struct thread *cur = thread_current();
	if (lock->holder)
	{
		// 현재 스레드가 어떤 락을 기다리는지 기록
		cur->wait_on_lock = lock;
		// 락 보유자의 donations 리스트에 현재 스레드를 우선순위 기준으로 삽입
		list_insert_ordered(&lock->holder->donations, &cur->d_elem, thread_compare_donate_priority, 0);

		// [*]1-2-3. nested donation 처리
		// 내가 기다리는 락을 가진 스레드에게 기부, 그 스레드도 다른 락을 기다리고 있다면 계속 전달
		donate_priority();
	}

	// 자원 요청(lock 획득 시도), value == 1이면 락을 획득하고 value = 0로 설정됨 → 바로 통과
	// value == 0이면 누군가 락을 보유 중 → 현재 스레드는 waiters 리스트에 들어가고 block 상태로 대기
	sema_down(&lock->semaphore);
	cur->wait_on_lock = NULL; //[*]1-2-3. 락 획득했으면 기다리고 있는 락 내용 없앰
	lock->holder = cur;
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
// 락이 “지금 가능한지”만 확인하고, 안 되면 다른 일 하려는 경우에 사용
bool lock_try_acquire(struct lock *lock)
{
	bool success;

	ASSERT(lock != NULL);
	ASSERT(!lock_held_by_current_thread(lock));

	success = sema_try_down(&lock->semaphore);
	if (success)
		lock->holder = thread_current();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release(struct lock *lock)
{
	ASSERT(lock != NULL);
	ASSERT(lock_held_by_current_thread(lock));

	remove_with_lock(lock);	   // [*]1-2-3. donations 리스트에서 현재 해제한 락 기다리던 애들 제거
	thread_refresh_priority(); //[*]1-2-3. 우선순위 복구, 필요하다면 donations 보고 갱신

	lock->holder = NULL;
	sema_up(&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock *lock)
{
	ASSERT(lock != NULL);

	return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem
{
	struct list_elem elem;		/* List element. */
	struct semaphore semaphore; /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond)
{
	ASSERT(cond != NULL);

	list_init(&cond->waiters);
}

// [*]1-2-2. semaphore_elem 받았을 때 정렬 삽입 시 이용하는 함수
bool sema_compare_priority(struct list_elem *a, struct list_elem *b, void *aux)
{
	struct semaphore_elem *l_sema = list_entry(a, struct semaphore_elem, elem);
	struct semaphore_elem *s_sema = list_entry(b, struct semaphore_elem, elem);

	struct list *waiter_l_sema = &(l_sema->semaphore.waiters);
	struct list *waiter_s_sema = &(s_sema->semaphore.waiters);

	return list_entry(list_begin(waiter_l_sema), struct thread, elem)->priority > list_entry(list_begin(waiter_s_sema), struct thread, elem)->priority;
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition *cond, struct lock *lock)
{

	struct semaphore_elem waiter;

	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));

	sema_init(&waiter.semaphore, 0);

	// list_push_back (&cond->waiters, &waiter.elem);
	// [*]1-2-2. 우선순위 넣기, semaphore_elem 구조체 받으므로 비교함수 다른 거 사용
	list_insert_ordered(&cond->waiters, &waiter.elem, sema_compare_priority, NULL);

	lock_release(lock);
	sema_down(&waiter.semaphore);
	lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition *cond, struct lock *lock UNUSED)
{
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));

	if (!list_empty(&cond->waiters))
	{
		// [*]1-2-2. wait 도중 우선순위 변동 주의, semaphore_elem 구조체 받으므로 비교함수 다른 거 사용
		list_sort(&cond->waiters, sema_compare_priority, NULL);
		sema_up(&list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem)->semaphore);
	}
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock)
{
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);

	while (!list_empty(&cond->waiters))
		cond_signal(cond, lock);
}