/* This program attempts to execute code at address 0, which is not mapped.
   This should terminate the process with a -1 exit code. */
// 코드를 실행하려고 0번 주소를 프로그램 카운터로 삼는 행위.

#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
  msg ("Congratulations - you have successfully called NULL: %d", 
        ((int (*)(void))NULL)());
  fail ("should have exited with -1");
}
