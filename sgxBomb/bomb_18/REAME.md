# This bomb is used for ubuntu18.04 
(sgx2.2 is compatable with ubuntu16.04 which docker used to create container)
(kernel module compilation does not work for 16.04)

ISSUES:

./arch/x86/include/asm/bug.h:35:22: error: expected identifier or '(' before string constant
  asm_inline volatile("1:\t" ins "\n"    \


bug.h seem to have problems? (kernel related compatability issue)