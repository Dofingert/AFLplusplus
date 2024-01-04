#!/bin/sh
clang -g -c libafl_stack_log.c -o libafl_stack_log.o
./afl-clang-fast -g test.c -o test_bin -fno-omit-frame-pointer
objdump -S test_bin > test.S
./test_bin 12
# echo 0 > /proc/sys/kernel/randomize_va_space