#!/bin/sh
clang -g -c libafl_stack_log.c -o libafl_stack_log.o
./afl-clang-fast -g -c test.c -o test.o -fno-omit-frame-pointer
./afl-clang-fast -g libafl_stack_log.o test.o -o test_bin
objdump -S test_bin > test.S
./test_bin 1 2 3 51651 6516 5165 1651 651 65 1651
# echo 0 > /proc/sys/kernel/randomize_va_space