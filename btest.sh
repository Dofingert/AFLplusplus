#!/bin/sh
gcc -g -c libafl_stack_log.c libafl_stack_log.o
./afl-gcc -g -c test.c test.o -fno-omit-frame-pointer
./afl-gcc -g libafl_stack_log.o test.o -o test_bin
objdump -S test_bin > test.S
./test_bin 1 2 3 51651 6516 5165 1651 651 65 1651
