#include <stdint.h>
#include <stdio.h>

#define TRACE_HISTORY_TABLE_SIZE 32 * 1024
#define TRACE_HISTORY_LENGTH 32

uint8_t enable_id;
uint64_t stack_hash_map[TRACE_HISTORY_TABLE_SIZE][TRACE_HISTORY_LENGTH] = {0}; // 为每一个 block id 分配 32 bytes trace history，共计 2 M
uint64_t fse, fsb;

void __afl_stack_log(int block_id)
{
    // 获取父函数栈区结束位置 == rbp + 8
    uint64_t *father_stack_end;
    asm("movq %%rbp, %0"
    : "=r"(father_stack_end)/* output */
    :/* inputs */
    :/**/);
    // 获取父函数栈区开始位置 == *rbp
    uint64_t *father_stack_begin = *(uint64_t**)father_stack_end;
    father_stack_end += 1;
    int iter = 0;
    fsb = father_stack_begin;
    fse = father_stack_end;
    for(uint64_t* xor_ptr = father_stack_end; xor_ptr != father_stack_begin ; xor_ptr += 1) {
        stack_hash_map[block_id % TRACE_HISTORY_TABLE_SIZE][iter++] ^= *xor_ptr;
        iter %= TRACE_HISTORY_LENGTH;
    }
}

extern int fb(int n);

int main_wrapper(int argc) {
    for (int i = 0 ; i < argc ; i ++) {
        // printf("%3d %16p %16p\n", fb(i), fsb, fse);
        fb(i);
    }
}

int main(int argc, char *argv[]) {
    main_wrapper(argc);
    for(int i = 0 ; i < TRACE_HISTORY_LENGTH ; i++) {
        printf("%16llx ", stack_hash_map[0][i]);
        if(i % 4 == 3) {
            putchar('\n');
        }
    }
}
