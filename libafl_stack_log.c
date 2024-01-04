#include <stdint.h>
#include <stdio.h>

#include "include/stack_param.h"

uint64_t *stack_hash_map = NULL; // 为每一个 func id 分配 32 bytes trace history，共计 2 M
uint64_t fsb;

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <wait.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
static void *helper_open_shm(int shm_key, int *create, void *location, size_t filesize)
{
  int shm_id = -1, shm_flag = 0;
  while (1)
  {
    shm_id = shmget(shm_key, filesize, shm_flag);
    if (shm_id >= 0)
      break;
    if (ENOENT != errno || *create == 0)
    {
       printf("Can not open shared memory 0x%x, errno %d\n", shm_key, errno);
         return NULL;
    }
    shm_flag = IPC_CREAT | 0660;
    *create = 0;
  }
  return shmat(shm_id, location, 0);
}

int __afl_err;

void __afl_stack_log(unsigned int func_id)
{
    // printf("func_id: %d\n", func_id);
    // 获取父函数栈区结束位置 == rbp + 8
    static unsigned int lfunc_id = 0;
    uint64_t *father_stack_end;
    asm("movq %%rbp, %0"
    : "=r"(father_stack_end)/* output */
    :/* inputs */
    :/**/);
    // 获取父函数栈区开始位置 == *rbp
    father_stack_end = *(uint64_t**)father_stack_end;
    uint64_t *father_ra = *(((uint64_t**)father_stack_end) + 1);
    uint64_t ra_id = (uint64_t)father_ra ^ ((uint64_t)father_ra >> 16);
    // printf("%d %d ra: %p\n", func_id, lfunc_id, father_ra);
    uint64_t *father_stack_begin = (*(uint64_t**)father_stack_end) - 1;
    father_stack_end += 2; // 排除 ra 及 rbp 影响
    // printf("from 0x%p to 0x%p\n", father_stack_begin, father_stack_end);

    // 初始化共享内存
    if(stack_hash_map == NULL) {
        int create = 1;
        stack_hash_map = helper_open_shm(1229,&create,NULL,TRACE_HISTORY_TABLE_SIZE * TRACE_HISTORY_LENGTH * 8);
        if(stack_hash_map == NULL) {
            __afl_err = 1;
            return;
        }
        memset(stack_hash_map,0,TRACE_HISTORY_TABLE_SIZE * TRACE_HISTORY_LENGTH * 8);
    }

    int iter = 0;
    fsb = (ra_id % TRACE_HISTORY_TABLE_SIZE) * TRACE_HISTORY_LENGTH;
    for(uint64_t* xor_ptr = father_stack_end; xor_ptr != father_stack_begin ; xor_ptr += 1) {
        stack_hash_map[(ra_id % TRACE_HISTORY_TABLE_SIZE) * TRACE_HISTORY_LENGTH + iter] = *xor_ptr;
        iter++;
        iter %= TRACE_HISTORY_LENGTH;
    }
    lfunc_id = func_id;
}

extern int fb(int n);

void __afl_stack_call_back() {
    if(stack_hash_map != NULL) {
        for(int i = 0 ; i < TRACE_HISTORY_LENGTH ; i++) {
            printf("%16llx ", stack_hash_map[fsb+i]);
            if(i % 4 == 3) {
                putchar('\n');
            }
        }
    }
    printf("%x %d\n", fsb, __afl_err);
}
