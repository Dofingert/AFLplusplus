/*
   This function is used to test difference between given stack trace map and trace sets.
   */

#include "afl-fuzz.h"
#include "stack_param.h"

float evaluate_diff(u64* new_inputs, u64* ref_set, u32 test_cnt)
{
    if(test_cnt > MAX_RECORD_HISTORY_SIZE) test_cnt = MAX_RECORD_HISTORY_SIZE;
    if(test_cnt < 0) test_cnt = 0;
    if(test_cnt == 0) {
        return 0.0f;
    }
    // 对 new_inputs 中的每个字，寻找其在 test_set 中 hammiing distance 的最小值
    // 以此最小值作为该 new_inputs 的该字的偏离值，最后返回所有偏离值之和
    float diff_score = 0;
    for(int i = 0 ; i < TRACE_HISTORY_TABLE_SIZE * TRACE_HISTORY_LENGTH ; i++) {
        u64 l_value = new_inputs[i];
        u8 min_distance = 64;
        for(int j = 0 ; j < test_cnt ; j++) {
            u64 r_value = ref_set[i * MAX_RECORD_HISTORY_SIZE + j];
            u64 lr_diff = l_value ^ r_value;
            u64 cur_distance;
            asm("popcnt %1,%0" : "=r"(cur_distance) : "r"(lr_diff) :);
            u8 flag = cur_distance < min_distance ? 1 : 0;
            min_distance = flag ? cur_distance : min_distance;
            if(min_distance==0)break;
        }
        if(min_distance != 0) {
            printf("None zero distance found %d !\n", test_cnt);
        }
        diff_score += min_distance;
    }
    printf("DIFF VALUE IS %f\n", diff_score);
    return diff_score;
}

void save_stacktrace(u64* new_inputs, u64* ref_set, u32 test_cnt)
{
    test_cnt = test_cnt % MAX_RECORD_HISTORY_SIZE;
    for(int i = 0 ; i < TRACE_HISTORY_TABLE_SIZE * TRACE_HISTORY_LENGTH ; i++) {
        // printf("%p %p\n",&ref_set[i * MAX_RECORD_HISTORY_SIZE + test_cnt], &new_inputs[i]);
        ref_set[i * MAX_RECORD_HISTORY_SIZE + test_cnt] = new_inputs[i];
    }
}
