/*
   american fuzzy lop++ - bitmap related routines
   ----------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <limits.h>
#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

void write_bitmap(afl_state_t *afl) {

  u8  fname[PATH_MAX];
  s32 fd;

  if (!afl->bitmap_changed) { return; }
  afl->bitmap_changed = 0;

  snprintf(fname, PATH_MAX, "%s/fuzz_bitmap", afl->out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  ck_write(fd, afl->virgin_bits, afl->fsrv.map_size, fname);

  close(fd);

}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

u32 count_bits(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (likely(v == 0xffffffff)) {

      ret += 32;
      continue;

    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

u32 count_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (likely(!v)) { continue; }
    if (v & 0x000000ffU) { ++ret; }
    if (v & 0x0000ff00U) { ++ret; }
    if (v & 0x00ff0000U) { ++ret; }
    if (v & 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

u32 count_non_255_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (likely(v == 0xffffffffU)) { continue; }
    if ((v & 0x000000ffU) != 0x000000ffU) { ++ret; }
    if ((v & 0x0000ff00U) != 0x0000ff00U) { ++ret; }
    if ((v & 0x00ff0000U) != 0x00ff0000U) { ++ret; }
    if ((v & 0xff000000U) != 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */
const u8 simplify_lookup[256] = {

    [0] = 1, [1 ... 255] = 128

};

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

const u8 count_class_lookup8[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

};

u16 count_class_lookup16[65536];

void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {

    for (b2 = 0; b2 < 256; b2++) {

      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];

    }

  }

}

/* Import coverage processing routines. */

#ifdef WORD_SIZE_64
  #include "coverage-64.h"
#else
  #include "coverage-32.h"
#endif

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

inline u8 has_new_bits(afl_state_t *afl, u8 *virgin_map) {

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)afl->fsrv.trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 7) >> 3);

#else

  u32 *current = (u32 *)afl->fsrv.trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 3) >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

  u8 ret = 0;
  while (i--) {

    if (unlikely(*current)) discover_word(&ret, current, virgin);

    current++;
    virgin++;

  }

  if (unlikely(ret) && likely(virgin_map == afl->virgin_bits))
    afl->bitmap_changed = 1;

  return ret;

}

/* A combination of classify_counts and has_new_bits. If 0 is returned, then the
 * trace bits are kept as-is. Otherwise, the trace bits are overwritten with
 * classified values.
 *
 * This accelerates the processing: in most cases, no interesting behavior
 * happen, and the trace bits will be discarded soon. This function optimizes
 * for such cases: one-pass scan on trace bits without modifying anything. Only
 * on rare cases it fall backs to the slow path: classify_counts() first, then
 * return has_new_bits(). */

inline u8 has_new_bits_unclassified(afl_state_t *afl, u8 *virgin_map) {

  /* Handle the hot path first: no new coverage */
  u8 *end = afl->fsrv.trace_bits + afl->fsrv.map_size;

#ifdef WORD_SIZE_64

  if (!skim((u64 *)virgin_map, (u64 *)afl->fsrv.trace_bits, (u64 *)end))
    return 0;

#else

  if (!skim((u32 *)virgin_map, (u32 *)afl->fsrv.trace_bits, (u32 *)end))
    return 0;

#endif                                                     /* ^WORD_SIZE_64 */
  classify_counts(&afl->fsrv);
  return has_new_bits(afl, virgin_map);

}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  u32 i = 0;

  while (i < afl->fsrv.map_size) {

    if (*(src++)) { dst[i >> 3] |= 1 << (i & 7); }
    ++i;

  }

}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Returns a ptr to afl->describe_op_buf_256. */

u8 *describe_op(afl_state_t *afl, u8 new_bits, size_t max_description_len) {

  u8 is_timeout = 0;

  if (new_bits & 0xf0) {

    new_bits -= 0x80;
    is_timeout = 1;

  }

  size_t real_max_len =
      MIN(max_description_len, sizeof(afl->describe_op_buf_256));
  u8 *ret = afl->describe_op_buf_256;

  if (unlikely(afl->syncing_party)) {

    sprintf(ret, "sync:%s,src:%06u", afl->syncing_party, afl->syncing_case);

  } else {

    sprintf(ret, "src:%06u", afl->current_entry);

    if (afl->splicing_with >= 0) {

      sprintf(ret + strlen(ret), "+%06d", afl->splicing_with);

    }

    sprintf(ret + strlen(ret), ",time:%llu,execs:%llu",
            get_cur_time() + afl->prev_run_time - afl->start_time,
            afl->fsrv.total_execs);

    if (afl->current_custom_fuzz &&
        afl->current_custom_fuzz->afl_custom_describe) {

      /* We are currently in a custom mutator that supports afl_custom_describe,
       * use it! */

      size_t len_current = strlen(ret);
      ret[len_current++] = ',';
      ret[len_current] = '\0';

      ssize_t size_left = real_max_len - len_current - strlen(",+cov") - 2;
      if (is_timeout) { size_left -= strlen(",+tout"); }
      if (unlikely(size_left <= 0)) FATAL("filename got too long");

      const char *custom_description =
          afl->current_custom_fuzz->afl_custom_describe(
              afl->current_custom_fuzz->data, size_left);
      if (!custom_description || !custom_description[0]) {

        DEBUGF("Error getting a description from afl_custom_describe");
        /* Take the stage name as description fallback */
        sprintf(ret + len_current, "op:%s", afl->stage_short);

      } else {

        /* We got a proper custom description, use it */
        strncat(ret + len_current, custom_description, size_left);

      }

    } else {

      /* Normal testcase descriptions start here */
      sprintf(ret + strlen(ret), ",op:%s", afl->stage_short);

      if (afl->stage_cur_byte >= 0) {

        sprintf(ret + strlen(ret), ",pos:%d", afl->stage_cur_byte);

        if (afl->stage_val_type != STAGE_VAL_NONE) {

          sprintf(ret + strlen(ret), ",val:%s%+d",
                  (afl->stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                  afl->stage_cur_val);

        }

      } else {

        sprintf(ret + strlen(ret), ",rep:%d", afl->stage_cur_val);

      }

    }

  }

  if (is_timeout) { strcat(ret, ",+tout"); }

  if (new_bits == 2) { strcat(ret, ",+cov"); }

  if (unlikely(strlen(ret) >= max_description_len))
    FATAL("describe string is too long");

  return ret;

}

#endif                                                     /* !SIMPLE_FILES */

/* Write a message accompanying the crash directory :-) */

void write_crash_readme(afl_state_t *afl) {

  u8    fn[PATH_MAX];
  s32   fd;
  FILE *f;

  u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

  sprintf(fn, "%s/crashes/README.txt", afl->out_dir);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  /* Do not die on errors here - that would be impolite. */

  if (unlikely(fd < 0)) { return; }

  f = fdopen(fd, "w");

  if (unlikely(!f)) {

    close(fd);
    return;

  }

  fprintf(
      f,
      "Command line used to find this crash:\n\n"

      "%s\n\n"

      "If you can't reproduce a bug outside of afl-fuzz, be sure to set the "
      "same\n"
      "memory limit. The limit used for this fuzzing session was %s.\n\n"

      "Need a tool to minimize test cases before investigating the crashes or "
      "sending\n"
      "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

      "Found any cool bugs in open-source tools using afl-fuzz? If yes, please "
      "post\n"
      "to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the "
      "issues\n"
      " are fixed :)\n\n",

      afl->orig_cmdline,
      stringify_mem_size(val_buf, sizeof(val_buf),
                         afl->fsrv.mem_limit << 20));      /* ignore errors */

  fclose(f);

}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define _VECTOR_DEFAULT_LEN_ 16

struct c_vector {
  size_t   elem_size;
  uint32_t elem_space;
  uint32_t elem_cnt;
  void    *data_ptr;
};

static inline void *extend_data_area(void *old_data, size_t old_size,
                                     size_t new_size) {
  void *ret = malloc(new_size);
  memcpy(ret, old_data, old_size);
  free(old_data);
  return ret;
}

static inline struct c_vector *new_c_vector(size_t elem_size) {
  struct c_vector *vec = malloc(sizeof(struct c_vector));
  vec->elem_size = elem_size;
  vec->elem_space = _VECTOR_DEFAULT_LEN_;
  vec->elem_cnt = 0;
  vec->data_ptr = extend_data_area(NULL, vec->elem_cnt * vec->elem_size, vec->elem_space * vec->elem_size);
  return vec;
}

static inline void *access_c_vector(struct c_vector *self, uint32_t index) {
  if (index >= self->elem_space) { return NULL; }
  return self->data_ptr + index * self->elem_size;
}

static inline void push_c_vector(struct c_vector *self, void *elem_ptr) {
  uint32_t new_cnt = self->elem_cnt + 1;
  if (new_cnt > self->elem_space) {
    self->elem_space *= 2;
    self->data_ptr =
        extend_data_area(self->data_ptr, self->elem_cnt * self->elem_size, self->elem_space * self->elem_size);
  }
  memcpy(access_c_vector(self, self->elem_cnt), elem_ptr, self->elem_size);
  self->elem_cnt = new_cnt;
}

static inline void pop_c_vector(struct c_vector *self, void *elem_ptr) {
  memcpy(elem_ptr, access_c_vector(self, self->elem_cnt - 1), self->elem_size);
}

int vec_elem_cnt = 4096;

int        k_value = 2;
struct c_vector *bitmap_set;
struct c_vector *belonging_set;
uint32_t         major_sel;
uint8_t        **means_data_ptr;
uint32_t        *means_data_cnt;

unsigned long long calculate_distance(uint8_t *data, uint8_t *ref,
                                      uint32_t cnt) {
  unsigned long long abs_sum = 0;
  for (uint32_t i = 0; i < cnt; i++) {
    // optimise me by simd
    int value = data[i] - ref[i];
    value = (value < 0) ? -value : value;
    abs_sum += value;
  }
  return abs_sum;
}

// this function update mneans_data.
void update_mean_value() {
  for (int k = 0; k < k_value; k++) {
    means_data_cnt[k] = 0;
    memset(means_data_ptr[k], 0, vec_elem_cnt);
  }
  for (int i = 0; i < bitmap_set->elem_cnt; i++) {
    for (int j = 0; j < vec_elem_cnt; j++) {
      int sel = *(int *)access_c_vector(belonging_set, i);
      means_data_ptr[sel][j] += ((uint8_t *)access_c_vector(bitmap_set, i))[j];
      means_data_cnt[sel] += 1;
    }
  }
  for (int k = 0; k < k_value; k++) {
    for (int j = 0; j < vec_elem_cnt; j++) {
      means_data_ptr[k][j] << 16;
      means_data_ptr[k][j] =
          means_data_cnt[k] ? (means_data_ptr[k][j] / means_data_cnt[k]) : 0;
    }
  }
}

// this is our interface for interacting.
int judge_area(uint8_t *data, unsigned long long *distance) {
  unsigned long long min_distance = 0xffffffffffffffff;
  int                sel;
  for (int j = 0; j < k_value; j++) {
    unsigned long long cur_value =
        calculate_distance(data, means_data_ptr[j], vec_elem_cnt);
    if (cur_value < min_distance) {
      min_distance = cur_value;
      sel = j;
    }
  }
  *distance += min_distance;
  return sel;
}

// divided vector to differenct area by it distance
unsigned long long partition() {
  unsigned long long distance = 0;
  for (int i = 0; i < bitmap_set->elem_cnt; i++) {
    *(int *)access_c_vector(belonging_set, i) =
        judge_area(access_c_vector(bitmap_set, i), &distance);
  }
  return distance;
}

static u8 initialized = 0;
void init_all() {
  bitmap_set = new_c_vector(vec_elem_cnt);
  belonging_set = new_c_vector(sizeof(int));
  printf("initialized ok.\n");
}

void print_vec(uint8_t *dat, int cnt) {
  for (int i = 0; i < cnt; i++) {
    printf("%d%c", dat[i], i == cnt - 1 ? '\n' : ' ');
  }
}

void init_km() {
  static unsigned long long last_sum = 0xffffffffffffffff;
  unsigned long long        sum = 0xffffffffffff0000;
  means_data_ptr = malloc(k_value * sizeof(void *));
  means_data_cnt = malloc(k_value * sizeof(int));
  for (int i = 0; i < k_value; i++) {
    means_data_ptr[i] = malloc(vec_elem_cnt);
    memcpy(means_data_ptr[i], access_c_vector(bitmap_set, i), vec_elem_cnt);
  }
  printf("im here 0\n");
  int iter = 0;
  while (last_sum - sum > (4 + (iter >> 9))) {
    // for (int k = 0; k < k_value; k++) {
    //   print_vec(means_data_ptr[k], vec_elem_cnt);
    // }
    last_sum = sum;
    sum = partition();
    update_mean_value();
    printf("iter %d: %llu\n", iter++, sum);
  }
  // Judge major means_sel
  major_sel = -1;
  long long max_cnt = 0x0;
  for(int k = 0 ; k < k_value ; k++) {
    if(means_data_cnt[k] > max_cnt) {
      max_cnt = means_data_cnt[k];
      major_sel = k;
    }
  }
}

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */
u8 gen_mode = 0; // 0 for exploration, 1 for generating.
double avg_byte_cnt = 0.f;
char filename_buf[4096];
u32 input_cnt = 0;
u8 __attribute__((hot))
save_if_interesting(afl_state_t *afl, void *mem, u32 len, u8 fault) {

  if(unlikely(!initialized)) {
    vec_elem_cnt = afl->shm.map_size;
    init_all();
    initialized = 1;
  }

  static u32 no_found_cnt = 0;
  static u32 valid_input_cnt = 0;

  if(gen_mode == 0 && no_found_cnt > /* LIMIT FOR NO FOUNDING EXPLORATION*/ 1000000) {
    // Mode transaction
    // Calculate kmeans...
    // init_km();
    gen_mode = 1;
    printf("GENMODE!");
  }

  if(gen_mode) {
    if(avg_byte_cnt * 1.5 < count_bytes(afl, afl->fsrv.trace_bits)) {
       // Valid test input.
        snprintf(filename_buf, 4095, "%s/queue/gen_%06u", afl->out_dir, ++valid_input_cnt);
        int fd = open(filename_buf, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
        if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", filename_buf); }
        ck_write(fd, mem, len, queue_fn);
        close(fd);
    }
  }

  // if(!gen_mode) {
  //   int tmp_zero = 0;
  //   push_c_vector(bitmap_set, afl->fsrv.trace_bits);
  //   push_c_vector(belonging_set, &tmp_zero);
  //   bitmap_set->elem_cnt -= 1;
  //   belonging_set->elem_cnt -= 1;
  // }
  if (unlikely(len == 0)) { 
    no_found_cnt++;
    return 0;
  }

  if (unlikely(fault == FSRV_RUN_TMOUT && afl->afl_env.afl_ignore_timeouts)) {

    no_found_cnt++;
    return 0;

  }

  u8  fn[PATH_MAX];
  u8 *queue_fn = "";
  u8  new_bits = 0, keeping = 0, res, classified = 0, is_timeout = 0,
     need_hash = 1;
  s32 fd;
  u64 cksum = 0;

  /* Update path frequency. */

  /* Generating a hash on every input is super expensive. Bad idea and should
     only be used for special schedules */
  if (likely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    classify_counts(&afl->fsrv);
    classified = 1;
    need_hash = 0;

    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    /* Saturated increment */
    if (likely(afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF))
      afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

  }

  if (likely(fault == afl->crash_mode)) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    // if(gen_mode) {
    //   // Judge by 2-kmeans, whether we add this node.
    //   unsigned long long distance = 0;
    //   if(major_sel != judge_area((u64 *)afl->fsrv.trace_bits, &distance)) {
    //     return 0;
    //   }
    //   new_bits = 1;
    // } else {
      if (likely(classified)) {

        new_bits = has_new_bits(afl, afl->virgin_bits);

      } else {

        new_bits = has_new_bits_unclassified(afl, afl->virgin_bits);

        if (unlikely(new_bits)) { classified = 1; }

      }

      if (likely(!new_bits)) {

        if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
        no_found_cnt++;
        return 0;

      }
    // }

  save_to_queue:

#ifndef SIMPLE_FILES

    queue_fn =
        alloc_printf("%s/queue/id:%06u,%s", afl->out_dir, afl->queued_items,
                     describe_op(afl, new_bits + is_timeout,
                                 NAME_MAX - strlen("id:000000,")));

#else

    queue_fn =
        alloc_printf("%s/queue/id_%06u", afl->out_dir, afl->queued_items);

#endif                                                    /* ^!SIMPLE_FILES */
    fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
    ck_write(fd, mem, len, queue_fn);
    close(fd);
    add_to_queue(afl, queue_fn, len, 0);
    // bitmap_set->elem_cnt += 1;
    // belonging_set->elem_cnt += 1;
    avg_byte_cnt = (avg_byte_cnt * input_cnt + count_bytes(afl, afl->fsrv.trace_bits)) / (input_cnt + 1);
    input_cnt = input_cnt + 1;
    no_found_cnt = 0;

    if (unlikely(afl->fuzz_mode) &&
        likely(afl->switch_fuzz_mode && !afl->non_instrumented_mode)) {

      if (afl->afl_env.afl_no_ui) {

        ACTF("New coverage found, switching back to exploration mode.");

      }

      afl->fuzz_mode = 0;

    }

#ifdef INTROSPECTION
    if (afl->custom_mutators_count && afl->current_custom_fuzz) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

          const char *ptr = el->afl_custom_introspection(el->data);

          if (ptr != NULL && *ptr != 0) {

            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);

          }

        }

      });

    } else if (afl->mutation[0] != 0) {

      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);

    }

#endif

    if (new_bits == 2) {

      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;

    }

    if (unlikely(need_hash && new_bits)) {

      /* due to classify counts we have to recalculate the checksum */
      afl->queue_top->exec_cksum =
          hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
      need_hash = 0;

    }

    /* For AFLFast schedules we update the new queue entry */
    if (likely(cksum)) {

      afl->queue_top->n_fuzz_entry = cksum % N_FUZZ_SIZE;
      afl->n_fuzz[afl->queue_top->n_fuzz_entry] = 1;

    }

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */
    res = calibrate_case(afl, afl->queue_top, mem, afl->queue_cycle - 1, 0);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (likely(afl->q_testcase_max_cache_size)) {

      queue_testcase_store_mem(afl, afl->queue_top, mem);

    }

    keeping = 1;

  }

  switch (fault) {

    case FSRV_RUN_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "non-instrumented"
         mode, we just keep everything. */

      ++afl->total_tmouts;

      if (afl->saved_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (unlikely(!classified)) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_tmout)) { return keeping; }

      }

      is_timeout = 0x80;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file,
                      "UNIQUE_TIMEOUT CUSTOM %s = %s\n", ptr,
                      afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_TIMEOUT %s\n", afl->mutation);

      }

#endif

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (afl->fsrv.exec_tmout < afl->hang_tmout) {

        u8  new_fault;
        u32 tmp_len = write_to_testcase(afl, &mem, len, 0);

        if (likely(tmp_len)) {

          len = tmp_len;

        } else {

          len = write_to_testcase(afl, &mem, len, 1);

        }

        new_fault = fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);
        classify_counts(&afl->fsrv);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!afl->stop_soon && new_fault == FSRV_RUN_CRASH) {

          goto keep_as_crash;

        }

        if (afl->stop_soon || new_fault != FSRV_RUN_TMOUT) {

          if (afl->afl_env.afl_keep_timeouts) {

            ++afl->saved_tmouts;
            goto save_to_queue;

          } else {

            return keeping;

          }

        }

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s", afl->out_dir,
               afl->saved_hangs,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,")));

#else

      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu", afl->out_dir,
               afl->saved_hangs);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_hangs;

      afl->last_hang_time = get_cur_time();

      break;

    case FSRV_RUN_CRASH:

    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (unlikely(!classified)) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_crash)) { return keeping; }

      }

      if (unlikely(!afl->saved_crashes) &&
          (afl->afl_env.afl_no_crash_readme != 1)) {

        write_crash_readme(afl);

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));

#else

      snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_crashes;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
                      ptr, afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

      }

#endif
      if (unlikely(afl->infoexec)) {

        // if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
        // we dont care if system errors, but we dont want a
        // compiler warning either
        // See
        // https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
        (void)(system(afl->infoexec) + 1);
#else
        WARNF("command execution unsupported");
#endif

      }

      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;

      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
  ck_write(fd, mem, len, fn);
  close(fd);

#ifdef __linux__
  if (afl->fsrv.nyx_mode && fault == FSRV_RUN_CRASH) {

    u8 fn_log[PATH_MAX];

    (void)(snprintf(fn_log, PATH_MAX, "%s.log", fn) + 1);
    fd = open(fn_log, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn_log); }

    u32 nyx_aux_string_len = afl->fsrv.nyx_handlers->nyx_get_aux_string(
        afl->fsrv.nyx_runner, afl->fsrv.nyx_aux_string, 0x1000);

    ck_write(fd, afl->fsrv.nyx_aux_string, nyx_aux_string_len, fn_log);
    close(fd);

  }

#endif

  return keeping;

}

