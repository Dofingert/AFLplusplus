#!/bin/sh
# firstly, gen rootfs
/workspace/wangzhe/for_trace/batch_build_rootfs_spike.py /workspace/wangzhe/for_trace/points_afltrace.json

# secondly, run trace
/workspace/wangzhe/for_trace/batch_run_afltrace.sh
