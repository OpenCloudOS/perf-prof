#ifndef __TP_STRUCT_H
#define __TP_STRUCT_H

#include <linux/list.h>
#include <linux/const.h>
#include <linux/compiler.h>


#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))

#define TP_RAW_SIZE(type) \
    (ALIGN(sizeof(type)+sizeof(u32), sizeof(u64)) - sizeof(u32))

#define COMMON_HEADER \
    unsigned short common_type;/*       offset:0;       size:2; signed:0; */ \
    unsigned char common_flags;/*       offset:2;       size:1; signed:0; */ \
    unsigned char common_preempt_count;/*       offset:3;       size:1; signed:0; */ \
    int common_pid;/*   offset:4;       size:4; signed:1; */


struct sched_wakeup {
    COMMON_HEADER

    char comm[16];//    offset:8;       size:16;        signed:1;
    pid_t pid;//        offset:24;      size:4; signed:1;
    int prio;// offset:28;      size:4; signed:1;
    int success;//      offset:32;      size:4; signed:1;
    int target_cpu;//   offset:36;      size:4; signed:1;
};

/*
 * upstream
 * 58b9987 sched/tracing: Remove the redundant 'success' in the sched tracepoint
**/
struct sched_wakeup_no_success {
    COMMON_HEADER

    char comm[16];//    offset:8;       size:16;        signed:1;
    pid_t pid;//        offset:24;      size:4; signed:1;
    int prio;// offset:28;      size:4; signed:1;
    int target_cpu;//      offset:32;      size:4; signed:1;
};

struct sched_switch {
    COMMON_HEADER

    char prev_comm[16];//       offset:8;       size:16;        signed:1;
    pid_t prev_pid;//   offset:24;      size:4; signed:1;
    int prev_prio;//    offset:28;      size:4; signed:1;
    long prev_state;//  offset:32;      size:8; signed:1;
    char next_comm[16];//       offset:40;      size:16;        signed:1;
    pid_t next_pid;//   offset:56;      size:4; signed:1;
    int next_prio;//    offset:60;      size:4; signed:1;
};

struct sched_migrate_task {
    COMMON_HEADER

    char comm[16];//    offset:8;       size:16;        signed:1;
    pid_t pid;//        offset:24;      size:4; signed:1;
    int prio;// offset:28;      size:4; signed:1;
    int orig_cpu;//     offset:32;      size:4; signed:1;
    int dest_cpu;//     offset:36;      size:4; signed:1;
};

struct sched_stat_runtime {
    COMMON_HEADER

    char comm[16];  //   offset:8;       size:16;        signed:1;
    pid_t pid;      //   offset:24;      size:4; signed:1;
    u64 runtime;    //   offset:32;      size:8; signed:0;
    u64 vruntime;   //   offset:40;      size:8; signed:0;
};

struct sched_process_free {
    COMMON_HEADER

    char comm[16];//    offset:8;       size:16;        signed:1;
    pid_t pid;//        offset:24;      size:4; signed:1;
    int prio;// offset:28;      size:4; signed:1;
};

struct sched_process_fork {
    COMMON_HEADER

    char parent_comm[16];//     offset:8;       size:16;        signed:1;
    pid_t parent_pid;// offset:24;      size:4; signed:1;
    char child_comm[16];//      offset:28;      size:16;        signed:1;
    pid_t child_pid;//  offset:44;      size:4; signed:1;
};

struct sched_process_exec {
    COMMON_HEADER

    short filename_offset, filename_len;//__data_loc char[] filename;       offset:8;       size:4; signed:1;
    pid_t pid;//        offset:12;      size:4; signed:1;
    pid_t old_pid;//    offset:16;      size:4; signed:1;
};

struct task_newtask {
    COMMON_HEADER

    pid_t pid;//        offset:8;       size:4; signed:1;
    char comm[16];//    offset:12;      size:16;        signed:1;
    unsigned long clone_flags;//        offset:32;      size:8; signed:0;
    short oom_score_adj;//      offset:40;      size:2; signed:1;
};

struct task_rename {
    COMMON_HEADER

    pid_t pid;//        offset:8;       size:4; signed:1;
    char oldcomm[16];// offset:12;      size:16;        signed:1;
    char newcomm[16];// offset:28;      size:16;        signed:1;
    short oom_score_adj;//      offset:44;      size:2; signed:1;
};


#endif
