#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "task_state.h"
#include "perf_output.bpf.h"

/* Filter configuration */
const volatile struct filters filter = {
    .pid = false,
    .comm = false,
    .comm_num = 0,
    .state = -1,
    .latency = 0,
    .stack = 0,
    .perins = false,
};

/* BPF maps definition */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct task_state_node);
} task_state_node SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct task_last_state);
} last_task_node SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct state_key);
    __type(value, struct state_info);
} state_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACKS * sizeof(__u64));
    __uint(max_entries, 10240);
} stack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, int);
} target_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, bool);
} target_comms_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_COMM_FILTER);
    __type(key, int);
    __type(value, char[16]);
} filter_comms_map SEC(".maps");

/* -------------------------------------------------------------------------- */
/* Utility functions                                                          */
/* -------------------------------------------------------------------------- */

/* Update state statistics info */
static struct state_info *__update_state_info(struct state_key *key, u64 delta)
{
    struct state_info *info = bpf_map_lookup_elem(&state_info, key);
    if (info) {
        info->calls++;
        info->total += delta;
        if (delta > info->max)
            info->max = delta;
        if (delta < info->min || !info->min)
            info->min = delta;
        return info;
    }
    struct state_info new_info = {
        .calls = 1,
        .total = delta,
        .min = delta,
        .max = delta,
    };
    bpf_map_update_elem(&state_info, key, &new_info, BPF_ANY);
    return bpf_map_lookup_elem(&state_info, key);
}

/* Update state statistics for process or system */
static struct state_info *update_state_info(pid_t pid, int state, u64 delta)
{
    struct state_key key = { .pid = pid, .state = state };
    return __update_state_info(&key, delta);
}

/* Get process comm */
static __always_inline int get_task_comm(char *comm, struct task_struct *task)
{
    __builtin_memset(comm, 0, TASK_COMM_LEN);
    return bpf_core_read_str(comm, TASK_COMM_LEN, &task->comm);
}

/* Prefix match for comm filter */
static __always_inline bool comm_prefix_match(const char comm[TASK_COMM_LEN],
                                              const char pattern[TASK_COMM_LEN])
{
#pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        char pc = pattern[i];
        char cc = comm[i];

        if (pc == '*')
            return true;
        if (pc == '\0')
            return cc == '\0';
        if (cc == '\0')
            return false;
        if (pc != cc)
            return false;
    }
    return true;
}

/* Check if comm matches target */
static __always_inline bool is_target_comm(const char comm[TASK_COMM_LEN])
{
    bool *exists = bpf_map_lookup_elem(&target_comms_map, comm);
    if (exists)
        return true;

    for (int i = 0; i < MAX_COMM_FILTER; i++) {
        if (i >= filter.comm_num)
            break;
        int key = i;
        const char *pattern = bpf_map_lookup_elem(&filter_comms_map, &key);
        if (!pattern)
            continue;
        if (comm_prefix_match(comm, pattern)) {
            bool one = 1;
            bpf_map_update_elem(&target_comms_map, comm, &one, BPF_ANY);
            return true;
        }
    }
    return false;
}

/* Output stacktrace event to perf buffer */
static __always_inline void update_info_to_perf(void *ctx, struct task_state_node *task_node, u64 latency, u64 total_delay)
{
    struct stacktrace_event event = {};
    event.pid = task_node->pid;
    event.state = task_node->last_state;
    event.latency = latency;
    event.total_delay = total_delay;

    if (filter.stack) {
        event.last_user_stack_id = task_node->last_user_stack_id;
        event.last_kern_stack_id = task_node->last_kern_stack_id;
        event.user_stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
        event.kern_stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_FAST_STACK_CMP);
    }
    perf_output(ctx, &event, sizeof(event));
}

/* Update process state node */
static __always_inline void update_task_state_node(struct task_state_node *node, int pid, int last_state, u64 time, struct task_struct *task, void *ctx)
{
    if (last_state != TASK_RUNNING) {
        struct percpu_counter *rss = BPF_CORE_READ(task, mm, rss_stat);
        node->curr_state_info.memused = rss[0].count + rss[1].count + rss[3].count;
        node->curr_state_info.readchar = BPF_CORE_READ(task, ioac.rchar);
        node->curr_state_info.writechar = BPF_CORE_READ(task, ioac.wchar);
        node->curr_state_info.freepages_delay = BPF_CORE_READ(task, delays, freepages_delay);
        node->curr_state_info.thrashing_delay = BPF_CORE_READ(task, delays, thrashing_delay);
        node->curr_state_info.swapin_delay = BPF_CORE_READ(task, delays, swapin_delay);
    }
    node->last_time = time;
    node->last_state = last_state;
    node->priority = BPF_CORE_READ(task, normal_prio);
    get_task_comm(node->comm, task);
    if (filter.stack) {
        node->last_user_stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
        node->last_kern_stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_FAST_STACK_CMP);
    }
    bpf_map_update_elem(&task_state_node, &pid, node, BPF_ANY);
}

/* Handle process context switch */
SEC("tp_btf/sched_switch")
void BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    u64 time = bpf_ktime_get_ns();
    pid_t prev_pid = BPF_CORE_READ(prev, pid);
    pid_t next_pid = BPF_CORE_READ(next, pid);
    int prev_tgid = BPF_CORE_READ(prev, tgid);
    int next_tgid = BPF_CORE_READ(next, tgid);
    int prev_state = BPF_CORE_READ(prev, __state);
    int next_state = BPF_CORE_READ(next, __state);
    char prev_comm[TASK_COMM_LEN], next_comm[TASK_COMM_LEN];
    struct task_state_node *prev_node, *next_node;

    /* Filter by pid or comm */
    if (filter.pid) {
        if (bpf_map_lookup_elem(&target_tgids, &prev_tgid))
            goto record_prev_info;
        else if (bpf_map_lookup_elem(&target_tgids, &next_tgid))
            goto record_next_info;
        else
            return;
    } else if (filter.comm) {
        get_task_comm(prev_comm, prev);
        get_task_comm(next_comm, next);
        if (is_target_comm(prev_comm))
            goto record_prev_info;
        else if (is_target_comm(next_comm))
            goto record_next_info;
        else
            return;
    }

record_prev_info:
    /* Update prev process running time and state */
    if (prev_pid > 0) {
        prev_node = bpf_map_lookup_elem(&task_state_node, &prev_pid);
        if (prev_node) {
            if (filter.state < 0 && prev_node->last_state == TASK_RUNNING &&
                time > prev_node->last_time && prev_pid > 0 && prev_pid != next_pid) {
                u64 delta = time - prev_node->last_time;
                if (filter.pid || filter.comm || filter.perins) {
                    struct state_info *info = update_state_info(prev_pid, TASK_RUNNING, delta);
                    if (prev_node && filter.latency > 0 && info &&
                        (info->total > filter.latency || delta > filter.latency))
                        update_info_to_perf(ctx, prev_node, delta, info->total);
                    if (!prev_node->has_state_info)
                        prev_node->has_state_info = true;
                }
                if (!(filter.pid || filter.comm || filter.perins))
                    update_state_info(-1, TASK_RUNNING, delta);
            }
            update_task_state_node(prev_node, prev_pid, prev_state, time, prev, ctx);
        } else if (prev_pid > 0 && prev_pid != next_pid) {
            struct task_state_node new_node = {
                .pid = prev_pid,
                .tgid = prev_tgid,
                .has_state_info = false,
            };
            update_task_state_node(&new_node, prev_pid, prev_state, time, prev, ctx);
        }
        if (filter.pid || filter.comm)
            return;
    }

record_next_info:
    /* Update next process RUNDELAY statistics */
    if (next_pid > 0) {
        next_node = bpf_map_lookup_elem(&task_state_node, &next_pid);
        if (next_node) {
            if (filter.state < 0 && next_node->last_state == TASK_RUNNING &&
                time > next_node->last_time && next_pid > 0 && prev_pid != next_pid) {
                u64 delta = time - next_node->last_time;
                if (filter.pid || filter.comm || filter.perins) {
                    struct state_info *info = update_state_info(next_pid, RUNDELAY, delta);
                    if (next_node && filter.latency > 0 && info &&
                        (info->total > filter.latency || delta > filter.latency))
                        update_info_to_perf(ctx, next_node, delta, info->total);
                    if (!next_node->has_state_info)
                        next_node->has_state_info = true;
                }
                if (!(filter.pid || filter.comm))
                    update_state_info(-1, RUNDELAY, delta);
            }
            update_task_state_node(next_node, next_pid, TASK_RUNNING, time, next, ctx);
        } else if (next_pid > 0 && prev_pid != next_pid) {
            struct task_state_node new_node = {
                .pid = next_pid,
                .tgid = next_tgid,
                .has_state_info = false,
            };
            update_task_state_node(&new_node, next_pid, TASK_RUNNING, time, next, ctx);
        }
    }
}

/* Handle process wakeup (from wait queue to ready queue) */
SEC("tp_btf/sched_wakeup")
void BPF_PROG(sched_wakeup, struct task_struct *task)
{
    u64 time = bpf_ktime_get_ns();
    pid_t pid = BPF_CORE_READ(task, pid);
    int tgid = BPF_CORE_READ(task, tgid);
    char comm[TASK_COMM_LEN];
    struct task_state_node *node = NULL;

    /* Filter by pid or comm */
    if (filter.pid) {
        if (bpf_map_lookup_elem(&target_tgids, &tgid))
            goto record_info;
        else
            return;
    } else if (filter.comm) {
        get_task_comm(comm, task);
        if (is_target_comm(comm))
            goto record_info;
        else
            return;
    }

record_info:
    node = bpf_map_lookup_elem(&task_state_node, &pid);
    if (pid <= 0)
        return;
    if (node) {
        if (filter.state != TASK_NO_INTERRUPTIBLE &&
            (filter.state == -1 || (filter.state & node->last_state) == node->last_state) &&
            node->last_state && time > node->last_time && pid > 0) {
            u64 delta = time - node->last_time;
            if (filter.pid || filter.comm || filter.perins) {
                struct state_info *info = update_state_info(pid, node->last_state, delta);
                if (node && filter.latency > 0 && info &&
                    (info->total > filter.latency || delta > filter.latency))
                    update_info_to_perf(ctx, node, delta, info->total);
                if (!node->has_state_info)
                    node->has_state_info = true;
            }
            if (!(filter.pid || filter.comm)) {
                update_state_info(-1, node->last_state, delta);
            }
        }
        update_task_state_node(node, pid, TASK_RUNNING, time, task, ctx);
    } else {
        struct task_state_node new_node = {
            .pid = pid,
            .tgid = tgid,
            .last_time = time,
            .has_state_info = false,
        };
        update_task_state_node(&new_node, pid, TASK_RUNNING, time, task, ctx);
    }
}

/* Handle new process wakeup (enter ready queue) */
SEC("tp_btf/sched_wakeup_new")
void BPF_PROG(sched_wakeup_new, struct task_struct *task)
{
    u64 time = bpf_ktime_get_ns();
    pid_t pid = BPF_CORE_READ(task, pid);
    int tgid = BPF_CORE_READ(task, tgid);
    char comm[TASK_COMM_LEN];
    struct task_state_node *node = NULL;

    /* Filter by pid or comm */
    if (filter.pid) {
        if (bpf_map_lookup_elem(&target_tgids, &tgid))
            goto record_info;
        else
            return;
    } else if (filter.comm) {
        get_task_comm(comm, task);
        if (is_target_comm(comm))
            goto record_info;
        else
            return;
    }

record_info:
    if (pid <= 0)
        return;
    node = bpf_map_lookup_elem(&task_state_node, &pid);
    if (node) {
        if (filter.state != TASK_NO_INTERRUPTIBLE &&
            (filter.state == -1 || (filter.state & node->last_state) == node->last_state) &&
            node->last_state && time > node->last_time && pid > 0) {
            u64 delta = time - node->last_time;
            if (filter.pid || filter.comm || filter.perins) {
                struct state_info *info = update_state_info(pid, node->last_state, delta);
                if (node && filter.latency > 0 && info &&
                    (info->total > filter.latency || delta > filter.latency))
                    update_info_to_perf(ctx, node, delta, info->total);
                if (!node->has_state_info)
                    node->has_state_info = true;
            }
            if (!(filter.pid || filter.comm)) {
                update_state_info(-1, node->last_state, delta);
            }
        }
        update_task_state_node(node, pid, TASK_RUNNING, time, task, ctx);
    } else {
        struct task_state_node new_node = {
            .pid = pid,
            .tgid = tgid,
            .last_time = time,
            .has_state_info = false,
        };
        update_task_state_node(&new_node, pid, TASK_RUNNING, time, task, ctx);
    }
}

char LICENSE[] SEC("license") = "GPL";