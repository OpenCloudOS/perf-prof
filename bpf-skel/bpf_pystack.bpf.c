#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpf_pystack.h"
#include <bpf/usdt.bpf.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const char fmt[] SEC(".rodata") = "%s %s";
const struct stack_t zero_stack = {.depth = 1};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, MAX_STR_LEN);
    __uint(max_entries, 1024);
} str_id_to_str SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct stack_t));
    __uint(max_entries, 10240);
} thread_stack SEC(".maps");

static __always_inline u64 fnv1a_hash(const char *str, int len) {
    u64 hash = 14695981039346656037ULL;
    #pragma unroll
    for (int i = 0; i < MAX_STR_LEN; i++) {
        char c = str[i];
        if (c == 0)
            break;
        hash ^= c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static __always_inline int my_bpf_strncmp(const char *s1, char *s2, int n)
{
    #pragma unroll
    for (int i = 0; i < n; i++) {
        char c1 = s1[i];
        char c2 = s2[i];
        if (c1 != c2)
            return 1;
        if (c1 == '\0')
            return 0;
    }
    return 0;
}

static __always_inline int fill_func_buf(char *buf, size_t buf_sz, long filename_ptr, long funcname_ptr) {
    __u64 data[2];
    data[0] = filename_ptr;
    data[1] = funcname_ptr;
    return bpf_snprintf(buf, buf_sz, fmt, data, sizeof(data));
}

static __always_inline char *get_or_insert_funcstr(u64 *hash_out, char *buf, int len) {
    u64 hash = fnv1a_hash(buf, len);
    char *filefunc = bpf_map_lookup_elem(&str_id_to_str, &hash);
    if (!filefunc) {
        if (len >= MAX_STR_LEN)
            return NULL;
        bpf_map_update_elem(&str_id_to_str, &hash, buf, BPF_ANY);
        *hash_out = hash;
        return buf;
    } else {
        if (my_bpf_strncmp(filefunc, buf, MAX_STR_LEN) != 0)
            return NULL;
        *hash_out = hash;
        return filefunc;
    }
}

static __always_inline struct stack_t *get_or_init_stack(u32 tid) {
    struct stack_t *stack = bpf_map_lookup_elem(&thread_stack, &tid);
    if (!stack) {
        bpf_map_update_elem(&thread_stack, &tid, &zero_stack, BPF_ANY);
        stack = bpf_map_lookup_elem(&thread_stack, &tid);
        if (!stack) 
            return NULL;
    }
    return stack;
}

static __always_inline int stack_push(struct stack_t *stack, u64 hash, int lineno, u64 now) {
    if (stack->depth < MAX_STACK_DEPTH) {
        stack->pystack[stack->depth].filefunc = hash;
        stack->pystack[stack->depth].lineno = lineno;
        stack->pystack[stack->depth].time = now;
        stack->depth++;
        return 0;
    }
    return -1;
}

static __always_inline int stack_pop_and_check(struct stack_t *stack, u64 hash, u64 time) {
    if (stack->depth > 1) {
        stack->depth--;
        int cur_depth = stack->depth;
        if (cur_depth < 1 || cur_depth >= MAX_STACK_DEPTH) {
            stack->depth++;
            return -1;
        }
        if (cur_depth > 0 && cur_depth < MAX_STACK_DEPTH) {
            if (stack->pystack[cur_depth].filefunc != hash) {
                stack->depth++;
                return -2;
            }
            u64 delay = time - stack->pystack[cur_depth].time;
            if (delay > stack->pystack[0].time) {
                stack->pystack[0].filefunc = stack->pystack[cur_depth].filefunc;
                stack->pystack[0].lineno = stack->pystack[cur_depth].lineno;
                stack->pystack[0].time = delay;
            }
            return 1;
        }
    }
    return 0;
}

SEC("usdt/python:function__entry")
int BPF_USDT(probe_function_entry,long filename_ptr,long funcname_ptr,long lineno) {
    char buf[128];
    long ret;
    u64 hash,now;
    char *filefunc;
    now = bpf_ktime_get_ns();

    ret = fill_func_buf(buf, sizeof(buf), filename_ptr, funcname_ptr);
    if (ret <= 0) return 0;

    filefunc = get_or_insert_funcstr(&hash, buf, ret);
    if (!filefunc) return 0; 

    u32 tid = bpf_get_current_pid_tgid();
    struct stack_t *stack = get_or_init_stack(tid);
    if (!stack) return 0;

    if (stack_push(stack, hash, lineno, now) < 0)
        bpf_printk("[entry] stack overflow for tid %d\n", tid);

    return 0;
}

SEC("usdt/python:function__return")
int BPF_USDT(probe_function_return,long filename_ptr,long funcname_ptr,long lineno) {
    char buf[128];
    long ret;
    u64 hash, now;
    char *filefunc;
    now = bpf_ktime_get_ns();

    ret = fill_func_buf(buf, sizeof(buf), filename_ptr, funcname_ptr);
    if (ret <= 0) return 0;
    filefunc = get_or_insert_funcstr(&hash, buf, ret);
    if (!filefunc) return 0;

    u32 tid = bpf_get_current_pid_tgid();
    struct stack_t *stack = get_or_init_stack(tid);
    if (!stack) return 0;

    stack_pop_and_check(stack, hash, now);
    return 0;
}

