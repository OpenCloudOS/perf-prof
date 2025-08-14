#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <monitor.h>
#include <trace_helpers.h>
#include <bpf-skel/task_state.h>
#include <bpf-skel/bpf_task_state.skel.h>
#include <internal/xyarray.h>
#include <internal/evsel.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stack_helpers.h>
#include <latency_helpers.h>

struct taskstate_ctx {
    struct bpf_task_state_bpf *obj;
    struct perf_thread_map *thread_map;
    struct perf_evsel *evsel;
    struct ksyms *ksyms;
    struct syms_cache *syms_cache;
};

// static struct ksyms *ksyms = NULL;

/* Initialize monitor context */
static int monitor_ctx_init(struct prof_dev *dev)
{
    struct taskstate_ctx *ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;

    ctx->obj = bpf_task_state_bpf__open();
    if (!ctx->obj) {
        printf("Failed to open BPF skeleton\n");
        goto free_ctx;
    }
    return 0;
free_ctx:
    free(ctx);
    return -1;
}

/* Cleanup monitor context */
static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct taskstate_ctx *ctx = dev->private;
    bpf_task_state_bpf__detach(ctx->obj);
    bpf_task_state_bpf__destroy(ctx->obj);
    free(ctx);
}

/* Get TGID for a given TID */
static int get_tgid(int tid)
{
    char path[256], line[256];
    FILE *fp;
    int pid = 0;

    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "Tgid: %d", &pid) == 1)
            break;
        pid = 0;
    }
    fclose(fp);

    return pid;
}

/* Count number of process names in filter string */
static int count_process_names(const char *filter_str)
{
    int count = 0;
    char *filter = strdup(filter_str);
    char *s = filter;
    char *sep;

    while ((sep = strchr(s, ',')) != NULL) {
        *sep = '\0';
        if (*s)
            count++;
        s = sep + 1;
    }
    if (*s)
        count++;
    free(filter);
    return count;
}

/* Pattern match for comm string */
static int comm_pattern_match(const char *comm, const char *pattern)
{
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        char pc = pattern[i];
        char cc = comm[i];
        if (pc == '*')           return 1;
        if (pc == '\0')          return cc == '\0';
        if (cc == '\0')          return 0;
        if (pc != cc)            return 0;
    }
    return 1;
}

/* Initialize filter_comms_map with filter string */
static int init_filter_comms_map(struct bpf_map *filter_comms_map, const char *filter_str)
{
    char *filter = strdup(filter_str);
    char *s;
    char *sep;
    char comm[16];
    int idx = 0;
    if (!filter) return -1;
    s = filter;
    while ((sep = strchr(s, ',')) != NULL && idx < MAX_COMM_FILTER) {
        *sep = '\0';
        if (*s) {
            memset(comm, 0, sizeof(comm));
            strncpy(comm, s, 15);
            bpf_map__update_elem(filter_comms_map, &idx, sizeof(idx), comm, sizeof(comm), 0);
            idx++;
        }
        s = sep + 1;
    }
    if (*s && idx < MAX_COMM_FILTER) {
        memset(comm, 0, sizeof(comm));
        strncpy(comm, s, 15);
        bpf_map__update_elem(filter_comms_map, &idx, sizeof(idx), comm, sizeof(comm), 0);
        idx++;
    }
    free(filter);
    return 0;
}

/* Initialize target_comms_map by scanning /proc and matching filter patterns */
static int init_target_comms_map(struct bpf_map *filter_comms_map, int filter_cnt, struct bpf_map *target_comms_map)
{
    DIR *proc;
    struct dirent *entry;
    char comm_path[300], comm[16], pattern[16];
    bool dummy = true;
    proc = opendir("/proc");
    if (!proc) return -1;
    while ((entry = readdir(proc)) != NULL) {
        FILE *f;
        if (!isdigit(entry->d_name[0]))
            continue;
        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
        f = fopen(comm_path, "r");
        if (!f) continue;
        if (!fgets(comm, sizeof(comm), f)) {
            fclose(f);
            continue;
        }
        fclose(f);
        comm[strcspn(comm, "\n")] = 0;
        for (int i = 0; i < filter_cnt; i++) {
            memset(pattern, 0, sizeof(pattern));
            if (bpf_map__lookup_elem(filter_comms_map, &i, sizeof(i), pattern, sizeof(pattern), 0) == 0) {
                if (comm_pattern_match(comm, pattern)) {
                    bpf_map__update_elem(target_comms_map, comm, sizeof(comm), &dummy, sizeof(dummy), 0);
                    break;
                }
            }
        }
    }
    closedir(proc);
    return 0;
}

static int bpf_task_state_init(struct prof_dev *dev)
{
    struct taskstate_ctx *ctx;
    struct env *env = dev->env;
    struct perf_evlist *evlist = dev->evlist;
    struct bpf_map *filter_comms_map;
    struct bpf_map *target_comms_map;
    int comm_num;
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_BPF_OUTPUT,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TIME | PERF_SAMPLE_RAW,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 0,
        .watermark     = 1,
        .wakeup_watermark = 1,
    };

    if (monitor_ctx_init(dev) < 0)
        return -1;

    ctx = dev->private;

    prof_dev_env2attr(dev, &attr);
    ctx->evsel = perf_evsel__new(&attr);
    if (!ctx->evsel)
        goto failed;
    perf_evlist__add(evlist, ctx->evsel);

    ctx->obj->rodata->filter.pid = env->pids ? true : false;
    ctx->obj->rodata->filter.comm = env->filter ? true : false;
    ctx->obj->rodata->filter.perins = env->perins ? true : false;
    ctx->obj->rodata->filter.latency = env->greater_than ? env->greater_than : ctx->obj->rodata->filter.latency;
    ctx->obj->rodata->filter.stack = env->callchain ? true : false;

    if (env->interruptible && env->uninterruptible) {
        ctx->obj->rodata->filter.state = TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE;
    } else if (env->interruptible) {
        ctx->obj->rodata->filter.state = TASK_INTERRUPTIBLE;
    } else if (env->uninterruptible) {
        ctx->obj->rodata->filter.state = TASK_UNINTERRUPTIBLE;
    } else if (env->interruptible_set && !env->interruptible){
        ctx->obj->rodata->filter.state = TASK_NO_INTERRUPTIBLE;
    }

    if (env->filter) {
        comm_num = count_process_names(env->filter);
        ctx->obj->rodata->filter.comm_num = comm_num;
    }

    if (bpf_task_state_bpf__load(ctx->obj)){
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto failed;
    }

    filter_comms_map = ctx->obj->maps.filter_comms_map;
    target_comms_map = ctx->obj->maps.target_comms_map;
    if (env->filter) {
        if (init_filter_comms_map(filter_comms_map, env->filter) < 0) {
            fprintf(stderr, "Failed to initialize filter_comms_map\n");
            return -1;
        }
        if (init_target_comms_map(filter_comms_map, comm_num, target_comms_map) < 0) {
            fprintf(stderr, "Failed to initialize target_comms_map\n");
            return -1;
        }
    }
    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

#define FD(e, x, y) ((int *) xyarray__entry(e->fd, x, y))
static int bpf_task_state_filter(struct prof_dev *dev)
{
    struct taskstate_ctx *ctx = dev->private;
    struct bpf_map *target_tgids = ctx->obj->maps.target_tgids;
    int idx, tid, err, cpu, ins, perf_event_fd;

    ctx->thread_map = dev->threads;
    perf_cpu_map__put(dev->cpus);
    dev->cpus = perf_cpu_map__new(NULL);
    dev->threads = perf_thread_map__new_dummy();

    if (ctx->thread_map) {
        perf_thread_map__for_each_thread(tid, idx, ctx->thread_map) {
            int tgid = get_tgid(tid);
            if (tgid > 0) {
                bpf_map__update_elem(target_tgids, &tgid, sizeof(tgid), &tgid, sizeof(tgid), 0);
            }
        }
    }

    perf_cpu_map__for_each_cpu(cpu, ins, dev->cpus) {
        tid = 0; idx = 0;
        perf_thread_map__for_each_thread(tid, idx, ctx->thread_map) {
            int *fd_ptr;
            fd_ptr = FD(ctx->evsel, ins, idx);
            if (!fd_ptr) {
                continue;
            }
            perf_event_fd = *fd_ptr;
            err = bpf_map__update_elem(ctx->obj->maps.perf_events, &cpu, sizeof(cpu), &perf_event_fd, sizeof(perf_event_fd), 0);
            if (err < 0) {
                printf("Failed to update perf_events map\n");
                return -1;
            }
        }
    }

    ctx->ksyms = ksyms__load();
    if (!ctx->ksyms) {
        printf("Failed to create ksyms map\n");
        return -1;
    }
    ctx->syms_cache = syms_cache__new();
    if (!ctx->syms_cache) {
        printf("Failed to create syms_cache map\n");
        ksyms__free(ctx->ksyms);
        return -1;
    }

    err = bpf_task_state_bpf__attach(ctx->obj);
    if (err) {
        printf("Failed to attach BPF skeleton\n");
    }
    return 1;
}

/* Convert state value to string */
static const char *state_to_str(int state)
{
    switch (state) {
        case TASK_RUNNING:         return "R";
        case TASK_INTERRUPTIBLE:   return "S";
        case TASK_UNINTERRUPTIBLE: return "D";
        case __TASK_STOPPED:       return "T";
        case TASK_IDLE:            return "I";
        case RUNDELAY:             return "RD";
        default:                   return "?";
    }
}

/* Print state statistics for a process */
static void print_state_info(struct bpf_map *map, pid_t pid)
{
    struct state_key key = { .pid = pid };
    struct state_info value = {0};
    static const int states[] = {
        TASK_RUNNING,
        TASK_INTERRUPTIBLE,
        TASK_UNINTERRUPTIBLE,
        __TASK_STOPPED,
        TASK_IDLE,
        RUNDELAY,
    };
    static const char *state_strs[] = { "R", "S", "D", "T", "I", "RD" };
    bool has_data = false;

    printf("%3s %10s %12s %12s %12s %12s\n",
        "St", "calls", "total(us)", "min(us)", "max(us)", "avg(us)");
    printf("%3s %10s %12s %12s %12s %12s\n",
        "---", "----------", "------------", "------------", "------------", "------------");
    for (int i = 0; i < (int)(sizeof(states)/sizeof(states[0])); i++) {
        key.state = states[i];
        if (bpf_map__lookup_elem(map, &key, sizeof(key), &value, sizeof(value), 0) == 0 && value.calls > 0) {
            has_data = true;
            printf("%3s %10u %12.3f %12.3f %12.3f %12.3f\n",
                state_strs[i],
                value.calls,
                value.total / 1000.0,
                value.min / 1000.0,
                value.max / 1000.0,
                value.calls ? (double)value.total / value.calls / 1000.0 : 0.0
            );
            bpf_map__delete_elem(map, &key, sizeof(key), 0);
        }
    }
    if (!has_data)
        printf("%3s %10s %12s %12s %12s %12s\n",
            "NULL", "NULL", "NULL", "NULL", "NULL", "NULL");
    printf("\n");
}

/* Print kernel symbol for a given address */
static void print_ksym(__u64 addr, struct taskstate_ctx *ctx)
{
    const struct ksym *sym;
    if (!addr)
        return;
    sym = ksyms__map_addr(ctx->ksyms, addr);
    if (!sym) {
        printf("    0x%llx Unknown", addr);
    } else {
        printf("    0x%llx %s+0x%llx", addr, sym->name, addr - sym->addr);
    }
    printf("  ([kernel.kallsysms])\n");
}

/* Print user symbol for a given address */
static int print_usym(__u64 addr, pid_t pid, struct taskstate_ctx *ctx)
{
    struct syms *syms;
    struct dso *dso = NULL;
    const struct sym *sym = NULL;
    uint64_t offset = 0;
    const char *symbol = "Unknown";
    int unknown = 0;

    // 获取用户符号缓存
    syms = syms_cache__get_syms(ctx->syms_cache, pid);
    if (syms) {
        dso = syms__find_dso(syms, addr, &offset);
        if (dso) {
            sym = dso__find_sym(dso, offset);
            if (sym) {
                symbol = sym__name(sym);
                offset = offset - sym->start;
                unknown = dso__name(dso) ? 0 : 1;
            }
        } else
            unknown = 1;
    }
    printf("    0x%llx %s+0x%lx (%s)\n", addr, symbol, offset, unknown? "Unknown" : dso__name(dso));
    return unknown;
}

/* Print stack trace for a given stack id */
static void print_stack(int fd, int key, bool kernel_user_stack, pid_t pid, struct taskstate_ctx *ctx)
{
    __u64 ip[PERF_MAX_STACK_DEPTH] = {};
    int i, unknown = 0;
    if (bpf_map_lookup_elem(fd, &key, &ip) != 0) {
        printf("not find;\n");
    } else {
        if(!kernel_user_stack)
            for (i = 0; i < PERF_MAX_STACK_DEPTH; i++)
                print_ksym(ip[i], ctx);
        else
            for (i = 0; i < PERF_MAX_STACK_DEPTH; i++){
                if(unknown < 2)
                    unknown += print_usym(ip[i], pid, ctx);
            }
    }
}

/* Print all stack traces for a stacktrace_event */
static void print_stacks(int fd, struct stacktrace_event *info, pid_t pid, struct taskstate_ctx *ctx)
{
    if (info->last_kern_stack_id) {
        printf("Last kernel stack trace:\n");
        print_stack(fd, info->last_kern_stack_id, 0, pid, ctx);
    }
    if (info->last_user_stack_id) {
        printf("Last user stack trace:\n");
        print_stack(fd, info->last_user_stack_id, 1, pid, ctx);
    }
    if (info->kern_stack_id) {
        printf("Kernel stack trace:\n");
        print_stack(fd, info->kern_stack_id, 0, pid, ctx);
    }
    if (info->user_stack_id) {
        printf("User stack trace:\n");
        print_stack(fd, info->user_stack_id, 1, pid, ctx);
    }
}

/* Print statistics for each process at interval */
static void bpf_task_state_interval(struct prof_dev *dev)
{
    struct taskstate_ctx *ctx = dev->private;
    if (dev->env->pids || dev->env->filter) {
        pid_t key = -1, next_key = -1;
        struct task_state_node task_node = {0};
        int task_state_node_fd = bpf_map__fd(ctx->obj->maps.task_state_node);
        int last_task_node_fd = bpf_map__fd(ctx->obj->maps.last_task_node);
        bool has_print_title = false;
        if (bpf_map_get_next_key(task_state_node_fd, &key, &next_key)) {
            return;
        }
        while (!bpf_map_get_next_key(task_state_node_fd, &key, &next_key)) {
            if (bpf_map_lookup_elem(task_state_node_fd, &next_key, &task_node) < 0) {
                printf("Failed to lookup task state node for PID in interval%d\n", next_key);
            } else {
                if (task_node.has_state_info) {
                    struct task_last_state last_task_node = {0};
                    unsigned long memtotal = sysconf(_SC_PHYS_PAGES);
                    if (!has_print_title) {
                        printf("\n======================== Per-Process State Statistics ============================\n");
                        print_time(stdout);
                        printf("\n");
                        has_print_title = true;
                    }
                    printf("TGID: %d, PID: %d, COMM: %s, PRIO: %d\n",
                        task_node.tgid, task_node.pid, task_node.comm, task_node.priority);
                    bpf_map_lookup_elem(last_task_node_fd, &next_key, &last_task_node);
                    printf("MEM: %.3f, Read: %.3fkb, Write: %.3fkb\n",
                        (task_node.curr_state_info.memused * 100.0 / memtotal),
                        1.0 * (task_node.curr_state_info.readchar - last_task_node.readchar) / 1024,
                        1.0 * (task_node.curr_state_info.writechar - last_task_node.writechar) / 1024);
                    if(task_node.curr_state_info.freepages_delay - last_task_node.freepages_delay)
                        printf("FreePages: %ld ",
                            task_node.curr_state_info.freepages_delay - last_task_node.freepages_delay);
                    if(task_node.curr_state_info.thrashing_delay - last_task_node.thrashing_delay)
                        printf("Thrashing: %ld ",
                            task_node.curr_state_info.thrashing_delay - last_task_node.thrashing_delay);
                    if(task_node.curr_state_info.swapin_delay - last_task_node.swapin_delay)
                        printf("SwapIn: %ld ",
                            task_node.curr_state_info.swapin_delay - last_task_node.swapin_delay);
                    if (task_node.curr_state_info.freepages_delay - last_task_node.freepages_delay ||
                        task_node.curr_state_info.thrashing_delay - last_task_node.thrashing_delay ||
                        task_node.curr_state_info.swapin_delay - last_task_node.swapin_delay)
                        printf("\n");
                    print_state_info(ctx->obj->maps.state_info, task_node.pid);

                    last_task_node.memused = task_node.curr_state_info.memused;
                    last_task_node.readchar = task_node.curr_state_info.readchar;
                    last_task_node.writechar = task_node.curr_state_info.writechar;
                    last_task_node.freepages_delay = task_node.curr_state_info.freepages_delay;
                    last_task_node.thrashing_delay = task_node.curr_state_info.thrashing_delay;
                    last_task_node.swapin_delay = task_node.curr_state_info.swapin_delay;
                    bpf_map_update_elem(last_task_node_fd, &next_key, &last_task_node, BPF_ANY);

                    if ((task_node.last_state & TASK_DEAD) ||
                        (task_node.last_state & EXIT_DEAD) ||
                        (task_node.last_state & EXIT_ZOMBIE)) {
                        printf("[DeadInfo]: %d dead at %u\n",
                            task_node.pid, (unsigned int)task_node.last_time);
                        bpf_map_delete_elem(task_state_node_fd, &next_key);
                    } else if (task_node.last_state & EXIT_ZOMBIE) {
                        printf("[ZombieInfo]: %d Zombie at %u not dead\n",
                            task_node.pid, (unsigned int)task_node.last_time);
                        task_node.has_state_info = false;
                        bpf_map_update_elem(task_state_node_fd, &next_key, &task_node, BPF_ANY);
                    } else {
                        task_node.has_state_info = false;
                        bpf_map_update_elem(task_state_node_fd, &next_key, &task_node, BPF_ANY);
                    }
                }
            }
            key = next_key;
        }
    } else {
        printf("========================= SYS-State Statistics ====================\n");
        print_time(stdout);
        printf("\n");
        print_state_info(ctx->obj->maps.state_info, -1);
        printf("\n");
    }
}

/* Print statistics for a process when sample event is triggered */
static void bpf_task_state_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct taskstate_ctx *ctx = dev->private;
    struct stacktrace_event *info = (void *)event->sample.array + sizeof(u64) + sizeof(u32);
    struct task_state_node task_node = {0};
    int task_state_fd = bpf_map__fd(ctx->obj->maps.task_state_node);
    int stack_map_fd = bpf_map__fd(ctx->obj->maps.stack_map);
    bool has_print_title = false;
    if (dev->env->greater_than) {
        if (bpf_map_lookup_elem(task_state_fd, &info->pid, &task_node) < 0) {
            printf("Failed to lookup task state node for PID in sample%d\n", info->pid);
        } else {
            if (task_node.has_state_info) {
                if (!has_print_title) {
                    printf("\n======================== Per-Process State Statistics ============================\n");
                    print_time(stdout);
                    printf("\n");
                    has_print_title = true;
                }
                printf("TGID: %d, PID: %d, COMM: %s, STATE: %s, PRIO: %d, latency: %luus, total_delay: %lums\n",
                    task_node.tgid, task_node.pid, task_node.comm, state_to_str(info->state), task_node.priority,
                    info->latency / NSEC_PER_USEC, info->total_delay / NSEC_PER_MSEC);
                print_state_info(ctx->obj->maps.state_info, task_node.pid);
                if (dev->env->callchain)
                    print_stacks(stack_map_fd, info, task_node.pid, ctx);

                task_node.has_state_info = false;
                bpf_map_update_elem(task_state_fd, &info->pid, &task_node, BPF_ANY);
            }
        }
    }
}

/* Cleanup and print interval statistics */
static void bpf_task_state_deinit(struct prof_dev *dev)
{
    bpf_task_state_interval(dev);
    monitor_ctx_exit(dev);
}

static const char *bpf_task_state_desc[] = PROFILER_DESC("bpf:task-state",
    "[OPTION...] [-S] [-D] [--filter comm] [--perins] [--than ns] [-g [--flame-graph file]]",
    "Show task state statistics via BPF.",
    "",
    "BPF-TASK-STATE",
    "    int pid         # process id",
    "    int state       # task state",
    "    u64 last_time   # last state change time",
    "",
    "EXAMPLES",
    "    "PROGRAME" bpf:task-state -i 1000",
    "    "PROGRAME" bpf:task-state -p 1234 -i 1000",
    "    "PROGRAME" bpf:task-state --filter 'java,python*' -i 1000",
    "    "PROGRAME" bpf:task-state -i 1000 --no-interruptible",
    "    "PROGRAME" bpf:task-state -p 1234 -SD --than 20ms -g",
    "    "PROGRAME" bpf:task-state --perins --than 1ms -i 1000"
);

static const char *bpf_task_state_argv[] = PROFILER_ARGV("bpf:task-state",
    PROFILER_ARGV_OPTION, "inherit",
    PROFILER_ARGV_PROFILER, "interruptible", "uninterruptible",
    "filter\nFilter process comm",
    "perins", "than", "call-graph", "bpf-python-callchain"
);

struct monitor bpf_task_state = {
    .name = "bpf:task-state",
    .desc = bpf_task_state_desc,
    .argv = bpf_task_state_argv,
    .pages = 8,
    .init = bpf_task_state_init,
    .filter = bpf_task_state_filter,
    .deinit = bpf_task_state_deinit,
    .interval = bpf_task_state_interval,
    .sample = bpf_task_state_sample,
};

MONITOR_REGISTER(bpf_task_state)