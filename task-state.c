#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <monitor.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/rblist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>

#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2
#define __TASK_STOPPED		4
#define __TASK_TRACED		8
/* in tsk->exit_state */
#define EXIT_ZOMBIE		16
#define EXIT_DEAD		32
/* in tsk->state again */
#define TASK_DEAD		64
#define TASK_WAKEKILL		128
#define TASK_WAKING		256
#define TASK_PARKED		512
#define TASK_STATE_MAX		1024

/* Convenience macros for the sake of set_task_state */
#define TASK_KILLABLE		(TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
#define TASK_STOPPED		(TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED		(TASK_WAKEKILL | __TASK_TRACED)


struct monitor task_state;
static struct monitor_ctx {
    struct callchain_ctx *cc;
    struct flame_graph *flame;
    struct perf_thread_map *thread_map;
    __u64 sched_switch;
    __u64 sched_wakeup;
    struct rblist backup;
    struct env *env;
} ctx;
struct perf_event_backup {
    struct rb_node rbnode;
    __u32    tid;
    union perf_event event;
};
struct perf_event_entry {
    __u32    tid;
    union perf_event *event;
};

static int node_cmp(struct rb_node *rbn, const void *entry)
{
    struct perf_event_backup *b = container_of(rbn, struct perf_event_backup, rbnode);
    const struct perf_event_entry *e = entry;

    if (b->tid > e->tid)
        return 1;
    else if (b->tid < e->tid)
        return -1;
    else
        return 0;
}
static struct rb_node *node_new(struct rblist *rlist, const void *new_entry)
{
    const struct perf_event_entry *e = new_entry;
    const union perf_event *event = e->event;
    struct perf_event_backup *b = malloc(offsetof(struct perf_event_backup, event) + event->header.size);
    if (b) {
        b->tid = e->tid;
        memmove(&b->event, event, event->header.size);
        return &b->rbnode;
    } else
        return NULL;
}
static void node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct perf_event_backup *b = container_of(rb_node, struct perf_event_backup, rbnode);
    free(b);
}

static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    if (env->callchain) {
        if (!env->flame_graph)
            ctx.cc = callchain_ctx_new(callchain_flags(CALLCHAIN_KERNEL | CALLCHAIN_USER), stdout);
        else
            ctx.flame = flame_graph_open(callchain_flags(CALLCHAIN_KERNEL | CALLCHAIN_USER), env->flame_graph);
        task_state.pages *= 2;
    }
    rblist__init(&ctx.backup);
    ctx.backup.node_cmp = node_cmp;
    ctx.backup.node_new = node_new;
    ctx.backup.node_delete = node_delete;
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    perf_thread_map__put(ctx.thread_map);
    rblist__exit(&ctx.backup);
    if (ctx.env->callchain) {
        if (!ctx.env->flame_graph)
            callchain_ctx_free(ctx.cc);
        else {
            flame_graph_output(ctx.flame);
            flame_graph_close(ctx.flame);
        }
    }
    tep__unref();
}

static int task_state_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = exclude_callchain_user(CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .exclude_callchain_kernel = exclude_callchain_kernel(CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;
    int id;

    if (monitor_ctx_init(env) < 0)
        return -1;

    reduce_wakeup_times(&task_state, &attr);

    /**
     * sched:sched_switch and sched:sched_wakeup are not suitable for binding to threads
    **/
    if (!monitor_instance_oncpu()) {
        ctx.thread_map = task_state.threads;
        perf_cpu_map__put(task_state.cpus);
        task_state.cpus = perf_cpu_map__new(NULL);
        task_state.threads = perf_thread_map__new_dummy();
    }

    id = tep__event_id("sched", "sched_switch");
    if (id < 0)
        return -1;
    attr.config = ctx.sched_switch = id;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    id = tep__event_id("sched", "sched_wakeup");
    if (id < 0)
        return -1;
    attr.comm = 1;
    attr.task = 1;
    attr.config = ctx.sched_wakeup = id;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}

static int task_state_filter(struct perf_evlist *evlist, struct env *env)
{
    char filter[1024];
    struct perf_evsel *evsel;
    int err;

    perf_evlist__for_each_evsel(evlist, evsel) {
        struct perf_event_attr *attr = perf_evsel__attr(evsel);
        if (attr->config == ctx.sched_switch) {
            struct tp_filter *prev_filter = NULL;
            struct tp_filter *next_filter = NULL;

            prev_filter = tp_filter_new(ctx.thread_map, "prev_pid", env->filter, "prev_comm");
            next_filter = tp_filter_new(ctx.thread_map, "next_pid", env->filter, "next_comm");

            if (env->interruptible && env->uninterruptible) {
                if (prev_filter) {
                    snprintf(filter, sizeof(filter), "(prev_state==%d || prev_state==%d || prev_state==%d) && (%s)",
                            TASK_INTERRUPTIBLE, TASK_UNINTERRUPTIBLE, TASK_KILLABLE, prev_filter->filter);
                } else
                    snprintf(filter, sizeof(filter), "prev_state==%d || prev_state==%d || prev_state==%d",
                            TASK_INTERRUPTIBLE, TASK_UNINTERRUPTIBLE, TASK_KILLABLE);
            } else if (env->interruptible) {
                if (prev_filter)
                    snprintf(filter, sizeof(filter), "prev_state==%d && (%s)",
                            TASK_INTERRUPTIBLE, prev_filter->filter);
                else
                    snprintf(filter, sizeof(filter), "prev_state==%d", TASK_INTERRUPTIBLE);
            } else if (env->uninterruptible) {
                if (prev_filter)
                    snprintf(filter, sizeof(filter), "(prev_state==%d || prev_state==%d) && (%s)",
                            TASK_UNINTERRUPTIBLE, TASK_KILLABLE, prev_filter->filter);
                else
                    snprintf(filter, sizeof(filter), "prev_state==%d || prev_state==%d",
                            TASK_UNINTERRUPTIBLE, TASK_KILLABLE);
            } else if (prev_filter && next_filter) {
                snprintf(filter, sizeof(filter), "(%s) || (%s)", prev_filter->filter, next_filter->filter);
            } else {
                err = -1;
                goto error_free;
            }

            if (env->verbose >= VERBOSE_NOTICE)
                printf("sched:sched_switch filter \"%s\"\n", filter);

            err = perf_evsel__apply_filter(evsel, filter);

        error_free:
            tp_filter_free(prev_filter);
            tp_filter_free(next_filter);
            if (err < 0) {
                fprintf(stderr, "sched:sched_switch filter \"%s\"\n", filter);
                return err;
            }
        } else if (attr->config == ctx.sched_wakeup) {
            struct tp_filter *tp_filter = NULL;

            tp_filter = tp_filter_new(ctx.thread_map, "pid", env->filter, "comm");
            if (tp_filter) {
                if (env->verbose >= VERBOSE_NOTICE)
                    printf("sched:sched_wakeup filter \"%s\"\n", tp_filter->filter);
                err = perf_evsel__apply_filter(evsel, tp_filter->filter);
                if (err < 0) {
                    fprintf(stderr, "sched:sched_wakeup filter \"%s\"\n", tp_filter->filter);
                    tp_filter_free(tp_filter);
                    return err;
                }
                tp_filter_free(tp_filter);
            }
        }
    }
    return 0;
}

static void task_state_deinit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
struct sample_type_header {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64   time;
    struct {
        __u32    cpu;
        __u32    reserved;
    }    cpu_entry;
};
struct sample_type_callchain {
    struct sample_type_header h;
    struct callchain callchain;
};
struct sample_type_raw {
    struct sample_type_header h;
    struct {
        __u32   size;
        __u8    data[0];
    } raw;
};

static void __raw_size(union perf_event *event, void **praw, int *psize)
{
    if (ctx.env->callchain) {
        struct sample_type_callchain *data = (void *)event->sample.array;
        struct {
            __u32   size;
            __u8    data[0];
        } *raw = (void *)data->callchain.ips + data->callchain.nr * sizeof(__u64);
        *praw = raw->data;
        *psize = raw->size;
    } else {
        struct sample_type_raw *raw = (void *)event->sample.array;
        *praw = raw->raw.data;
        *psize = raw->raw.size;
    }
}

static inline void __print_callchain(union perf_event *event)
{
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (ctx.env->callchain) {
        if (!ctx.env->flame_graph)
            print_callchain_common(ctx.cc, &data->callchain, data->h.tid_entry.pid);
        else {
            const char *comm = tep__pid_to_comm((int)data->h.tid_entry.pid);
            flame_graph_add_callchain(ctx.flame, &data->callchain, data->h.tid_entry.pid, !strcmp(comm, "<...>") ? NULL : comm);
        }
    }
}

static void task_state_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_header *data = (void *)event->sample.array, *data0;
    struct perf_event_entry entry;
    struct tep_record record;
    struct tep_handle *tep;
    struct trace_seq s;
    struct tep_event *e;
    struct rb_node *rbn;
    struct perf_event_backup *sched_switch;
    unsigned long long pid;
    int type;
    int rc;
    void *raw;
    int size;

    __raw_size(event, &raw, &size);

    if (ctx.env->greater_than == 0) {
        tep__update_comm(NULL, data->tid_entry.tid);
        print_time(stdout);
        tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
        __print_callchain(event);
        return;
    }

    trace_seq_init(&s);

    memset(&record, 0, sizeof(record));
    record.ts = data->time/1000;
    record.cpu = data->cpu_entry.cpu;
    record.size = size;
    record.data = raw;

    tep = tep__ref();
    type = tep_data_type(tep, &record);

    e = tep_find_event_by_record(tep, &record);
    if (type == ctx.sched_switch) {
        if (tep_get_field_val(&s, e, "prev_pid", &record, &pid, 1) < 0) {
            trace_seq_putc(&s, '\n');
            trace_seq_do_fprintf(&s, stderr);
            goto __return;
        }

        entry.tid = (__u32)pid;
        entry.event = event;
        rc = rblist__add_node(&ctx.backup, &entry);
        if (rc == -EEXIST) {
            rbn = rblist__find(&ctx.backup, &entry);
            sched_switch = container_of(rbn, struct perf_event_backup, rbnode);
            if (sched_switch->event.header.size == event->header.size) {
                memmove(&sched_switch->event, event, event->header.size);
            } else {
                rblist__remove_node(&ctx.backup, rbn);
                rblist__add_node(&ctx.backup, &entry);
            }
        }
    } else if (type == ctx.sched_wakeup) {
        if (tep_get_field_val(&s, e, "pid", &record, &pid, 1) < 0) {
            trace_seq_putc(&s, '\n');
            trace_seq_do_fprintf(&s, stderr);
            goto __return;
        }

        entry.tid = (__u32)pid;
        entry.event = event;
        rbn = rblist__find(&ctx.backup, &entry);
        if (rbn == NULL)
            goto __return;
        sched_switch = container_of(rbn, struct perf_event_backup, rbnode);
        data0 = (void *)sched_switch->event.sample.array;

        if (data->time > data0->time &&
            data->time - data0->time > ctx.env->greater_than) {
            const char *comm;
            int len;

            comm = tep_get_field_raw(&s, e, "comm", &record, &len, 0);
            if (comm) {
                tep__update_comm(comm, pid);
            }

            print_time(stdout);
            printf(" == %s %d WAIT %llu ms\n", tep__pid_to_comm((int)pid), (int)pid, (data->time - data0->time)/1000000UL);

            __raw_size(&sched_switch->event, &raw, &size);
            tep__print_event(data0->time/1000, data0->cpu_entry.cpu, raw, size);
            __print_callchain(&sched_switch->event);

            __raw_size(event, &raw, &size);
            tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
            __print_callchain(event);
        }

        rblist__remove_node(&ctx.backup, rbn);
    }
__return:
    trace_seq_destroy(&s);
    tep__unref();
}

static void task_state_exit(union perf_event *event, int instance)
{
    task_exit_free_syms(event);
}

static void task_state_sigusr1(int signum)
{
    obj__stat(stderr);
}

static const char *task_state_desc[] = PROFILER_DESC("task-state",
    "[OPTION...] [-S] [-D] [--than ns] [--filter comm] [-g [--flame-graph file]]",
    "Trace task state, wakeup, switch, INTERRUPTIBLE, UNINTERRUPTIBLE.", "",
    "TRACEPOINT", "",
    "    sched:sched_switch, sched:sched_wakeup", "",
    "EXAMPLES", "",
    "    "PROGRAME" task-state -p 2347 -SD --than 20ms -g",
    "    "PROGRAME" task-state --filter 'java,python*' -S --than 100ms -g",
    "    "PROGRAME" task-state -- ip link show eth0");
static const char *task_state_argv[] = PROFILER_ARGV("task-state",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_CALLCHAIN_FILTER,
    PROFILER_ARGV_PROFILER, "interruptible", "uninterruptible", "than", "filter", "call-graph", "flame-graph");
struct monitor task_state = {
    .name = "task-state",
    .desc = task_state_desc,
    .argv = task_state_argv,
    .pages = 8,
    .init = task_state_init,
    .filter = task_state_filter,
    .deinit = task_state_deinit,
    .sigusr1 = task_state_sigusr1,
    .comm   = monitor_tep__comm,
    .exit   = task_state_exit,
    .sample = task_state_sample,
};
MONITOR_REGISTER(task_state)


