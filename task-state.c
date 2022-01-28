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

#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2


struct monitor task_state;
static struct monitor_ctx {
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
        callchain_ctx_init(true, true);
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
    rblist__exit(&ctx.backup);
    if (ctx.env->callchain) {
        callchain_ctx_deinit(true, true);
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
        //.exclude_callchain_user = 1,
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;
    int id;

    if (monitor_ctx_init(env) < 0)
        return -1;

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
    char filter[128];
    struct perf_evsel *evsel;
    int err;

    perf_evlist__for_each_evsel(evlist, evsel) {
        struct perf_event_attr *attr = perf_evsel__attr(evsel);
        if (attr->config == ctx.sched_switch) {
            if (env->interruptible && env->uninterruptible) {
                if (env->filter)
                    snprintf(filter, sizeof(filter), "prev_comm~\"%s\" && (prev_state==%d || prev_state==%d)",
                            env->filter, TASK_INTERRUPTIBLE, TASK_UNINTERRUPTIBLE);
                else
                    snprintf(filter, sizeof(filter), "prev_state==%d || prev_state==%d",
                            TASK_INTERRUPTIBLE, TASK_UNINTERRUPTIBLE);
            } else if (env->interruptible || env->uninterruptible) {
                if (env->filter)
                    snprintf(filter, sizeof(filter), "prev_comm~\"%s\" && prev_state==%d",
                            env->filter, env->interruptible ? TASK_INTERRUPTIBLE:TASK_UNINTERRUPTIBLE);
                else
                    snprintf(filter, sizeof(filter), "prev_state==%d",
                            env->interruptible ? TASK_INTERRUPTIBLE:TASK_UNINTERRUPTIBLE);
            } else
                return -1;

            err = perf_evsel__apply_filter(evsel, filter);
            if (err < 0)
                return err;
        } else if (attr->config == ctx.sched_wakeup) {
            if (env->filter) {
                snprintf(filter, sizeof(filter), "comm~\"%s\"", env->filter);
                err = perf_evsel__apply_filter(evsel, filter);
                if (err < 0)
                    return err;
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

    if (ctx.env->callchain)
        print_callchain(stdout, &data->callchain, data->h.tid_entry.pid);
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
            data->time - data0->time > ctx.env->greater_than * 1000000UL) {
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

struct monitor task_state = {
    .name = "task-state",
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


