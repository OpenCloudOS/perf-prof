#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <monitor.h>
#include <dlfcn.h>
#include <tep.h>
#include <trace_helpers.h>


struct monitor trace;
struct monitor_ctx {
    struct ksyms *ksyms;
    struct syms_cache *syms_cache;
    struct env *env;
} ctx;
static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    if (env->callchain) {
        ctx.ksyms = ksyms__load();
        ctx.syms_cache = syms_cache__new(0);
        trace.pages *= 2;
    }
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    if (ctx.env->callchain) {
        ksyms__free(ctx.ksyms);
        syms_cache__free(ctx.syms_cache);
    }
    tep__unref();
}

static int trace_init(struct perf_evlist *evlist, struct env *env)
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
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;

    if (monitor_ctx_init(env) < 0)
        return -1;

    if (env->event) {
        char *sys = strtok(env->event, ":");
        char *name = strtok(NULL, ":");
         int id = tep__event_id(sys, name);
        if (id < 0)
            return -1;
        attr.config = id;
    } else
        return -1;

    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}

static int trace_filter(struct perf_evlist *evlist, struct env *env)
{
    struct perf_evsel *evsel;
    int err;
    if (env->filter) {
        perf_evlist__for_each_evsel(evlist, evsel) {
            err = perf_evsel__apply_filter(evsel, env->filter);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static void trace_exit(struct perf_evlist *evlist)
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
    struct {
        __u64   nr;
        __u64   ips[0];
    } callchain;
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

static void __print_callchain(union perf_event *event)
{
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (ctx.env->callchain && ctx.ksyms) {
        __u64 i;
        bool kernel, user;
        struct syms *syms;
        for (i = 0; i < data->callchain.nr; i++) {
            __u64 ip = data->callchain.ips[i];
            if (ip == PERF_CONTEXT_KERNEL) {
                kernel = true;
                user = false;
                continue;
            } else if (ip == PERF_CONTEXT_USER) {
                __u32 pid = data->h.tid_entry.pid;
                kernel = false;
                user = false;
                if (ctx.syms_cache) {
                    syms = syms_cache__get_syms(ctx.syms_cache, pid);
                    if (syms)
                        user = true;
                }
                continue;
            }
            if (kernel) {
                const struct ksym *ksym = ksyms__map_addr(ctx.ksyms, ip);
                printf("    %016llx %s+0x%llx ([kernel.kallsyms])\n", ip, ksym ? ksym->name : "Unknown", ip - ksym->addr);
            } else if (user) {
                struct dso *dso;
                uint64_t offset;
                dso = syms__find_dso(syms, ip, &offset);
                if (dso) {
                    const struct sym *sym = dso__find_sym(dso, offset);
                    printf("    %016llx %s+0x%lx (%s)\n", ip, sym ? sym->name : "Unknown", offset - sym->start, dso__name(dso));
                }
            }
        }
    }
}

static void trace_sample(union perf_event *event, int instance)
{
    struct sample_type_header *data = (void *)event->sample.array;
    void *raw;
    int size;

    __raw_size(event, &raw, &size);
    tep__update_comm(NULL, data->tid_entry.tid);
    print_time(stdout);
    tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
    __print_callchain(event);
}

struct monitor trace = {
    .name = "trace",
    .pages = 2,
    .init = trace_init,
    .filter = trace_filter,
    .deinit = trace_exit,
    .sample = trace_sample,
};
MONITOR_REGISTER(trace)

