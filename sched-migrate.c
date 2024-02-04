#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/compiler.h>
#include <api/fs/fs.h>
#include <monitor.h>
#include <dlfcn.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>
#include <tp_struct.h>


struct sched_migrate_stat {
    unsigned long same_l2;
    unsigned long same_llc;
    unsigned long total;
};
struct sched_migrate_ctx {
    int nr_cpus;
    struct perf_cpu_map **l2_cpumap;
    struct perf_cpu_map **llc_cpumap;
    struct callchain_ctx *cc;
    struct flame_graph *flame;
    struct sched_migrate_stat stat;
};

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

static int read_cpumap(struct perf_cpu_map **cpumaps, int cpu, int level)
{
    struct perf_cpu_map *cpumap;
    char buff[PATH_MAX];
    char *cpu_list;
    size_t len = 0;
    int err, idx;

    snprintf(buff, sizeof(buff), "devices/system/cpu/cpu%d/cache/index%d/shared_cpu_list", cpu, level);
    if ((err = sysfs__read_str(buff, &cpu_list, &len)) < 0 ||
        len == 0) {
        fprintf(stderr, "failed to read %s, %d Not Supported.\n", buff, err);
        return -1;
    }
    cpu_list[len] = '\0';
    cpumap = perf_cpu_map__new(cpu_list);

    perf_cpu_map__for_each_cpu(cpu, idx, cpumap) {
        if (cpu < 0) {
            fprintf(stderr, "cpu < 0 %s, Not Supported.\n", cpu_list);
            free(cpu_list);
            return -1;
        }
        cpumaps[cpu] = perf_cpu_map__get(cpumap);
    }
    perf_cpu_map__put(cpumap);
    free(cpu_list);
    return 0;
}
static void monitor_ctx_exit(struct prof_dev *dev);
static int monitor_ctx_init(struct prof_dev *dev)
{
    int i;
    struct env *env = dev->env;
    struct sched_migrate_ctx *ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;

    tep__ref();

    ctx->nr_cpus = get_present_cpus();
    ctx->l2_cpumap = calloc(ctx->nr_cpus, sizeof(*ctx->l2_cpumap));
    ctx->llc_cpumap = calloc(ctx->nr_cpus, sizeof(*ctx->llc_cpumap));
    if (!ctx->l2_cpumap || !ctx->llc_cpumap)
        goto failed;
    for (i = 0; i < ctx->nr_cpus; i++) {
        if (!ctx->l2_cpumap[i]) {
            if (read_cpumap(ctx->l2_cpumap, i, 2) < 0)
                goto failed;
        }
        if (!ctx->llc_cpumap[i]) {
            if (read_cpumap(ctx->llc_cpumap, i, 3) < 0)
                goto failed;
        }
    }

    if (env->callchain) {
        if (!env->flame_graph)
            ctx->cc = callchain_ctx_new(callchain_flags(dev, CALLCHAIN_KERNEL), stdout);
        else {
            ctx->flame = flame_graph_open(callchain_flags(dev, CALLCHAIN_KERNEL), env->flame_graph);
        }
        dev->pages *= 2;
    }

    memset(&ctx->stat, 0 , sizeof(ctx->stat));

    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct sched_migrate_ctx *ctx = dev->private;
    int i;
    if (ctx->l2_cpumap) {
        for (i = 0; i < ctx->nr_cpus; i++)
            perf_cpu_map__put(ctx->l2_cpumap[i]);
        free(ctx->l2_cpumap);
    }
    if (ctx->llc_cpumap) {
        for (i = 0; i < ctx->nr_cpus; i++)
            perf_cpu_map__put(ctx->llc_cpumap[i]);
        free(ctx->llc_cpumap);
    }
    if (dev->env->callchain) {
        if (!dev->env->flame_graph)
            callchain_ctx_free(ctx->cc);
        else {
            flame_graph_output(ctx->flame);
            flame_graph_close(ctx->flame);
        }
    }
    tep__unref();
    free(ctx);
}

static int sched_migrate_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
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
        .exclude_callchain_user = exclude_callchain_user(dev, CALLCHAIN_KERNEL),
        .exclude_callchain_kernel = exclude_callchain_kernel(dev, CALLCHAIN_KERNEL),
        .watermark     = 1,
        .wakeup_watermark = (dev->pages << 12) / 2,
    };
    struct perf_evsel *evsel;

    if (monitor_ctx_init(dev) < 0)
        return -1;

    reduce_wakeup_times(dev, &attr);

    attr.config = tep__event_id("sched", "sched_migrate_task");
    evsel = perf_evsel__new(&attr);
    if (!evsel)
        goto failed;
    perf_evlist__add(evlist, evsel);
    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

static int sched_migrate_filter(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
    struct perf_evsel *evsel;
    int err;
    if (env->filter && env->filter[0]) {
        perf_evlist__for_each_evsel(evlist, evsel) {
            err = perf_evsel__apply_filter(evsel, env->filter);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static void sched_migrate_interval(struct prof_dev *dev)
{
    struct sched_migrate_ctx *ctx = dev->private;
    print_time(stdout);
    printf("sched-migrate total %lu, same LLC %lu hit %lu%%, same L2 %lu hit %lu%%\n", ctx->stat.total,
                ctx->stat.same_llc,ctx->stat.total ? ctx->stat.same_llc*100/ctx->stat.total : 0,
                ctx->stat.same_l2, ctx->stat.total ? ctx->stat.same_l2*100/ctx->stat.total : 0);
    memset(&ctx->stat, 0 , sizeof(ctx->stat));
}

static void sched_migrate_exit(struct prof_dev *dev)
{
    sched_migrate_interval(dev);
    monitor_ctx_exit(dev);
}

static void __raw_size(struct prof_dev *dev, union perf_event *event, void **praw, int *psize)
{
    if (dev->env->callchain) {
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

static inline void __print_callchain(struct prof_dev *dev, union perf_event *event)
{
    struct sched_migrate_ctx *ctx = dev->private;
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (dev->env->callchain) {
        if (!dev->env->flame_graph)
            print_callchain_common(ctx->cc, &data->callchain, data->h.tid_entry.pid);
        else
            flame_graph_add_callchain(ctx->flame, &data->callchain, data->h.tid_entry.pid, NULL);
    }
}

static bool same_l2(struct sched_migrate_ctx *ctx, int orig_cpu, int dest_cpu)
{
    return ctx->l2_cpumap[orig_cpu] == ctx->l2_cpumap[dest_cpu];
}

static bool same_llc(struct sched_migrate_ctx *ctx, int orig_cpu, int dest_cpu)
{
    return ctx->llc_cpumap[orig_cpu] == ctx->llc_cpumap[dest_cpu];
}

static void sched_migrate_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct sched_migrate_ctx *ctx = dev->private;
    struct sample_type_header *data = (void *)event->sample.array;
    void *raw;
    int size;
    struct sched_migrate_task *migrate;
    int print = 0;

    __raw_size(dev, event, &raw, &size);
    migrate = raw;

    if (same_l2(ctx, migrate->orig_cpu, migrate->dest_cpu))
        ctx->stat.same_l2 ++;

    if (!same_llc(ctx, migrate->orig_cpu, migrate->dest_cpu)) {
        if (dev->env->detail) {
            print = 1;
        }
    } else
        ctx->stat.same_llc ++;

    ctx->stat.total ++;

    if (print || dev->env->verbose >= VERBOSE_EVENT) {
        tep__update_comm(NULL, data->tid_entry.tid);
        if (dev->print_title) print_time(stdout);
        tep__print_event(data->time, data->cpu_entry.cpu, raw, size);
        __print_callchain(dev, event);
    }
}


static const char *sched_migrate_desc[] = PROFILER_DESC("sched-migrate",
    "[OPTION...] [--detail] [--filter filter] [-g [--flame-graph file]]",
    "Monitor system process migrations.", "",
    "SYNOPSIS",
    "    Monitor system process migrations. Determine if source and destination cpu belong",
    "    to the same LLC, L2 cache", "",
    "TRACEPOINT",
    "    sched:sched_migrate_task", "",
    "EXAMPLES",
    "    "PROGRAME" sched-migrate --detail");
static const char *sched_migrate_argv[] = PROFILER_ARGV("sched-migrate",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_CALLCHAIN_FILTER,
    PROFILER_ARGV_PROFILER, "detail", "filter", "call-graph", "flame-graph");
static profiler sched_migrate = {
    .name = "sched-migrate",
    .desc = sched_migrate_desc,
    .argv = sched_migrate_argv,
    .pages = 2,
    .init = sched_migrate_init,
    .filter = sched_migrate_filter,
    .deinit = sched_migrate_exit,
    .interval = sched_migrate_interval,
    .sample = sched_migrate_sample,
};
PROFILER_REGISTER(sched_migrate)


