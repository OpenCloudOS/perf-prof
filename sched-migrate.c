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


static profiler sched_migrate;
struct sched_migrate_stat {
    unsigned long same_llc;
    unsigned long total;
};
static struct monitor_ctx {
    int nr_cpus;
    struct perf_cpu_map **llc_cpumap;
    struct callchain_ctx *cc;
    struct flame_graph *flame;
    struct sched_migrate_stat stat;
    struct env *env;
} ctx;

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

struct sched_migrate_task {
    unsigned short common_type;//	offset:0;	size:2;	signed:0;
	unsigned char common_flags;//	offset:2;	size:1;	signed:0;
	unsigned char common_preempt_count;//	offset:3;	size:1;	signed:0;
	int common_pid;//	offset:4;	size:4;	signed:1;

	char comm[16];//	offset:8;	size:16;	signed:1;
	pid_t pid;//	offset:24;	size:4;	signed:1;
	int prio;//	offset:28;	size:4;	signed:1;
	int orig_cpu;//	offset:32;	size:4;	signed:1;
	int dest_cpu;//	offset:36;	size:4;	signed:1;
};

static int monitor_ctx_init(struct env *env)
{
    tep__ref();

    ctx.nr_cpus = get_possible_cpus();
    ctx.llc_cpumap = calloc(ctx.nr_cpus, sizeof(*ctx.llc_cpumap));
    if (!ctx.llc_cpumap)
        return -1;

    if (env->callchain) {
        if (!env->flame_graph)
            ctx.cc = callchain_ctx_new(CALLCHAIN_KERNEL, stdout);
        else {
            ctx.flame = flame_graph_open(CALLCHAIN_KERNEL, env->flame_graph);
        }
        sched_migrate.pages *= 2;
    }

    memset(&ctx.stat, 0 , sizeof(ctx.stat));
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    int i;
    for (i = 0; i < ctx.nr_cpus; i++) {
        perf_cpu_map__put(ctx.llc_cpumap[i]);
    }
    free(ctx.llc_cpumap);
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

static int sched_migrate_init(struct perf_evlist *evlist, struct env *env)
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
        .exclude_callchain_user = 1,
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;

    if (monitor_ctx_init(env) < 0)
        return -1;

    attr.config = tep__event_id("sched", "sched_migrate_task");
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}

static void sched_migrate_interval(void)
{
    print_time(stdout);
    printf("sched-migrate total %lu, same llc %lu, hit %lu%%\n", ctx.stat.total, ctx.stat.same_llc,
                ctx.stat.same_llc*100/ctx.stat.total);
    memset(&ctx.stat, 0 , sizeof(ctx.stat));
}

static void sched_migrate_exit(struct perf_evlist *evlist)
{
    sched_migrate_interval();
    monitor_ctx_exit();
}

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
            print_callchain_common(ctx.cc, &data->callchain, 0);
        else
            flame_graph_add_callchain(ctx.flame, &data->callchain, 0, NULL);
    }
}

static void read_llc_cpumap(int cpu)
{
    struct perf_cpu_map *cpumap;
    char buff[PATH_MAX];
    char *cpu_list;
    size_t len;
    int err, idx;

    if (cpu > ctx.nr_cpus)
        exit(1);

    snprintf(buff, sizeof(buff), "devices/system/cpu/cpu%d/cache/index3/shared_cpu_list", cpu);
    if ((err = sysfs__read_str(buff, &cpu_list, &len)) < 0 &&
        len == 0) {
        fprintf(stderr, "failed to read %s, Not Supported.\n", buff);
        exit(1);
    }

    cpumap = perf_cpu_map__new(cpu_list);
    free(cpu_list);

    perf_cpu_map__for_each_cpu(cpu, idx, cpumap) {
        ctx.llc_cpumap[cpu] = perf_cpu_map__get(cpumap);
    }
    perf_cpu_map__put(cpumap);
}

static bool same_llc(int orig_cpu, int dest_cpu)
{
    if (!ctx.llc_cpumap[orig_cpu])
        read_llc_cpumap(orig_cpu);
    if (!ctx.llc_cpumap[dest_cpu])
        read_llc_cpumap(dest_cpu);
    return ctx.llc_cpumap[orig_cpu] == ctx.llc_cpumap[dest_cpu];
}

static void sched_migrate_sample(union perf_event *event, int instance)
{
    struct sample_type_header *data = (void *)event->sample.array;
    void *raw;
    int size;
    struct sched_migrate_task *migrate;

    __raw_size(event, &raw, &size);
    if (ctx.env->verbose) {
        tep__update_comm(NULL, data->tid_entry.tid);
        print_time(stdout);
        tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
        __print_callchain(event);
    }

    migrate = raw;
    if (!same_llc(migrate->orig_cpu, migrate->dest_cpu)) {
        if (ctx.env->detail && !ctx.env->verbose) {
            tep__update_comm(NULL, data->tid_entry.tid);
            print_time(stdout);
            tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
            __print_callchain(event);
        }
    } else
        ctx.stat.same_llc ++;
    ctx.stat.total ++;
}

static profiler sched_migrate = {
    .name = "sched-migrate",
    .pages = 2,
    .init = sched_migrate_init,
    .deinit = sched_migrate_exit,
    .interval = sched_migrate_interval,
    .sample = sched_migrate_sample,
};
PROFILER_REGISTER(sched_migrate)


