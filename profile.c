#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "monitor.h"
#include "trace_helpers.h"
#include "tep.h"
#include "stack_helpers.h"

struct monitor profile;

static struct monitor_ctx {
    int nr_ins;
    uint64_t *counter;
    uint64_t *cycles;
    struct {
        uint64_t start_time;
        uint64_t num;
    }*stat;
    struct callchain_ctx *cc;
    struct flame_graph *flame;
    struct bpf_filter filter;
    struct perf_evsel *evsel;
    time_t time;
    char time_str[32];
    int in_guest;
    int tsc_khz;
    int vendor;
    struct env *env;
} ctx;

static void profile_interval(void);
static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    ctx.nr_ins = monitor_nr_instance();
    ctx.counter = calloc(ctx.nr_ins, sizeof(uint64_t));
    if (!ctx.counter) {
        return -1;
    }
    ctx.cycles = calloc(ctx.nr_ins, sizeof(uint64_t));
    if (!ctx.cycles) {
        free(ctx.counter);
        return -1;
    }
    ctx.stat = calloc(ctx.nr_ins, sizeof(*ctx.stat));
    if (!ctx.stat) {
        free(ctx.counter);
        free(ctx.cycles);
        return -1;
    }
    ctx.time = 0;
    ctx.time_str[0] = '\0';
    if (env->callchain) {
        if (!env->flame_graph)
            ctx.cc = callchain_ctx_new(callchain_flags(CALLCHAIN_KERNEL | CALLCHAIN_USER), stdout);
        else {
            ctx.flame = flame_graph_open(callchain_flags(CALLCHAIN_KERNEL | CALLCHAIN_USER), env->flame_graph);
            if (env->interval) {
                profile_interval();
                profile.interval = profile_interval;
            }
        }
    }

    if (bpf_filter_init(&ctx.filter, env))
        bpf_filter_open(&ctx.filter);

    ctx.in_guest = in_guest();
    ctx.tsc_khz = ctx.in_guest ? 0 : get_tsc_khz();
    ctx.vendor = get_cpu_vendor();
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    free(ctx.counter);
    free(ctx.cycles);
    free(ctx.stat);
    bpf_filter_close(&ctx.filter);
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

static int profile_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_HARDWARE,
        .config        = PERF_COUNT_HW_CPU_CYCLES,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = env->freq,
        .freq          = env->freq ? 1 : 0,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_READ |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_user  = env->exclude_user,
        .exclude_kernel = env->exclude_kernel,
        .exclude_guest = env->exclude_guest,
        .exclude_host = env->exclude_host,
        .exclude_callchain_user = exclude_callchain_user(CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .exclude_callchain_kernel = exclude_callchain_kernel(CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;

    if (env->exclude_guest && env->exclude_host)
        return -1;
    if (env->exclude_user && env->exclude_kernel)
        return -1;

    if (monitor_ctx_init(env) < 0)
        return -1;

    if (ctx.tsc_khz > 0 && env->freq > 0) {
        attr.freq = 0;
        attr.sample_period = ctx.tsc_khz * 1000ULL / env->freq;
    }
    if (ctx.in_guest) {
        attr.type = PERF_TYPE_SOFTWARE;
        attr.config = PERF_COUNT_SW_CPU_CLOCK;
        attr.exclude_idle = 1;
    } else if (ctx.vendor == X86_VENDOR_INTEL)
        attr.config = PERF_COUNT_HW_REF_CPU_CYCLES;

    if (env->callchain)
        profile.pages *= 2;

    if (env->verbose) {
        printf("tsc_khz = %d\n", ctx.tsc_khz);
    }

    reduce_wakeup_times(current_base_profiler(), &attr);

    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    ctx.evsel = evsel;
    return 0;
}

static int profile_filter(struct perf_evlist *evlist, struct env *env)
{
    int err;

    if (ctx.filter.bpf_fd >= 0) {
        err = perf_evsel__set_bpf(ctx.evsel, ctx.filter.bpf_fd);
        if (err < 0)
            return err;
    }
    return 0;
}

static void profile_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

static void profile_read(struct perf_evsel *evsel, struct perf_counts_values *count, int instance)
{
    uint64_t cycles = 0;
    const char *str_in[] = {"host,guest", "host", "guest", "error"};
    const char *str_mode[] = {"all", "usr", "sys", "error"};
    int in, mode;

    if (count->val > ctx.cycles[instance]) {
        cycles = count->val - ctx.cycles[instance];
        ctx.cycles[instance] = count->val;
    }
    if (cycles) {
        in = (ctx.env->exclude_host << 1) | ctx.env->exclude_guest;
        mode = (ctx.env->exclude_user << 1) | ctx.env->exclude_kernel;
        print_time(stdout);
        if (ctx.tsc_khz > 0 && ctx.vendor == X86_VENDOR_INTEL)
            printf("%s %d [%s] %.2f%% [%s] %lu cycles\n", monitor_instance_oncpu() ? "cpu" : "thread",
                    monitor_instance_oncpu() ? monitor_instance_cpu(instance) : monitor_instance_thread(instance),
                    str_in[in],
                    (float)cycles * 100 / (ctx.tsc_khz * (__u64)ctx.env->interval),
                    str_mode[mode], cycles);
        else
            printf("%s %d [%s] [%s] %lu cycles\n", monitor_instance_oncpu() ? "cpu" : "thread",
                    monitor_instance_oncpu() ? monitor_instance_cpu(instance) : monitor_instance_thread(instance),
                    str_in[in], str_mode[mode], cycles);
    }
}

static void profile_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_READ | PERF_SAMPLE_CALLCHAIN
    struct sample_type_data {
        struct {
            __u32    pid;
            __u32    tid;
        }    tid_entry;
        __u64   time;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        __u64 counter;
        struct callchain callchain;
    } *data = (void *)event->sample.array;
    uint64_t counter = 0;
    int print = 1;

    if (data->counter > ctx.counter[instance]) {
        counter = data->counter - ctx.counter[instance];
        ctx.counter[instance] = data->counter;
    }

    if (ctx.env->greater_than) {
        uint64_t time = ctx.stat[instance].start_time;
        ctx.stat[instance].num ++;
        if (data->time - time >= NSEC_PER_SEC) {
            print = 0;
            ctx.stat[instance].start_time = data->time;
            ctx.stat[instance].num = 1;
        } else {
            int x = (ctx.env->freq * ctx.env->greater_than + 99) / 100;
            if (ctx.stat[instance].num < x)
                print = 0;
        }
    }

    if (print) {
        print_time(stdout);
        tep__update_comm(NULL, data->tid_entry.tid);
        printf("%16s %6u [%03d] %llu.%06llu: %lu cpu-cycles\n", tep__pid_to_comm(data->tid_entry.tid), data->tid_entry.tid,
                        data->cpu_entry.cpu, data->time / NSEC_PER_SEC, (data->time % NSEC_PER_SEC)/1000, counter);
        if (ctx.env->callchain) {
            if (!ctx.env->flame_graph)
                print_callchain_common(ctx.cc, &data->callchain, data->tid_entry.pid);
            else {
                const char *comm = tep__pid_to_comm((int)data->tid_entry.pid);
                flame_graph_add_callchain_at_time(ctx.flame, &data->callchain, data->tid_entry.pid,
                                                  !strcmp(comm, "<...>") ? NULL : comm,
                                                  ctx.time, ctx.time_str);
            }
        }
    }
}

static void profile_interval(void)
{
    ctx.time = time(NULL);
    strftime(ctx.time_str, sizeof(ctx.time_str), "%Y-%m-%d;%H:%M:%S", localtime(&ctx.time));
    flame_graph_output(ctx.flame);
    flame_graph_reset(ctx.flame);
}

static const char *profile_desc[] = PROFILER_DESC("profile",
    "[OPTION...] [-F freq] [-g [--flame-graph file [-i INT]]] [--than percent]",
    "Sampling at the specified frequency to profile high CPU utilization.", "",
    "EXAMPLES", "",
    "    "PROGRAME" profile -F 997 -p 2347 -g --flame-graph cpu",
    "    "PROGRAME" profile -F 997 -C 0-3 --than 30 -g --flame-graph cpu");
static const char *profile_argv[] = PROFILER_ARGV("profile",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_FILTER,
    PROFILER_ARGV_PROFILER, "freq", "call-graph", "flame-graph", "than");
struct monitor profile = {
    .name = "profile",
    .desc = profile_desc,
    .argv = profile_argv,
    .pages = 2,
    .init = profile_init,
    .filter = profile_filter,
    .deinit = profile_exit,
    .sample = profile_sample,
};
PROFILER_REGISTER(profile);

static int cpu_util_init(struct perf_evlist *evlist, struct env *env)
{
    if (in_guest()) {
        fprintf(stderr, "cpu-util not support in guest\n");
        return -1;
    }
    env->freq = 0;
    env->interval = env->interval?:1000;
    return profile_init(evlist, env);
}

static void empty_sample(union perf_event *event, int instance)
{
}

static const char *cpu_util_desc[] = PROFILER_DESC("cpu-util",
    "[OPTION...] [--exclude-*] [-G]",
    "Report CPU utilization for guest or host.", "",
    "SYNOPSIS", "",
    "    Based on profile. See '"PROGRAME" profile -h' for more information.", "",
    "EXAMPLES", "",
    "    "PROGRAME" cpu-util -C 1-4",
    "    "PROGRAME" cpu-util -C 1-4 -G");
static const char *cpu_util_argv[] = PROFILER_ARGV("cpu-util",
    PROFILER_ARGV_OPTION,
    "FILTER OPTION:",
    "exclude-host", "exclude-guest", "exclude-user", "exclude-kernel");
struct monitor cpu_util = {
    .name = "cpu-util",
    .desc = cpu_util_desc,
    .argv = cpu_util_argv,
    .pages = 0,
    .init = cpu_util_init,
    .deinit = profile_exit,
    .read   = profile_read,
    .sample = empty_sample,
};
PROFILER_REGISTER(cpu_util);

