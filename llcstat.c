#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/compiler.h>
#include <api/fs/fs.h>
#include <monitor.h>
#include <tep.h>
#include <stack_helpers.h>

static profiler llcstat;

struct cache {
    uint64_t counter;
    uint64_t incremental;
};
static struct monitor_ctx {
    int nr_ins;
    struct cpuinfo_x86 cpuinfo;
    struct cache *l3_cache_references;
    struct cache *l3_cache_misses;
    struct cache *l3_cache_miss_latency;
    struct cache *l3_misses_by_request_type;
    __u64 l3_cache_reference_config;
    __u64 l3_cache_miss_config;
    __u64 l3_cache_miss_latency_config;
    __u64 l3_misses_by_request_type_config;
} ctx;

static int llcstat_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type        = PERF_TYPE_HARDWARE,
        .config      = 0,
        .size        = sizeof(struct perf_event_attr),
        .sample_period = 0, //env->trigger_freq,  //每trigger_freq个计数发起一个PMI中断, 发起1个采样.
        .sample_type = 0, //PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_READ,
        .read_format = 0,
        .exclude_host = env->exclude_host,  //only guest
        .pinned        = 0,
        .disabled      = 1,
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int type;
    __u64 l3_cache_reference = 0;
    __u64 l3_cache_miss = 0;
    __u64 l3_cache_miss_latency = 0;
    __u64 l3_misses_by_request_type = 0;

    if (get_cpuinfo(&ctx.cpuinfo) < 0)
        return -1;

    if (!monitor_instance_oncpu()) {
        fprintf(stderr, "can only be bound to CPU\n");
        return -1;
    }

    if (env->interval == 0)
        env->interval = 1000;

    if (ctx.cpuinfo.vendor == X86_VENDOR_INTEL) {
        type = PERF_TYPE_HARDWARE;
        l3_cache_reference = PERF_COUNT_HW_CACHE_REFERENCES;
        l3_cache_miss = PERF_COUNT_HW_CACHE_MISSES;
    } else if (ctx.cpuinfo.vendor == X86_VENDOR_AMD) {
        int err;
        char *cpumask = NULL;
        size_t size = 0;
        struct perf_cpu_map *cpus = NULL;

        if ((err = sysfs__read_int("bus/event_source/devices/amd_l3/type", &type)) < 0) {
            fprintf(stderr, "failed to read /sys/bus/event_source/devices/amd_l3/type."
                            "Not Supported.\n");
            return -1;
        }
        if ((err = sysfs__read_str("bus/event_source/devices/amd_l3/cpumask", &cpumask, &size)) < 0 &&
            size == 0) {
            fprintf(stderr, "failed to read /sys/bus/event_source/devices/amd_l3/cpumask."
                            "Not Supported.\n");
            return -1;
        }
        cpus = perf_cpu_map__new(cpumask);
        llcstat.cpus = perf_cpu_map__and(llcstat.cpus, cpus);
        perf_cpu_map__put(cpus);
        free(cpumask);

        if (ctx.cpuinfo.family == 0x17) { // AMD rome
            l3_cache_reference = 0xFF0F00000040FF04UL;
            l3_cache_miss = 0xFF0F000000400104UL;
            l3_cache_miss_latency = 0xFF0F000000400090UL;
            l3_misses_by_request_type = 0xFF0F000000401F9AUL;
        } else if (ctx.cpuinfo.family == 0x19) { // AMD milan
            l3_cache_reference = 0x0300C0000040FF04UL;
            l3_cache_miss = 0x0300C00000400104UL;
            l3_cache_miss_latency = 0x0300C00000400090UL;
            l3_misses_by_request_type = 0x0300C00000401F9AUL;
        }
    } else
        return -1;

    ctx.nr_ins = perf_cpu_map__nr(llcstat.cpus);
    ctx.l3_cache_references = calloc(ctx.nr_ins, sizeof(struct cache));
    ctx.l3_cache_misses = calloc(ctx.nr_ins, sizeof(struct cache));
    if (!ctx.l3_cache_references || !ctx.l3_cache_misses)
        return -1;

    attr.type = type;
    ctx.l3_cache_reference_config = attr.config = l3_cache_reference;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        fprintf(stderr, "failed to init l3_cache_reference counter\n");
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    ctx.l3_cache_miss_config = attr.config = l3_cache_miss;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        fprintf(stderr, "failed to init l3_cache_miss counter\n");
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    if (ctx.cpuinfo.vendor != X86_VENDOR_AMD)
        return 0;

    ctx.l3_cache_miss_latency = calloc(ctx.nr_ins, sizeof(struct cache));
    ctx.l3_misses_by_request_type = calloc(ctx.nr_ins, sizeof(struct cache));
    if (!ctx.l3_cache_miss_latency || !ctx.l3_misses_by_request_type)
        return -1;

    ctx.l3_cache_miss_latency_config = attr.config = l3_cache_miss_latency;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        fprintf(stderr, "failed to init l3_cache_miss_latency counter\n");
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    ctx.l3_misses_by_request_type_config = attr.config = l3_misses_by_request_type;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        fprintf(stderr, "failed to init l3_misses_by_request_type counter\n");
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}

static void llcstat_exit(struct perf_evlist *evlist)
{
    free(ctx.l3_cache_references);
    free(ctx.l3_cache_misses);
    if (ctx.cpuinfo.vendor != X86_VENDOR_AMD)
        return ;
    free(ctx.l3_cache_miss_latency);
    free(ctx.l3_misses_by_request_type);
}

static void llcstat_read(struct perf_evsel *evsel, struct perf_counts_values *count, int instance)
{
    struct cache *cache;
    __u64 config = perf_evsel__attr(evsel)->config;

    if (config == ctx.l3_cache_reference_config)
        cache = ctx.l3_cache_references;
    else if (config == ctx.l3_cache_miss_config)
        cache = ctx.l3_cache_misses;
    else if (config == ctx.l3_cache_miss_latency_config)
        cache = ctx.l3_cache_miss_latency;
    else if (config == ctx.l3_misses_by_request_type_config)
        cache = ctx.l3_misses_by_request_type;
    else
        return;

    if (count->val > cache[instance].counter) {
        cache[instance].incremental = count->val - cache[instance].counter;
        cache[instance].counter = count->val;
    }
}

static void llcstat_interval(void)
{
    int ins;

    print_time(stdout); printf("\n");
    printf("[CPU] L3 %9s %9s  %6s  %12s\n", "REFERENCE", "MISSES", "HIT%", "MISS-LATENCY");
    for (ins = 0; ins < ctx.nr_ins; ins ++) {
        float hit = 0.0;
        if (ctx.l3_cache_references[ins].incremental > ctx.l3_cache_misses[ins].incremental)
            hit = (ctx.l3_cache_references[ins].incremental - ctx.l3_cache_misses[ins].incremental) * 100.0 /
                   ctx.l3_cache_references[ins].incremental;
        printf("[%03d]    %9lu %9lu  %5.2f%%  ", monitor_instance_cpu(ins),
                ctx.l3_cache_references[ins].incremental, ctx.l3_cache_misses[ins].incremental,
                hit);
        if (ctx.cpuinfo.vendor == X86_VENDOR_AMD) {
            printf("%12lu\n", ctx.l3_cache_miss_latency[ins].incremental * 16 /
                                ctx.l3_misses_by_request_type[ins].incremental);
        } else
            printf("<not supported>\n");
    }
}


static const char *llcstat_desc[] = PROFILER_DESC("llcstat",
    "[OPTION...]",
    "Last level cache state on x86 platform.", "",
    "EXAMPLES", "",
    "    "PROGRAME" llcstat -i 1000",
    "    "PROGRAME" llcstat -C 0-3 -i 1000");
static const char *llcstat_argv[] = PROFILER_ARGV("llcstat",
    "OPTION:",
    "cpus",
    "interval", "output", "order", "order-mem", "mmap-pages",
    "version", "verbose", "quiet", "help");
static profiler llcstat = {
    .name = "llcstat",
    .desc = llcstat_desc,
    .argv = llcstat_argv,
    .pages = 0,
    .init = llcstat_init,
    .deinit = llcstat_exit,
    .interval = llcstat_interval,
    .read = llcstat_read,
};
PROFILER_REGISTER(llcstat)

