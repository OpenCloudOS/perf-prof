#include <stdio.h>
#include <stdlib.h>
#include "monitor.h"
#include "trace_helpers.h"
#include "tep.h"

struct monitor percpu_stat;

#define PERCPU_COUNTER_MAX 20
struct swevent_stat {
    uint64_t count[PERCPU_COUNTER_MAX];
    uint64_t diff[PERCPU_COUNTER_MAX];
};
struct monitor_ctx {
    int nr_cpus;
    struct swevent_stat *stats;
    struct {
        struct perf_evsel *evsel;
        const char *name;
        int name_len;
    } evsels[PERCPU_COUNTER_MAX];
    int nr_evsels;
    int n;
    uint64_t num;
    int min_cpu;
    struct env *env;
} ctx;

static int monitor_ctx_init(struct env *env)
{
    ctx.nr_cpus = get_possible_cpus();
    ctx.stats = calloc(ctx.nr_cpus, sizeof(struct swevent_stat));
    if (!ctx.stats) {
        return -1;
    }
    ctx.nr_evsels = 0;
    ctx.n = 0;
    ctx.num = 0;
    ctx.min_cpu = -1;
    ctx.env = env;
    tep__ref();
    return 0;
}

static void monitor_ctx_exit(void)
{
    tep__unref();
    free(ctx.stats);
}

static struct perf_evsel *perf_tp_event(struct perf_evlist *evlist, const char *sys, const char *name)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 0,
        .freq          = 0,
        .sample_type   = 0,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
    };
    struct perf_evsel *evsel;
    int id;

    id = tep__event_id(sys, name);
    if (id < 0)
        return NULL;

    attr.config = id;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return NULL;
    }
    perf_evlist__add(evlist, evsel);

    return evsel;
}

static struct perf_evsel *perf_sw_event(struct perf_evlist *evlist, int config)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_SOFTWARE,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 0,
        .freq          = 0,
        .sample_type   = 0,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
    };
    struct perf_evsel *evsel;

    attr.config = config;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return NULL;
    }
    perf_evlist__add(evlist, evsel);

    return evsel;
}

static void evsel_name(struct perf_evsel *evsel, const char *name)
{
    if (evsel && ctx.nr_evsels < PERCPU_COUNTER_MAX) {
        ctx.evsels[ctx.nr_evsels].evsel = evsel;
        ctx.evsels[ctx.nr_evsels].name = name;
        ctx.evsels[ctx.nr_evsels].name_len = (int)strlen(name);
        ctx.nr_evsels ++;
    }
}

static int percpu_stat_init(struct perf_evlist *evlist, struct env *env)
{
    if (monitor_ctx_init(env) < 0)
        return -1;

    if (env->interval == 0)
        env->interval = 1000;

    //software event
    evsel_name(perf_sw_event(evlist, PERF_COUNT_SW_CONTEXT_SWITCHES), " SOFT csw");
    evsel_name(perf_sw_event(evlist, PERF_COUNT_SW_CPU_MIGRATIONS), "cpu-mig");
    evsel_name(perf_sw_event(evlist, PERF_COUNT_SW_PAGE_FAULTS_MIN), "minflt");
    evsel_name(perf_sw_event(evlist, PERF_COUNT_SW_PAGE_FAULTS_MAJ), "majflt");
    //syscalls
    if (env->syscalls)
        evsel_name(perf_tp_event(evlist, "raw_syscalls", "sys_enter"), " syscalls");
    //irq, softirq, workqueue
    evsel_name(perf_tp_event(evlist, "irq", "irq_handler_entry"), " hardirq");
    evsel_name(perf_tp_event(evlist, "irq", "softirq_entry"), "softirq");
    evsel_name(perf_tp_event(evlist, "timer", "hrtimer_expire_entry"), "hrtimer");
    evsel_name(perf_tp_event(evlist, "workqueue", "workqueue_execute_start"), "workqueue");
    //kvm
    evsel_name(perf_tp_event(evlist, "kvm", "kvm_exit"), " KVM exit");
    //net
    evsel_name(perf_tp_event(evlist, "net", "netif_receive_skb"), " NET recv");
    evsel_name(perf_tp_event(evlist, "net", "net_dev_xmit"), " xmit");
    evsel_name(perf_tp_event(evlist, "net", "napi_gro_receive_entry"), "gro");
    //page alloc
    evsel_name(perf_tp_event(evlist, "kmem", "mm_page_alloc"), " MM alloc");
    evsel_name(perf_tp_event(evlist, "compaction", "mm_compaction_migratepages"), "compact");
    evsel_name(perf_tp_event(evlist, "vmscan", "mm_vmscan_direct_reclaim_begin"), "reclaim");
    evsel_name(perf_tp_event(evlist, "migrate", "mm_migrate_pages"), "migrate");
    //page cache
    evsel_name(perf_tp_event(evlist, "filemap", "mm_filemap_add_to_page_cache"), " PAGE cache");
    evsel_name(perf_tp_event(evlist, "writeback", "wbc_writepage"), " WB pages");
    //cpu_idle, must be last
    evsel_name(perf_tp_event(evlist, "power", "cpu_idle"), " idle");

    return 0;
}

static void percpu_stat_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

static void percpu_stat_read(struct perf_evsel *evsel, struct perf_counts_values *count, int instance)
{
    int cpu = monitor_instance_cpu(instance);
    int n;

    for (n = ctx.n; n < ctx.nr_evsels; n++)
        if (evsel == ctx.evsels[n].evsel)
            break;
    if (n == ctx.nr_evsels) {
        for (n = 0; n < ctx.n; n++)
            if (evsel == ctx.evsels[n].evsel)
                break;
        if (n == ctx.n)
            return ;
    }

    ctx.n = n;
    ctx.stats[cpu].diff[n] = 0;
    if (count->val > ctx.stats[cpu].count[n]) {
        ctx.stats[cpu].diff[n] = count->val - ctx.stats[cpu].count[n];
        ctx.stats[cpu].count[n] = count->val;
        if (n == ctx.nr_evsels-1) {
            //cpu_idle, contains enter and exit, must be divided by 2
            ctx.stats[cpu].diff[n] /= 2;
        }
    }

    if (evsel == ctx.evsels[ctx.nr_evsels-1].evsel) {
        if ((ctx.num % 60) == 0 && (ctx.min_cpu == cpu || ctx.min_cpu == -1)) {
            print_time(stdout);
            printf(" %3s ", "CPU");
            for (n = 0; n < ctx.nr_evsels; n++)
                printf("%s ", ctx.evsels[n].name);
            printf("\n");
        }
        if (ctx.min_cpu == -1 || cpu < ctx.min_cpu)
            ctx.min_cpu = cpu;
        if (ctx.min_cpu == cpu)
            ctx.num ++;
        print_time(stdout);
        printf(" %3d ", cpu);
        for (n = 0; n < ctx.nr_evsels; n++)
            printf("%*lu ", ctx.evsels[n].name_len, ctx.stats[cpu].diff[n]);
        printf("\n");
    }
}

static void percpu_stat_sample(union perf_event *event, int instance)
{
}

struct monitor percpu_stat = {
    .name = "percpu-stat",
    .pages = 0,
    .init = percpu_stat_init,
    .deinit = percpu_stat_exit,
    .read   = percpu_stat_read,
    .sample = percpu_stat_sample,
};
MONITOR_REGISTER(percpu_stat)

