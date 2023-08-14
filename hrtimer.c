#include <stdio.h>
#include <stdlib.h>
#include "monitor.h"
#include "trace_helpers.h"
#include "stack_helpers.h"

static profiler hrtimer;
typedef int (*analyzer)(int instance, int nr_tp, u64 *counters);

#define BREAK 0
#define PRINT 1

static struct monitor_ctx {
    char *expression;
    struct expr_prog *prog;
    struct perf_evlist *evlist;
    struct callchain_ctx *cc;
    struct perf_evsel *leader;
    struct tp_list *tp_list;
    u64 *counters;
    u64 *ins_counters;
    analyzer analyzer;
    struct bpf_filter filter;
    struct env *env;
} ctx;

static int __analyzer(int instance, int nr_tp, u64 *counters)
{
    if (expr_load_data(ctx.prog, counters, nr_tp+1) != 0)
        return BREAK;
    return (int)expr_run(ctx.prog);
}

static int __analyzer_irq_off(int instance, int nr_tp, u64 *counters)
{
    if (nr_tp == 0 && counters[0] > ctx.env->greater_than)
        return PRINT;
    else
        return BREAK;
}

static int monitor_ctx_init(struct env *env)
{
    if (env->event) {
        tep__ref();

        ctx.tp_list = tp_list_new(env->event);
        if (!ctx.tp_list)
            return -1;

        ctx.counters = calloc(1, monitor_nr_instance() * (ctx.tp_list->nr_tp + 1) * sizeof(u64));
        if (!ctx.counters)
            return -1;

        ctx.ins_counters = malloc((ctx.tp_list->nr_tp + 1) * sizeof(u64));
        if (!ctx.ins_counters)
            return -1;

        ctx.analyzer = __analyzer;

        if (bpf_filter_init(&ctx.filter, env))
            bpf_filter_open(&ctx.filter);
    } else if (env->greater_than) {
        ctx.counters = calloc(1, monitor_nr_instance() * sizeof(u64));
        if (!ctx.counters)
            return -1;

        ctx.ins_counters = malloc(sizeof(u64));
        if (!ctx.ins_counters)
            return -1;

        ctx.analyzer = __analyzer_irq_off;

        if (bpf_filter_init(&ctx.filter, env))
            bpf_filter_open(&ctx.filter);
    }

    if (env->callchain) {
        ctx.cc = callchain_ctx_new(callchain_flags(CALLCHAIN_KERNEL), stdout);
    }

    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    if (ctx.env->callchain) {
        callchain_ctx_free(ctx.cc);
    }

    if (ctx.counters)
        free(ctx.counters);
    if (ctx.ins_counters)
        free(ctx.ins_counters);

    if (ctx.env->event) {
        bpf_filter_close(&ctx.filter);
        tp_list_free(ctx.tp_list);
        tep__unref();
    } else if (ctx.env->greater_than) {
        bpf_filter_close(&ctx.filter);
    }
}

static int hrtimer_argc_init(int argc, char *argv[])
{
    if (argc >= 1)
        ctx.expression = strdup(argv[0]);
    else
        ctx.expression = NULL;
    return 0;
}

static int hrtimer_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_CPU_CLOCK,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = env->sample_period ?   : env->freq, //ns
        .freq          = env->sample_period ? 0 : 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_READ |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = PERF_FORMAT_ID | PERF_FORMAT_GROUP,
        .pinned        = 0,
        .disabled      = 1,
        .exclude_user  = env->exclude_user,
        .exclude_kernel = env->exclude_kernel,
        .exclude_guest = env->exclude_guest,
        .exclude_host = env->exclude_host,
        .exclude_callchain_user = exclude_callchain_user(CALLCHAIN_KERNEL),
        .exclude_callchain_kernel = exclude_callchain_kernel(CALLCHAIN_KERNEL),
        .watermark     = 1,
    };
    struct perf_event_attr tp_attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 0,
        .freq          = 0,
        .sample_type   = 0,
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 0,
        .disabled      = 0,
    };
    struct perf_evsel *evsel;
    int i;

    if (!monitor_instance_oncpu())
        return -1;
    if (env->sample_period == 0 && env->freq == 0)
        return -1;
    if (env->event && !ctx.expression) {
        fprintf(stderr, " {expression} needs to be specified.\n");
        return -1;
    }
    if (monitor_ctx_init(env) < 0)
        return -1;

    if (!env->event && !env->greater_than) {
        // perf-prof hrtimer -C 0-1 -F 100
        // no events, no sampling, only hrtimer
        current_base_profiler()->pages = 0;
        current_base_profiler()->sample = NULL;
    }

    if (env->callchain) {
        current_base_profiler()->pages *= 2;
    }
    attr.wakeup_watermark = (current_base_profiler()->pages << 12) / 2;

    reduce_wakeup_times(current_base_profiler(), &attr);

    ctx.leader = evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    if (env->event) {
        struct global_var_declare *declare = NULL;

        declare = calloc(ctx.tp_list->nr_tp+2, sizeof(*declare));
        if (!declare)
            return -1;

        for (i = 0; i < ctx.tp_list->nr_tp; i++) {
            struct tp *tp = &ctx.tp_list->tp[i];

            tp_attr.config = tp->id;
            evsel = perf_evsel__new(&tp_attr);
            if (!evsel) {
                return -1;
            }
            perf_evlist__add(evlist, evsel);

            tp->evsel = evsel;

            declare[i].name = tp->alias ? : tp->name;
            declare[i].offset = i * sizeof(u64);
            declare[i].size = declare[i].elementsize = sizeof(u64);
        }
        declare[i].name = (char *)"period";
        declare[i].offset = i * sizeof(u64);
        declare[i].size = declare[i].elementsize = sizeof(u64);

        ctx.prog = expr_compile(ctx.expression, declare);
        if (!ctx.prog)
            return -1;
        free(declare);

        if(env->verbose)
            expr_dump(ctx.prog);
    }
    perf_evlist__set_leader(evlist);

    ctx.evlist = evlist;
    return 0;
}

static int hrtimer_filter(struct perf_evlist *evlist, struct env *env)
{
    int i, err;

    if (ctx.env->event) {
        for (i = 0; i < ctx.tp_list->nr_tp; i++) {
            struct tp *tp = &ctx.tp_list->tp[i];
            if (tp->filter && tp->filter[0]) {
                err = perf_evsel__apply_filter(tp->evsel, tp->filter);
                if (err < 0)
                    return err;
            }
        }
        if (ctx.filter.bpf_fd >= 0) {
            err = perf_evsel__set_bpf(ctx.leader, ctx.filter.bpf_fd);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static void hrtimer_exit(struct perf_evlist *evlist)
{
    if (ctx.expression)
        free(ctx.expression);
    if (ctx.prog)
        expr_destroy(ctx.prog);
    monitor_ctx_exit();
}

static void hrtimer_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_READ | PERF_SAMPLE_CALLCHAIN
    struct sample_type_data {
        struct {
            u32    pid;
            u32    tid;
        }    tid_entry;
        u64  time;
        struct {
            u32    cpu;
            u32    reserved;
        }    cpu_entry;
        struct {
            u64 nr;
            struct {
                u64 value;
                u64 id;
            } ctnr[0];
        } groups;
    } *data = (void *)event->sample.array;
    struct callchain *callchain;
    int n = ctx.env->event ? ctx.tp_list->nr_tp : 0;
    u64 *jcounter = ctx.counters + instance * (n + 1);
    u64 counter, cpu_clock = 0;
    u64 i, j, print = BREAK;
    int verbose = ctx.env->verbose;
    int header_end = 0;

    if (verbose) {
        print_time(stdout);
        printf(" %6d/%-6d [%03d]  %lu.%06lu: cpu-clock:", data->tid_entry.pid, data->tid_entry.tid,
                data->cpu_entry.cpu, data->time/1000000000UL, (data->time%1000000000UL)/1000UL);
    }

    for (i = 0; i < data->groups.nr; i++) {
        struct perf_evsel *evsel;
        evsel = perf_evlist__id_to_evsel(ctx.evlist, data->groups.ctnr[i].id, NULL);
        if (!evsel)
            continue;
        if (evsel == ctx.leader) {
            cpu_clock = data->groups.ctnr[i].value - jcounter[n];
            jcounter[n] = data->groups.ctnr[i].value;
            ctx.ins_counters[n] = cpu_clock;
            if (verbose) {
                if (!header_end) {
                    printf(" %lu ns\n", cpu_clock);
                    header_end = 1;
                } else
                    printf("  cpu-clock: %lu ns\n", cpu_clock);
            }
            continue;
        }
        for (j = 0; j < n; j++) {
            struct tp *tp = &ctx.tp_list->tp[j];
            if (tp->evsel == evsel) {
                counter = data->groups.ctnr[i].value - jcounter[j];
                jcounter[j] = data->groups.ctnr[i].value;
                ctx.ins_counters[j] = counter;
                if (verbose) {
                    if (!header_end) {
                        printf("\n");
                        header_end = 1;
                    }
                    printf("  %s:%s %lu\n", tp->sys, tp->name, counter);
                }
                break;
            }
        }
    }

    print = ctx.analyzer(instance, n, ctx.ins_counters);

    if (print == PRINT || verbose) {
        if (!verbose) {
            print_time(stdout);
            printf(" %6d/%-6d [%03d]  %lu.%06lu: cpu-clock: %lu ns\n", data->tid_entry.pid, data->tid_entry.tid,
                data->cpu_entry.cpu, data->time/1000000000UL, (data->time%1000000000UL)/1000UL, cpu_clock);
        }
        if (ctx.env->callchain) {
            callchain = (struct callchain *)&data->groups.ctnr[data->groups.nr];
            print_callchain_common(ctx.cc, callchain, data->tid_entry.pid);
        }
    }
}

static void hrtimer_help(struct help_ctx *hctx)
{
    int i, j;
    struct env *env = hctx->env;

    printf(PROGRAME " %s ", hrtimer.name);
    printf("-e \"");
    for (i = 0; i < hctx->nr_list; i++) {
        for (j = 0; j < hctx->tp_list[i]->nr_tp; j++) {
            struct tp *tp = &hctx->tp_list[i]->tp[j];
            printf("%s:%s/%s/", tp->sys, tp->name, tp->filter&&tp->filter[0]?tp->filter:".");
            if (i != hctx->nr_list - 1 ||
                j != hctx->tp_list[i]->nr_tp - 1)
                printf(",");
        }
    }
    printf("\" ");

    if (env->sample_period)
        printf("--period %lu ", env->sample_period);
    if (env->freq)
        printf("-F %d ", env->freq);
    if (env->callchain)
        printf("-g ");
    common_help(hctx, true, true, false, false, true, true, false);

    if (!env->sample_period)
        printf("[--period ns] ");
    if (!env->freq)
        printf("[-F freq] ");
    if (!env->callchain)
        printf("[-g] ");
    common_help(hctx, false, true, false, false, true, true, false);
    printf("\n");
}


static const char *hrtimer_desc[] = PROFILER_DESC("hrtimer",
    "[OPTION...] [-e EVENT[...]] [-F freq] [--period ns] [-g] {expression}",
    "High-resolution conditional timing sampling.",
    "",
    "SYNOPSIS",
    "    High-resolution timer sampling. During the sampling interval, it is up to",
    "    whether the events occurs or not to print samples. Whether the event occurs",
    "    or not is determined by {expression}. The expression uses the event name as",
    "    a variable, which represents the number of occurrences within the specified",
    "    period. If the expression is true, the sample is printed, otherwise it is",
    "    not printed.",
    "",
    "EXAMPLES",
    "    "PROGRAME" hrtimer -e sched:sched_switch -C 0 --period 50ms 'sched_switch==0'",
    "    "PROGRAME" hrtimer -e sched:sched_switch,sched:sched_wakeup -C 0-5 -F 20 -g \\",
    "        'sched_switch==0 && sched_wakeup==0'");
static const char *hrtimer_argv[] = PROFILER_ARGV("hrtimer",
    "OPTION:",
    "cpus", "output", "mmap-pages", "exit-N",
    "version", "verbose", "quiet", "help",
    PROFILER_ARGV_FILTER,
    PROFILER_ARGV_PROFILER, "event", "freq", "period", "call-graph");
static profiler hrtimer = {
    .name = "hrtimer",
    .desc = hrtimer_desc,
    .argv = hrtimer_argv,
    .pages = 2,
    .help = hrtimer_help,
    .argc_init = hrtimer_argc_init,
    .init = hrtimer_init,
    .filter = hrtimer_filter,
    .deinit = hrtimer_exit,
    .sample = hrtimer_sample,
};
PROFILER_REGISTER(hrtimer);


static int irq_off_read(struct perf_evsel *ev, struct perf_counts_values *count, int instance)
{
    int n = ctx.env->event ? ctx.tp_list->nr_tp : 0;
    u64 *jcounter = ctx.counters + instance * (n + 1);
    u64 counter, cpu_clock = 0;
    struct {
        u64 nr;
        struct {
            u64 value;
            u64 id;
        } ctnr[0];
    } *groups = (void *)count;
    int i, j, print = BREAK;
    int verbose = ctx.env->verbose;

    for (i = 0; i < groups->nr; i++) {
        struct perf_evsel *evsel;
        evsel = perf_evlist__id_to_evsel(ctx.evlist, groups->ctnr[i].id, NULL);
        if (!evsel)
            continue;
        if (evsel == ctx.leader) {
            cpu_clock = groups->ctnr[i].value - jcounter[n];
            ctx.ins_counters[n] = cpu_clock;
            continue;
        }
        for (j = 0; j < n; j++) {
            struct tp *tp = &ctx.tp_list->tp[j];
            if (tp->evsel == evsel) {
                counter = groups->ctnr[i].value - jcounter[j];
                ctx.ins_counters[j] = counter;
                break;
            }
        }
    }

    print = ctx.analyzer(instance, n, ctx.ins_counters);

    if (print == PRINT || verbose) {
        print_time(stdout);
        printf(" %13s [%03d]  cpu-clock: %lu ns\n", "read", monitor_instance_cpu(instance), cpu_clock);
    }
    return 0;
}

static const char *irq_off_desc[] = PROFILER_DESC("irq-off",
    "[OPTION...] [-F freq] [--period ns] [--than ns] [-g]",
    "Detect the hrtimer latency to determine if the irq is off.",
    "",
    "SYNOPSIS",
    "    Hrtimer latency detection, --period specifies the hrtimer period, if the period",
    "    exceeds the time specified by --than, it will be printed.",
    "",
    "    Based on hrtimer. See '"PROGRAME" hrtimer -h' for more information.",
    "",
    "EXAMPLES",
    "    "PROGRAME" irq-off --period 10ms --than 20ms -g",
    "    "PROGRAME" irq-off -C 0 --period 10ms --than 20ms -g -i 200");
static const char *irq_off_argv[] = PROFILER_ARGV("irq-off",
    "OPTION:",
    "cpus", "interval", "output", "mmap-pages", "exit-N",
    "version", "verbose", "quiet", "help",
    PROFILER_ARGV_FILTER,
    PROFILER_ARGV_PROFILER, "freq", "period", "than", "call-graph");
struct monitor irq_off = {
    .name = "irq-off",
    .desc = irq_off_desc,
    .argv = irq_off_argv,
    .pages = 2,
    .init = hrtimer_init,
    .filter = hrtimer_filter,
    .deinit = hrtimer_exit,
    .read = irq_off_read,
    .sample = hrtimer_sample,
};
MONITOR_REGISTER(irq_off);

