#include <stdio.h>
#include <stdlib.h>
#include "monitor.h"
#include "trace_helpers.h"
#include "stack_helpers.h"

static profiler hrtimer;
typedef int (*analyzer)(int instance, int nr_tp, u64 *counters);

static int __analyzer_eqzero(int instance, int nr_tp, u64 *counters)
{
    int i;
    for (i = 0; i < nr_tp; i++) // exclude counters[nr_tp]
        if (counters[i] != 0)
            return 0;
    return 1;
}

struct monitor_ctx {
    struct perf_evlist *evlist;
    struct callchain_ctx *cc;
    struct perf_evsel *leader;
    struct tp_list *tp_list;
    u64 *counters;
    u64 *ins_counters;
    analyzer analyzer;
    struct perf_event_filter filter;
    struct env *env;
} ctx;

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

        ctx.analyzer = __analyzer_eqzero;

        if (perf_event_filter_init(&ctx.filter, env))
            perf_event_filter_open(&ctx.filter);
    }

    if (env->callchain) {
        ctx.cc = callchain_ctx_new(CALLCHAIN_KERNEL, stdout);
    }

    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    if (ctx.env->callchain) {
        callchain_ctx_free(ctx.cc);
    }
    if (ctx.env->event) {
        perf_event_filter_close(&ctx.filter);
        if (ctx.counters)
            free(ctx.counters);
        tp_list_free(ctx.tp_list);
        tep__unref();
    }
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
        .exclude_callchain_user = 1,
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
        .disabled      = 1,
    };
    struct perf_evsel *evsel;
    int i;

    if (!monitor_instance_oncpu())
        return -1;
    if (env->sample_period == 0 && env->freq == 0)
        return -1;

    if (monitor_ctx_init(env) < 0)
        return -1;

    if (!env->event) {
        // perf-prof hrtimer -C 0-1 -F 100
        // no events, no sampling, only hrtimer
        hrtimer.pages = 0;
        hrtimer.sample = NULL;
    }

    if (env->callchain) {
        hrtimer.pages *= 2;
    }
    attr.wakeup_watermark = (hrtimer.pages << 12) / 2;

    ctx.leader = evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    if (env->event)
    for (i = 0; i < ctx.tp_list->nr_tp; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];

        tp_attr.config = tp->id;
        evsel = perf_evsel__new(&tp_attr);
        if (!evsel) {
            return -1;
        }
        perf_evlist__add(evlist, evsel);

        tp->evsel = evsel;
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
        if (ctx.filter.perf_event_prog_fd >= 0) {
            err = perf_evsel__set_bpf(ctx.leader, ctx.filter.perf_event_prog_fd);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static void hrtimer_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

static void hrtimer_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_READ | PERF_SAMPLE_CALLCHAIN
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
    int n = ctx.tp_list->nr_tp;
    u64 *jcounter = ctx.counters + instance * (n + 1);
    u64 counter, cpu_clock;
    u64 i;
    int j;
    int print = 0;
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

    if (print || verbose) {
        if (!verbose) {
            print_time(stdout);
            printf(" %6d/%-6d [%03d]  %lu.%06lu: cpu-clock: %lu ns\n", data->tid_entry.pid, data->tid_entry.tid,
                data->cpu_entry.cpu, data->time/1000000000UL, (data->time%1000000000UL)/1000UL, cpu_clock);
        }
        if (ctx.env->callchain) {
            callchain = (struct callchain *)&data->groups.ctnr[data->groups.nr];
            print_callchain_common(ctx.cc, callchain, 0/*only kernel stack*/);
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
            if (i != hctx->nr_list - 1)
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

static profiler hrtimer = {
    .name = "hrtimer",
    .pages = 2,
    .help = hrtimer_help,
    .init = hrtimer_init,
    .filter = hrtimer_filter,
    .deinit = hrtimer_exit,
    .sample = hrtimer_sample,
};
PROFILER_REGISTER(hrtimer);

