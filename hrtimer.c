#include <stdio.h>
#include <stdlib.h>
#include "monitor.h"
#include "trace_helpers.h"
#include "stack_helpers.h"

static profiler hrtimer;

struct monitor_ctx {
    struct perf_evlist *evlist;
    struct callchain_ctx *cc;
    struct perf_evsel *leader;
    struct tp_list *tp_list;
    u64 *counters;
    struct env *env;
} ctx;

static int monitor_ctx_init(struct env *env)
{
    if (env->event) {
        tep__ref();

        ctx.tp_list = tp_list_new(env->event);
        if (!ctx.tp_list)
            return -1;

        ctx.counters = calloc(1, monitor_nr_instance() * ctx.tp_list->nr_tp * sizeof(u64));
        if (!ctx.counters)
            return -1;
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
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_READ |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = PERF_FORMAT_ID | PERF_FORMAT_GROUP,
        .pinned        = 0,
        .disabled      = 1,
        .exclude_user  = env->precise ? 0 : 1,
        .exclude_idle  = env->precise ? 0 : 1,
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

    if (ctx.env->event)
    for (i = 0; i < ctx.tp_list->nr_tp; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];
        if (tp->filter && tp->filter[0]) {
            err = perf_evsel__apply_filter(tp->evsel, tp->filter);
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
    u64 *jcounter = ctx.counters + instance * ctx.tp_list->nr_tp;
    u64 counter;
    u64 i;
    int j;
    int print = 0;

    for (i = 0; i < data->groups.nr; i++) {
        struct perf_evsel *evsel;
        evsel = perf_evlist__id_to_evsel(ctx.evlist, data->groups.ctnr[i].id, NULL);
        if (!evsel)
            continue;
        if (evsel == ctx.leader) {
            continue;
        }
        for (j = 0; j < ctx.tp_list->nr_tp; j++) {
            struct tp *tp = &ctx.tp_list->tp[j];
            if (tp->evsel == evsel) {
                counter = data->groups.ctnr[i].value - jcounter[j];
                jcounter[j] = data->groups.ctnr[i].value;
                if (counter == 0)
                    print ++;
                break;
            }
        }
    }

    if (print) {
        print_time(stdout);
        printf("cpu %d pid %d tid %d\n", data->cpu_entry.cpu, data->tid_entry.pid, data->tid_entry.tid);
        if (ctx.env->callchain) {
            callchain = (struct callchain *)&data->groups.ctnr[data->groups.nr];
            print_callchain_common(ctx.cc, callchain, 0/*only kernel stack*/);
        }
    }
}

static profiler hrtimer = {
    .name = "hrtimer",
    .pages = 2,
    .init = hrtimer_init,
    .filter = hrtimer_filter,
    .deinit = hrtimer_exit,
    .sample = hrtimer_sample,
};
PROFILER_REGISTER(hrtimer);

