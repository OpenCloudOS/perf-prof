#define _STRUCT_TIMESPEC
#define _STRUCT_TIMEVAL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cpuid.h>

#include <monitor.h>
#include <linux/time.h>
#include <tep.h>
#include "trace_helpers.h"


struct monitor watchdog;
static void watchdog_sample(union perf_event *event, int instance);
#define STAGE_INIT 0
#define STAGE_MONITOR 1

struct watchdog_ctx {
    int watchdog_running;
    void *watchdog_hrtimer;
    unsigned long watchdog_touch_ts;
    unsigned long hrtimer_interrupts;
    unsigned long hrtimer_interrupts_saved;
    __u64 hrtimer_touch_ts;

    int print_stack;
    int print_sched;
};
static struct monitor_ctx {
    int stage;
    struct perf_evlist *evlist;
    struct perf_evsel *perf_evsel_hrtimer_expire_entry;
    struct ksyms *ksyms;
    int in_guest;
    int comm;
    int nr_cpus;
    struct watchdog_ctx *watchdog;
    int nr_watchdog;
    int watchdog_thresh;
    __u64 hrtimer_expire_entry;
    __u64 hrtimer_start;
    __u64 hrtimer_cancel;
    __u64 sched_switch;
    __u32 profile_type;
    struct env *env;
} ctx = {
    .stage = STAGE_INIT,
};

static char *path_read(const char *path)
{
    char buff[256];
    int fd, len;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;
    len = (int)read(fd, buff, sizeof(buff));
    close(fd);
    if (len <= 0)
        return NULL;
    len--;
    if (buff[len] == '\n' || len == sizeof(buff)-1)
        buff[len] = '\0';
    return strdup(buff);
}
static int monitor_ctx_init(struct env *env)
{
    char *str;

    tep__ref();
    if (env->callchain) {
        ctx.ksyms = ksyms__load();
        watchdog.pages *= 2;
    }
    ctx.in_guest = in_guest();
    ctx.comm = 1;

    ctx.nr_cpus = get_possible_cpus();
    ctx.watchdog = calloc(ctx.nr_cpus, sizeof(struct watchdog_ctx));
    if (ctx.watchdog == NULL)
        return -1;
    ctx.nr_watchdog = 0;

    if (env->cpumask == NULL)
        env->cpumask = path_read("/proc/sys/kernel/watchdog_cpumask");

    str = path_read("/proc/sys/kernel/watchdog_thresh");
    if (str) {
        ctx.watchdog_thresh = strtol(str, NULL, 10);
        free(str);
    } else
        return -1;

    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    tep__unref();
    if (ctx.env->callchain) {
        ksyms__free(ctx.ksyms);
    }
    free(ctx.watchdog);
    ctx.watchdog = NULL;
}

static struct perf_evsel *perf_tp_event(struct perf_evlist *evlist, const char *sys, const char *name)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW,
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .wakeup_events = 1, //1个事件
        .comm          = ctx.comm,
        //.use_clockid   = 1,
        //.clockid       = CLOCK_MONOTONIC,
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
    if (ctx.stage == STAGE_MONITOR)
        ctx.comm = 0;
    return evsel;
}

static int watchdog_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = ctx.in_guest ? PERF_TYPE_SOFTWARE : PERF_TYPE_HARDWARE,
        .config        = ctx.in_guest ? PERF_COUNT_SW_CPU_CLOCK : PERF_COUNT_HW_CPU_CYCLES,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = env->freq,
        .freq          = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = 1,
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;

    if (ctx.stage == STAGE_INIT && monitor_ctx_init(env) < 0)
        return -1;

    evsel = perf_tp_event(evlist, "timer", "hrtimer_expire_entry");
    if (!evsel)
        return -1;
    ctx.perf_evsel_hrtimer_expire_entry = evsel;
    ctx.hrtimer_expire_entry = perf_evsel__attr(evsel)->config;

    if (ctx.stage == STAGE_MONITOR) {

        evsel = perf_tp_event(evlist, "timer", "hrtimer_start");
        if (!evsel)
            return -1;
        ctx.hrtimer_start = perf_evsel__attr(evsel)->config;

        evsel = perf_tp_event(evlist, "timer", "hrtimer_cancel");
        if (!evsel)
            return -1;
        ctx.hrtimer_cancel = perf_evsel__attr(evsel)->config;

        evsel = perf_tp_event(evlist, "sched", "sched_switch");
        if (!evsel)
            return -1;
        ctx.sched_switch = perf_evsel__attr(evsel)->config;

        evsel = perf_evsel__new(&attr);
        if (!evsel) {
            return -1;
        }
        perf_evlist__add(evlist, evsel);
        ctx.profile_type = attr.type;

        watchdog.sample = watchdog_sample;
    }
    ctx.evlist = evlist;
    return 0;
}

static int watchdog_filter(struct perf_evlist *evlist, struct env *env)
{
    struct perf_evsel *evsel;
    char filter[64];
    int err;

    if (ctx.stage == STAGE_INIT) {
        struct ksyms *ksyms;
        const struct ksym *ksym;

        ksyms = ksyms__load();
        if (!ksyms)
            return -1;

        ksym = ksyms__get_symbol(ksyms, "watchdog_timer_fn");
        if (!ksym)
            return -1;

        snprintf(filter, sizeof(filter), "function==0x%lx", ksym->addr);
        err = perf_evsel__apply_filter(ctx.perf_evsel_hrtimer_expire_entry, filter);
        if (err < 0)
            return err;
        ksyms__free(ksyms);
    } else if (ctx.stage == STAGE_MONITOR) {
        perf_evlist__for_each_evsel(evlist, evsel) {
            if (perf_evsel__attr(evsel)->type == PERF_TYPE_TRACEPOINT) {
                __u64 config = perf_evsel__attr(evsel)->config;

                if (config == ctx.hrtimer_expire_entry ||
                    config == ctx.hrtimer_start ||
                    config == ctx.hrtimer_cancel) {
                    int cpu, idx;
                    struct perf_cpu_map *cpus = perf_evsel__cpus(evsel);
                    perf_cpu_map__for_each_cpu(cpu, idx, cpus) {
                        snprintf(filter, sizeof(filter), "hrtimer==%p", ctx.watchdog[cpu].watchdog_hrtimer);
                        perf_evsel__apply_filter_cpu(evsel, filter, idx);
                    }
                } else if (config == ctx.sched_switch) {
                    snprintf(filter, sizeof(filter), "next_comm~\"watchdog/*\"");
                    err = perf_evsel__apply_filter(evsel, filter);
                    if (err < 0)
                        return err;
                }
            }
        }
    }
    return 0;
}

static void watchdog_exit(struct perf_evlist *evlist)
{
    if (!watchdog.reinit)
        monitor_ctx_exit();
}

// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW,
struct sample_type_header {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64   time;
    __u64   stream_id;
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

static void watchdog_sample_stage_init(union perf_event *event, int instance)
{
    struct sample_type_raw *data = (void *)event->sample.array;

    if (ctx.watchdog[data->h.cpu_entry.cpu].watchdog_hrtimer == NULL) {
        struct tep_record record;
    	struct trace_seq s;
        struct tep_event *e;
        unsigned long long hrtimer;

        memset(&record, 0, sizeof(record));
        record.ts = data->h.time/1000;
        record.cpu = data->h.cpu_entry.cpu;
        record.size = data->raw.size;
        record.data = data->raw.data;

        trace_seq_init(&s);
        e = tep_find_event_by_record(tep__ref(), &record);
        tep__unref();
        if (tep_get_field_val(&s, e, "hrtimer", &record, &hrtimer, 1) < 0) {
            trace_seq_putc(&s, '\n');
            trace_seq_do_fprintf(&s, stderr);
            return;
        }
        ctx.watchdog[data->h.cpu_entry.cpu].watchdog_hrtimer = (void *)hrtimer;
        ctx.nr_watchdog ++;
        if (ctx.nr_watchdog == perf_cpu_map__nr(perf_evsel__cpus(ctx.perf_evsel_hrtimer_expire_entry))) {
            watchdog.reinit = 1;
            ctx.stage = STAGE_MONITOR;
        }
        trace_seq_destroy(&s);
    }
    tep__update_comm(NULL, data->h.tid_entry.tid);
    tep__print_event(data->h.time/1000, data->h.cpu_entry.cpu, data->raw.data, data->raw.size);
    if (watchdog.reinit == 1) {
        print_time(stdout);
        printf(" == collect all %d watchdog hrtimer\n", ctx.nr_watchdog);
    }
}

static int get_softlockup_thresh(void)
{
	return ctx.watchdog_thresh * 2;
}
static unsigned long get_timestamp(__u64 time)
{
	return time >> 30LL;  /* 2^30 ~= 10^9 */
}
static unsigned long hrtimer_sample_period(void)
{
	/*
	 * convert watchdog_thresh from seconds to ns
	 * the divide by 5 is to give hrtimer several chances (two
	 * or three with the current relation between the soft
	 * and hard thresholds) to increment before the
	 * hardlockup detector generates a warning
	 */
	return get_softlockup_thresh() * ((__u64)NSEC_PER_SEC / 5);
}
static unsigned long sample_period(void)
{
	/*
	 * convert watchdog_thresh from seconds to ns
	 * the divide by 5 is to give hrtimer several chances (two
	 * or three with the current relation between the soft
	 * and hard thresholds) to increment before the
	 * hardlockup detector generates a warning
	 */
	/*get_softlockup_thresh() * ((u64)NSEC_PER_SEC / 5);*/
	return get_softlockup_thresh() / 5;
}
static int will_hardlockup(__u32 cpu, __u64 now)
{
    unsigned long thresh;

    if (!ctx.watchdog[cpu].watchdog_running ||
        !ctx.watchdog[cpu].hrtimer_touch_ts)
        return 0;

    thresh = hrtimer_sample_period() + (NSEC_PER_SEC / 5);

    if (ctx.watchdog[cpu].hrtimer_interrupts == ctx.watchdog[cpu].hrtimer_interrupts_saved &&
        now - ctx.watchdog[cpu].hrtimer_touch_ts > thresh) {
        print_time(stdout);
        printf("WILL: hard lockup - CPU#%u [%llu - %llu > %lu]\n", cpu, now,
                    ctx.watchdog[cpu].hrtimer_touch_ts, thresh);
        return 1;
    } else if (ctx.env->verbose) {
        print_time(stdout);
        printf("DEBUG: hard lockup - CPU#%u [%llu - %llu <= %lu]\n", cpu, now,
                    ctx.watchdog[cpu].hrtimer_touch_ts, thresh);
    }
    return 0;
}
static int will_softlockup(__u32 cpu, __u64 now)
{
    if (!ctx.watchdog[cpu].watchdog_running ||
        !ctx.watchdog[cpu].watchdog_touch_ts)
        return 0;

    if (get_timestamp(now) - ctx.watchdog[cpu].watchdog_touch_ts > sample_period()) {
        print_time(stdout);
        printf("WILL: soft lockup - CPU#%u [%lu - %lu > %lu]\n", cpu, get_timestamp(now),
                    ctx.watchdog[cpu].watchdog_touch_ts, sample_period());
        return 1;
    } else if (ctx.env->verbose) {
        print_time(stdout);
        printf("DEBUG: soft lockup - CPU#%u [%lu - %lu <= %lu]\n", cpu, get_timestamp(now),
                    ctx.watchdog[cpu].watchdog_touch_ts, sample_period());
    }
    return 0;
}

static void __print_callchain(union perf_event *event)
{
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (ctx.env->callchain && ctx.ksyms) {
        __u64 i;
        for (i = 0; i < data->callchain.nr; i++) {
            __u64 ip = data->callchain.ips[i];
            const struct ksym *ksym = ksyms__map_addr(ctx.ksyms, ip);
            printf("    %016llx %s+0x%llx\n", ip, ksym ? ksym->name : "Unknown", ip - ksym->addr);
        }
    }
}

static void watchdog_sample(union perf_event *event, int instance)
{
    struct sample_type_header *data = (void *)event->sample.array;
    struct perf_evsel *evsel;
    __u32 cpu = data->cpu_entry.cpu;
    __u32 type;
    __u64 config;

    evsel = perf_evlist__id_to_evsel(ctx.evlist, data->stream_id, NULL);
    if (!evsel) {
        print_time(stderr);
        fprintf(stderr, "%16s %6u [%03d] %llu.%06llu: ID %llu TO EVSEL FAILED!\n", tep__pid_to_comm(data->tid_entry.tid), data->tid_entry.tid,
                    data->cpu_entry.cpu, data->time / NSEC_PER_SEC, (data->time % NSEC_PER_SEC)/1000, data->stream_id);
        return ;
    }

    type = perf_evsel__attr(evsel)->type;
    config = perf_evsel__attr(evsel)->config;

    if (type == ctx.profile_type) {
        if (will_hardlockup(cpu, data->time)) {
            ctx.watchdog[cpu].print_stack = 1;
        } else {
            ctx.watchdog[cpu].print_stack = 0;
        }
        ctx.watchdog[cpu].hrtimer_interrupts_saved = ctx.watchdog[cpu].hrtimer_interrupts;

        if (ctx.watchdog[cpu].print_stack ||
            ctx.watchdog[cpu].print_sched ||
            ctx.env->verbose) {
            print_time(stdout);
            printf("%16s %6u [%03d] %llu.%06llu: cpu-cycles\n", tep__pid_to_comm(data->tid_entry.tid), data->tid_entry.tid,
                    data->cpu_entry.cpu, data->time / NSEC_PER_SEC, (data->time % NSEC_PER_SEC)/1000);
            __print_callchain(event);
            fflush(stdout);
            fsync(fileno(stdout));
        }
    } else if (type == PERF_TYPE_TRACEPOINT) {
        if (config == ctx.hrtimer_expire_entry) {
            ctx.watchdog[cpu].watchdog_running = 1;
            ctx.watchdog[cpu].hrtimer_interrupts ++;
            ctx.watchdog[cpu].hrtimer_touch_ts = data->time;
            if (will_softlockup(cpu, data->time)) {
                ctx.watchdog[cpu].print_sched = 1;
            } else {
                ctx.watchdog[cpu].print_sched = 0;
            }
        } else if (config == ctx.hrtimer_start) {
            ctx.watchdog[cpu].watchdog_running = 1;
            ctx.watchdog[cpu].hrtimer_touch_ts = data->time;
        } else if (config == ctx.hrtimer_cancel) {
            ctx.watchdog[cpu].watchdog_running = 0;
        } else if (config == ctx.sched_switch) {
            ctx.watchdog[cpu].watchdog_touch_ts = get_timestamp(data->time);
        }

        if (ctx.watchdog[cpu].print_sched ||
            ctx.env->verbose) {
            struct sample_type_raw *raw = (void *)event->sample.array;;
            tep__update_comm(NULL, data->tid_entry.tid);
            tep__print_event(data->time/1000, data->cpu_entry.cpu, raw->raw.data, raw->raw.size);
            fflush(stdout);
            fsync(fileno(stdout));
        }
    }
}

static void watchdog_throttle(union perf_event *event, int instance)
{
    struct perf_evsel *evsel;
    int cpu;
    const char *str;
    __u32 type;
    __u64 time;

    if (!ctx.env->verbose)
        return;

    evsel = perf_evlist__id_to_evsel(ctx.evlist, event->throttle.stream_id, &cpu);
    if (!evsel)
        return;

    type = event->header.type;
    time = event->throttle.time;
    if (type == PERF_RECORD_THROTTLE) {
        str = "throttle";
    } else if (type == PERF_RECORD_UNTHROTTLE) {
        str = "unthrottle";
    } else
        return;

    type = perf_evsel__attr(evsel)->type;
    if (type == ctx.profile_type) {
        print_time(stdout);
        printf("==> [%03d] %llu.%06llu: %s\n", cpu, time / NSEC_PER_SEC, (time % NSEC_PER_SEC)/1000, str);
    } else if (type == PERF_TYPE_TRACEPOINT) {
        /* This won't happen */
    }
}


struct monitor watchdog = {
    .name = "watchdog",
    .pages = 2,
    .init = watchdog_init,
    .filter = watchdog_filter,
    .deinit = watchdog_exit,
    .comm   = monitor_tep__comm,
    .sample = watchdog_sample_stage_init,
    .throttle = watchdog_throttle,
    .unthrottle = watchdog_throttle,
};
MONITOR_REGISTER(watchdog)

