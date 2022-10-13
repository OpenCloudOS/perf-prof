#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/rblist.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <termios.h>
#include <monitor.h>
#include <count_helpers.h>

static profiler hrcount;
static profiler stat;

static struct monitor_ctx {
    struct perf_evlist *evlist;
    struct perf_evsel *leader;
    struct tp_list *tp_list;
    int nr_ins;
    u64 *counters;
    u64 *perins_pos;
    struct count_dist *count_dist;
    int hist_size;
    u64 period;
    bool packed_display;

    u64 rounds;
    int slots;
    int round_nr;

    bool need_reset;

    int all_counters_max_len;
    int *pertp_counter_max_len;

    int ws_row;
    int ws_col;
    bool tty;
    struct env *env;
} ctx;

static void sig_winch(int sig)
{
    struct winsize size;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0) {
        ctx.ws_row = size.ws_row;
        ctx.ws_col = size.ws_col;
    }

    ctx.packed_display = ctx.hist_size <= 5;

    if (ctx.tty && ctx.packed_display) {
        int i, len = 0;
        for (i = 0; i < ctx.tp_list->nr_tp; i++) {
            struct tp *tp = &ctx.tp_list->tp[i];
            len += strlen(tp->alias ?: tp->name) + 1;
        }
        if (len-1 > ctx.ws_col)
            ctx.packed_display = false;
    }
}

static int monitor_ctx_init(struct env *env)
{
    if (!env->event)
        return -1;

    if (!env->interval)
        env->interval = 1000;
    if (!env->sample_period)
        env->sample_period = env->interval * 1000000UL;

    tep__ref();

    ctx.tp_list = tp_list_new(env->event);
    if (!ctx.tp_list)
        return -1;

    ctx.nr_ins = monitor_nr_instance();
    ctx.counters = calloc(ctx.nr_ins, (ctx.tp_list->nr_tp + 1) * sizeof(u64));
    if (!ctx.counters)
        return -1;

    ctx.perins_pos = calloc(ctx.nr_ins, sizeof(u64));
    if (!ctx.perins_pos)
        return -1;

    ctx.rounds = 0;
    ctx.slots = 2;
    ctx.round_nr = 0;

    ctx.hist_size = env->interval * 1000000UL / env->sample_period;
    ctx.count_dist = count_dist_new(env->perins, true, false, ctx.hist_size * ctx.slots);
    if (!ctx.count_dist)
        return -1;

    ctx.period = env->sample_period;
    ctx.packed_display = ctx.hist_size <= 5;

    ctx.ws_row = ctx.ws_col = 0;
    ctx.tty = false;
    if (isatty(STDOUT_FILENO)) {
        ctx.tty = true;
        sig_winch(SIGWINCH);
        signal(SIGWINCH, sig_winch);
    }

    ctx.all_counters_max_len = 2;
    ctx.pertp_counter_max_len = calloc(ctx.tp_list->nr_tp, sizeof(int));
    if (!ctx.pertp_counter_max_len)
        return -1;
    else {
        int i;
        for (i = 0; i < ctx.tp_list->nr_tp; i++) {
            struct tp *tp = &ctx.tp_list->tp[i];
            ctx.pertp_counter_max_len[i] = strlen(tp->alias ?: tp->name);
        }
    }

    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    count_dist_free(ctx.count_dist);
    if (ctx.counters)
        free(ctx.counters);
    if (ctx.perins_pos)
        free(ctx.perins_pos);
    if (ctx.pertp_counter_max_len)
        free(ctx.pertp_counter_max_len);
    tp_list_free(ctx.tp_list);
    tep__unref();
}

static int hrcount_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_CPU_CLOCK,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 0, //ns
        .freq          = 0,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_READ,
        .read_format   = PERF_FORMAT_ID | PERF_FORMAT_GROUP,
        .pinned        = 0,
        .disabled      = 1,
        .watermark     = 0,
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

    if (monitor_ctx_init(env) < 0)
        return -1;

    attr.sample_period = ctx.period;
    attr.wakeup_events = ctx.hist_size; // Wake up every N events
    ctx.leader = evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);

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

static int hrcount_filter(struct perf_evlist *evlist, struct env *env)
{
    int i, err;

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

static void hrcount_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

static void hrcount_reset(void)
{
    print_time(stdout);
    printf("hrcount reset\n");
    perf_evsel__disable(ctx.leader);
    perf_evsel__enable(ctx.leader);
    count_dist_reset(ctx.count_dist);
    memset(ctx.perins_pos, 0, ctx.nr_ins * sizeof(u64));
    ctx.rounds = 0;
    ctx.round_nr = 0;
}

static void direct_print(void *opaque, struct count_node *node)
{
    int i, h;
    char buf[64];
    static u32 max_len = 0;
    struct tp *tp = &ctx.tp_list->tp[node->id];
    int len;

    if (tp->alias)
        len = snprintf(buf, sizeof(buf), "%s", tp->alias);
    else
        len = snprintf(buf, sizeof(buf), "%s:%s", tp->sys, tp->name);

    if (len > max_len)
        max_len = len;
    if (ctx.env->perins)
        printf("[%03d] ", monitor_instance_cpu(node->ins));
    printf("%*s ", max_len, buf);

    h = (ctx.rounds % ctx.slots) * ctx.hist_size;
    printf("%*lu", ctx.all_counters_max_len, node->hist[h++]);
    for (i = 1; i < ctx.hist_size; i++) {
        printf("|%*lu", ctx.all_counters_max_len, node->hist[h++]);
    }
    h = (ctx.rounds % ctx.slots) * ctx.hist_size;
    memset(&node->hist[h], 0, sizeof(u64) * ctx.hist_size);
    printf("\n");
}

static void packed_print(void *opaque, struct count_node *node)
{
    int i, h, len = 0;
    u64 max = node->max;
    struct {
        u64 ins;
        u64 id;
        int line_len;
    } *iter = opaque;

    node->max = 0;
    len = 1;
    while (max >= 10) {
        max /= 10;
        len ++;
    }
    if (ctx.pertp_counter_max_len[node->id] < ctx.hist_size * (len+1) - 1)
        ctx.pertp_counter_max_len[node->id] = ctx.hist_size * (len+1) - 1;

    if (ctx.env->perins && iter->ins != node->ins) {
        iter->ins = node->ins;
        iter->id = 0;
        iter->line_len = printf("[%03d] ", monitor_instance_cpu(node->ins));
    }

    while (iter->id != node->id) {
        iter->line_len += printf("%-*s", ctx.pertp_counter_max_len[iter->id], "ERROR");
        iter->id ++;
    }

    h = (ctx.rounds % ctx.slots) * ctx.hist_size;
    len = printf("%lu", node->hist[h++]);
    for (i = 1; i < ctx.hist_size; i++) {
        len += printf("|%lu", node->hist[h++]);
    }
    h = (ctx.rounds % ctx.slots) * ctx.hist_size;
    memset(&node->hist[h], 0, sizeof(u64) * ctx.hist_size);
    iter->line_len += len;

    if (iter->id + 1 != ctx.tp_list->nr_tp) {
        iter->line_len += printf("%*s ", ctx.pertp_counter_max_len[node->id] - len, "");
        iter->id ++;
    } else {
        if (ctx.tty && iter->line_len > ctx.ws_col)
            ctx.packed_display = false;
        printf("\n");
    }
}

static void __hrcount_interval(void)
{
    int len, i;
    u64 max;
    u64 print_pos = (ctx.rounds + 1) * ctx.hist_size;
    u64 max_pos = 0;

    // Determine if all instances are complete
    for (i = 0; i < ctx.nr_ins; i++) {
        if (ctx.perins_pos[i] < print_pos)
            return ;
        if (ctx.perins_pos[i] > max_pos)
            max_pos = ctx.perins_pos[i];
    }
    if (ctx.nr_ins >= 2 && ctx.hist_size >= 2 &&
        max_pos - print_pos >= ctx.hist_size/2)
        ctx.need_reset = true;

    len = 1;
    max = count_dist_max(ctx.count_dist);
    while (max >= 10) {
        max /= 10;
        len ++;
    }
    if (len > ctx.all_counters_max_len)
        ctx.all_counters_max_len = len;

    print_time(stdout);
    printf("\n");

    if (ctx.packed_display) {
        struct {
            u64 ins;
            u64 id;
            int line_len;
        } iter;
        if (ctx.env->perins)
            printf("[CPU] ");
        for (i = 0; i < ctx.tp_list->nr_tp; i++) {
            struct tp *tp = &ctx.tp_list->tp[i];
            if (i + 1 != ctx.tp_list->nr_tp)
                printf("%-*s ", ctx.pertp_counter_max_len[i], tp->alias ?: tp->name);
            else
                printf("%s\n", tp->alias ?: tp->name);
        }
        iter.ins = ~0UL;
        iter.id = 0;
        iter.line_len = 0;
        count_dist_print(ctx.count_dist, packed_print, &iter);
    } else
        count_dist_print(ctx.count_dist, direct_print, NULL);

    ctx.rounds ++;
}

static void hrcount_interval(void)
{
    __hrcount_interval();
    if (ctx.need_reset) {
        ctx.need_reset = false;
        hrcount_reset();
    }
}

static void hrcount_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_READ
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
    int n = ctx.tp_list->nr_tp;
    u64 *ins_counter = ctx.counters + instance * (n + 1);
    u64 counter, cpu_clock = 0;
    u64 i, j;
    int verbose = ctx.env->verbose;
    u64 print_pos = (ctx.rounds + 1) * ctx.hist_size;

    for (i = 0; i < data->groups.nr; i++) {
        struct perf_evsel *evsel;
        evsel = perf_evlist__id_to_evsel(ctx.evlist, data->groups.ctnr[i].id, NULL);
        if (!evsel)
            continue;
        if (evsel == ctx.leader) {
            cpu_clock = data->groups.ctnr[i].value - ins_counter[n];
            ins_counter[n] = data->groups.ctnr[i].value;
            if (cpu_clock >= ctx.period * 2) {
                ctx.perins_pos[instance] += cpu_clock / ctx.period - 1;
                verbose = 1;
            }
            continue;
        }
        for (j = 0; j < n; j++) {
            struct tp *tp = &ctx.tp_list->tp[j];
            if (tp->evsel == evsel) {
                counter = data->groups.ctnr[i].value - ins_counter[j];
                ins_counter[j] = data->groups.ctnr[i].value;
                count_dist_insert(ctx.count_dist, instance, j, 0, ctx.perins_pos[instance], counter);
                break;
            }
        }
    }

    ctx.perins_pos[instance] ++;

    if (verbose) {
        print_time(stdout);
        printf(" %6d/%-6d [%03d]  %lu.%06lu: cpu-clock: %lu ns\n", data->tid_entry.pid, data->tid_entry.tid,
                data->cpu_entry.cpu, data->time/1000000000UL, (data->time%1000000000UL)/1000UL, cpu_clock);
    }

    /* KERNEL BUG: maybe stuck
     *
     * perf_swevent_hrtimer ->
     *   __perf_event_overflow(throttle=1) ->
     *     __perf_event_account_interrupt ->
     *       perf_log_throttle
     *
     * After the perf event is throttled, it needs to wait for a tick to resume.
     * However, tick may be closed by nohz. It takes a long time to be unthrottled.
    **/
    if (ctx.perins_pos[instance] >= print_pos) {
        ctx.round_nr ++;
        if (ctx.round_nr >= ctx.nr_ins) {
            ctx.round_nr = 0;
            __hrcount_interval();
        }
    }
}

static void __common_help(struct help_ctx *hctx, const char *name)
{
    int i, j;
    struct env *env = hctx->env;

    printf(PROGRAME " %s ", name);
    printf("-e \"");
    for (i = 0; i < hctx->nr_list; i++) {
        for (j = 0; j < hctx->tp_list[i]->nr_tp; j++) {
            struct tp *tp = &hctx->tp_list[i]->tp[j];
            printf("%s:%s/%s/", tp->sys, tp->name, tp->filter&&tp->filter[0]?tp->filter:".");
            if (tp->alias)
                printf("alias=%s/", tp->alias);
            if (!tp->alias)
                printf("[");
            if (!tp->alias)
                printf("alias=./");
            if (!tp->alias)
                printf("]");
            if (i != hctx->nr_list - 1)
                printf(",");
        }
    }
    printf("\" ");

    if (env->sample_period)
        printf("--period %lu ", env->sample_period);
    common_help(hctx, true, true, false, true, false, true, true);

    if (!env->sample_period)
        printf("[--period ns] ");
    common_help(hctx, false, true, false, true, false, true, true);
    printf("\n");
}

static void hrcount_help(struct help_ctx *hctx)
{
    __common_help(hctx, hrcount.name);
}

static profiler hrcount = {
    .name = "hrcount",
    .pages = 2,
    .help = hrcount_help,
    .init = hrcount_init,
    .filter = hrcount_filter,
    .deinit = hrcount_exit,
    .interval = hrcount_interval,
    .sample = hrcount_sample,
};
PROFILER_REGISTER(hrcount);

static void stat_help(struct help_ctx *hctx)
{
    __common_help(hctx, stat.name);
}

static profiler stat = {
    .name = "stat",
    .pages = 2,
    .help = stat_help,
    .init = hrcount_init,
    .filter = hrcount_filter,
    .deinit = hrcount_exit,
    .interval = hrcount_interval,
    .sample = hrcount_sample,
};
PROFILER_REGISTER(stat);

