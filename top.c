#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <termios.h>
#include <monitor.h>
#include <dlfcn.h>
#include <tep.h>
#include <linux/rblist.h>
#include <trace_helpers.h>
#include <stack_helpers.h>

#define TASK_COMM_LEN 16

static profiler top;
struct termios save;
static struct monitor_ctx {
    struct perf_evlist *evlist;
    struct tp_list *tp_list;
    struct rblist pid_list;
    unsigned long nr_events;
    char *name;
    int name_len;
    int ws_row;
    int ws_col;
    bool tty;
    struct env *env;
} ctx;

struct top_info {
    struct rb_node rbnode;
    int pid;
    char comm[TASK_COMM_LEN];
    unsigned long long counter;
};

static int top_info_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct top_info *t = container_of(rbn, struct top_info, rbnode);
    const struct top_info *e = entry;

    if (t->pid > e->pid)
        return 1;
    else if (t->pid < e->pid)
        return -1;
    else
        return 0;
}

static struct rb_node *top_info_node_new(struct rblist *rlist, const void *new_entry)
{
    const struct top_info *e = new_entry;
    struct top_info *t = malloc(sizeof(struct top_info));
    if (t) {
        memcpy(t, e, sizeof(struct top_info));
        RB_CLEAR_NODE(&t->rbnode);
        return &t->rbnode;
    } else
        return NULL;
}
static void top_info_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct top_info *t = container_of(rb_node, struct top_info, rbnode);
    free(t);
}
static void top_info_node_delete_empty(struct rblist *rblist, struct rb_node *rb_node)
{
}
static int top_info_sorted_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct top_info *t = container_of(rbn, struct top_info, rbnode);
    const struct top_info *e = entry;

    if (t->counter > e->counter)
        return -1;
    else if (t->counter < e->counter)
        return 1;
    else
        return 0;
}
static struct rb_node *top_info_sorted_node_new(struct rblist *rlist, const void *new_entry)
{
    struct top_info *t = (void *)new_entry;
    RB_CLEAR_NODE(&t->rbnode);
    return &t->rbnode;
}
static void set_term_quiet_input(struct termios *old)
{
	struct termios tc;

	tcgetattr(0, old);
	tc = *old;
	tc.c_lflag &= ~(ICANON | ECHO);
	tc.c_cc[VMIN] = 0;
	tc.c_cc[VTIME] = 0;
	tcsetattr(0, TCSANOW, &tc);
}

static void sig_winch(int sig)
{
    struct winsize size;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0) {
        ctx.ws_row = size.ws_row;
        ctx.ws_col = size.ws_col;
    }
}

static int monitor_ctx_init(struct env *env)
{
    int i;

    if (!env->event)
        return -1;

    tep__ref();

    ctx.tp_list = tp_list_new(env->event);
    if (!ctx.tp_list)
        return -1;

    if (ctx.tp_list->nr_tp > 1) {
        fprintf(stderr, "More than one event\n");
        return -1;
    }

    ctx.name = strdup(ctx.tp_list->tp[0].top_by ?: ctx.tp_list->tp[0].name);
    ctx.name_len = strlen(ctx.name);
    for (i = 0; i < ctx.name_len; i++)
        ctx.name[i] = (char)toupper(ctx.name[i]);
    if (ctx.name_len < 12)
        ctx.name_len = 12;

    rblist__init(&ctx.pid_list);
    ctx.pid_list.node_cmp = top_info_node_cmp;
    ctx.pid_list.node_new = top_info_node_new;
    ctx.pid_list.node_delete = top_info_node_delete;

    ctx.ws_row = ctx.ws_col = 0;
    ctx.tty = false;
    if (isatty(STDOUT_FILENO)) {
        ctx.tty = true;
        sig_winch(SIGWINCH);
        signal(SIGWINCH, sig_winch);
        set_term_quiet_input(&save);
        printf("\033[?1049h\033[H\033[2J\033[?25l\n");
    }

    if (env->interval == 0)
        env->interval = 1000;

    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    if (ctx.tty) {
        tcsetattr(0, TCSANOW, &save);
        printf("\033[?1049l\033[?25h");
    }
    rblist__exit(&ctx.pid_list);
    tp_list_free(ctx.tp_list);
    tep__unref();
}

static int top_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD |
                         PERF_SAMPLE_RAW,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 1,
        .wakeup_watermark = (top.pages << 12) / 2,
    };
    struct perf_evsel *evsel;
    int i;

    if (monitor_ctx_init(env) < 0)
        return -1;

    for (i = 0; i < ctx.tp_list->nr_tp; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];

        attr.config = tp->id;

        evsel = perf_evsel__new(&attr);
        if (!evsel) {
            return -1;
        }
        perf_evlist__add(evlist, evsel);

        tp->evsel = evsel;
    }

    ctx.evlist = evlist;
    return 0;
}

static int top_filter(struct perf_evlist *evlist, struct env *env)
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

static void top_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW
struct sample_type_raw {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64   time;
    struct {
        __u32    cpu;
        __u32    reserved;
    }    cpu_entry;
    __u64		period;
    struct {
        __u32   size;
        __u8    data[0];
    } raw;
};

static void top_sample(union perf_event *event, int instance)
{
    struct sample_type_raw *raw = (void *)event->sample.array;
    void *data = raw->raw.data;
    int size = raw->raw.size;
    struct tep_record record;
    struct tep_handle *tep;
    struct trace_seq s;
    struct tep_event *e;
    char *comm;
    int len;
    struct top_info info;
    struct rb_node *rbn;
    struct top_info *p;

    tep = tep__ref();

    if (!tep_is_pid_registered(tep, raw->tid_entry.tid))
        tep__update_comm(NULL, raw->tid_entry.tid);

    if (ctx.env->verbose) {
        print_time(stdout);
        tep__print_event(raw->time/1000, raw->cpu_entry.cpu, data, size);
    }

    trace_seq_init(&s);

    memset(&record, 0, sizeof(record));
    record.ts = raw->time/1000;
    record.cpu = raw->cpu_entry.cpu;
    record.size = size;
    record.data = data;

    e = tep_find_event_by_record(tep, &record);
    if (tep_get_field_val(&s, e, "pid", &record, (unsigned long long *)&info.pid, 0) < 0) {
        info.pid = raw->tid_entry.tid;
    }
    if (!ctx.tp_list->tp[0].top_by ||
        tep_get_field_val(&s, e, ctx.tp_list->tp[0].top_by, &record, &info.counter, 0) < 0) {
        info.counter = 1;
    }

    rbn = rblist__find(&ctx.pid_list, &info);
    if (rbn == NULL) {
        comm = tep_get_field_raw(&s, e, "comm", &record, &len, 0);
        strncpy(info.comm, comm?:tep__pid_to_comm(raw->tid_entry.tid), sizeof(info.comm));
        rblist__add_node(&ctx.pid_list, &info);
    } else {
        p = container_of(rbn, struct top_info, rbnode);
        p->counter += info.counter;
    }

    ctx.nr_events ++;

    trace_seq_destroy(&s);
    tep__unref();
}

static void top_interval(void)
{
    struct rb_node *rbn;
    struct top_info *t;
    struct rblist sorted;
    int row = 3;
    int printed;

    if (rblist__empty(&ctx.pid_list))
        return;

    rblist__init(&sorted);
    sorted.node_cmp = top_info_sorted_node_cmp;
    sorted.node_new = top_info_sorted_node_new;
    sorted.node_delete = ctx.pid_list.node_delete;
    ctx.pid_list.node_delete = top_info_node_delete_empty; //empty, not really delete

    /* sort, remove from `ctx.pid_list', add to `sorted'. */
    do {
        rbn = rblist__entry(&ctx.pid_list, 0);
        t = container_of(rbn, struct top_info, rbnode);
        rblist__remove_node(&ctx.pid_list, rbn);
        rblist__add_node(&sorted, t);
    } while (!rblist__empty(&ctx.pid_list));

    if (!ctx.tty)
        print_time(stdout);
    else {
        printf("\033[H\033[2J\033[?25h\033[7m");
    }
    printed = printf("Samples: %lu of event '%s', NR %u", ctx.nr_events, ctx.tp_list->tp[0].name, rblist__nr_entries(&sorted));
    printf("%*s\n", ctx.tty?ctx.ws_col-printed:0, "");
    printed = printf("%8s %*s %-*s", "PID", ctx.name_len, ctx.name, TASK_COMM_LEN, "COMM");
    printf("%*s\n", ctx.tty?ctx.ws_col-printed:0, "");
    if (ctx.tty) printf("\033[0m");

    do {
        rbn = rblist__entry(&sorted, 0);

        if (!ctx.tty || !ctx.ws_row || ++row < ctx.ws_row) {
            t = container_of(rbn, struct top_info, rbnode);
            printf("%8d %*llu %-s\n", t->pid, ctx.name_len, t->counter, t->comm);
        }

        rblist__remove_node(&sorted, rbn);
    } while (!rblist__empty(&sorted));

    ctx.pid_list.node_delete = sorted.node_delete;
}

static profiler top = {
    .name = "top",
    .pages = 4,
    .init = top_init,
    .filter = top_filter,
    .deinit = top_exit,
    .interval = top_interval,
    .sample = top_sample,
};
PROFILER_REGISTER(top)


