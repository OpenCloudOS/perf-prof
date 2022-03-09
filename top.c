#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <linux/compiler.h>
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

    char *EVENT; //toupper(env->event)
    int nr_fields;
    int nr_top_by;
    struct {
        char *field;
        int len;
        bool top_by;
    } *fields;

    int ws_row;
    int ws_col;
    bool tty;
    struct env *env;
} ctx;

struct top_info {
    struct rb_node rbnode;
    int pid;
    char comm[TASK_COMM_LEN];
    unsigned long long counter[0];
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
    int size = offsetof(struct top_info, counter[ctx.nr_fields]);
    const struct top_info *e = new_entry;
    struct top_info *t = malloc(size);
    if (t) {
        memcpy(t, e, sizeof(struct top_info));
        memset((void *)t + sizeof(struct top_info), 0, size - sizeof(struct top_info));
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
    int i;

    if (ctx.nr_top_by)
    for (i = 0; i < ctx.nr_fields; i++) {
        if (!ctx.fields[i].top_by)
            continue;
        if (t->counter[i] > e->counter[i])
            return -1;
        else if (t->counter[i] < e->counter[i])
            return 1;
    }
    for (i = 0; i < ctx.nr_fields; i++) {
        if (ctx.fields[i].top_by)
            continue;
        if (t->counter[i] > e->counter[i])
            return -1;
        else if (t->counter[i] < e->counter[i])
            return 1;
    }
    return top_info_node_cmp(rbn, entry);
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
    int i, j, f = 0;
    int len;

    if (!env->event)
        return -1;

    tep__ref();

    ctx.EVENT = strdup(env->event);
    len = strlen(ctx.EVENT);
    for (i = 0; i < len; i++)
        ctx.EVENT[i] = (char)toupper(ctx.EVENT[i]);

    ctx.tp_list = tp_list_new(env->event);
    if (!ctx.tp_list)
        return -1;

    ctx.nr_fields = ctx.tp_list->nr_top;
    ctx.fields = calloc(ctx.nr_fields, sizeof(*ctx.fields));
    if (!ctx.fields)
        return -1;
    for (i = 0; i < ctx.tp_list->nr_tp; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];
        for (j = 0; j < tp->nr_top; j++) {
            ctx.fields[f].field = ctx.EVENT + (tp->top_add[j].field - env->event);
            ctx.fields[f].len = strlen(tp->top_add[j].field);
            ctx.fields[f].field[ctx.fields[f].len] = '\0';
            ctx.fields[f].top_by = tp->top_add[j].top_by;
            if (ctx.fields[f].len < 12)
                ctx.fields[f].len = 12;
            if (ctx.fields[f].top_by)
                ctx.nr_top_by ++;
            f ++;
        }
    }

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
        printf("\033[?1049h\033[?25l\033[H\033[2J\n");
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
        printf("\033[?25h\n\033[?1049l");
    }
    rblist__exit(&ctx.pid_list);
    free(ctx.fields);
    free(ctx.EVENT);
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
        .comm          = 1,
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

        attr.comm = 0;
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
        union {
            __u8    data[0];
            unsigned short common_type;
        } __packed;
    } raw;
};

static void top_sample(union perf_event *event, int instance)
{
    struct sample_type_raw *raw = (void *)event->sample.array;
    unsigned short common_type = raw->raw.common_type;
    void *data = raw->raw.data;
    int size = raw->raw.size;
    struct tp *tp = NULL;
    int field = 0;
    struct tep_record record;
    struct tep_handle *tep;
    struct trace_seq s;
    struct tep_event *e;
    char *comm;
    int len, i;
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

    for (i = 0; i < ctx.tp_list->nr_tp; i++) {
        struct tp *tmp = &ctx.tp_list->tp[i];
        if (common_type == tmp->id) {
            tp = tmp;
            break;
        } else
            field += tmp->nr_top;
    }

    if (tp == NULL)
        goto unref;

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

    rbn = rblist__find(&ctx.pid_list, &info);
    if (rbn == NULL) {
        comm = tep_get_field_raw(&s, e, "comm", &record, &len, 0);
        strncpy(info.comm, comm?:tep__pid_to_comm(raw->tid_entry.tid), sizeof(info.comm));
        rbn = rblist__findnew(&ctx.pid_list, &info);
        if (rbn == NULL)
            goto destroy;
    }

    p = container_of(rbn, struct top_info, rbnode);

    for (i = 0; i < tp->nr_top; i++, field++) {
        unsigned long long counter;
        if (!tp->top_add[i].event &&
            tep_get_field_val(&s, e, tp->top_add[i].field, &record, &counter, 0) == 0) {
            p->counter[field] += counter;
        } else
            p->counter[field] += 1;
    }

    ctx.nr_events ++;

destroy:
    trace_seq_destroy(&s);
unref:
    tep__unref();
}

static inline int top_print_time(const char *fmt)
{
    char timebuff[64];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    strftime(timebuff, sizeof(timebuff), "%H:%M:%S", localtime(&tv.tv_sec));
    return printf(fmt, timebuff);
}

static void top_interval(void)
{
    struct rb_node *rbn;
    struct top_info *t;
    struct rblist sorted;
    int row = 3;
    int printed;
    int i;

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

    printed = top_print_time("perf-prof - %s  ");
    printed += printf("sample %lu events", ctx.nr_events);
    printf("%*s\n", ctx.tty && ctx.ws_col>printed ? ctx.ws_col-printed : 0, "");

    // PID FIELD FIELD ... COMM
    printed = printf("%8s ", "PID");
    for (i = 0; i < ctx.nr_fields; i++)
        printed += printf("%*s ", ctx.fields[i].len, ctx.fields[i].field);
    printed += printf("%-*s", TASK_COMM_LEN, "COMM");
    printf("%*s\n", ctx.tty && ctx.ws_col>printed ? ctx.ws_col-printed : 0, "");

    if (ctx.tty) printf("\033[0m");

    do {
        rbn = rblist__entry(&sorted, 0);

        if (!ctx.tty || !ctx.ws_row || ++row < ctx.ws_row) {
            t = container_of(rbn, struct top_info, rbnode);
            printf("%8d ", t->pid);
            for (i = 0; i < ctx.nr_fields; i++)
                printf("%*llu ", ctx.fields[i].len, t->counter[i]);
            printf("%-s\n", *(u64*)t->comm == 0x3e2e2e2e3c /*<...>*/ ? tep__pid_to_comm(t->pid) : t->comm);
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
    .comm   = monitor_tep__comm,
    .sample = top_sample,
};
PROFILER_REGISTER(top)


