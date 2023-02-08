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
    struct rblist top_list;
    unsigned long nr_events;

    char *EVENT; //toupper(env->event)
    int nr_fields;
    int nr_top_by;
    struct {
        char *field;
        int len;
        bool top_by;
    } *fields;
    char *key_name;// toupper(env->key)
    int  key_len;
    char *comm;
    bool show_comm; // show COMM
    bool only_comm; // only COMM

    int ws_row;
    int ws_col;
    bool tty;
    struct env *env;
} ctx;

struct top_info {
    struct rb_node rbnode;
    unsigned long key;
    char comm[TASK_COMM_LEN];
    char *pcomm;
    unsigned long counter[0];
};

static int top_info_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct top_info *t = container_of(rbn, struct top_info, rbnode);
    const struct top_info *e = entry;

    if (t->key > e->key)
        return 1;
    else if (t->key < e->key)
        return -1;
    else
        return e->pcomm ? strcmp(t->pcomm, e->pcomm) : 0;
}

static struct rb_node *top_info_node_new(struct rblist *rlist, const void *new_entry)
{
    int size = offsetof(struct top_info, counter[ctx.nr_fields]);
    const struct top_info *e = new_entry;
    struct top_info *t = malloc(size);
    if (t) {
        RB_CLEAR_NODE(&t->rbnode);
        t->key = e->key;
        if (e->pcomm) {
            int len = strlen(e->pcomm);
            if (len < TASK_COMM_LEN) {
                t->pcomm = t->comm;
                strcpy(t->pcomm, e->pcomm);
            } else {
                t->pcomm = strdup(e->pcomm);
                if (!t->pcomm) {
                    t->pcomm = t->comm;
                    strncpy(t->pcomm, e->pcomm, TASK_COMM_LEN - 1);
                    t->pcomm[TASK_COMM_LEN - 1] = '\0';
                }
            }
        } else
            t->pcomm = NULL;
        memset((void *)t + sizeof(struct top_info), 0, size - sizeof(struct top_info));
        return &t->rbnode;
    } else
        return NULL;
}
static void top_info_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct top_info *t = container_of(rb_node, struct top_info, rbnode);
    if (t->pcomm && t->pcomm != t->comm)
        free(t->pcomm);
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
    struct tep_handle *tep;
    int i, j, f = 0;
    int len;
    char *key_name = NULL;
    char *comm = NULL;

    if (!env->event)
        return -1;

    tep = tep__ref();

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
            char *field = (j == 0 && tp->alias) ? tp->alias : tp->top_add[j].field;
            ctx.fields[f].field = ctx.EVENT + (field - env->event);
            ctx.fields[f].len = strlen(field);
            ctx.fields[f].field[ctx.fields[f].len] = '\0';
            ctx.fields[f].top_by = tp->top_add[j].top_by;
            if (ctx.fields[f].len < 12)
                ctx.fields[f].len = 12;
            if (ctx.fields[f].top_by)
                ctx.nr_top_by ++;
            f ++;
        }
        if (env->key && !tp->key) {
            struct tep_event *event = tep_find_event_by_name(tep, tp->sys, tp->name);
            if (!tep_find_any_field(event, env->key)) {
                fprintf(stderr, "Cannot find %s field at %s:%s\n", env->key, tp->sys, tp->name);
                return -1;
            }
            tp->key_prog = tp_new_prog(tp, env->key);
            tp->key = env->key;
        }
        // default key=pid comm=comm
        // If key is specified, the comm field is ignored. Because the meaning of key may not be pid.
        if (!env->key && !tp->key) {
            struct tep_event *event = tep_find_event_by_name(tep, tp->sys, tp->name);
            if (tep_find_any_field(event, "pid")) {
                tp->key_prog = tp_new_prog(tp, (char *)"pid");
                tp->key = "pid";
                // The pid has been found, and then comm.
                if (!tp->comm_prog && tep_find_any_field(event, "comm")) {
                    tp->comm_prog = tp_new_prog(tp, (char *)"comm");
                    tp->comm = "comm";
                    ctx.tp_list->nr_comm += 1;
                }
            }
        }

        if (tp->key && !key_name) {
            key_name = strdup(tp->key);
        }
        if (tp->comm && !comm) {
            comm = strdup(tp->comm);
        }
    }

    /*
     * tp->key:  show_comm = !!nr_comm;
     * env->key: show_comm = !!nr_comm;
     * raw->tid: show_comm = true;
    **/
    if (key_name) {
        len = strlen(key_name);
        for (i = 0; i < len; i++)
            key_name[i] = (char)toupper(key_name[i]);
        ctx.key_name = key_name;

        // key!=PID, whether to display COMM is determined by the comm attr.
        ctx.show_comm = !!ctx.tp_list->nr_comm;
    } else {
        ctx.key_name = strdup("PID");

        // key=PID can display COMM
        ctx.show_comm = true;
    }
    ctx.key_len = strlen(ctx.key_name);
    if (ctx.key_len < 8)
        ctx.key_len = 8;

    if (comm) {
        len = strlen(comm);
        for (i = 0; i < len; i++)
            comm[i] = (char)toupper(comm[i]);
        ctx.comm = comm;
    } else
        ctx.comm = strdup("COMM");

    ctx.only_comm = env->only_comm;
    if (ctx.only_comm && !ctx.show_comm) {
        fprintf(stderr, "--only-comm need 'comm' attr\n");
        return -1;
    }

    rblist__init(&ctx.top_list);
    ctx.top_list.node_cmp = top_info_node_cmp;
    ctx.top_list.node_new = top_info_node_new;
    ctx.top_list.node_delete = top_info_node_delete;

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
    rblist__exit(&ctx.top_list);
    free(ctx.fields);
    free(ctx.EVENT);
    free(ctx.key_name);
    free(ctx.comm);
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

static void top_interval(void);
static void top_exit(struct perf_evlist *evlist)
{
    top_interval();
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
    __u64       period;
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
    int i;
    struct top_info info;
    struct rb_node *rbn;
    struct top_info *p;

    if (ctx.env->verbose >= VERBOSE_EVENT) {
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
        return;

    if (!ctx.only_comm) {
        if (tp->key_prog)
            info.key = tp_get_key(tp, data, size);
        else
            info.key = raw->tid_entry.tid;
    } else
        info.key = 0;

    if (ctx.show_comm) {
        if (tp->comm_prog)
            info.pcomm = tp_get_comm(tp, data, size);
        else {
            if (!tep_is_pid_registered(tep__ref(), raw->tid_entry.tid))
                tep__update_comm(NULL, raw->tid_entry.tid);
            info.pcomm = (void *)tep__pid_to_comm(raw->tid_entry.tid);
            tep__unref();
        }
    } else
        info.pcomm = NULL;

    rbn = rblist__findnew(&ctx.top_list, &info);
    if (!rbn)
        return;

    p = container_of(rbn, struct top_info, rbnode);
    for (i = 0; i < tp->nr_top; i++, field++) {
        if (!tp->top_add[i].event)
            p->counter[field] += (unsigned long)tp_prog_run(tp, tp->top_add[i].field_prog, data, size);
        else
            p->counter[field] += 1;
    }

    ctx.nr_events ++;
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

    if (!ctx.tty)
        print_time(stdout);
    else {
        printf("\033[H\033[2J\033[?25h\033[7m");
    }

    printed = top_print_time("perf-prof - %s  ");
    printed += printf("sample %lu events", ctx.nr_events);
    printf("%*s\n", ctx.tty && ctx.ws_col>printed ? ctx.ws_col-printed : 0, "");

    // PID FIELD FIELD ... COMM
    printed = 0;
    if (!ctx.only_comm)
        printed += printf("%*s ", ctx.key_len, ctx.key_name);
    for (i = 0; i < ctx.nr_fields; i++)
        printed += printf("%*s ", ctx.fields[i].len, ctx.fields[i].field);
    if (ctx.show_comm)
        printed += printf("%s", ctx.comm);
    printf("%*s\n", ctx.tty && ctx.ws_col>printed ? ctx.ws_col-printed : 0, "");

    if (ctx.tty) printf("\033[0m");

    //pid_list is empty still print header
    if (rblist__empty(&ctx.top_list))
        return;

    rblist__init(&sorted);
    sorted.node_cmp = top_info_sorted_node_cmp;
    sorted.node_new = top_info_sorted_node_new;
    sorted.node_delete = ctx.top_list.node_delete;
    ctx.top_list.node_delete = top_info_node_delete_empty; //empty, not really delete

    /* sort, remove from `ctx.pid_list', add to `sorted'. */
    do {
        rbn = rblist__entry(&ctx.top_list, 0);
        t = container_of(rbn, struct top_info, rbnode);
        rblist__remove_node(&ctx.top_list, rbn);
        rblist__add_node(&sorted, t);
    } while (!rblist__empty(&ctx.top_list));

    do {
        rbn = rblist__entry(&sorted, 0);

        if (!ctx.tty || !ctx.ws_row || ++row < ctx.ws_row) {
            t = container_of(rbn, struct top_info, rbnode);
            if (!ctx.only_comm) {
                if (t->key < 100000000UL)
                    printf("%*lu ", ctx.key_len, t->key);
                else
                    printf("0x%*lx ", ctx.key_len, t->key);
            }
            for (i = 0; i < ctx.nr_fields; i++)
                printf("%*lu ", ctx.fields[i].len, t->counter[i]);
            if (ctx.show_comm)
                printf("%-s", t->pcomm);
            printf("\n");
        }

        rblist__remove_node(&sorted, rbn);
    } while (!rblist__empty(&sorted));

    ctx.top_list.node_delete = sorted.node_delete;
}

static void top_help(struct help_ctx *hctx)
{
    struct env *env = hctx->env;
    int i, j, k;
    bool top_by, top_add;
    bool has_key = false;

    printf(PROGRAME " %s ", top.name);
    printf("-e \"");
    for (i = 0; i < hctx->nr_list; i++) {
        for (j = 0; j < hctx->tp_list[i]->nr_tp; j++) {
            struct tp *tp = &hctx->tp_list[i]->tp[j];
            printf("%s:%s/%s/", tp->sys, tp->name, tp->filter&&tp->filter[0]?tp->filter:".");
            top_by = false;
            top_add = false;
            if (tp->alias)
                printf("alias=%s/", tp->alias);
            if (tp->nr_top) {
                for (k = 0; k < tp->nr_top; k++)
                    if (!tp->top_add[k].event) {
                        if (tp->top_add[k].top_by) {
                            top_by = true;
                            printf("top-by=%s/", tp->top_add[k].field?:".");
                        } else {
                            top_add = true;
                            printf("top-add=%s/", tp->top_add[k].field?:".");
                        }
                    }
            }
            if (tp->key) {
                has_key = true;
                printf("key=%s/", tp->key);
            }
            if (tp->comm) {
                printf("comm=%s/", tp->comm);
            }
            if (!tp->alias || !top_by || !top_add || !tp->key || !tp->comm)
                printf("[");
            if (!tp->alias)
                printf("alias=./");
            if (!top_by)
                printf("top-by=./");
            if (!top_add)
                printf("top-add=./");
            if (!tp->key)
                printf("key=./");
            if (!tp->comm)
                printf("comm=./");
            if (!tp->alias || !top_by || !top_add || !tp->key || !tp->comm)
                printf("]");
            if (i != hctx->nr_list - 1 ||
                j != hctx->tp_list[i]->nr_tp - 1)
                printf(",");
        }
    }
    printf("\" ");

    if (env->key)
        printf("-k %s ", env->key);
    common_help(hctx, true, true, true, true, false, true, true);

    if (!env->key && !has_key)
        printf("[-k .] ");
    common_help(hctx, false, true, true, true, false, true, true);
    printf("\n");
}


static const char *top_desc[] = PROFILER_DESC("top",
    "[OPTION...] -e EVENT[...] [-i INT] [-k key] [--only-comm]",
    "Display key-value counters in top mode.", "",
    "SYNOPSIS",
    "    Get the key from the event 'key' ATTR. Default, key=pid. Get the value from",
    "    the event's 'top-by' or 'top-add' ATTR. Key is the counter and value is the",
    "    value of the counter. Therefore, from multiple events, multiple counters are",
    "    constructed with different keys. The same key, the value is accumulated.",
    "    Finally, display these counters in top mode.",
    "",
    "    If the -e parameter specifies multiple events, the key ATTR of these events",
    "    must have the same meaning.",
    "",
    "    For each event, multiple top-by and top-add ATTR can be specified.",
    "",
    "    For events whose key has the meaning of pid, you can specify the 'comm' ATTR",
    "    to display the process name.",
    "",
    "EXAMPLES",
    "    "PROGRAME" top -e kvm:kvm_exit//key=exit_reason/ -i 1000",
    "    "PROGRAME" top -e irq:irq_handler_entry//key=irq/ -C 0",
    "    "PROGRAME" top -e 'sched:sched_stat_runtime//top-by=\"runtime/1000\"/alias=run(us)/' -C 0 -i 1000",
    "    "PROGRAME" top -e sched:sched_stat_runtime//top-by=runtime/,sched:sched_switch//key=prev_pid/comm=prev_comm/ -C 0 -i 1000",
    "    "PROGRAME" top -e 'sched:sched_process_exec//comm=\"(char *)&common_type+filename_offset\"/' --only-comm",
    "    "PROGRAME" top -e 'workqueue:workqueue_execute_start//key=common_pid/alias=NUM/comm=ksymbol(function)/' --only-comm",
    "    "PROGRAME" top -e 'skb:kfree_skb//key=protocol/comm=ksymbol(location)/' -m 32",
    "",
    "NOTE",
    "    Default, key=pid, comm=comm.",
    "",
    "        -e sched:sched_stat_runtime//top-by=runtime/",
    "        -e sched:sched_stat_runtime//top-by=runtime/key=pid/comm=comm/",
    "",
    "    Are the same.");
static const char *top_argv[] = PROFILER_ARGV("top",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "event", "key", "only-comm");
static profiler top = {
    .name = "top",
    .desc = top_desc,
    .argv = top_argv,
    .pages = 4,
    .help = top_help,
    .init = top_init,
    .filter = top_filter,
    .deinit = top_exit,
    .interval = top_interval,
    .comm   = monitor_tep__comm,
    .sample = top_sample,
};
PROFILER_REGISTER(top)


