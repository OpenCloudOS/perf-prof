#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <api/fs/fs.h>
#include <monitor.h>

static void monitor_help(struct monitor *m, struct help_ctx *ctx)
{
    if (m && m->help)
        m->help(ctx);
}

static void monitors_help(struct help_ctx *ctx)
{
    struct monitor *m = NULL;
    while((m = monitor_next(m))) {
        monitor_help(m, ctx);
    }
}

static void print_events_format(struct help_ctx *ctx)
{
    int i, j;
    char path[256];
    char *format;
    size_t size;

    for (i = 0; i < ctx->nr_list; i++) {
        for (j = 0; j < ctx->tp_list[i]->nr_tp; j++) {
            struct tp *tp = &ctx->tp_list[i]->tp[j];
            printf("%s:%s\n", tp->sys, tp->name);
            snprintf(path, sizeof(path), "kernel/debug/tracing/events/%s/%s/format", tp->sys, tp->name);
            if (sysfs__read_str(path, &format, &size) == 0) {
                printf("%s", format);
                free(format);
            }
            printf("\n");
        }
    }
}

static int help_init(struct perf_evlist *evlist, struct env *env)
{
    struct help_ctx _ctx;
    struct help_ctx *ctx = &_ctx;
    int i;

    if (!env->nr_events)
        exit(0);

    tep__ref();

    ctx->env = env;
    ctx->nr_list = env->nr_events;
    ctx->tp_list = calloc(ctx->nr_list, sizeof(*ctx->tp_list));
    if (!ctx->tp_list)
        exit(-1);

    for (i = 0; i < ctx->nr_list; i++) {
        ctx->tp_list[i] = tp_list_new(env->events[i]);
        if (!ctx->tp_list[i]) {
            exit(-1);
        }
    }

    printf("\n");
    if (env->help_monitor)
        monitor_help(env->help_monitor, ctx);
    else
        monitors_help(ctx);

    printf("\n");
    print_events_format(ctx);

    exit(0);
}

static void help_exit(struct perf_evlist *evlist)
{

}

static profiler help = {
    .name = "help",
    .init = help_init,
    .deinit = help_exit,
};
PROFILER_REGISTER(help)


