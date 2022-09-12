#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <monitor.h>

// comm ~ "xyz*" || comm ~ "abc?"
static int comm_filter(struct tp_filter *tp_filter, const char *s, const char *comm_field)
{
    const char *op;
    int ret;

    if (!s || strlen(s) == 0)
        return 0;

    if (strchr(s, '*') || strchr(s, '?') || strchr(s, '['))
        op = "~";
    else
        op = "==";

    if (tp_filter->comm == NULL)
        ret = asprintf(&tp_filter->comm, "%s %s \"%s\"", comm_field, op, s);
    else {
        char *tmp;
        ret = asprintf(&tmp, "%s || %s %s \"%s\"", tp_filter->comm, comm_field, op, s);
        if (ret >= 0) {
            free(tp_filter->comm);
            tp_filter->comm = tmp;
        }
    }
    return ret;
}

// pid==x || pid==y || pid==z
static int pid_filter(struct tp_filter *tp_filter, int pid, const char *pid_field)
{
    int ret;

    if (tp_filter->pid == NULL)
        ret = asprintf(&tp_filter->pid, "%s==%d", pid_field, pid);
    else {
        char *tmp;
        ret = asprintf(&tmp, "%s || %s==%d", tp_filter->pid, pid_field, pid);
        if (ret >= 0) {
            free(tp_filter->pid);
            tp_filter->pid = tmp;
        }
    }
    return ret;
}


/*
 * https://docs.kernel.org/trace/events.html
 * 5. Event filtering
 *
 * The operators available for numeric fields are:
 * ==, !=, <, <=, >, >=, &
 *
 * And for string fields they are:
 * ==, !=, ~
 *
**/
struct tp_filter *tp_filter_new(struct perf_thread_map *threads, const char *pid_field,
                                     const char *filter, const char *comm_field)
{
    struct tp_filter *tp_filter = NULL;

    tp_filter = malloc(sizeof(*tp_filter));
    if (!tp_filter)
        return NULL;

    memset(tp_filter, 0, sizeof(*tp_filter));

    if (filter) {
        char *sep;
        char *f = strdup(filter);
        char *s = f;

        while ((sep = strchr(s, ',')) != NULL) {
            *sep = '\0';
            comm_filter(tp_filter, s, comm_field);
            s = sep + 1;
        }
        comm_filter(tp_filter, s, comm_field);

        free(f);

        tp_filter->filter = tp_filter->comm;
    } else if (threads) {
        int pid;
        int idx;

        perf_thread_map__for_each_thread(pid, idx, threads) {
            if (pid >= 0)
                pid_filter(tp_filter, pid, pid_field);
        }
        tp_filter->filter = tp_filter->pid;
    }

    if (tp_filter->comm || tp_filter->pid)
        return tp_filter;
    else {
        free(tp_filter);
        return NULL;
    }
}

void tp_filter_free(struct tp_filter *tp_filter)
{
    if (tp_filter) {
        if (tp_filter->comm)
            free(tp_filter->comm);
        if (tp_filter->pid)
            free(tp_filter->pid);
    }
}

