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

// pid==x || pid==y || (pid>=z0&&pid<=z1)
static int pid_filter(struct tp_filter *tp_filter, int pid_start, int pid_end, const char *pid_field)
{
    int ret = 0;

    if (pid_start < 0 || pid_end < 0)
        return -1;

    if (tp_filter->pid == NULL) {
        if (pid_start == pid_end)
            ret = asprintf(&tp_filter->pid, "%s==%d", pid_field, pid_start);
        else
            ret = asprintf(&tp_filter->pid, "(%s>=%d&&%s<=%d)", pid_field, pid_start, pid_field, pid_end);
    } else {
        char *tmp;
        if (pid_start == pid_end)
            ret = asprintf(&tmp, "%s || %s==%d", tp_filter->pid, pid_field, pid_start);
        else
            ret = asprintf(&tmp, "%s || (%s>=%d&&%s<=%d)", tp_filter->pid, pid_field, pid_start, pid_field, pid_end);
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
        int pid, pid_1 = -2, pid_start = -2;
        int idx;

        perf_thread_map__for_each_thread(pid, idx, threads) {
            if (pid >= 0) {
                // The pids are sorted from small to large and can be used to
                // judge whether they are numerically continuous.
                if (pid_1 + 1 != pid) {
                    pid_filter(tp_filter, pid_start, pid_1, pid_field);
                    pid_start = pid;
                }
                pid_1 = pid;
            }
        }
        pid_filter(tp_filter, pid_start, pid_1, pid_field);
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
        free(tp_filter);
    }
}

