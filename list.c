#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pager.h>
#include <linux/zalloc.h>
#include <api/fs/tracing_path.h>
#include <monitor.h>

#define for_each_subsystem(sys_dir, sys_dirent)         \
    while ((sys_dirent = readdir(sys_dir)) != NULL)     \
        if (sys_dirent->d_type == DT_DIR &&     \
            (strcmp(sys_dirent->d_name, ".")) &&    \
            (strcmp(sys_dirent->d_name, "..")))

static int tp_event_has_id(const char *dir_path, struct dirent *evt_dir)
{
    char evt_path[MAXPATHLEN];
    int fd;

    snprintf(evt_path, MAXPATHLEN, "%s/%s/id", dir_path, evt_dir->d_name);
    fd = open(evt_path, O_RDONLY);
    if (fd < 0)
        return -EINVAL;
    close(fd);

    return 0;
}

#define for_each_event(dir_path, evt_dir, evt_dirent)       \
    while ((evt_dirent = readdir(evt_dir)) != NULL)     \
        if (evt_dirent->d_type == DT_DIR &&     \
            (strcmp(evt_dirent->d_name, ".")) &&    \
            (strcmp(evt_dirent->d_name, "..")) &&   \
            (!tp_event_has_id(dir_path, evt_dirent)))


static int cmp_string(const void *a, const void *b)
{
    const char * const *as = a;
    const char * const *bs = b;

    return strcmp(*as, *bs);
}

/*
 * Print the events from <debugfs_mount_point>/tracing/events
 */

void print_tracepoint_events(tracepoint_cb cb, void *opaque)
{
    DIR *sys_dir, *evt_dir;
    struct dirent *sys_dirent, *evt_dirent;
    char evt_path[MAXPATHLEN];
    char *dir_path;
    char **evt_list = NULL;
    unsigned int evt_i = 0, evt_num = 0;
    bool evt_num_known = false;

restart:
    sys_dir = tracing_events__opendir();
    if (!sys_dir)
        return;

    if (evt_num_known) {
        evt_list = zalloc(sizeof(char *) * evt_num);
        if (!evt_list)
            goto out_close_sys_dir;
    }

    for_each_subsystem(sys_dir, sys_dirent) {
        dir_path = get_events_file(sys_dirent->d_name);
        if (!dir_path)
            continue;
        evt_dir = opendir(dir_path);
        if (!evt_dir)
            goto next;

        for_each_event(dir_path, evt_dir, evt_dirent) {
            if (!evt_num_known) {
                evt_num++;
                continue;
            }

            snprintf(evt_path, MAXPATHLEN, "%s:%s",
                    sys_dirent->d_name, evt_dirent->d_name);

            evt_list[evt_i] = strdup(evt_path);
            if (evt_list[evt_i] == NULL) {
                put_events_file(dir_path);
                goto out_close_evt_dir;
            }
            evt_i++;
        }
        closedir(evt_dir);
next:
        put_events_file(dir_path);
    }
    closedir(sys_dir);

    if (!evt_num_known) {
        evt_num_known = true;
        goto restart;
    }
    qsort(evt_list, evt_num, sizeof(char *), cmp_string);

    if (cb)
        cb(evt_list, evt_num, opaque);
    else {
        evt_i = 0;
        while (evt_i < evt_num) {
            printf("%s\n", evt_list[evt_i]);
            evt_i++;
        }
    }

out_free:
    for (evt_i = 0; evt_i < evt_num; evt_i++)
        zfree(&evt_list[evt_i]);
    zfree(&evt_list);
    return;

out_close_evt_dir:
    closedir(evt_dir);
out_close_sys_dir:
    closedir(sys_dir);

    evt_num = evt_i;
    if (evt_list)
        goto out_free;
}

static void event_match(char **evt_list, int evt_num, void *opaque)
{
    int i;
    char *e = opaque;

    for (i = 0; i < evt_num; i++)
        if (strstr(evt_list[i], e))
            printf("%s\n", evt_list[i]);
}

static int list_argc_init(int argc, char *argv[])
{
    setup_pager();
    if (argc == 0)
        print_tracepoint_events(NULL, NULL);
    else
        print_tracepoint_events(event_match, argv[0]);
    exit(0);
}

static const char *list_desc[] = PROFILER_DESC("list",
    "[OPTION...] event",
    "List all tracepoint events.",
    "",
    "SYNOPSIS",
    "    Print the events from <debugfs_mount_point>/tracing/events",
    "",
    "EXAMPLES",
    "    "PROGRAME" list");
static const char *list_argv[] = PROFILER_ARGV("list",
    "OPTION:",
    "version", "verbose", "quiet", "help"
);
static profiler list = {
    .name = "list",
    .desc = list_desc,
    .argv = list_argv,
    .pages = 0,
    .argc_init = list_argc_init,
};
PROFILER_REGISTER(list);

