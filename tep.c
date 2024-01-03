#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/time64.h>
#include <api/fs/fs.h>
#include <monitor.h>
#include <tep.h>
#include <stack_helpers.h>

#define PLUGINS_DIR "/usr/lib64/perf-prof-traceevent/plugins"

static struct tep_handle *tep = NULL;
static struct tep_plugin_list *plugins = NULL;
static int global_comm = 0;

void pr_stat(const char *fmt, ...)
{
    /* Disable libtraceevent printing.
     *
     * registering plugin:
     * overriding event
     * removing override handler for event
     */
}

struct tep_handle *tep__ref(void)
{
    if (tep != NULL) {
        tep_ref(tep);
        return tep;
    }
    tep = tep_alloc();
    tep_add_plugin_path(tep, (char *)PLUGINS_DIR, TEP_PLUGIN_FIRST);
    plugins = tep_load_plugins(tep);
    function_resolver_ref();
    tep_set_function_resolver(tep, function_resolver, NULL);
    if (global_comm_ref() == 0)
        global_comm = 1;
    return tep;
}

void tep__unref(void)
{
    if (tep == NULL)
        return;

    if (tep_get_ref(tep) == 1) {
        if (global_comm) {
            global_comm_unref();
            global_comm = 0;
        }
        tep_reset_function_resolver(tep);
        function_resolver_unref();
        tep_unload_plugins(plugins, tep);
        tep_free(tep);
        tep = NULL;
    } else
        tep_unref(tep);
}

int tep__event_id(const char *sys, const char *name)
{
    char format[256];
    struct stat st;
    struct tep_event *event;
    int id = -1;
    int i;
    struct mountpoint {
        const char *path;
        const char *subdir;
    } mountpoints[] = {
        {debugfs__mountpoint(), "/tracing"},
        {tracefs__mountpoint(), ""},
    };

    tep__ref();
    event = tep_find_event_by_name(tep, sys, name);
    if (event) {
        id = event->id;
        goto unref;
    }

    for (i = 0; i < sizeof(mountpoints)/sizeof(mountpoints[0]); i++) {
        snprintf(format, sizeof(format), "%s%s/events/%s/%s/format", mountpoints[i].path,
                                          mountpoints[i].subdir, sys, name);
        if (stat(format, &st) == 0) {
            FILE *fp;
            size_t size = 65536;
            char *buff = malloc(size);

            fp = fopen(format, "r");
            size = fread(buff, 1, size, fp);
            fclose(fp);

            tep_parse_format(tep, &event, buff, size, sys);

            free(buff);

            id = event->id;
            break;
        }
    }

unref:
    tep__unref();
    return id;
}

void tep__update_comm(const char *comm, int pid)
{
    char buff[16];

    if (global_comm)
        return;

    if (comm == NULL) {
        char path[64];
        int fd, len;

        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        fd = open(path, O_RDONLY);
        if (fd < 0)
            return;
        len = (int)read(fd, buff, sizeof(buff));
        close(fd);
        if (len <= 0)
            return;
        len--;
        if (buff[len] == '\n' || len == sizeof(buff)-1)
            buff[len] = '\0';
        comm = buff;
    }
    tep__ref();
    tep_override_comm(tep, comm, pid);
    tep__unref();
}

const char *tep__pid_to_comm(int pid)
{
    const char *comm;

    if (global_comm) {
        comm = global_comm_get(pid);
        return comm ? comm : "<...>";
    }

    tep__ref();
    comm = tep_data_comm_from_pid(tep, pid);
    tep__unref();
    return comm;
}

void tep__print_event(unsigned long long ts, int cpu, void *data, int size)
{
    struct tep_record record;
    struct trace_seq s;
    struct tep_event *e;

    memset(&record, 0, sizeof(record));
    record.ts = ts;
    record.cpu = cpu;
    record.size = size;
    record.data = data;

    tep__ref();
    e = tep_find_event_by_record(tep, &record);

    trace_seq_init(&s);
    if (global_comm) {
        int pid = tep_data_pid(tep, &record);
        char *comm = global_comm_get(pid);
        trace_seq_printf(&s, "%16s %6u ", comm ? : "<...>", pid);
        tep_print_event(tep, &s, &record, "%s", TEP_PRINT_LATENCY);
        trace_seq_printf(&s, " [%03d] %llu.%06llu: %s:%s: ", cpu, ts/USEC_PER_SEC, ts%USEC_PER_SEC,
                         e->system, e->name);
    } else {
        tep_print_event(tep, &s, &record, "%16s %6u %s [%03d] %6d: ", TEP_PRINT_COMM, TEP_PRINT_PID,
                    TEP_PRINT_LATENCY, TEP_PRINT_CPU, TEP_PRINT_TIME);
        trace_seq_printf(&s, "%s:%s: ", e->system, e->name);
    }
    tep_print_event(tep, &s, &record, "%s\n", TEP_PRINT_INFO);
    tep__unref();
    trace_seq_do_fprintf(&s, stdout);
    trace_seq_destroy(&s);
}

bool tep__event_has_field(int id, const char *field)
{
    bool has_field = false;
    struct tep_event *event;

    tep__ref();
    event = tep_find_event(tep, id);
    if (event) {
        has_field = !!tep_find_any_field(event, field);
    }
    tep__unref();

    return has_field;
}

bool tep__event_field_size(int id, const char *field)
{
    struct tep_event *event;
    struct tep_format_field *format;
    int size = -1;

    tep__ref();
    event = tep_find_event(tep, id);
    if (event) {
        format = tep_find_any_field(event, field);
        if (format)
            size = format->size;
    }
    tep__unref();

    return size;
}

int tep__event_size(int id)
{
    struct tep_event *event;
    struct tep_format_field **fields;
    int size = -1;

    tep__ref();
    event = tep_find_event(tep, id);
    if (event) {
        fields = tep_event_fields(event);
        if (fields) {
            int i = 0;
            while (fields[i]) {
                if (fields[i]->offset + fields[i]->size > size)
                    size = fields[i]->offset + fields[i]->size;
                i++;
            }
            free(fields);
        }
    }
    tep__unref();
    return size;
}

event_fields *tep__event_fields(int id)
{
    struct tep_event *event;
    struct tep_format_field **common_fields;
    struct tep_format_field **fields;
    int nr_common = 0, nr_fields = 0, nr_dynamic = 0;
    int extra_len = 0;
    event_fields *ef = NULL;
    char *extra = NULL;
    int i = 0, f = 0;

    tep__ref();
    event = tep_find_event(tep, id);
    if (!event)
        goto _return;

    common_fields = tep_event_common_fields(event);
    fields = tep_event_fields(event);
    if (!common_fields || !fields)
        goto _return;

    while (common_fields[nr_common]) nr_common++;
    while (fields[nr_fields]) {
        if (fields[nr_fields]->flags & TEP_FIELD_IS_DYNAMIC) {
            nr_dynamic++;
            extra_len += 2*strlen(fields[nr_fields]->name) + sizeof("_offset") + sizeof("_len");
        }
        nr_fields++;
    }

    ef = calloc(1, (nr_common + nr_fields + nr_dynamic + 1) * sizeof(*ef) + extra_len);
    if (!ef)
        goto _free;
    extra = (char *)ef + (nr_common + nr_fields + nr_dynamic + 1) * sizeof(*ef);

    f = 0;
    while (common_fields[f]) {
        ef[i].name = common_fields[f]->name;
        ef[i].offset = common_fields[f]->offset;
        ef[i].size = common_fields[f]->size;
        ef[i].elementsize = common_fields[f]->elementsize;
        i++;
        f++;
    }
    f = 0;
    while (fields[f]) {
        if (fields[f]->flags & TEP_FIELD_IS_DYNAMIC) {
            ef[i].name = extra;
            extra += sprintf((char *)ef[i].name, "%s_offset", fields[f]->name)+1;
            ef[i].offset = fields[f]->offset;
            ef[i].size = 2;
            ef[i].elementsize = 2;
            i++;

            ef[i].name = extra;
            extra += sprintf((char *)ef[i].name, "%s_len", fields[f]->name)+1;
            ef[i].offset = fields[f]->offset + 2;
            ef[i].size = 2;
            ef[i].elementsize = 2;
        } else {
            ef[i].name = fields[f]->name;
            ef[i].offset = fields[f]->offset;
            ef[i].size = fields[f]->size;
            ef[i].elementsize = fields[f]->elementsize;
        }
        i++;
        f++;
    }
    ef[i].name = NULL;

_free:
    if (common_fields) free(common_fields);
    if (fields) free(fields);
_return:
    tep__unref();
    return ef;
}

static char *next_sep(char *s, int c)
{
    while (*s) {
        if (*s == (char)c)
            return (char *)s;
        if (*s == '\'' || *s == '"') {
            int quote = *s++;
            while (*s && *s++ != quote);
        } else
            s++;
    }
    return NULL;
}

struct tp_list *tp_list_new(struct prof_dev *dev, char *event_str)
{
    char *s = event_str;
    char *sep;
    int i;
    int nr_tp = 0;
    struct tp_list *tp_list = NULL;

    if (!s)
        return NULL;

    while ((sep = next_sep(s, ',')) != NULL) {
        nr_tp ++;
        s = sep + 1;
    }
    if (*s)
        nr_tp ++;

    if (nr_tp == 0)
        return NULL;

    tp_list = calloc(1, sizeof(struct tp_list) + nr_tp * sizeof(struct tp));
    if (!tp_list)
        return NULL;

    tp_list->nr_tp = nr_tp;
    s = event_str;
    i = 0;
    while ((sep = next_sep(s, ',')) != NULL) {
        tp_list->tp[i++].name = s;
        *sep = '\0';
        s = sep + 1;
    }
    if (*s)
        tp_list->tp[i++].name = s;

    tep__ref();
    /*
     * Event syntax:
     *    EVENT,EVENT,...
     * EVENT:
     *    sys:name[/filter/ATTR/ATTR/.../]
     *    profiler[/option/ATTR/ATTR/.../]
     * ATTR:
     *    stack : sample_type PERF_SAMPLE_CALLCHAIN
     *    max-stack=int : sample_max_stack
     *    top-by=field : top add and sort by this field
     *    top-add=field: top add this field
     *    ...
    **/
    for (i = 0; i < nr_tp; i++) {
        struct tp *tp = &tp_list->tp[i];
        struct tep_event *event = NULL;
        char *slash = NULL;
        char *sys = NULL;
        char *name = NULL;
        char *filter = NULL;
        int stack = 0;
        int max_stack = 0;
        bool top_by;
        char *alias = NULL;
        int id = -1;
        event_fields *fields = NULL;
        struct expr_prog *prog = NULL;
        profiler *prof = NULL;
        struct env *env = NULL;

        s = tp->name;
        slash = next_sep(s, '/');
        if (slash) {
            *slash = '\0';
            filter = slash + 1;
            slash = next_sep(filter, '/');
            if (!slash)
                goto err_out;
            *slash = '\0';
        }

        sys = s = tp->name;
        sep = strchr(s, ':');
        if (!sep) { // profiler/option/
            prof = monitor_find(sys);
            if (!prof) {
                fprintf(stderr, "profiler %s not found\n", sys);
                goto err_out;
            }
            if (filter && filter[0])
                filter[-1] = ' ';

            // Remove single and double quotes around filter
            if (filter && (filter[0] == '\'' || filter[0] == '"')) {
                int len = strlen(filter);
                if (filter[len-1] == filter[0]) {
                    filter[len-1] = ' ';
                    filter[0] = ' ';
                }
            }

            env = parse_string_options(s);
            // --tsc remains the same.
            env->tsc = dev->env->tsc;
            env->tsc_offset = dev->env->tsc_offset;
            // Using (dev->cpus, dev->threads).
            // Make sure instance is consistent between source_dev and dev.
            tp->source_dev = prof_dev_open_cpu_thread_map(prof, env, dev->cpus, dev->threads);
            name = sys;
            sys = NULL;
        } else { // sys:name/filter/
            *sep = '\0';

            name = sep + 1;
            id = tep__event_id(sys, name);
            if (id < 0) {
                fprintf(stderr, "%s:%s not found\n", sys, name);
                goto err_out;
            }
            event = tep_find_event_by_name(tep, sys, name);
            if (!event)
                goto err_out;
        }
        // ATTR
        if (slash) {
            *slash = '\0';
            s = slash + 1;
            while ((sep = next_sep(s, '/')) != NULL) {
                char *attr = s;
                char *value = NULL;
                *sep = '\0';
                s = sep + 1;
                if ((sep = next_sep(attr, '=')) != NULL) {
                    *sep = '\0';
                    value = sep + 1;
                }
                // Remove single and double quotes around value
                if (value && (value[0] == '\'' || value[0] == '"')) {
                    int len = strlen(value);
                    if (value[len-1] == value[0]) {
                        value[len-1] = '\0';
                        value ++;
                    }
                }
                top_by = false;
                prog = NULL;
                if (strcmp(attr, "stack") == 0)
                    stack = 1;
                else if (strcmp(attr, "max-stack") == 0) {
                    stack = 1;
                    max_stack = value ? atoi(value) : 0;
                    if (max_stack > PERF_MAX_STACK_DEPTH)
                        max_stack = PERF_MAX_STACK_DEPTH;
                } else if (strcmp(attr, "top-by") == 0 ||
                           strcmp(attr, "top_by") == 0) {
                    top_by = true;
                    goto top_add;
                } else if (strcmp(attr, "top-add") == 0 ||
                           strcmp(attr, "top_add") == 0) {
                    top_add:
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->nr_top ++;
                    tp->top_add = realloc(tp->top_add, tp->nr_top * sizeof(*tp->top_add));
                    tp->top_add[tp->nr_top-1].field_prog = prog;
                    tp->top_add[tp->nr_top-1].field = value;
                    tp->top_add[tp->nr_top-1].event = false;
                    tp->top_add[tp->nr_top-1].top_by = top_by;
                } else if (strcmp(attr, "comm") == 0) {
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->comm_prog = prog;
                    tp->comm = value;
                } else if (strcmp(attr, "alias") == 0) {
                    alias = value;
                } else if (strcmp(attr, "ptr") == 0) {
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->mem_ptr_prog = prog;
                    tp->mem_ptr = value;
                } else if (strcmp(attr, "size") == 0) {
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->mem_size_prog = prog;
                    tp->mem_size = value;
                } else if (strcmp(attr, "num") == 0) {
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->num_prog = prog;
                    tp->num = value;
                } else if (strcmp(attr, "key") == 0) {
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->key_prog = prog;
                    tp->key = value;
                } else if (strcmp(attr, "untraced") == 0) {
                    tp->untraced = true;
                } else if (strcmp(attr, "trigger") == 0) {
                    tp->trigger = true;
                } else if (strcmp(attr, "push") == 0) {
                    if (id >= 0 && tp_broadcast_new(tp, value) < 0) goto err_out;
                } else if (strcmp(attr, "pull") == 0) {
                    if (id >= 0 && tp_receive_new(tp, value) < 0) goto err_out;
                } else if (strcmp(attr, "vm") == 0) {
                    tp->vcpu = vcpu_info_new(value);
                    if (tp->vcpu)
                        tp->vm = value;
                } else  if (strcmp(attr, "exec") == 0){
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->exec_prog = prog;
                    tp->exec = value;
                }
            }
        }

        tp->dev = dev;
        tp->id = id;
        tp->sys = sys;
        tp->name = name;
        tp->filter = (filter && filter[0]) ? strdup(filter) : NULL;
        tp->stack = stack;
        tp->max_stack = max_stack;
        tp->alias = alias;
        tp->kernel = !tp->receive;
        if (tp->nr_top == 0) {
            tp->nr_top = 1;
            tp->top_add = realloc(tp->top_add, tp->nr_top * sizeof(*tp->top_add));
            tp->top_add[0].field_prog = NULL;
            tp->top_add[0].field = alias ? : name;
            tp->top_add[0].event = true;
            tp->top_add[0].top_by = false;
        }

        if (!tp->mem_ptr && event && tep_find_any_field(event, "ptr")) {
            if (!fields) fields = tep__event_fields(id);
            if (fields)  prog = expr_compile((char *)"ptr", fields);
            if (!prog) { free(fields); goto err_out; }

            tp->mem_ptr_prog = prog;
            tp->mem_ptr = "ptr";
        }
        if (!tp->mem_size && event && tep_find_any_field(event, "bytes_alloc")) {
            if (!fields) fields = tep__event_fields(id);
            if (fields)  prog = expr_compile((char *)"bytes_alloc", fields);
            if (!prog) { free(fields); goto err_out; }

            tp->mem_size_prog = prog;
            tp->mem_size = "bytes_alloc";
        }

        tp_list->nr_real_tp += id >= 0;
        tp_list->nr_need_stack += stack;
        tp_list->nr_top += tp->nr_top;
        tp_list->nr_comm += !!tp->comm_prog;
        tp_list->nr_mem_size += !!tp->mem_size_prog;
        tp_list->nr_num_prog += !!tp->num_prog;
        tp_list->nr_untraced += !!tp->untraced;
        tp_list->nr_push_to += !!tp->broadcast;
        tp_list->nr_pull_from += !!tp->receive;
        tp_list->nr_exec_prog += !!tp->exec_prog;

        if (fields)
            free(fields);
    }

    tp_list->need_stream_id = (tp_list->nr_need_stack && tp_list->nr_need_stack != tp_list->nr_real_tp);

    tep__unref();
    return tp_list;

err_out:
    tep__unref();
    tp_list_free(tp_list);
    return NULL;
}

void tp_list_free(struct tp_list *tp_list)
{
    int i, j;
    if (!tp_list)
        return ;
    for (i = 0; i < tp_list->nr_tp; i++) {
        struct tp *tp = &tp_list->tp[i];
        if (tp_is_dev(tp) && tp->source_dev)
            prof_dev_close(tp->source_dev);
        if (tp->filter)
            free(tp->filter);
        for (j = 0; j < tp->nr_top; j++) {
            if (tp->top_add[j].field_prog)
                expr_destroy(tp->top_add[j].field_prog);
        }
        if (tp->top_add)
            free(tp->top_add);
        if (tp->comm_prog)
            expr_destroy(tp->comm_prog);
        if (tp->mem_ptr_prog)
            expr_destroy(tp->mem_ptr_prog);
        if (tp->mem_size_prog)
            expr_destroy(tp->mem_size_prog);
        if (tp->num_prog)
            expr_destroy(tp->num_prog);
        if (tp->key_prog)
            expr_destroy(tp->key_prog);
        tp_broadcast_free(tp);
        tp_receive_free(tp);
        if (tp->vcpu)
            vcpu_info_free(tp->vcpu);
        if (tp->exec_prog)
            expr_destroy(tp->exec_prog);
    }
    free(tp_list);
}

void tp_update_filter(struct tp *tp, const char *filter)
{
    if (tp->filter)
        free(tp->filter);
    tp->filter = strdup(filter);
}

void tp_print_marker(struct tp *tp)
{
    printf("%c ", (!tp || tp_kernel(tp)) ? ' ' : 'G');
}

struct expr_prog *tp_new_prog(struct tp *tp, char *expr_str)
{
    event_fields *fields = tep__event_fields(tp->id);
    struct expr_prog *prog = NULL;
    if (fields) {
        prog = expr_compile(expr_str, fields);
        free(fields);
    }
    return prog;
}

long tp_prog_run(struct tp *tp, struct expr_prog *prog, void *data, int size)
{
    if (expr_load_data(prog, data, size) != 0) {
        expr_dump(prog);
        fprintf(stderr, "tp %s:%s prog load data failed!\n", tp->sys, tp->name);
        return -1;
    }
    return expr_run(prog);
}

char *tp_get_comm(struct tp *tp, void *data, int size)
{
    long comm = tp_prog_run(tp, tp->comm_prog, data, size);
    return comm == -1 ? (char *)"Error" : (char *)(unsigned long)comm;
}

unsigned long tp_get_key(struct tp *tp, void *data, int size)
{
    long key = tp_prog_run(tp, tp->key_prog, data, size);
    return key == -1 ? 0 : (unsigned long)key;
}

unsigned long tp_get_num(struct tp *tp, void *data, int size)
{
    long num = tp_prog_run(tp, tp->num_prog, data, size);
    return num == -1 ? 0 : (unsigned long)num;
}

void *tp_get_mem_ptr(struct tp *tp, void *data, int size)
{
    long mem_ptr = tp_prog_run(tp, tp->mem_ptr_prog, data, size);
    return mem_ptr == -1 ? NULL : (void *)mem_ptr;
}

unsigned long tp_get_mem_size(struct tp *tp, void *data, int size)
{
    long mem_size = tp_prog_run(tp, tp->mem_size_prog, data, size);
    return mem_size == -1 ? 1 : (unsigned long)mem_size;
}

