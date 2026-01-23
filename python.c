// SPDX-License-Identifier: GPL-2.0
/*
 * python - Python scripting profiler for perf-prof
 *
 * Convert perf events to Python objects and process them with Python scripts.
 *
 * Usage: perf-prof python -e EVENT script.py
 */

/* Python.h must be included first */
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <monitor.h>
#include <dlfcn.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>
#include <event-parse-local.h>

/* Global script path, set by argc_init before init */
static char *script_path = NULL;

/*
 * Sample type for Python profiler (no callchain support in initial version)
 * PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID | PERF_SAMPLE_CPU |
 * PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW
 *
 * Same layout as struct sql_sample_type in sqlite/ext.h
 */
struct python_sample_type {
    struct {
        u32    pid;
        u32    tid;
    }    tid_entry;
    u64   time;
    u64   id;
    struct {
        u32    cpu;
        u32    reserved;
    }    cpu_entry;
    u64   period;
    struct {
        u32   size;
        union {
            u8    data[0];
            struct trace_entry common;
        };
    } raw;
};

/*
 * Cached Python string objects for common dict keys.
 * Using interned strings avoids repeated string hashing in PyDict_SetItem.
 */
struct python_key_cache {
    /* Common sample fields */
    PyObject *key_pid;          /* "_pid" */
    PyObject *key_tid;          /* "_tid" */
    PyObject *key_time;         /* "_time" */
    PyObject *key_cpu;          /* "_cpu" */
    PyObject *key_period;       /* "_period" */
    PyObject *key_event;        /* "_event" */
    PyObject *key_callchain;    /* "_callchain" */
    /* Common trace_entry fields */
    PyObject *key_raw;
};

/*
 * Per-event data: handler, fields, and cached Python strings.
 */
struct python_event_data {
    PyObject *handler;              /* sys__event_name handler */
    PyObject *event_name;           /* Cached "sys:name" or "sys:alias" string */
    struct tep_format_field **fields;  /* Event fields from tep */
    PyObject **field_keys;          /* Cached PyUnicode for each field name */
    int nr_fields;
};

struct python_ctx {
    struct tp_list *tp_list;
    char *script_path;
    PyObject *module;
    PyObject *func_init;
    PyObject *func_exit;
    PyObject *func_print_stat;
    PyObject *func_interval;
    PyObject *func_lost;
    PyObject *func_sample;  /* default __sample__ handler */
    /* Cached common key strings */
    struct python_key_cache key_cache;
    /* Per-event data array */
    struct python_event_data *events;
    int nr_events;
    /* Callchain support */
    int callchain_flags;    /* CALLCHAIN_KERNEL | CALLCHAIN_USER flags */
};

static void python_exit(struct prof_dev *dev);

/*
 * Get Python function from module, returns NULL if not found (not an error)
 * Only returns user-defined functions, not built-in module attributes like __init__.
 */
static PyObject *get_python_func(PyObject *module, const char *name)
{
    PyObject *func = PyObject_GetAttrString(module, name);
    if (func) {
        /* Must be a user-defined function, not built-in or other callable */
        if (!PyFunction_Check(func)) {
            Py_DECREF(func);
            func = NULL;
        }
    }
    if (!func)
        PyErr_Clear();
    return func;
}

/*
 * Build event handler function name: sys__event_name or sys__alias
 * e.g., "sched:sched_wakeup" -> "sched__sched_wakeup"
 * e.g., "sched:sched-wakeup" -> "sched__sched_wakeup"
 * e.g., "sched:sched_wakeup" with alias="wakeup1" -> "sched__wakeup1"
 * Convert invalid characters (like '-') to '_' for valid Python function names.
 *
 * When alias is provided, use sys__alias to allow distinguishing multiple
 * instances of the same event with different aliases.
 */
static char *build_handler_name(const char *sys, const char *name, const char *alias)
{
    char *handler_name;
    const char *event_part = alias ? alias : name;
    size_t len = strlen(sys) + 2 + strlen(event_part) + 1;
    char *p;

    handler_name = malloc(len);
    if (handler_name) {
        snprintf(handler_name, len, "%s__%s", sys, event_part);
        /* Convert invalid characters to underscore */
        for (p = handler_name; *p; p++) {
            if (*p == '-' || *p == '.' || *p == ':')
                *p = '_';
        }
    }
    return handler_name;
}

/*
 * Convert raw event data to Python dict
 * Fields are extracted based on tep_format_field.
 * Uses cached PyObject keys for faster dict operations.
 *
 * @ctx: Python context
 * @tp: Tracepoint
 * @data: Sample data (header portion)
 * @tp_index: Index of the tracepoint
 * @callchain: Callchain data (NULL if no callchain)
 * @raw: Raw event data
 * @raw_size: Size of raw data
 */
static PyObject *event_to_dict(struct python_ctx *ctx, struct tp *tp,
                               struct python_sample_type *data, int tp_index,
                               struct callchain *callchain, void *raw, int raw_size)
{
    PyObject *dict, *val;
    struct python_key_cache *kc = &ctx->key_cache;
    struct python_event_data *ev;
    struct tep_format_field **fields;
    PyObject **field_keys;
    void *base;
    int i;

    dict = PyDict_New();
    if (!dict)
        return NULL;

    /* Add common sample fields using cached keys (PyDict_SetItem is faster) */
#define SET_DICT_ITEM(dict, key, value) do { \
        val = (value); \
        PyDict_SetItem(dict, key, val); \
        Py_DECREF(val); \
    } while (0)

    SET_DICT_ITEM(dict, kc->key_pid, PyLong_FromLong(data->tid_entry.pid));
    SET_DICT_ITEM(dict, kc->key_tid, PyLong_FromLong(data->tid_entry.tid));
    SET_DICT_ITEM(dict, kc->key_time, PyLong_FromUnsignedLongLong(data->time));
    SET_DICT_ITEM(dict, kc->key_cpu, PyLong_FromLong(data->cpu_entry.cpu));
    SET_DICT_ITEM(dict, kc->key_period, PyLong_FromUnsignedLongLong(data->period));

    /* Add callchain if present */
    if (callchain && ctx->callchain_flags) {
        PyObject *callchain_list = callchain_to_pylist(callchain, data->tid_entry.pid,
                                                        ctx->callchain_flags);
        if (callchain_list) {
            PyDict_SetItem(dict, kc->key_callchain, callchain_list);
            Py_DECREF(callchain_list);
        }
    }

    /* Add _raw field containing complete raw event data */
    SET_DICT_ITEM(dict, kc->key_raw, PyBytes_FromStringAndSize((char *)raw, raw_size));

#undef SET_DICT_ITEM

    /* Get cached event data */
    if (tp_index < 0 || tp_index >= ctx->nr_events)
        return dict;

    ev = &ctx->events[tp_index];
    fields = ev->fields;
    field_keys = ev->field_keys;

    if (!fields || !field_keys)
        return dict;

    base = raw;

    /* Parse event-specific fields using cached keys */
    for (i = 0; i < ev->nr_fields; i++) {
        struct tep_format_field *field = fields[i];
        PyObject *value = NULL;
        void *ptr;
        int len;

        if (field->flags & TEP_FIELD_IS_STRING) {
            /* String field */
            if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                ptr = base + *(unsigned short *)(base + field->offset);
                len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
                if (len > 0)
                    value = PyUnicode_FromStringAndSize((char *)ptr, len - 1); /* exclude null */
                else
                    value = PyUnicode_FromString("");
            } else {
                ptr = base + field->offset;
                value = PyUnicode_FromString((char *)ptr);
            }
        } else if (field->flags & TEP_FIELD_IS_ARRAY) {
            /* Array field -> bytes */
            if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                ptr = base + *(unsigned short *)(base + field->offset);
                len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
            } else {
                ptr = base + field->offset;
                len = field->size;
            }
            value = PyBytes_FromStringAndSize((char *)ptr, len);
        } else {
            /* Numeric field */
            bool is_signed = field->flags & TEP_FIELD_IS_SIGNED;
            long long val = 0;

            if (field->size == 1)
                val = is_signed ? *(char *)(base + field->offset)
                                : *(unsigned char *)(base + field->offset);
            else if (field->size == 2)
                val = is_signed ? *(short *)(base + field->offset)
                                : *(unsigned short *)(base + field->offset);
            else if (field->size == 4)
                val = is_signed ? *(int *)(base + field->offset)
                                : *(unsigned int *)(base + field->offset);
            else if (field->size == 8)
                val = is_signed ? *(long long *)(base + field->offset)
                                : *(unsigned long long *)(base + field->offset);

            if (field->size <= 8)
                value = PyLong_FromLongLong(val);
        }

        if (value) {
            PyDict_SetItem(dict, field_keys[i], value);
            Py_DECREF(value);
        }
    }

    return dict;
}

/*
 * Check if a field requires special pointer format output (e.g., %pI4, %pM).
 * These fields have TEP_FIELD_IS_STRING flag but should be treated as binary data.
 * Returns true if the field's IS_STRING flag should be cleared.
 *
 * Reference: arg_pointer_register() in sqlite/perf_tp.c
 */
static bool field_needs_binary_output(struct tep_event *event, const char *field_name)
{
    struct tep_print_parse *parse = event->print_fmt.print_cache;

    while (parse) {
        if (parse->type == PRINT_FMT_ARG_POINTER &&
            parse->arg && parse->arg->type == TEP_PRINT_FIELD) {
            if (strcmp(parse->arg->field.name, field_name) == 0) {
                const char *format = parse->format;

                /* Skip to 'p' in format string */
                while (*format) if (*format++ == 'p') break;
                switch (*format) {
                    case 'I': /* %pI4, %pi4, %pI6, %pi6, %pIS, %piS */
                    case 'i':
                    case 'U': /* %pUb, %pUB, %pUl, %pUL */
                    case 'M': /* %pM, %pMR, %pMF, %pm, %pmR */
                    case 'm':
                        return true;
                    default:
                        break;
                }
            }
        }
        parse = parse->next;
    }
    return false;
}

/*
 * Initialize common key cache with interned strings.
 * Interned strings are guaranteed unique and allow pointer comparison.
 */
static int init_key_cache(struct python_key_cache *kc)
{
#define INTERN_KEY(field, str) do { \
        kc->field = PyUnicode_InternFromString(str); \
        if (!kc->field) return -1; \
    } while (0)

    INTERN_KEY(key_pid, "_pid");
    INTERN_KEY(key_tid, "_tid");
    INTERN_KEY(key_time, "_time");
    INTERN_KEY(key_cpu, "_cpu");
    INTERN_KEY(key_period, "_period");
    INTERN_KEY(key_event, "_event");
    INTERN_KEY(key_callchain, "_callchain");
    INTERN_KEY(key_raw, "_raw");

#undef INTERN_KEY
    return 0;
}

static void free_key_cache(struct python_key_cache *kc)
{
    Py_XDECREF(kc->key_pid);
    Py_XDECREF(kc->key_tid);
    Py_XDECREF(kc->key_time);
    Py_XDECREF(kc->key_cpu);
    Py_XDECREF(kc->key_period);
    Py_XDECREF(kc->key_event);
    Py_XDECREF(kc->key_callchain);
    Py_XDECREF(kc->key_raw);
    memset(kc, 0, sizeof(*kc));
}

/*
 * Cache event fields for faster lookup during sampling.
 * After tep__ref(), tep_find_event() returns pointers that remain valid.
 *
 * Also clears TEP_FIELD_IS_STRING flag for fields that require special pointer
 * format output (e.g., %pI4, %pM), as they should be treated as binary data.
 */
static int cache_event_fields(struct python_ctx *ctx)
{
    struct tep_handle *tep;
    struct tp *tp;
    int i, j, ret = -1;

    /* Initialize common key cache */
    if (init_key_cache(&ctx->key_cache) < 0)
        return -1;

    ctx->nr_events = ctx->tp_list->nr_tp;
    ctx->events = calloc(ctx->nr_events, sizeof(struct python_event_data));

    if (!ctx->events)
        return -1;

    tep = tep__ref();

    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tep_event *event = tep_find_event(tep, tp->id);
        struct python_event_data *ev = &ctx->events[i];
        char *handler_name;
        char event_name[256];

        if (event) {
            ev->fields = tep_event_fields(event);
            if (!ev->fields)
                goto failed;

            /* Count fields and allocate key cache */
            for (j = 0; ev->fields[j]; j++) ;
            ev->nr_fields = j;

            ev->field_keys = calloc(ev->nr_fields, sizeof(PyObject *));
            if (!ev->field_keys)
                goto failed;

            /* Cache field keys and fix IS_STRING flag */
            for (j = 0; j < ev->nr_fields; j++) {
                struct tep_format_field *field = ev->fields[j];

                /* Clear IS_STRING flag for fields requiring special pointer format.
                 * These fields (e.g., IP addresses, MAC addresses, UUIDs) have IS_STRING
                 * flag but their data should be treated as binary (bytes in Python). */
                if ((field->flags & TEP_FIELD_IS_STRING) &&
                    field_needs_binary_output(event, field->name)) {
                    field->flags &= ~TEP_FIELD_IS_STRING;
                }

                /* Cache interned string for field name */
                ev->field_keys[j] = PyUnicode_InternFromString(field->name);
                if (!ev->field_keys[j])
                    goto failed;
            }
        }

        /* Cache event name string for __sample__ handler */
        snprintf(event_name, sizeof(event_name), "%s:%s", tp->sys,
                    tp->alias ? tp->alias : tp->name);
        ev->event_name = PyUnicode_InternFromString(event_name);
        if (!ev->event_name)
            goto failed;

        /* Look for event-specific handler */
        handler_name = build_handler_name(tp->sys, tp->name, tp->alias);
        if (handler_name) {
            ev->handler = get_python_func(ctx->module, handler_name);
            free(handler_name);
        }
    }
    ret = 0;

failed:
    tep__unref();
    return ret;
}

/*
 * Initialize Python interpreter and load script
 */
static int python_script_init(struct python_ctx *ctx)
{
    PyObject *sys_path, *path;
    char *script_dir, *script_name, *base, *dot;
    char *script_path_copy;

    /* Initialize Python */
    Py_Initialize();
    if (!Py_IsInitialized()) {
        fprintf(stderr, "Failed to initialize Python interpreter\n");
        return -1;
    }

    /* Add script directory to sys.path */
    script_path_copy = strdup(ctx->script_path);
    if (!script_path_copy)
        return -1;

    script_dir = dirname(script_path_copy);
    sys_path = PySys_GetObject("path");
    if (sys_path) {
        path = PyUnicode_FromString(script_dir);
        if (path) {
            PyList_Insert(sys_path, 0, path);
            Py_DECREF(path);
        }
    }

    /* Get module name (script filename without .py) */
    script_name = strdup(ctx->script_path);
    if (!script_name) {
        free(script_path_copy);
        return -1;
    }

    /* Remove directory path */
    base = strrchr(script_name, '/');
    if (base)
        base++;
    else
        base = script_name;

    /* Remove .py extension */
    dot = strrchr(base, '.');
    if (dot && strcmp(dot, ".py") == 0)
        *dot = '\0';

    /* Import the module */
    ctx->module = PyImport_ImportModule(base);
    free(script_name);
    free(script_path_copy);

    if (!ctx->module) {
        PyErr_Print();
        fprintf(stderr, "Failed to load Python script: %s\n", ctx->script_path);
        return -1;
    }

    /* Get callback functions */
    ctx->func_init = get_python_func(ctx->module, "__init__");
    ctx->func_exit = get_python_func(ctx->module, "__exit__");
    ctx->func_print_stat = get_python_func(ctx->module, "__print_stat__");
    ctx->func_interval = get_python_func(ctx->module, "__interval__");
    ctx->func_lost = get_python_func(ctx->module, "__lost__");
    ctx->func_sample = get_python_func(ctx->module, "__sample__");

    return 0;
}

static void python_script_exit(struct python_ctx *ctx)
{
    int i, j;

    if (ctx->func_init) Py_DECREF(ctx->func_init);
    if (ctx->func_exit) Py_DECREF(ctx->func_exit);
    if (ctx->func_print_stat) Py_DECREF(ctx->func_print_stat);
    if (ctx->func_interval) Py_DECREF(ctx->func_interval);
    if (ctx->func_lost) Py_DECREF(ctx->func_lost);
    if (ctx->func_sample) Py_DECREF(ctx->func_sample);

    /* Free per-event data */
    if (ctx->events) {
        for (i = 0; i < ctx->nr_events; i++) {
            struct python_event_data *ev = &ctx->events[i];

            Py_XDECREF(ev->handler);
            Py_XDECREF(ev->event_name);

            if (ev->field_keys) {
                for (j = 0; j < ev->nr_fields; j++) {
                    Py_XDECREF(ev->field_keys[j]);
                }
                free(ev->field_keys);
            }

            if (ev->fields)
                free(ev->fields);
        }
        free(ctx->events);
    }

    /* Free common key cache */
    free_key_cache(&ctx->key_cache);

    if (ctx->module) Py_DECREF(ctx->module);

    if (Py_IsInitialized())
        Py_Finalize();
}

/*
 * Call Python __init__() function
 */
static int python_call_init(struct python_ctx *ctx)
{
    PyObject *result;

    if (!ctx->func_init)
        return 0;

    result = PyObject_CallObject(ctx->func_init, NULL);
    if (!result) {
        PyErr_Print();
        return -1;
    }
    Py_DECREF(result);
    return 0;
}

/*
 * Call Python __exit__() function
 */
static void python_call_exit(struct python_ctx *ctx)
{
    PyObject *result;

    if (!ctx->func_exit)
        return;

    result = PyObject_CallObject(ctx->func_exit, NULL);
    if (!result) {
        PyErr_Print();
        return;
    }
    Py_DECREF(result);
}

/*
 * Call Python __print_stat__(indent) function
 */
static void python_call_print_stat(struct python_ctx *ctx, int indent)
{
    PyObject *result;

    if (!ctx->func_print_stat)
        return;

    result = PyObject_CallFunction(ctx->func_print_stat, "i", indent);
    if (!result) {
        PyErr_Print();
        return;
    }
    Py_DECREF(result);
}

/*
 * Call Python __interval__() function
 */
static void python_call_interval(struct python_ctx *ctx)
{
    PyObject *result;

    if (!ctx->func_interval)
        return;

    result = PyObject_CallObject(ctx->func_interval, NULL);
    if (!result) {
        PyErr_Print();
        return;
    }
    Py_DECREF(result);
}

/*
 * Call Python __lost__() function
 */
static void python_call_lost(struct python_ctx *ctx)
{
    PyObject *result;

    if (!ctx->func_lost)
        return;

    result = PyObject_CallObject(ctx->func_lost, NULL);
    if (!result) {
        PyErr_Print();
        return;
    }
    Py_DECREF(result);
}

/*
 * python_argc_init - Parse extra command line arguments (script.py)
 * Called before init() to capture the script path from remaining arguments.
 */
static int python_argc_init(int argc, char *argv[])
{
    if (script_path) {
        free(script_path);
        script_path = NULL;
    }

    if (argc >= 1) {
        script_path = strdup(argv[0]);
        if (!script_path)
            return -1;
    }
    return 0;
}

/*
 * monitor_ctx_init - Initialize the Python profiler context
 */
static int monitor_ctx_init(struct prof_dev *dev)
{
    struct env *env = dev->env;
    struct python_ctx *ctx;

    if (!env->event) {
        fprintf(stderr, "Error: -e EVENT is required\n");
        return -1;
    }

    if (!script_path) {
        fprintf(stderr, "Error: Python script path is required\n");
        fprintf(stderr, "Usage: perf-prof python -e EVENT script.py\n");
        return -1;
    }

    /* Verify script exists */
    if (access(script_path, R_OK) != 0) {
        fprintf(stderr, "Error: Cannot read script: %s\n", script_path);
        return -1;
    }

    ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;

    tep__ref();

    ctx->script_path = strdup(script_path);
    if (!ctx->script_path)
        goto failed;

    ctx->tp_list = tp_list_new(dev, env->event);
    if (!ctx->tp_list)
        goto failed;

    /* Initialize callchain support if enabled */
    if (env->callchain || ctx->tp_list->nr_need_stack) {
        ctx->callchain_flags = callchain_flags(dev, CALLCHAIN_KERNEL);
        if (ctx->callchain_flags) {
            if (callchain_pylist_init(ctx->callchain_flags) < 0)
                goto failed;
            dev->pages *= 2;  /* Increase buffer for callchain data */
        }
    }

    /* Initialize Python and load script */
    if (python_script_init(ctx) < 0)
        goto failed;

    /* Cache event fields */
    if (cache_event_fields(ctx) < 0)
        goto failed;

    dev->private = ctx;
    return 0;

failed:
    if (ctx->callchain_flags)
        callchain_pylist_exit(ctx->callchain_flags);
    python_script_exit(ctx);
    if (ctx->tp_list)
        tp_list_free(ctx->tp_list);
    if (ctx->script_path)
        free(ctx->script_path);
    tep__unref();
    free(ctx);
    return -1;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct python_ctx *ctx = dev->private;

    if (ctx->callchain_flags)
        callchain_pylist_exit(ctx->callchain_flags);

    python_call_exit(ctx);
    python_script_exit(ctx);

    tp_list_free(ctx->tp_list);
    free(ctx->script_path);
    tep__unref();
    free(ctx);
}

static int python_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
    struct python_ctx *ctx;
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID |
                         PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 1,
        .exclude_callchain_user = exclude_callchain_user(dev, CALLCHAIN_KERNEL),
        .exclude_callchain_kernel = exclude_callchain_kernel(dev, CALLCHAIN_KERNEL),
    };
    struct perf_evsel *evsel;
    struct tp *tp;
    int i;

    if (monitor_ctx_init(dev) < 0)
        return -1;
    ctx = dev->private;

    reduce_wakeup_times(dev, &attr);

    for_each_real_tp(ctx->tp_list, tp, i) {
        /* Enable callchain for events with stack attribute if not globally enabled */
        if (!env->callchain) {
            if (tp->stack)
                attr.sample_type |= PERF_SAMPLE_CALLCHAIN;
            else
                attr.sample_type &= (~PERF_SAMPLE_CALLCHAIN);
        }

        evsel = tp_evsel_new(tp, &attr);
        if (!evsel)
            goto failed;
        perf_evlist__add(evlist, evsel);
    }

    /* Call Python __init__ */
    if (python_call_init(ctx) < 0)
        goto failed;

    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

static int python_filter(struct prof_dev *dev)
{
    struct python_ctx *ctx = dev->private;
    return tp_list_apply_filter(dev, ctx->tp_list);
}

static void python_exit(struct prof_dev *dev)
{
    monitor_ctx_exit(dev);
}

static void python_lost(struct prof_dev *dev, union perf_event *event,
                        int instance, u64 lost_start, u64 lost_end)
{
    struct python_ctx *ctx = dev->private;
    print_lost_fn(dev, event, instance);
    python_call_lost(ctx);
}

/*
 * Extract raw data from sample, handling both callchain and non-callchain cases.
 */
static inline void get_raw_data(union perf_event *event, bool has_callchain,
                         struct callchain **pcallchain, void **praw, int *psize)
{
    struct python_sample_type *data = (void *)event->sample.array;

    if (has_callchain) {
        /* With callchain: header -> callchain -> raw */
        struct callchain *cc = (struct callchain *)&data->raw;
        struct {
            __u32 size;
            __u8 data[0];
        } *raw = (void *)cc->ips + cc->nr * sizeof(__u64);

        *pcallchain = cc;
        *praw = raw->data;
        *psize = raw->size;
    } else {
        /* Without callchain: header -> raw */
        *pcallchain = NULL;
        *praw = data->raw.data;
        *psize = data->raw.size;
    }
}

static void python_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct python_ctx *ctx = dev->private;
    struct python_sample_type *data = (void *)event->sample.array;
    struct perf_evsel *evsel;
    struct tp *tp;
    struct python_event_data *ev;
    struct callchain *callchain;
    void *raw;
    int raw_size;
    PyObject *dict, *result;
    int i;

    /* Find the matching tp */
    evsel = perf_evlist__id_to_evsel(dev->evlist, data->id, NULL);
    for_each_real_tp(ctx->tp_list, tp, i) {
        if (tp->evsel == evsel)
            break;
    }

    if (i >= ctx->tp_list->nr_tp)
        return;

    ev = &ctx->events[i];

    /* Determine if this sample has callchain and extract raw data */
    get_raw_data(event, tp->stack, &callchain, &raw, &raw_size);

    /* Convert event to Python dict */
    dict = event_to_dict(ctx, tp, data, i, callchain, raw, raw_size);
    if (!dict)
        return;

    /* Call event-specific handler or default __sample__ */
    if (ev->handler) {
        result = PyObject_CallFunctionObjArgs(ev->handler, dict, NULL);
        if (!result)
            PyErr_Print();
        else
            Py_DECREF(result);
    } else if (ctx->func_sample) {
        /* Add cached _event field for default handler */
        PyDict_SetItem(dict, ctx->key_cache.key_event, ev->event_name);

        result = PyObject_CallFunctionObjArgs(ctx->func_sample, dict, NULL);
        if (!result)
            PyErr_Print();
        else
            Py_DECREF(result);
    }

    Py_DECREF(dict);
}

static void python_interval(struct prof_dev *dev)
{
    struct python_ctx *ctx = dev->private;
    python_call_interval(ctx);
}

static void python_print_dev(struct prof_dev *dev, int indent)
{
    struct python_ctx *ctx = dev->private;
    python_call_print_stat(ctx, indent);
}

/*
 * Generate Python type hint based on field flags
 */
static const char *python_type_hint(struct tep_event *event, struct tep_format_field *field)
{
    if (field->flags & TEP_FIELD_IS_STRING) {
        /* Check if field needs binary output despite having IS_STRING flag */
        if (field_needs_binary_output(event, field->name))
            return "bytes";
        return "str";
    } else if (field->flags & TEP_FIELD_IS_ARRAY)
        return "bytes";
    else
        return "int";
}

/*
 * Output Python script template with event handler functions
 */
static void python_help_script_template(struct help_ctx *hctx)
{
    struct tep_handle *tep;
    int i, j, k;
    int has_events = 0;

    /* Check if we have any events */
    for (i = 0; i < hctx->nr_list; i++) {
        if (hctx->tp_list[i]->nr_tp > 0) {
            has_events = 1;
            break;
        }
    }

    printf("\n");
    printf("# =============================================================================\n");
    printf("# Python Script Template for perf-prof python\n");
    printf("# =============================================================================\n");
    printf("#\n");
    printf("# Save this template to a .py file and customize as needed.\n");
    printf("# Functions marked [OPTIONAL] can be safely deleted if not needed.\n");
    printf("# Exceptions raised in functions will be printed but won't stop processing.\n");
    printf("#\n");
    printf("# Event dict common fields:\n");
    printf("#   _pid, _tid    : Process/thread ID (int)\n");
    printf("#   _time         : Event timestamp in nanoseconds (int)\n");
    printf("#   _cpu          : CPU number (int)\n");
    printf("#   _period       : Sample period (int)\n");
    printf("#   _event        : Event name with alias if set (str, only in __sample__)\n");
    printf("#   _callchain    : Call stack list (when -g or stack attribute is set)\n");
    printf("#                   Each frame dict: {'addr': int, 'symbol': str,\n");
    printf("#                                     'offset': int, 'kernel': bool, 'dso': str}\n");
    printf("#   _raw          : Raw tracepoint data (bytes)\n");
    printf("#\n");
    printf("# =============================================================================\n");
    printf("\n");

    /* Import section */
    printf("# Import modules as needed (examples)\n");
    printf("# import json\n");
    printf("# import time\n");
    printf("# from collections import defaultdict, Counter\n");
    printf("\n");

    /* Global variables section */
    printf("# Global variables for statistics\n");
    printf("event_count = 0\n");
    printf("interval_count = 0\n");
    printf("\n");

    /* __init__ function - optional */
    printf("# [OPTIONAL] Delete if no initialization needed\n");
    printf("def __init__():\n");
    printf("    \"\"\"Called once before event processing starts.\"\"\"\n");
    printf("    global event_count, interval_count\n");
    printf("    event_count = 0\n");
    printf("    interval_count = 0\n");
    printf("    print(\"Python script initialized\")\n");
    printf("\n");

    /* __exit__ function - optional */
    printf("# [OPTIONAL] Delete if no cleanup/summary needed\n");
    printf("def __exit__():\n");
    printf("    \"\"\"Called once before program exit.\"\"\"\n");
    printf("    print(f\"Total events processed: {event_count}\")\n");
    printf("    print(f\"Total intervals: {interval_count}\")\n");
    printf("\n");

    /* __interval__ function - optional */
    printf("# [OPTIONAL] Delete if -i interval not used\n");
    printf("def __interval__():\n");
    printf("    \"\"\"Called at each -i interval.\"\"\"\n");
    printf("    global interval_count\n");
    printf("    interval_count += 1\n");
    printf("    print(f\"Interval {interval_count}: {event_count} events so far\")\n");
    printf("\n");

    /* __print_stat__ function - optional */
    printf("# [OPTIONAL] Delete if SIGUSR2 stats not needed\n");
    printf("def __print_stat__(indent: int):\n");
    printf("    \"\"\"Called on SIGUSR2 signal.\"\"\"\n");
    printf("    prefix = ' ' * indent\n");
    printf("    print(f\"{prefix}Events: {event_count}\")\n");
    printf("\n");

    /* __lost__ function - optional */
    printf("# [OPTIONAL] Delete if event loss notification not needed\n");
    printf("def __lost__():\n");
    printf("    \"\"\"Called when events are lost.\"\"\"\n");
    printf("    print(\"Warning: events lost!\")\n");
    printf("\n");

    /* Generate event-specific handlers if events are specified */
    if (has_events) {
        tep = tep__ref_light();

        printf("# =============================================================================\n");
        printf("# Event-specific handlers (higher priority than __sample__)\n");
        printf("# [OPTIONAL] Delete these if using __sample__ for all events\n");
        printf("# =============================================================================\n");
        printf("\n");

        for (i = 0; i < hctx->nr_list; i++) {
            struct tp *tp;
            for_each_real_tp(hctx->tp_list[i], tp, j) {
                struct tep_event *event = tep_find_event(tep, tp->id);
                struct tep_format_field **fields = NULL;
                char *handler_name;

                /* Build handler name using alias if available */
                handler_name = build_handler_name(tp->sys, tp->name, tp->alias);
                if (!handler_name)
                    continue;

                /* Function definition with docstring */
                printf("def %s(event: dict):\n", handler_name);
                printf("    \"\"\"\n");
                printf("    Handler for %s:%s", tp->sys, tp->name);
                if (tp->alias)
                    printf(" (alias: %s)", tp->alias);
                printf("\n");

                /* Document event-specific fields */
                if (event) {
                    fields = tep_event_fields(event);
                    if (fields) {
                        printf("    \n");
                        printf("    Event-specific fields:\n");
                        for (k = 0; fields[k]; k++) {
                            printf("        %s : %s\n", fields[k]->name,
                                   python_type_hint(event, fields[k]));
                        }
                    }
                }
                printf("    \"\"\"\n");

                /* Function body with field access examples */
                printf("    global event_count\n");
                printf("    event_count += 1\n");
                printf("    \n");
                printf("    # Access common fields\n");
                printf("    pid = event['_pid']\n");
                printf("    time_ns = event['_time']\n");
                printf("    \n");

                if (fields) {
                    printf("    # Access event-specific fields\n");
                    for (k = 0; fields[k]; k++) {
                        printf("    # %s = event['%s']  # %s\n", fields[k]->name,
                               fields[k]->name, python_type_hint(event, fields[k]));
                    }
                    printf("    \n");
                    free(fields);
                }

                printf("    # Example: print event info\n");
                printf("    # print(f\"[CPU{cpu}] {event}\")\n");
                printf("\n");

                free(handler_name);
            }
        }

        tep__unref();
    }

    /* Default __sample__ handler */
    printf("# =============================================================================\n");
    printf("# Default event handler (used when no specific handler is defined)\n");
    printf("# [OPTIONAL] Delete if using event-specific handlers for all events\n");
    printf("# =============================================================================\n");
    printf("\n");
    printf("def __sample__(event: dict):\n");
    printf("    \"\"\"\n");
    printf("    Default handler for all events without specific handlers.\n");
    printf("    The event dict includes '_event' field with format 'sys:name' or 'sys:alias'.\n");
    printf("    \"\"\"\n");
    printf("    global event_count\n");
    printf("    event_count += 1\n");
    printf("    \n");
    printf("    event_name = event['_event']\n");
    printf("    cpu = event['_cpu']\n");
    printf("    \n");
    printf("    # Example: print event\n");
    printf("    # print(f\"[CPU{cpu}] {event_name}: pid={pid}\")\n");
}

static void python_help(struct help_ctx *hctx)
{
    int i, j;

    printf("# " PROGRAME " python ");
    printf("-e \"");
    for (i = 0; i < hctx->nr_list; i++) {
        struct tp *tp;
        for_each_real_tp(hctx->tp_list[i], tp, j) {
            printf("%s:%s/%s/alias=%s/", tp->sys, tp->name,
                   tp->filter && tp->filter[0] ? tp->filter : "", tp->alias ? tp->alias : "");
            if (i != hctx->nr_list - 1 ||
                j != hctx->tp_list[i]->nr_tp - 1)
                printf(",");
        }
    }
    printf("\" script.py\n");

    /* Output Python script template */
    python_help_script_template(hctx);
}

static const char *python_desc[] = PROFILER_DESC("python",
    "[OPTION...] -e EVENT[,EVENT...] script.py",
    "Process perf events with Python scripts.",
    "",
    "SYNOPSIS",
    "    Convert perf events to Python dict objects and process them with custom",
    "    Python scripts. Provides a flexible way to analyze events using Python.",
    "",
    "SCRIPT SYNTAX",
    "  CALLBACK FUNCTIONS",
    "    __init__()              - Called once before event processing",
    "    __exit__()              - Called once before program exit",
    "    __print_stat__(indent)  - Called on SIGUSR2 signal",
    "    __interval__()          - Called at each -i interval",
    "    __lost__()              - Called when events are lost",
    "",
    "  EVENT HANDLERS (priority: specific > default)",
    "    sys__event_name(event)  - Event-specific handler",
    "                              e.g., sched__sched_wakeup for sched:sched_wakeup",
    "                              Characters '-', '.', ':' converted to '_'",
    "    sys__alias(event)       - Alias-specific handler (when alias= is used)",
    "                              e.g., sched__wakeup1 for alias=wakeup1",
    "    __sample__(event)       - Default handler (dict includes _event field)",
    "",
    "  EVENT DICT FIELDS",
    "    _pid, _tid              - Process/thread ID",
    "    _time                   - Event timestamp (ns)",
    "    _cpu                    - CPU number",
    "    _period                 - Sample period",
    "    _event                  - Event name, uses alias if set (only in __sample__)",
    "    _callchain              - Call stack list (when -g or stack attribute is set)",
    "                              Each frame: {'addr', 'symbol', 'offset', 'kernel', 'dso'}",
    "    _raw                    - Raw tracepoint data (bytes)",
    "    <field>                 - Event-specific fields (int/str/bytes)",
    "",
    "EXAMPLES",
    "    "PROGRAME" python -e sched:sched_wakeup counter.py",
    "    "PROGRAME" python -e sched:sched_wakeup,sched:sched_switch -i 1000 analyzer.py",
    "    "PROGRAME" python -e 'sched:sched_wakeup/pid>1000/' -C 0-3 filter.py",
    "    "PROGRAME" python -e 'sched:sched_wakeup//alias=w1/,sched:sched_wakeup//alias=w2/' multi.py",
    "    "PROGRAME" python -e sched:sched_wakeup -g callstack.py  # with callchain");

static const char *python_argv[] = PROFILER_ARGV("python",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_CALLCHAIN_FILTER,
    PROFILER_ARGV_PROFILER, "event", "call-graph");

static profiler python = {
    .name = "python",
    .desc = python_desc,
    .argv = python_argv,
    .pages = 8,
    .help = python_help,
    .argc_init = python_argc_init,
    .init = python_init,
    .filter = python_filter,
    .deinit = python_exit,
    .print_dev = python_print_dev,
    .interval = python_interval,
    .lost = python_lost,
    .sample = python_sample,
};
PROFILER_REGISTER(python);
