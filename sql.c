#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <monitor.h>
#include <tep.h>

#include <sqlite3.h>

struct tp_private {
    sqlite3_stmt *insert_stmt;
    struct tep_format_field **fields;
    int nr_fields;
};

struct sql_ctx {
    sqlite3 *sql;
    struct tp_list *tp_list;
    struct tep_handle *tep;
    int nr_query;
    int **col_widths;

    /* Transaction optimization fields */
    bool in_transaction;
    int pending_inserts;
    int batch_size;

    /* Performance statistics */
    uint64_t total_inserts;
    uint64_t total_commits;
};

static int monitor_ctx_init(struct prof_dev *dev)
{
    struct env *env = dev->env;
    struct sql_ctx *ctx;

    if (!env->event)
        return -1;

    /*
     * Valid usage scenarios matrix:
     *
     * -i  --query --output2  Behavior
     * --  ------- ---------  --------
     * 0   0       0          Events stored in memory, never used (BLOCKED)
     * 0   0       1          Events saved to database file
     * 0   1       0          Events stored in memory, query on exit (BLOCKED)
     * 0   1       1          Events saved to file, query on exit
     *
     * 1   0       0          Events stored in memory, never used (BLOCKED)
     * 1   0       1          Events saved to file periodically
     * 1   1       0          Periodic query, memory cleared after each query
     * 1   1       1          Periodic query, file table cleared after each query
     *
     * Prevent useless scenarios that consume large amounts of memory:
     * 1. Neither --query nor --output2 is specified.
     *    Events stored in memory database but never queried or persisted.
     * 2. --query without -i (periodic output) and without --output2.
     *    Events accumulated in memory database until program exit.
     */
    if ((!env->query || !env->query[0]) && !env->output2) {
        fprintf(stderr, "Error: Must specify either --query or --output2 (or both).\n");
        fprintf(stderr, "  --query: Execute SQL queries on collected events\n");
        fprintf(stderr, "  --output2: Save events to a database file\n");
        fprintf(stderr, "Without either option, events will be stored in memory with no output.\n");
        return -1;
    }

    if ((env->query && env->query[0]) && !env->output2 && !env->interval) {
        fprintf(stderr, "Error: --query without --output2 requires -i (periodic interval).\n");
        fprintf(stderr, "  Without -i, events accumulate in memory until program exit.\n");
        fprintf(stderr, "  Use -i to periodically execute queries and clear memory,\n");
        fprintf(stderr, "  or use --output2 to persist events to a database file.\n");
        return -1;
    }

    ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;

    if (env->query && env->query[0]) {
        char *query = env->query, *sep;
        ctx->nr_query = 1;
        while ((sep = next_sep(query, ';'))) {
            query = sep + 1;
            if (query[0])
                ctx->nr_query ++;
        }
    }

    if (ctx->nr_query) {
        ctx->col_widths = calloc(ctx->nr_query, sizeof(*ctx->col_widths));
        if (!ctx->col_widths)
            goto failed;
    }

    ctx->tep = tep__ref_light();

    ctx->tp_list = tp_list_new(dev, env->event);
    if (!ctx->tp_list)
        goto failed;

    if (sqlite3_config(SQLITE_CONFIG_SINGLETHREAD) != SQLITE_OK)
        goto failed;

    if (sqlite3_open(env->output2 ? : ":memory:", &ctx->sql) != SQLITE_OK)
        goto failed;

    /* Single-threaded serial write optimization */
    sqlite3_exec(ctx->sql, "PRAGMA page_size = 65536;", NULL, NULL, NULL);
    sqlite3_exec(ctx->sql, "PRAGMA journal_mode = OFF;", NULL, NULL, NULL);
    sqlite3_exec(ctx->sql, "PRAGMA synchronous = OFF;", NULL, NULL, NULL);
    sqlite3_exec(ctx->sql, "PRAGMA locking_mode = EXCLUSIVE;", NULL, NULL, NULL);
    sqlite3_exec(ctx->sql, "PRAGMA temp_store = MEMORY;", NULL, NULL, NULL);

    if (env->output2) {
        /* File database: aggressive optimization for maximum performance */
        sqlite3_exec(ctx->sql, "PRAGMA cache_size = -131072;", NULL, NULL, NULL);  /* 128MB cache */
        sqlite3_exec(ctx->sql, "PRAGMA mmap_size = 536870912;", NULL, NULL, NULL); /* 512MB mmap */
    } else {
        /* Memory database: lighter configuration */
        sqlite3_exec(ctx->sql, "PRAGMA cache_size = -65536;", NULL, NULL, NULL);   /* 64MB cache */
    }

    ctx->in_transaction = false;
    ctx->pending_inserts = 0;
    ctx->batch_size = env->output2 ? 2000 : 5000;  /* Larger batch for memory db */

    ctx->total_inserts = 0;
    ctx->total_commits = 0;

    dev->private = ctx;
    return 0;

failed:
    if (ctx->tp_list)
        tp_list_free(ctx->tp_list);
    if (ctx->tep)
        tep__unref();
    free(ctx);
    return -1;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct sql_ctx *ctx = dev->private;
    struct tp *tp;
    int i;
    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tp_private *priv = tp->private;
        if (priv) {
            if (priv->insert_stmt)
                sqlite3_finalize(priv->insert_stmt);
            if (priv->fields)
                free(priv->fields);
            free(priv);
        }
    }
    if (ctx->col_widths) {
        for (i = 0; i < ctx->nr_query; i++)
            if (ctx->col_widths[i])
                free(ctx->col_widths[i]);
        free(ctx->col_widths);
    }
    tp_list_free(ctx->tp_list);
    sqlite3_close(ctx->sql);
    tep__unref();
    free(ctx);
}

static int sql_create_table(struct prof_dev *dev)
{
    struct sql_ctx *ctx = dev->private;
    struct tp *tp;
    int i;
    const char *table_fmt = "DROP TABLE IF EXISTS %s; "
        "CREATE TABLE %s ("
                "_pid INTEGER, "
                "_tid INTEGER, "
                "_time INTEGER, "
                "_cpu INTEGER, "
                "_period INTEGER, "
                "common_type INTEGER, "
                "common_flags INTEGER, "
                "common_preempt_count INTEGER, "
                "common_pid INTEGER"
                "%s" // raw data columns
        ");";
    const char *insert_fmt = "INSERT INTO %s VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?%s);";
    char buf[1024];

    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tep_format_field **fields;
        struct tp_private *priv;
        char col_buf[512];
        char ins_buf[512];
        int j = 0, col_len = 0, ins_len = 0;
        char *errmsg = NULL;

        if (!tp->private) {
            struct tep_event *event = tep_find_event(ctx->tep, tp->id);
            fields = event ? tep_event_fields(event) : NULL;
            priv = calloc(1, sizeof(struct tp_private));
            if (!priv)
                return -1;
            priv->fields = fields;
            tp->private = priv;
        } else {
            priv = (struct tp_private *)tp->private;
            fields = priv->fields;
        }

        while (fields && fields[j]) {
            if (fields[j]->flags & TEP_FIELD_IS_STRING)
                col_len += snprintf(col_buf + col_len, sizeof(col_buf) - col_len,
                                ", %s TEXT", fields[j]->name);
            else if (fields[j]->flags & TEP_FIELD_IS_ARRAY)
                col_len += snprintf(col_buf + col_len, sizeof(col_buf) - col_len,
                                ", %s BLOB", fields[j]->name);
            else
                col_len += snprintf(col_buf + col_len, sizeof(col_buf) - col_len,
                                ", %s INTEGER", fields[j]->name);
            if (!priv->insert_stmt)
                ins_len += snprintf(ins_buf + ins_len, sizeof(ins_buf) - ins_len,
                                ", ?");
            j++;
        }
        priv->nr_fields = 9 + j;
        col_buf[col_len] = '\0';
        ins_buf[ins_len] = '\0';

        snprintf(buf, sizeof(buf), table_fmt, tp->name, tp->name, col_buf);
        if (dev->env->verbose)
            printf("CREATE SQL: %s\n", buf);
        if (sqlite3_exec(ctx->sql, buf, NULL, NULL, &errmsg) != SQLITE_OK) {
            fprintf(stderr, "Failed to create table %s: %s\n", tp->name, errmsg);
            return -1;
        }

        if (priv->insert_stmt)
            continue;

        snprintf(buf, sizeof(buf), insert_fmt, tp->name, ins_buf);
        if (dev->env->verbose)
            printf("INSERT SQL: %s\n", buf);
        if (sqlite3_prepare_v3(ctx->sql, buf, -1, SQLITE_PREPARE_PERSISTENT, &priv->insert_stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare insert statement for %s: %s\n", tp->name, sqlite3_errmsg(ctx->sql));
            return -1;
        }
    }
    return 0;
}

static int sql_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct sql_ctx *ctx;
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD |
                         PERF_SAMPLE_RAW,
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 1,
    };
    struct perf_evsel *evsel;
    struct tp *tp;
    int i;

    if (monitor_ctx_init(dev) < 0)
        return -1;
    ctx = dev->private;

    prof_dev_env2attr(dev, &attr);

    for_each_real_tp(ctx->tp_list, tp, i) {
        evsel = tp_evsel_new(tp, &attr);
        if (!evsel) {
            goto failed;
        }
        perf_evlist__add(evlist, evsel);
    }

    if (sql_create_table(dev) < 0)
        goto failed;

    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

static int sql_filter(struct prof_dev *dev)
{
    struct sql_ctx *ctx = dev->private;
    return tp_list_apply_filter(dev, ctx->tp_list);
}
static void sql_interval(struct prof_dev *dev);
static void sql_exit(struct prof_dev *dev)
{
    struct sql_ctx *ctx = dev->private;

    /* Final flush before exit */
    sql_interval(dev);

    /* Force final flush to disk for file database */
    if (dev->env->output2)
        sqlite3_db_cacheflush(ctx->sql);

    monitor_ctx_exit(dev);
}

// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW
struct sample_type_header {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64   time;
    __u64   id;
    struct {
        __u32    cpu;
        __u32    reserved;
    }    cpu_entry;
    __u64		period;
    struct {
        __u32   size;
        union {
            __u8    data[0];
            struct trace_entry common;
        };
    } raw;
};

static long sql_ftrace_filter(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct sql_ctx *ctx = dev->private;
    struct sample_type_header *data = (void *)event->sample.array;
    struct perf_evsel *evsel;
    struct tp *tp;
    int i;

    if (event->header.type == PERF_RECORD_DEV)
        return 1;

    evsel = perf_evlist__id_to_evsel(dev->evlist, data->id, NULL);
    for_each_real_tp(ctx->tp_list, tp, i) {
        if (tp->evsel == evsel) {
            if (!tp->ftrace_filter)
                return 1;
            return tp_prog_run(tp, tp->ftrace_filter, GLOBAL(data->cpu_entry.cpu, data->tid_entry.pid, data->raw.data, data->raw.size));
        }
    }
    return 0;
}

static void commit_transaction(struct sql_ctx *ctx, bool new_transaction)
{
    if (ctx->in_transaction) {
        if (!new_transaction) {
             sqlite3_exec(ctx->sql, "COMMIT;", NULL, NULL, NULL);
             ctx->in_transaction = false;
        } else if (ctx->pending_inserts > 0)
             sqlite3_exec(ctx->sql, "COMMIT; BEGIN IMMEDIATE TRANSACTION;", NULL, NULL, NULL);

        ctx->total_commits++;
        ctx->pending_inserts = 0;
    }
}

static void ensure_transaction(struct sql_ctx *ctx)
{
    if (!ctx->in_transaction) {
        sqlite3_exec(ctx->sql, "BEGIN IMMEDIATE TRANSACTION;", NULL, NULL, NULL);
        ctx->in_transaction = true;
        ctx->pending_inserts = 0;
    }
}

static void sql_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct sql_ctx *ctx = dev->private;
    struct sample_type_header *data = (void *)event->sample.array;
    struct perf_evsel *evsel;
    struct tp *tp;
    int i;

    ensure_transaction(ctx);

    evsel = perf_evlist__id_to_evsel(dev->evlist, data->id, NULL);
    for_each_real_tp(ctx->tp_list, tp, i) {
        if (tp->evsel == evsel) {
            struct tp_private *priv = tp->private;
            int idx = 1;
            int j;

            // Reset the statement for new use
            sqlite3_reset(priv->insert_stmt);

            // Bind common fields
            sqlite3_bind_int(priv->insert_stmt, idx++, data->tid_entry.pid);
            sqlite3_bind_int(priv->insert_stmt, idx++, data->tid_entry.tid);
            sqlite3_bind_int64(priv->insert_stmt, idx++, data->time);
            sqlite3_bind_int(priv->insert_stmt, idx++, data->cpu_entry.cpu);
            sqlite3_bind_int64(priv->insert_stmt, idx++, data->period);
            // common_*
            sqlite3_bind_int(priv->insert_stmt, idx++, data->raw.common.common_type);
            sqlite3_bind_int(priv->insert_stmt, idx++, data->raw.common.common_flags);
            sqlite3_bind_int(priv->insert_stmt, idx++, data->raw.common.common_preempt_count);
            sqlite3_bind_int(priv->insert_stmt, idx++, data->raw.common.common_pid);

            // Parse and bind event-specific fields
            for (j = 0; priv->fields && priv->fields[j]; j++) {
                struct tep_format_field *field = priv->fields[j];
                void *base = data->raw.data;
                unsigned long long val;
                void *ptr;
                int len, v = 0;

                if (field->flags & TEP_FIELD_IS_STRING) {
                    // For string fields, get the pointer and bind as text
                    if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                        ptr = base + *(unsigned short *)(base + field->offset);
                        len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
                    } else {
                        ptr = base + field->offset;
                        len = -1;
                    }
                    // Use SQLITE_STATIC for zero-copy: data valid during sqlite3_step()
                    sqlite3_bind_text(priv->insert_stmt, idx++, ptr, len, SQLITE_STATIC);
                } else if (field->flags & TEP_FIELD_IS_ARRAY) {
                    // For array fields, get the pointer and bind as blob
                    ptr = base + field->offset;
                    len = field->size;
                    // Use SQLITE_STATIC for zero-copy: data valid during sqlite3_step()
                    sqlite3_bind_blob(priv->insert_stmt, idx++, ptr, len, SQLITE_STATIC);
                } else {
                    // For numeric fields, get the value and bind as integer
                    if (field->size == 1)
                        v = *(unsigned char *)(base + field->offset);
                    else if (field->size == 2)
                        v = *(unsigned short *)(base + field->offset);
                    else if (field->size == 4)
                        v = *(unsigned int *)(base + field->offset);
                    else if (field->size == 8) {
                        val = *(unsigned long long *)(base + field->offset);
                        sqlite3_bind_int64(priv->insert_stmt, idx++, val);
                    } else
                        sqlite3_bind_null(priv->insert_stmt, idx++);

                    if (field->size < 8)
                        sqlite3_bind_int(priv->insert_stmt, idx++, v);
                }
            }

            // Execute the insert statement
            if (sqlite3_step(priv->insert_stmt) != SQLITE_DONE) {
                if (dev->env->verbose) {
                    fprintf(stderr, "Failed to insert record into %s: %s\n",
                            tp->name, sqlite3_errmsg(ctx->sql));
                }
            } else {
                ctx->total_inserts++;
                ctx->pending_inserts++;
            }
            break;
        }
    }

    /* Optimized commit strategy: batch size only (no time check for single-threaded) */
    if (ctx->pending_inserts >= ctx->batch_size)
        commit_transaction(ctx, true);
}

static void sql_interval(struct prof_dev *dev)
{
    struct env *env = dev->env;
    struct sql_ctx *ctx = dev->private;
    char *query = env->query;
    char *to_free = NULL;
    char *sep = NULL;
    struct tp *tp;
    int i, nr_query = 0;

    /* Commit pending transaction */
    commit_transaction(ctx, false);

    if (!env->query || !env->query[0]) {
        /* Flush to disk for file database */
        if (env->output2)
            sqlite3_db_cacheflush(ctx->sql);

        printf("Total Inserts: %lu\n", ctx->total_inserts);
        return;
    }

    if (ctx->nr_query > 1) {
        to_free = query = strdup(query);
        sep = next_sep(query, ';');
        if (sep && sep[1])
            *sep = '\0';
    }

    print_time(stdout);
    printf("\n");

    while (nr_query < ctx->nr_query) {
        sqlite3_stmt *stmt;

        printf("=== %s ===\n", query);
        if (sqlite3_prepare_v3(ctx->sql, query, -1, 0, &stmt, NULL) == SQLITE_OK) {
            int column_count = sqlite3_column_count(stmt);
            int *col_widths = ctx->col_widths[nr_query];
            int j, k, width;

            // Allocate memory and initialize column widths
            if (!col_widths) {
                col_widths = malloc(column_count * sizeof(int));
                if (!col_widths)
                    goto cleanup;

                for (j = 0; j < column_count; j++)
                    col_widths[j] = strlen(sqlite3_column_name(stmt, j));
                ctx->col_widths[nr_query] = col_widths;
            }

            // Print column headers with proper alignment
            for (j = 0; j < column_count; j++) {
                if (j > 0) printf(" | ");
                printf("%-*s", col_widths[j], sqlite3_column_name(stmt, j));
            }
            printf("\n");

            // Print separator
            for (j = 0; j < column_count; j++) {
                if (j > 0) printf("-+-");
                for (k = 0; k < col_widths[j]; k++)
                    printf("-");
            }
            printf("\n");

            // Print rows data
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                for (j = 0; j < column_count; j++) {
                    if (j > 0) printf(" | ");
                    switch (sqlite3_column_type(stmt, j)) {
                    case SQLITE_INTEGER:
                        width = printf("%-*lld", col_widths[j], sqlite3_column_int64(stmt, j));
                        break;
                    case SQLITE_FLOAT:
                        width = printf("%-*.6f", col_widths[j], sqlite3_column_double(stmt, j));
                        break;
                    case SQLITE_TEXT:
                        width = printf("%-*s", col_widths[j], sqlite3_column_text(stmt, j));
                        break;
                    case SQLITE_BLOB:
                        width = printf("[BLOB:%d]", sqlite3_column_bytes(stmt, j));
                        break;
                    case SQLITE_NULL:
                        width = printf("NULL");
                        break;
                    default:
                        width = printf("?");
                        break;
                    }

                    if (width < col_widths[j])
                        printf("%-*s", col_widths[j] - width, "");
                    else
                        col_widths[j] = width;
                }
                printf("\n");
            }
            printf("\n");

        cleanup:
            sqlite3_finalize(stmt);
        } else
            fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(ctx->sql));

        nr_query ++;
        if (sep) {
            query = sep + 1;
            sep = next_sep(query, ';');
            if (sep && sep[1])
                *sep = '\0';
        }
    }

    if (to_free)
        free(to_free);

    // Finalize all prepared statements before dropping tables
    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tp_private *priv = tp->private;
        if (priv && priv->insert_stmt) {
            sqlite3_finalize(priv->insert_stmt);
            priv->insert_stmt = NULL;
        }
    }

    // Recreate tables
    if (sql_create_table(dev) < 0)
        fprintf(stderr, "Failed to recreate tables after query\n");
}

static void sql_print_dev(struct prof_dev *dev, int indent)
{
    struct sql_ctx *ctx = dev->private;
    dev_printf("Total Inserts: %lu\n", ctx->total_inserts);
    dev_printf("Total Commits: %lu\n", ctx->total_commits);
}

static const char *sql_desc[] = PROFILER_DESC("sql",
    "[OPTION...] -e EVENT [--query 'SQL_STATEMENT'] [--output2 DB_FILE] [-i INT]",
    "Convert trace events to SQL tables for analysis.",
    "",
    "Events are stored as SQL tables where event fields become table columns.",
    "Use --query to execute custom SQL queries on the collected data.",
    "Use --output2 to save events to a database file instead of memory.",
    "",
    "EXAMPLES",
    "    "PROGRAME" sql -e sched:sched_wakeup -i 1000 --query 'SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm ORDER BY COUNT(*) DESC'",
    "    "PROGRAME" sql -e sched:sched_wakeup,sched:sched_switch -i 1000 --query 'SELECT * FROM sched_wakeup WHERE pid > 1000'",
    "    "PROGRAME" sql -e sched:sched_wakeup --output2 events.db -i 10000");
static const char *sql_argv[] = PROFILER_ARGV("sql",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "event", "query", "output2\nSpecify DB file path");
static profiler sql = {
    .name = "sql",
    .desc = sql_desc,
    .argv = sql_argv,
    .pages = 8,
    .init = sql_init,
    .filter = sql_filter,
    .deinit = sql_exit,
    .print_dev = sql_print_dev,
    .interval = sql_interval,
    .ftrace_filter = sql_ftrace_filter,
    .sample = sql_sample,
};
PROFILER_REGISTER(sql);
