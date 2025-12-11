/*
 * perf_tp.c - SQLite interface for perf tracepoint events
 *
 * This module provides two storage backends for tracepoint events:
 *
 * 1. File mode (sql_tp_file):
 *    - Events are inserted into SQLite tables using sqlite3_bind_*() + INSERT
 *    - Suitable for persistent storage to database files
 *    - Higher overhead due to SQLite's bind operations for each column.
 *
 * 2. Memory mode (sql_tp_mem):
 *    - Events are stored in a linked list (mem-copy from perf ring buffer)
 *    - Accessed via SQLite Virtual Table interface
 *    - Fields are read on-demand during query execution
 *    - Lower overhead: avoids sqlite3_bind_*() for unused columns
 *
 * Architecture:
 *
 *   File mode:                      Memory mode:
 *   ──────────                      ───────────
 *   perf_event                      perf_event
 *       │                               │
 *       ▼                               ▼
 *   sqlite3_bind_*()               memcpy to list
 *       │                               │
 *       ▼                               ▼
 *   SQLite B-tree                  Virtual Table
 *       │                               │
 *       ▼                               ▼
 *   SQL Query                      SQL Query
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <monitor.h>
#include <tep.h>
#include <linux/rblist.h>
#include <linux/bitmap.h>
#include <event-parse-local.h>
#include <stack_helpers.h>
#include <arpa/inet.h>

#include <sqlite/ext.h>

extern const char *syscalls_table[];
extern const int syscalls_table_size;

/*
 * SQL scalar functions for kernel pointer format specifiers (%p extensions).
 * These functions convert raw binary data to human-readable strings.
 *
 * Format    Function      Description
 * ──────    ────────      ───────────
 * %pS,%ps   ksymbol()     Kernel symbol name from address
 * %pI4      ipv4_str()    IPv4 address (network byte order)
 * %pi4h     ipv4_hstr()   IPv4 address (host byte order)
 * %pI6      ipv6_str()    IPv6 address
 * %pIS      ipsa_str()    Sockaddr (network byte order)
 * %pISh     ipsa_hstr()   Sockaddr (host byte order)
 * %pUb      uuid_str()    UUID (big endian)
 * %pUl      guid_str()    GUID (little endian)
 * %pM       mac_str()     MAC address
 * (special) syscall()     Syscall number to name
 */
#define ARG_POINTER_FUNC \
    FUNC(KSYMBOL, "ksymbol"), \
    FUNC(IPV4_STR, "ipv4_str"), \
    FUNC(IPV4_HSTR, "ipv4_hstr"), \
    FUNC(IPV6_STR, "ipv6_str"), \
    FUNC(IPSA_STR, "ipsa_str"), \
    FUNC(IPSA_HSTR, "ipsa_hstr"), \
    FUNC(UUID_STR, "uuid_str"), \
    FUNC(GUID_STR, "guid_str"), \
    FUNC(MAC_STR, "mac_str"), \
    FUNC(SYSCALL, "syscall")

#define FUNC(enum_name, func_name) enum_name
enum {
    ARG_POINTER_FUNC,
    ARG_POINTER_MAX,
};
#undef FUNC

#define FUNC(enum_name, func_name) func_name
const char *arg_pointer_func[] = {
    ARG_POINTER_FUNC,
};
#undef FUNC

struct symbolic_node {
    struct rb_node rbnode;
    union {
        uint64_t event_field;
        struct {
            int event_id;
            int field_offset;
        };
    };
    uint64_t value;
    const char *str;
};

static int symbolic_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct symbolic_node *node = container_of(rbn, struct symbolic_node, rbnode);
    const struct symbolic_node *e = entry;

    if (node->event_field > e->event_field)
        return 1;
    else if (node->event_field < e->event_field)
        return -1;
    else {
        if (node->value > e->value)
            return 1;
        else if (node->value < e->value)
            return -1;
        else
            return 0;
    }
}

static struct rb_node *symbolic_node_new(struct rblist *rlist, const void *new_entry)
{
    struct symbolic_node *node = malloc(sizeof(*node));
    if (node) {
        const struct symbolic_node *e = new_entry;
        node->event_field = e->event_field;
        node->value = e->value;
        /* Note: str points to TEP internal data structure.
         * It's safe as long as TEP handle lifetime covers the entire program execution.
         * No string duplication for performance reasons. */
        node->str = e->str;
        RB_CLEAR_NODE(&node->rbnode);
    }
    return node ? &node->rbnode : NULL;
}

static void symbolic_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct symbolic_node *node = container_of(rb_node, struct symbolic_node, rbnode);
    free(node);
}

static void symbolic_update(struct sql_tp_ctx *ctx, int event_id, int field_offset,
                            const char *value_str, const char *str)
{
    char *endptr = NULL;
    uint64_t value = strtoull(value_str, &endptr, 0);
    struct symbolic_node key;

    if (endptr == value_str || *endptr != '\0') {
        // Not a valid number
        return;
    }

    key.event_id = event_id;
    key.field_offset = field_offset;
    key.value = value;
    key.str = str;
    rblist__findnew(&ctx->symbolic_table, &key);
}

static const char *symbolic_lookup(struct sql_tp_ctx *ctx, int event_id, int field_offset,
                                   uint64_t value)
{
    struct symbolic_node key, *node;
    struct rb_node *rbn;

    key.event_id = event_id;
    key.field_offset = field_offset;
    key.value = value;
    rbn = rblist__find(&ctx->symbolic_table, &key);
    if (rbn) {
        node = container_of(rbn, struct symbolic_node, rbnode);
        return node->str;
    } else
        return NULL;
}

struct symbolic_ctx {
    struct sql_tp_ctx *ctx;
    int event_id;
    int do_update;
    int nr_print_symbolic;
    const char *field_name;

    // Only for kvm:* events, to evaluate the isa expression.
    // (REC->isa == 1) ? __print_symbolic() : __print_symbolic()
    int isa;
    int has_isa;
    int has_unknown;
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"

static unsigned long
tep_try_eval_num_arg(struct tep_print_arg *arg, struct symbolic_ctx *sym_ctx)
{
    unsigned long val = -1;
    unsigned long left, right;

    switch (arg->type) {
    case TEP_PRINT_NULL: // ~ ! + -
        return 0;
    case TEP_PRINT_ATOM:
        return strtoul(arg->atom.atom, NULL, 0);
    case TEP_PRINT_FIELD:
        if (strcmp(arg->field.name, "isa") == 0) {
            sym_ctx->has_isa = 1;
            return sym_ctx->isa;
        }
        sym_ctx->has_unknown++;
        return val;
    case TEP_PRINT_OP:
        if (arg->op.op[0] == '[' || arg->op.op[0] == '?')
            return val;

        left = tep_try_eval_num_arg(arg->op.left, sym_ctx);
        right = tep_try_eval_num_arg(arg->op.right, sym_ctx);
        switch (arg->op.op[0]) {
        case '!':
            switch (arg->op.op[1]) {
            case 0: val = !right; break;
            case '=': val = left != right; break;
            default: goto out;
            } break;
        case '~': val = ~right; break;
        case '|': if (arg->op.op[1]) val = left || right;
                  else val = left | right;
            break;
        case '&': if (arg->op.op[1]) val = left && right;
                  else val = left & right;
            break;
        case '<':
            switch (arg->op.op[1]) {
            case 0: val = left < right; break;
            case '<': val = left << right; break;
            case '=': val = left <= right; break;
            default: goto out;
            } break;
        case '>':
            switch (arg->op.op[1]) {
            case 0: val = left > right; break;
            case '>': val = left >> right; break;
            case '=': val = left >= right; break;
            default: goto out;
            } break;
        case '=': if (arg->op.op[1] != '=') goto out;
                  val = left == right; break;
        case '-': val = left - right; break;
        case '+': val = left + right; break;
        case '/': val = left / right; break;
        case '%': val = left % right; break;
        case '*': val = left * right; break;
        default: goto out;
        }
        break;
    default:
        break;
    }
out:
    return val;
}

static void tep_symbolic(struct tep_print_arg *arg, struct symbolic_ctx *sym_ctx)
{
    switch (arg->type) {
    case TEP_PRINT_SYMBOL: {
        struct tep_print_arg *field = arg->symbol.field;
        struct tep_print_flag_sym *symbols = arg->symbol.symbols;

        /* Only handle simple case: __print_symbolic(REC->field, ...)
         * Where the first argument is a direct field reference (TEP_PRINT_FIELD).
         *
         * Supported: __print_symbolic(REC->vec, {0, "str0"}, {1, "str1"}, ...)
         * Not supported: __print_symbolic((REC->dm >> 8 & 0x7), ...)
         *                (complex expressions with bit operations)
         *
         * This ensures we can unambiguously map the field offset to symbolic values. */
        if (field && field->type == TEP_PRINT_FIELD) {
            sym_ctx->nr_print_symbolic++;
            if (sym_ctx->do_update) {
                int field_offset = field->field.field->offset;
                sym_ctx->field_name = field->field.field->name;
                /* Register all value->string mappings for this field */
                while (symbols) {
                    symbolic_update(sym_ctx->ctx, sym_ctx->event_id, field_offset,
                                    symbols->value, symbols->str);
                    symbols = symbols->next;
                }
            }
        }
        break;
    }
    case TEP_PRINT_OP: {
        struct tep_print_arg *left = arg->op.left;
        unsigned long val;

        /* The only op for __print_symbolic string should be ? :
         * Example: (REC->isa == 1) ? __print_symbolic(...) : __print_symbolic(...) */
        if (arg->op.op[0] != '?')
            break;

        arg = arg->op.right;
        sym_ctx->has_isa = sym_ctx->has_unknown = 0;
        val = tep_try_eval_num_arg(left, sym_ctx);

        /* Special handling for kvm events with isa-based conditional symbolic.
         * If the condition can be evaluated at registration time (has_isa && !has_unknown),
         * only process the matching branch. Otherwise, process both branches.
         *
         * Example: kvm:kvm_exit has (REC->isa == 1) ? VMX_reasons : SVM_reasons */
        if (sym_ctx->has_isa && !sym_ctx->has_unknown) {
            /* Condition is evaluable: process only the matching branch */
            if (val) tep_symbolic(arg->op.left, sym_ctx);
            else tep_symbolic(arg->op.right, sym_ctx);
        } else {
            /* Condition has unknown fields: process both branches */
            tep_symbolic(arg->op.left, sym_ctx);
            tep_symbolic(arg->op.right, sym_ctx);
        }
        break;
    }
    default:
        break;
    }
}
#pragma GCC diagnostic pop

static void symbolic_register(struct sql_tp_ctx *ctx)
{
    struct tp *tp;
    int i;
    int vendor = get_cpu_vendor();
    int isa = 0;

    if (vendor == X86_VENDOR_INTEL) isa = 1;
    else if (vendor == X86_VENDOR_AMD || vendor == X86_VENDOR_HYGON) isa = 2;

    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tp_private *priv = tp->private;
        struct tep_event *event = tep_find_event(ctx->tep, tp->id);
        if (event && event->print_fmt.args) {
            struct tep_print_arg *arg = event->print_fmt.args;
            while (arg) {
                struct symbolic_ctx sym_ctx = {ctx, tp->id, 0, 0, NULL, isa, 0, 0};
                int nr_entries, ret;

                tep_symbolic(arg, &sym_ctx);
                /* Only register symbolic() function when there's exactly one __print_symbolic.
                 * Multiple __print_symbolic in one format would require more complex parsing
                 * to determine which field maps to which symbolic table - not supported yet.
                 * This check ensures we only handle the simple, unambiguous case. */
                if (sym_ctx.nr_print_symbolic == 1) {
                    nr_entries = rblist__nr_entries(&ctx->symbolic_table);
                    sym_ctx.do_update = 1;
                    tep_symbolic(arg, &sym_ctx);

                    if (nr_entries != rblist__nr_entries(&ctx->symbolic_table)) {
                        char *function_list = NULL;
                        const char *prefix = priv->function_list ? : "";
                        const char *separator = priv->function_list ? ", " : "";
                        ret = asprintf(&function_list, "%s%ssymbolic('%s.%s', %s)", prefix, separator,
                                        tp->name, sym_ctx.field_name, sym_ctx.field_name);
                        if (ret > 0) {
                            if (priv->function_list)
                                free(priv->function_list);
                            priv->function_list = function_list;
                        }
                    }
                }
                arg = arg->next;
            }
        }
    }
}

static void arg_pointer_register(struct sql_tp_ctx *ctx)
{
    struct tp *tp;
    int i, ret;
    char *function_list;

    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tp_private *priv = tp->private;
        struct tep_event *event = tep_find_event(ctx->tep, tp->id);
        struct tep_print_parse *parse = event ? event->print_fmt.print_cache : NULL;
        while (parse) {
            if (parse->type == PRINT_FMT_ARG_POINTER &&
                parse->arg && parse->arg->type == TEP_PRINT_FIELD) {
                const char *format = parse->format;
                const char *field_name = parse->arg->field.name;
                int func = -1, data_type = 0;

                while (*format) if (*format++ == 'p') break;
                switch (*format) {
                    case 'F': // %pS %ps %pF %pf
                    case 'f':
                    case 'S':
                    case 's': func = KSYMBOL; data_type = SQLITE_INTEGER; ctx->ksymbol = 1; break;
                    case 'I':
                    case 'i': {
                        switch (format[1]) {
                            case '4': // %pI4, %pi4, %p[Ii]4[hnbl]
                                func = (format[2] == 'h' || format[2] == 'l') ? IPV4_HSTR : IPV4_STR;
                                data_type = SQLITE_BLOB;
                                break;
                            case '6': // %pI6, %pi6, %pI6c
                                func = IPV6_STR; data_type = SQLITE_BLOB;
                                break;
                            case 'S': { // %pIS, %piS, %pISc, %pISpc, %p[Ii]S[pfschnbl]
                                char *fmt = (char *)&format[1];
                                func = IPSA_STR; data_type = SQLITE_BLOB;
                                while (*++fmt)
                                    if (*fmt == 'h' || *fmt == 'l') { // host endian
                                        func = IPSA_HSTR;
                                        break;
                                    }
                                break;
                            }
                            default: break;
                        }
                        break;
                    }
                    case 'U': // %pUb %pUB %pUl %pUL little endian(L,l) big endian(B,b)
                        func = (format[1] == 'L' || format[1] == 'l') ? GUID_STR : UUID_STR;
                        data_type = SQLITE_BLOB;
                        break;
                    case 'M': // %pM %pMR %pMF %pm %pmR
                    case 'm': func = MAC_STR; data_type = SQLITE_BLOB; break;
                    default: break;
                }

                if (func >= 0) {
                    const char *prefix = priv->function_list ? : "";
                    const char *separator = priv->function_list ? ", " : "";
                    ret = asprintf(&function_list, "%s%s%s(%s)", prefix, separator, arg_pointer_func[func], field_name);
                    if (ret > 0) {
                        if (priv->function_list)
                            free(priv->function_list);
                        priv->function_list = function_list;
                        ctx->sqlite_funcs[func].data_type = data_type;
                        ctx->sqlite_funcs[func].func_name = arg_pointer_func[func];
                    }
                    if (data_type == SQLITE_BLOB) {
                        struct tep_format_field *field = tep_find_field(event, field_name);
                        if (field)
                            field->flags &= ~TEP_FIELD_IS_STRING;
                    }
                }
            }
            parse = parse->next;
        }
    }

    if (ctx->ksymbol)
        function_resolver_ref();
}

static void sqlite_symbolic(sqlite3_context *context, int argc, sqlite3_value **argv)
{
    struct sql_tp_ctx *ctx = (struct sql_tp_ctx *)sqlite3_user_data(context);
    const char *table_field_name;
    long long value;
    int table_name_len = 0;
    const char *field_name;
    const char *symbol = NULL;
    struct tp *tp;
    int i, j;

    /* Validate argument count */
    if (argc != 2) {
        sqlite3_result_error(context, "symbolic() requires exactly 2 arguments", -1);
        return;
    }

    /* Validate first argument type (table_field_name) */
    if (sqlite3_value_type(argv[0]) != SQLITE_TEXT) {
        sqlite3_result_error(context, "symbolic() first argument must be TEXT", -1);
        return;
    }

    /* Validate second argument type (value) */
    if (sqlite3_value_type(argv[1]) != SQLITE_INTEGER) {
        sqlite3_result_error(context, "symbolic() second argument must be INTEGER", -1);
        return;
    }

    table_field_name = (const char *)sqlite3_value_text(argv[0]);
    value = sqlite3_value_int64(argv[1]);

    /* Check for NULL table_field_name */
    if (!table_field_name) {
        sqlite3_result_error(context, "symbolic() table_field_name is NULL", -1);
        return;
    }

    field_name = strchr(table_field_name, '.'); // "table_name.field_name"
    if (field_name) {
        field_name++; // skip '.'
        table_name_len = field_name - table_field_name - 1;
    } else
        field_name = table_field_name;

    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tp_private *tp_priv = tp->private;
        int match = 0;

        if (!table_name_len) {
            /* No table name specified, match all tables */
            match = 1;
        } else {
            /* Exact match: ensure the table name is followed by '\0' or '.' */
            if ((strncmp(tp->name, table_field_name, table_name_len) == 0 &&
                 tp->name[table_name_len] == '\0') ||
                (strncmp(tp_priv->table_name, table_field_name, table_name_len) == 0 &&
                 tp_priv->table_name[table_name_len] == '\0')) {
                match = 1;
            }
        }

        if (match) {
            for (j = 0; j < tp_priv->nr_fields; j++) {
                struct tep_format_field *field = tp_priv->fields[j];
                if (strcmp(field->name, field_name) == 0) {
                    symbol = symbolic_lookup(ctx, tp->id, field->offset, value);
                    goto found;
                }
            }
        }
    }

found:
    if (symbol)
        sqlite3_result_text(context, symbol, -1, SQLITE_STATIC);
    else
        sqlite3_result_text(context, "UNKNOWN", -1, SQLITE_STATIC);
}

static void sqlite_ksymbol(sqlite3_context *context, int argc, sqlite3_value **argv)
{
    long func = (long)(long *)sqlite3_user_data(context);
    long long value;
    const char *symbol = NULL;

    /* Validate argument count */
    if (argc != 1) {
        sqlite3_result_error(context, "ksymbol() requires exactly 1 argument", -1);
        return;
    }

    /* Validate argument type (value) */
    if (sqlite3_value_type(argv[0]) != SQLITE_INTEGER) {
        sqlite3_result_error(context, "ksymbol() argument must be INTEGER", -1);
        return;
    }

    value = sqlite3_value_int64(argv[0]);
    if (func == KSYMBOL)
        symbol = function_resolver(NULL, (unsigned long long *)&value, NULL);
    else if (func == SYSCALL) {
        if (value >= 0 && value < syscalls_table_size && syscalls_table[value])
            symbol = syscalls_table[value];
    }

    if (symbol)
        sqlite3_result_text(context, symbol, -1, SQLITE_STATIC);
    else
        sqlite3_result_text(context, "??", -1, SQLITE_STATIC);
}

static void sqlite_blob(sqlite3_context *context, int argc, sqlite3_value **argv)
{
    long func = (long)(long *)sqlite3_user_data(context);
    const void *value;
    int bytes;
    char buf[256];
    int len = -1;
    uint32_t addr;
    const unsigned char *u;
    char *symbol = NULL;

    /* Validate argument count */
    if (argc != 1) {
        snprintf(buf, sizeof(buf), "%s() requires exactly 1 argument", arg_pointer_func[func]);
        sqlite3_result_error(context, buf, -1);
        return;
    }

    /* Validate argument type */
    if (sqlite3_value_type(argv[0]) != SQLITE_BLOB) {
        snprintf(buf, sizeof(buf), "%s() argument must be BLOB", arg_pointer_func[func]);
        sqlite3_result_error(context, buf, -1);
        return;
    }

    value = sqlite3_value_blob(argv[0]);
    bytes = sqlite3_value_bytes(argv[0]);

    switch (func) {
        case IPV4_STR: // network endian
            if (bytes != 4) break;
            symbol = (char *)inet_ntop(AF_INET, value, buf, sizeof(buf));
            break;
        case IPV4_HSTR: // host endian
            if (bytes != 4) break;
            addr = htonl(*(uint32_t *)value);
            symbol = (char *)inet_ntop(AF_INET, &addr, buf, sizeof(buf));
            break;
        case IPV6_STR:
            if (bytes != 16) break;
            symbol = (char *)inet_ntop(AF_INET6, value, buf, sizeof(buf));
            break;
        case IPSA_STR: // network endian
        case IPSA_HSTR: { // host endian
            struct sockaddr *sa = (struct sockaddr *)value;

            if (sa->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)sa;

                if (bytes < sizeof(struct sockaddr_in)) break;
                addr = func == IPSA_STR ?
                       sin->sin_addr.s_addr : htonl(sin->sin_addr.s_addr);
                if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
                    len = asprintf(&symbol, "%s:%d", buf, ntohs(sin->sin_port));
                    if (len < 0) symbol = NULL;
                }
            } else if (sa->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

                if (bytes < sizeof(struct sockaddr_in6)) break;
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf))) {
                    len = asprintf(&symbol, "[%s]:%d", buf, ntohs(sin6->sin6_port));
                    if (len < 0) symbol = NULL;
                }
            }
            break;
        }
        case UUID_STR:
            if (bytes != 16) break;
            u = value;
            len = snprintf(buf, sizeof(buf), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                    u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
            if (len > 0) symbol = buf;
            break;
        case GUID_STR:
            if (bytes != 16) break;
            u = value;
            len = snprintf(buf, sizeof(buf), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                    u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
            if (len > 0) symbol = buf;
            break;
        case MAC_STR:
            if (bytes != 6) break;
            u = value;
            len = snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", u[0], u[1], u[2], u[3], u[4], u[5]);
            if (len > 0) symbol = buf;
            break;
        default: break;
    }

    if (symbol)
        sqlite3_result_text(context, symbol, len, symbol == buf ? SQLITE_TRANSIENT : free);
    else
        sqlite3_result_text(context, "??", -1, SQLITE_STATIC);
}

/*
 * Common initialization for both file and memory modes.
 * Sets up tp_private for each tracepoint and registers SQL functions.
 */
static struct sql_tp_ctx *sql_tp_common_init(sqlite3 *sql, struct tp_list *tp_list)
{
    struct sql_tp_ctx *ctx;
    struct tp *tp;
    int i, j;
    /* Stack-allocated array, only used during initialization */
    struct sqlite_func sqlite_funcs[ARG_POINTER_MAX];

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->sql = sql;
    ctx->tp_list = tp_list;
    ctx->tep = tep__ref_light();
    if (!ctx->tep)
        goto failed;

    rblist__init(&ctx->symbolic_table);
    ctx->symbolic_table.node_cmp = symbolic_node_cmp;
    ctx->symbolic_table.node_new = symbolic_node_new;
    ctx->symbolic_table.node_delete = symbolic_node_delete;

    memset(sqlite_funcs, 0, sizeof(sqlite_funcs));
    ctx->sqlite_funcs = sqlite_funcs;

    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tep_event *event = tep_find_event(ctx->tep, tp->id);
        struct tep_format_field **fields;
        struct tp_private *priv;

        fields = event ? tep_event_fields(event) : NULL;
        priv = calloc(1, sizeof(struct tp_private));
        if (!priv) {
            if (fields) free (fields);
            goto failed;
        }
        priv->fields = fields;

        for (j = 0; priv->fields && priv->fields[j]; j++);
        /*
         * nr_fields = 8 system columns + j event-specific columns
         * System columns: _pid, _tid, _time, _cpu, _period,
         *                 common_flags, common_preempt_count, common_pid
         */
        priv->nr_fields = 8 + j;

        priv->table_name = tp->alias ? tp->alias : tp->name;

        if (strcmp(tp->sys, "raw_syscalls") == 0 || strcmp(tp->sys, "syscalls") == 0) {
            ctx->sqlite_funcs[SYSCALL].data_type = SQLITE_INTEGER;
            ctx->sqlite_funcs[SYSCALL].func_name = arg_pointer_func[SYSCALL];
            priv->function_list = strdup(strcmp(tp->sys, "raw_syscalls") == 0 ?
                                         "syscall(id)" : "syscall(__syscall_nr)");
        }
        INIT_LIST_HEAD(&priv->event_list);

        tp->private = priv;
    }

    /* Register symbolic() function */
    symbolic_register(ctx);

    /* Register arg pointer functions */
    arg_pointer_register(ctx);

    if (rblist__nr_entries(&ctx->symbolic_table) > 0 &&
        sqlite3_create_function(ctx->sql, "symbolic", 2, SQLITE_UTF8, ctx,
                                sqlite_symbolic, NULL, NULL) != SQLITE_OK)
        goto failed;

    for (i = 0; i < ARG_POINTER_MAX; i++) {
        if (ctx->sqlite_funcs[i].func_name) {
            void *func = ctx->sqlite_funcs[i].data_type == SQLITE_BLOB ? sqlite_blob : sqlite_ksymbol;
            if (sqlite3_create_function(ctx->sql, ctx->sqlite_funcs[i].func_name, 1, SQLITE_UTF8,
                                       (void *)(unsigned long)i, func, NULL, NULL) != SQLITE_OK)
                goto failed;
        }
    }

    ctx->sqlite_funcs = NULL;
    return ctx;

failed:
    sql_tp_free(ctx);
    return NULL;
}

static int sql_create_table(struct sql_tp_ctx *ctx)
{
    struct tp *tp;
    int i;
    const char *table_fmt = "DROP TABLE IF EXISTS %s; "
        "CREATE TABLE %s ("
                "_pid INTEGER, "
                "_tid INTEGER, "
                "_time INTEGER, "
                "_cpu INTEGER, "
                "_period INTEGER, "
                "common_flags INTEGER, "
                "common_preempt_count INTEGER, "
                "common_pid INTEGER"
                "%s" // raw data columns
        ");";
    const char *insert_fmt = "INSERT INTO %s VALUES(?, ?, ?, ?, ?, ?, ?, ?%s);";
    char buf[1024 + strlen(table_fmt)];
    char *errmsg = NULL;

    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tp_private *priv = (struct tp_private *)tp->private;
        struct tep_format_field **fields = priv->fields;
        char col_buf[1024];
        char ins_buf[512];
        int j = 0, col_len = 0, ins_len = 0;

        while (fields && fields[j]) {
            /* Field type mapping to SQLite types:
             *
             * 1. TEXT: String fields (IS_STRING flag)
             *    - char comm[16];            offset:8;  size:16; -> TEXT
             *    - __data_loc char[] cmd;    offset:40; size:4;  -> TEXT
             *    Note: Fields requiring special format (e.g., %pI4, %pM) have IS_STRING
             *    flag cleared during arg_pointer_register() to be treated as BLOB.
             *    Note: IS_SIGNED flag is no longer reliable for char arrays because:
             *    - arm64 kernel: char is unsigned by default
             *    - kernel commit 3bc753c06dd0 ("kbuild: treat char as always unsigned")
             *
             * 2. BLOB: Array fields (IS_ARRAY flag, without IS_STRING)
             *    - __u8 saddr[4];            offset:28; size:4;  -> BLOB
             *    - long sysctl_mem[3];       offset:40; size:24; -> BLOB
             *    Arrays without string semantics are stored as binary data.
             *
             * 3. INTEGER: All other fields (numeric types)
             *    - int pid;                  offset:24; size:4;  -> INTEGER
             */
            if ((fields[j]->flags & TEP_FIELD_IS_STRING))
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
        col_buf[col_len] = '\0';
        ins_buf[ins_len] = '\0';

        snprintf(buf, sizeof(buf), table_fmt, priv->table_name, priv->table_name, col_buf);
        if (tp->dev->env->verbose)
            printf("CREATE SQL: %s\n", buf);
        if (sqlite3_exec(ctx->sql, buf, NULL, NULL, &errmsg) != SQLITE_OK) {
            fprintf(stderr, "Failed to create table %s: %s\n", priv->table_name, errmsg);
            sqlite3_free(errmsg);
            return -1;
        }
        priv->created_time = time(NULL);

        if (priv->insert_stmt)
            continue;

        snprintf(buf, sizeof(buf), insert_fmt, priv->table_name, ins_buf);
        if (tp->dev->env->verbose)
            printf("INSERT SQL: %s\n", buf);

    #ifdef USE_SQLITE_PREPARE_V3
        if (sqlite3_prepare_v3(ctx->sql, buf, -1, SQLITE_PREPARE_PERSISTENT, &priv->insert_stmt, NULL) != SQLITE_OK) {
    #else
        if (sqlite3_prepare_v2(ctx->sql, buf, -1, &priv->insert_stmt, NULL) != SQLITE_OK) {
    #endif
            fprintf(stderr, "Failed to prepare insert statement for %s: %s\n", priv->table_name, sqlite3_errmsg(ctx->sql));
            return -1;
        }
    }
    return 0;
}

static int sql_tp_file_sample(struct sql_tp_ctx *ctx, struct tp *tp, union perf_event *event)
{
    struct tp_private *priv = tp->private;
    struct sql_sample_type *data = (void *)event->sample.array;
    int idx = 1;
    int i, ret = -1;

    // Reset the statement for new use
    sqlite3_reset(priv->insert_stmt);

    // Bind common fields
    sqlite3_bind_int(priv->insert_stmt, idx++, data->tid_entry.pid);
    sqlite3_bind_int(priv->insert_stmt, idx++, data->tid_entry.tid);
    sqlite3_bind_int64(priv->insert_stmt, idx++, data->time);
    sqlite3_bind_int(priv->insert_stmt, idx++, data->cpu_entry.cpu);
    sqlite3_bind_int64(priv->insert_stmt, idx++, data->period);

    // common_* (common_type removed - use event_id from event_metadata table)
    sqlite3_bind_int(priv->insert_stmt, idx++, data->raw.common.common_flags);
    sqlite3_bind_int(priv->insert_stmt, idx++, data->raw.common.common_preempt_count);
    sqlite3_bind_int(priv->insert_stmt, idx++, data->raw.common.common_pid);

    /* Parse and bind event-specific fields
        *
        * Field type handling must match the SQLite type mapping in sql_create_table():
        *
        * 1. TEXT binding: String fields (IS_STRING flag)
        *    - char comm[16];         -> sqlite3_bind_text()
        *    - __data_loc char[] cmd; -> sqlite3_bind_text() with dynamic offset
        *
        * 2. BLOB binding: Array fields (IS_ARRAY flag, without IS_STRING)
        *    - __u8 saddr[4];         -> sqlite3_bind_blob()
        *    - __data_loc __u8[] buf  -> sqlite3_bind_blob() with dynamic offset
        *
        * 3. INTEGER binding: Numeric fields (default)
        *    - int pid;               -> sqlite3_bind_int64()
        */
    for (i = 0; priv->fields && priv->fields[i]; i++) {
        struct tep_format_field *field = priv->fields[i];
        void *base = data->raw.data;
        long long val = 0;
        void *ptr;
        int len;

        if ((field->flags & TEP_FIELD_IS_STRING)) {
            // TEXT: String fields (IS_STRING flag)
            if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                // Dynamic string: __data_loc char[] field
                ptr = base + *(unsigned short *)(base + field->offset);
                len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
            } else {
                // Fixed string: char field[N]
                ptr = base + field->offset;
                len = -1;
            }
            // Use SQLITE_STATIC for zero-copy: data valid during sqlite3_step()
            sqlite3_bind_text(priv->insert_stmt, idx++, ptr, len, SQLITE_STATIC);
        } else if (field->flags & TEP_FIELD_IS_ARRAY) {
            // BLOB: Array fields without string semantics
            if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                // Dynamic array: __data_loc __u8[] buf
                ptr = base + *(unsigned short *)(base + field->offset);
                len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
            } else {
                // Fixed array: __u8 saddr[4], long sysctl_mem[3]
                ptr = base + field->offset;
                len = field->size;
            }
            // Use SQLITE_STATIC for zero-copy: data valid during sqlite3_step()
            sqlite3_bind_blob(priv->insert_stmt, idx++, ptr, len, SQLITE_STATIC);
        } else {
            // INTEGER: Numeric fields
            // Must respect signedness to correctly bind values to SQLite:
            //   - unsigned char 255 should bind as 255, not -1
            //   - signed char -1 should bind as -1, not 255
            // Using proper type casts ensures correct sign/zero extension to int64.
            bool is_signed = field->flags & TEP_FIELD_IS_SIGNED;
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
                sqlite3_bind_int64(priv->insert_stmt, idx++, val);
            else
                sqlite3_bind_null(priv->insert_stmt, idx++);
        }
    }

    // Execute the insert statement
    if (sqlite3_step(priv->insert_stmt) != SQLITE_DONE) {
        if (tp->dev->env->verbose) {
            fprintf(stderr, "Failed to insert record into %s: %s\n",
                    priv->table_name, sqlite3_errmsg(ctx->sql));
        }
    } else {
        priv->sample_count++;
        if (priv->first_sample_time == 0 || data->time < priv->first_sample_time)
            priv->first_sample_time = data->time;
        if (data->time > priv->last_sample_time)
            priv->last_sample_time = data->time;
        ret = 0;
    }

    return ret;
}

static void sql_tp_file_reset(struct sql_tp_ctx *ctx)
{
    struct tp *tp;
    int i;

    // Finalize all prepared statements before dropping tables
    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tp_private *priv = tp->private;
        if (priv->insert_stmt) {
            sqlite3_finalize(priv->insert_stmt);
            priv->insert_stmt = NULL;
        }
        priv->sample_count = 0;
        priv->first_sample_time = 0;
        priv->last_sample_time = 0;
    }

    // Recreate tables
    if (sql_create_table(ctx) < 0)
        fprintf(stderr, "Failed to recreate tables\n");
}

/*
 * Initialize file mode: events stored in SQLite tables via INSERT.
 * Used when --output2 specifies a database file.
 */
struct sql_tp_ctx *sql_tp_file(sqlite3 *sql, struct tp_list *tp_list)
{
    struct sql_tp_ctx *ctx = sql_tp_common_init(sql, tp_list);
    if (ctx && sql_create_table(ctx) < 0) {
        sql_tp_free(ctx);
        return NULL;
    }

    ctx->sample = sql_tp_file_sample;
    ctx->reset = sql_tp_file_reset;
    return ctx;
}

/*
 * SQLite Virtual Table for memory mode.
 *
 * perf_tp module allows SQL queries to directly access events stored in memory
 * without sqlite3_bind_*() overhead. Fields are extracted on-demand when
 * xColumn() is called, so unused columns have zero cost.
 */
struct perf_tp_table {
    sqlite3_vtab base;              /* Base class. Must be first */
    struct sql_tp_ctx *ctx;
    struct tp *tp;                  /* Associated tracepoint */
    int verbose;
};

/* Cursor for iterating over events in the linked list */
struct perf_tp_cursor {
    sqlite3_vtab_cursor base;       /* Base class. Must be first */
    struct tp_event *start;         /* List head (sentinel), its next is a real tp_event */
    struct tp_event *curr;          /* Current event in iteration */
    /*
     * Constraint filter table built from xBestIndex decisions.
     * Each entry represents one WHERE clause condition on an INTEGER column.
     */
    struct one_op {
        int field;                  /* Column index (0-7: system cols, 8+: event fields) */
        int op;                     /* Comparison operator (EQ, GT, LE, LT, GE, NE) */
        sqlite3_int64 value;        /* Comparison value from sqlite3_value_int64() */
    } *op_table;
    int nr_ops;                     /* Number of active constraints */
};

/* Internal operator codes for constraint filtering */
enum {
    EQ, GT, LE, LT, GE, NE          /* Maps to SQLITE_INDEX_CONSTRAINT_* */
};


static int perf_tp_xConnect(sqlite3 *db, void *pAux, int argc, const char *const*argv,
                            sqlite3_vtab **ppVtab, char **pzErr)
{
    struct perf_tp_table *table;
    struct sql_tp_ctx *ctx = pAux;
    struct tp *tp;
    int i, rc;
    struct tp_private *priv = NULL;

    table = sqlite3_malloc(sizeof(*table));
    if (!table)
        return SQLITE_NOMEM;

    memset(table, 0, sizeof(*table));
    table->ctx = ctx;

    for_each_real_tp(ctx->tp_list, tp, i) {
        priv = tp->private;
        if (strcmp(priv->table_name, argv[2]) == 0) {
            table->tp = tp;
            table->verbose = tp->dev->env->verbose;
            break;
        }
    }

    if (table->tp) {
        const char *table_fmt =
                "CREATE TABLE x ("
                        "_pid INTEGER, "
                        "_tid INTEGER, "
                        "_time INTEGER, "
                        "_cpu INTEGER, "
                        "_period INTEGER, "
                        "common_flags INTEGER, "
                        "common_preempt_count INTEGER, "
                        "common_pid INTEGER"
                        "%s" // raw data columns
                ");";
        char buf[1024 + strlen(table_fmt)];
        struct tep_format_field **fields = priv->fields;
        char col_buf[1024];
        int j = 0, col_len = 0;

        while (fields && fields[j]) {
            /* Field type mapping to SQLite types:
             *
             * 1. TEXT: String fields (IS_STRING flag)
             *    - char comm[16];            offset:8;  size:16; -> TEXT
             *    - __data_loc char[] cmd;    offset:40; size:4;  -> TEXT
             *    Note: Fields requiring special format (e.g., %pI4, %pM) have IS_STRING
             *    flag cleared during arg_pointer_register() to be treated as BLOB.
             *    Note: IS_SIGNED flag is no longer reliable for char arrays because:
             *    - arm64 kernel: char is unsigned by default
             *    - kernel commit 3bc753c06dd0 ("kbuild: treat char as always unsigned")
             *
             * 2. BLOB: Array fields (IS_ARRAY flag, without IS_STRING)
             *    - __u8 saddr[4];            offset:28; size:4;  -> BLOB
             *    Arrays without string semantics are stored as binary data.
             *
             * 3. INTEGER: All other fields (numeric types)
             */
            if ((fields[j]->flags & TEP_FIELD_IS_STRING))
                col_len += snprintf(col_buf + col_len, sizeof(col_buf) - col_len,
                                ", %s TEXT", fields[j]->name);
            else if (fields[j]->flags & TEP_FIELD_IS_ARRAY)
                col_len += snprintf(col_buf + col_len, sizeof(col_buf) - col_len,
                                ", %s BLOB", fields[j]->name);
            else
                col_len += snprintf(col_buf + col_len, sizeof(col_buf) - col_len,
                                ", %s INTEGER", fields[j]->name);
            j++;
        }
        col_buf[col_len] = '\0';

        snprintf(buf, sizeof(buf), table_fmt, col_buf);
        if (table->verbose)
            printf("DECLARE SQL: %s\n", buf);

        rc = sqlite3_declare_vtab(db, buf);
        if (rc != SQLITE_OK) {
            *pzErr = sqlite3_mprintf("Failed to declare virtual table %s: %s",
                                     priv->table_name, sqlite3_errmsg(db));
            goto error;
        }

        priv->created_time = time(NULL);
    } else {
        *pzErr = sqlite3_mprintf("No such event: %s", argv[2]);
        rc = SQLITE_ERROR;
        goto error;
    }

    *ppVtab = &table->base;
    return SQLITE_OK;

error:
    if (table) sqlite3_free(table);
    return rc;
}

static int perf_tp_xCreate(sqlite3 *db, void *pAux, int argc, const char *const*argv,
                           sqlite3_vtab **ppVtab, char **pzErr)
{
    int rc = perf_tp_xConnect(db, pAux, argc, argv, ppVtab, pzErr);
    return rc;
}

static const char *IndexOpName(unsigned char op)
{
    switch(op) {
        case SQLITE_INDEX_CONSTRAINT_EQ:        return "EQ";
        case SQLITE_INDEX_CONSTRAINT_GT:        return "GT";
        case SQLITE_INDEX_CONSTRAINT_LE:        return "LE";
        case SQLITE_INDEX_CONSTRAINT_LT:        return "LT";
        case SQLITE_INDEX_CONSTRAINT_GE:        return "GE";
        case SQLITE_INDEX_CONSTRAINT_MATCH:     return "MATCH";
    #if SQLITE_VERSION_NUMBER > 3010000
        case SQLITE_INDEX_CONSTRAINT_LIKE:      return "LIKE";
        case SQLITE_INDEX_CONSTRAINT_GLOB:      return "GLOB";
        case SQLITE_INDEX_CONSTRAINT_REGEXP:    return "REGEXP";
    #endif
    #if SQLITE_VERSION_NUMBER > 3021000
        case SQLITE_INDEX_CONSTRAINT_NE:        return "NE";
        case SQLITE_INDEX_CONSTRAINT_ISNOT:     return "ISNOT";
        case SQLITE_INDEX_CONSTRAINT_ISNOTNULL: return "ISNOTNULL";
        case SQLITE_INDEX_CONSTRAINT_ISNULL:    return "ISNULL";
        case SQLITE_INDEX_CONSTRAINT_IS:        return "IS";
    #endif
    #if SQLITE_VERSION_NUMBER > 3038000
        case SQLITE_INDEX_CONSTRAINT_LIMIT:     return "LIMIT";
        case SQLITE_INDEX_CONSTRAINT_OFFSET:    return "OFFSET";
    #endif
    #ifdef SQLITE_INDEX_CONSTRAINT_FUNCTION
        case SQLITE_INDEX_CONSTRAINT_FUNCTION:  return "FUNCTION";
    #endif
        default: break;
    }
    return "UNKNOWN";
}

static const char *ColumnName(struct perf_tp_table *table, int i)
{
    switch (i) {
        // common fields
        case 0: return "_pid";
        case 1: return "_tid";
        case 2: return "_time";
        case 3: return "_cpu";
        case 4: return "_period";
        // common_* (common_type removed - use event_id from event_metadata table)
        case 5: return "common_flags";
        case 6: return "common_preempt_count";
        case 7: return "common_pid";
        default: {
            struct tp_private *priv = table->tp->private;
            struct tep_format_field *field = i < priv->nr_fields ? priv->fields[i - 8] : NULL;
            if (field)
                return field->name;
            break;
        }
    }
    return "unknown";
}

/*
 * Check if column i is an INTEGER type (suitable for constraint filtering).
 * System columns (0-7) are always integers. Event fields depend on TEP flags.
 */
static inline bool Column_isInt(struct perf_tp_table *table, int i)
{
    if (i < 8) return 1;
    else {
        struct tp_private *priv = table->tp->private;
        struct tep_format_field *field = i < priv->nr_fields ? priv->fields[i - 8] : NULL;
        if (field && !(field->flags & TEP_FIELD_IS_STRING) &&
                     !(field->flags & TEP_FIELD_IS_ARRAY))
            return 1;
        else
            return 0;
    }
}

/*
 * xBestIndex: Query planner interface.
 *
 * Analyzes WHERE clause constraints and communicates filtering strategy to xFilter:
 * - idxNum: Number of usable INTEGER constraints
 * - idxStr: Encoded constraint info as "column,op;column,op;..." string
 * - argvIndex: Maps constraint values to xFilter's argv[] array
 * - omit=1: Tells SQLite we handle filtering (no double-check needed)
 *
 * Only INTEGER columns support constraint pushdown (EQ, GT, LE, LT, GE, NE).
 * STRING/BLOB columns are filtered by SQLite after xColumn returns.
 */
static int perf_tp_xBestIndex(sqlite3_vtab *pVtab, sqlite3_index_info *pIdxInfo)
{
    struct perf_tp_table *table = (void *)pVtab;
    struct tp_private * __maybe_unused priv;
    int i, column, op;
    int idx_num = 0;
    char *idx_str = NULL;

    if (table->verbose) {
    #if SQLITE_VERSION_NUMBER > 3010000
        printf("colUsed: 0x%016llx, ", pIdxInfo->colUsed);
        for_each_set_bit(i, (unsigned long *)&pIdxInfo->colUsed, 64) {
            printf("%s ", ColumnName(table, i));
        }
        printf("\n");
    #endif
        for (i = 0; i < pIdxInfo->nOrderBy; i++) {
            printf("OrderBy[%d]: %s %s\n", i,
                        ColumnName(table, pIdxInfo->aOrderBy[i].iColumn),
                        pIdxInfo->aOrderBy[i].desc ? "DESC" : "ASC");
        }
    }

    for (i = 0; i < pIdxInfo->nConstraint; i++) {
        if (!pIdxInfo->aConstraint[i].usable)
            continue;

        if (table->verbose)
            printf("Constraint[%d]: %s %s ?\n", i,
                        ColumnName(table, pIdxInfo->aConstraint[i].iColumn),
                        IndexOpName(pIdxInfo->aConstraint[i].op));

        column = pIdxInfo->aConstraint[i].iColumn;
        switch(pIdxInfo->aConstraint[i].op) {
            case SQLITE_INDEX_CONSTRAINT_EQ: op = EQ; break;
            case SQLITE_INDEX_CONSTRAINT_GT: op = GT; break;
            case SQLITE_INDEX_CONSTRAINT_LE: op = LE; break;
            case SQLITE_INDEX_CONSTRAINT_LT: op = LT; break;
            case SQLITE_INDEX_CONSTRAINT_GE: op = GE; break;
        #if SQLITE_VERSION_NUMBER > 3021000
            case SQLITE_INDEX_CONSTRAINT_NE: op = NE; break;
        #endif
            default: continue;
        }
        if (Column_isInt(table, column)) {
            if (!idx_str) {
                idx_str = sqlite3_mprintf("%d,%d;", column, op);
                if (!idx_str) continue;
            } else {
                char *tmp = sqlite3_mprintf("%s%d,%d;", idx_str, column, op);
                if (tmp) {
                    sqlite3_free(idx_str);
                    idx_str = tmp;
                } else continue;
            }
            idx_num++;
            pIdxInfo->aConstraintUsage[i].argvIndex = idx_num;
            pIdxInfo->aConstraintUsage[i].omit = 1;
        }
    }

    if (idx_num) {
        pIdxInfo->idxNum = idx_num;
        pIdxInfo->idxStr = idx_str;
        pIdxInfo->needToFreeIdxStr = 1;
        pIdxInfo->estimatedCost = 100;
    } else
        pIdxInfo->estimatedCost = 1000;

    /*
     * Collect colUsed during initialization phase (priv->init == true).
     * OR accumulates columns from multi-statement queries like:
     *   --query "select pid from sched_wakeup; select comm from sched_wakeup;"
     * After init, col_used determines whether to use Virtual Table (col_used==0)
     * or create a regular table with only the needed columns (col_used!=0).
     */
    #if SQLITE_VERSION_NUMBER > 3010000
    priv = table->tp->private;
    if (priv->init)
        priv->col_used |= pIdxInfo->colUsed;
    #endif
    return SQLITE_OK;
}

static int perf_tp_xDisconnect(sqlite3_vtab *pVtab)
{
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

static int perf_tp_xOpen(sqlite3_vtab *pVtab, sqlite3_vtab_cursor **ppCursor)
{
    struct perf_tp_table *table = (void *)pVtab;
    struct tp_private *priv = table->tp->private;
    struct perf_tp_cursor *cursor;

    cursor = sqlite3_malloc(sizeof(*cursor));
    if (!cursor)
        return SQLITE_NOMEM;

    memset (cursor, 0, sizeof(*cursor));
    cursor->start = list_entry(&priv->event_list, struct tp_event, link);
    *ppCursor = &cursor->base;
    return SQLITE_OK;
}

static int perf_tp_xClose(sqlite3_vtab_cursor *pCursor)
{
    struct perf_tp_cursor *cursor = (void *)pCursor;
    if (cursor->op_table)
        sqlite3_free(cursor->op_table);
    sqlite3_free(pCursor);
    return SQLITE_OK;
}

/*
 * Extract INTEGER field value from event for constraint comparison.
 * Used by xNext to filter events against op_table conditions.
 * Only called for INTEGER columns (validated by Column_isInt in xBestIndex).
 */
static inline sqlite3_int64 perf_tp_field(struct perf_tp_table *table, struct tp_event *e, int i)
{
    struct sql_sample_type *data = (void *)e->event.sample.array;
    switch (i) {
        // common fields
        case 0: return data->tid_entry.pid;
        case 1: return data->tid_entry.tid;
        case 2: return data->time;
        case 3: return data->cpu_entry.cpu;
        case 4: return data->period;

        // common_* (common_type removed - use event_id from event_metadata table)
        case 5: return data->raw.common.common_flags;
        case 6: return data->raw.common.common_preempt_count;
        case 7: return data->raw.common.common_pid;
        // event-specific fields
        default: {
            struct tp_private *priv = table->tp->private;
            struct tep_format_field *field = priv->fields[i - 8];
            void *base = data->raw.data;
            sqlite3_int64 val = 0;
            // INTEGER: Numeric fields
            bool is_signed = field->flags & TEP_FIELD_IS_SIGNED;
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

            return val;
        }
    }
    return -1;
}

/*
 * xNext: Advance cursor to next matching event.
 *
 * If op_table is set (constraints from xBestIndex), filter events by evaluating
 * all conditions. Event must satisfy ALL constraints (AND logic) to be returned.
 * Skips non-matching events until a match is found or list exhausted.
 */
static int perf_tp_xNext(sqlite3_vtab_cursor *pCursor)
{
    struct perf_tp_cursor *cursor = (void *)pCursor;
    sqlite3_int64 value;
    int i;

    while (1) {
        cursor->curr = list_next_entry(cursor->curr, link);

        /* No constraints or reached end of list */
        if (!cursor->nr_ops ||
            cursor->curr == cursor->start)
            break;

        /* Check all constraints (AND logic) */
        for (i = 0; i < cursor->nr_ops; i++) {
            value = perf_tp_field((void *)pCursor->pVtab, cursor->curr, cursor->op_table[i].field);
            switch (cursor->op_table[i].op) {
                case EQ: if (value == cursor->op_table[i].value) break; else goto next;
                case GT: if (value >  cursor->op_table[i].value) break; else goto next;
                case LE: if (value <= cursor->op_table[i].value) break; else goto next;
                case LT: if (value <  cursor->op_table[i].value) break; else goto next;
                case GE: if (value >= cursor->op_table[i].value) break; else goto next;
                case NE: if (value != cursor->op_table[i].value) break; else goto next;
                default: goto next;
            }
        }
        break; /* all conditions met */
    next:
        continue;
    }
    return SQLITE_OK;
}

/*
 * Convert SQL query planner constraints to kernel trace event filter.
 *
 * During initialization (priv->init), generate ftrace_filter from op_table.
 * Supports multiple xFilter calls with logical OR relationships between constraints.
 *
 * Only fields supported by kernel ftrace filter are included:
 *   - field == 3 (_cpu)  -> "CPU" (ftrace built-in variable)
 *   - field > 4          -> event fields (common_*, event-specific)
 *
 * Excluded fields (no kernel filter equivalent):
 *   - field 0 (_pid), field 1 (_tid), field 2 (_time), field 4 (_period)
 *
 * Multiple constraints from different xFilter calls are combined with || operator:
 *   - First call: pid > 1000 -> filter = "pid>1000"
 *   - Second call: prio == 120 -> filter = "(pid>1000)||(prio==120)"
 *
 * The filter is stored in priv->ftrace_filter and applied later by tp_list_apply_filter().
 */
static inline void perf_tp_op_to_filter(struct perf_tp_cursor *cursor)
{
    int i;
    const char *op_str[] = {"==", ">", "<=", "<", ">=", "!="};
    struct perf_tp_table *table = (void *)cursor->base.pVtab;
    struct tp_private *priv = table->tp->private;

    if (table->verbose) {
        for (i = 0; i < cursor->nr_ops; i++) {
            printf("FILTER[%d]: %s %s %lld\n", i,
                    ColumnName((void *)cursor->base.pVtab, cursor->op_table[i].field),
                    op_str[cursor->op_table[i].op], cursor->op_table[i].value);
        }
    }

    /* Generate kernel filter only during init and if not already set */
    if (priv->init && !table->tp->filter) {
        char *filter = NULL;
        for (i = 0; i < cursor->nr_ops; i++) {
            /* Only include fields supported by kernel ftrace filter */
            if (cursor->op_table[i].field > 4 ||
                cursor->op_table[i].field == 3) {
                char *tmp;
                const char *name;

                if (cursor->op_table[i].field == 3) name = "CPU";
                else name = ColumnName((void *)cursor->base.pVtab, cursor->op_table[i].field);

                tmp = sqlite3_mprintf("%s%s%s%s%lld", filter ?: "", filter ? "&&" : "",
                        name, op_str[cursor->op_table[i].op], cursor->op_table[i].value);
                if (tmp) {
                    if (filter) sqlite3_free(filter);
                    filter = tmp;
                }
            }
        }
        if (filter) {
            if (!priv->ftrace_filter)
                priv->ftrace_filter = filter;
            else {
                const char *fmt = priv->ftrace_filter[0] == '(' ? "%s||(%s)" : "(%s)||(%s)";
                char *tmp = sqlite3_mprintf(fmt, priv->ftrace_filter, filter);
                if (tmp) {
                    sqlite3_free(priv->ftrace_filter);
                    priv->ftrace_filter = tmp;
                }
                sqlite3_free(filter);
            }
        }
    }
}

/*
 * xFilter: Initialize cursor and build constraint filter table.
 *
 * Parses idxStr ("column,op;column,op;...") from xBestIndex and binds
 * actual values from argv[] to build op_table for xNext filtering.
 * Then calls xNext to position cursor at first matching event.
 */
static int perf_tp_xFilter(sqlite3_vtab_cursor *pCursor, int idxNum, const char *idxStr,
                           int argc, sqlite3_value **argv)
{
    struct perf_tp_cursor *cursor = (void *)pCursor;
    cursor->curr = cursor->start;

    /* Reset previous filter state */
    if (cursor->op_table) {
        sqlite3_free(cursor->op_table);
        cursor->op_table = NULL;
        cursor->nr_ops = 0;
    }

    /* Parse idxStr and bind constraint values from argv[] */
    if (idxNum && idxStr && argc == idxNum) {
        int column, op, i = 0;
        const char *ptr = idxStr;

        cursor->op_table = sqlite3_malloc(idxNum * sizeof(*cursor->op_table));
        if (cursor->op_table) {
            while (sscanf(ptr, "%d,%d;", &column, &op) == 2) {
                cursor->op_table[i].field = column;
                cursor->op_table[i].op = op;
                cursor->op_table[i].value = sqlite3_value_int64(argv[i]);
                while (*ptr && *ptr != ';') ptr++;
                if (*ptr == ';') ptr++;
                i++;
            }
            if (i != idxNum) {
                sqlite3_free(cursor->op_table);
                cursor->op_table = NULL;
            } else
                cursor->nr_ops = i;
            perf_tp_op_to_filter(cursor);
        }
    }
    /* Position cursor at first matching event */
    return perf_tp_xNext(pCursor);
}

static int perf_tp_xEof(sqlite3_vtab_cursor *pCursor)
{
    struct perf_tp_cursor *cursor = (void *)pCursor;
    return cursor->curr == cursor->start;
}

static int perf_tp_xColumn(sqlite3_vtab_cursor *pCursor, sqlite3_context *ctx, int i)
{
    struct perf_tp_table *table = (void *)pCursor->pVtab;
    struct perf_tp_cursor *cursor = (void *)pCursor;
    struct tp_event *e = cursor->curr;
    struct sql_sample_type *data = (void *)e->event.sample.array;

    switch (i) {
        // common fields
        case 0: sqlite3_result_int(ctx, data->tid_entry.pid); break;
        case 1: sqlite3_result_int(ctx, data->tid_entry.tid); break;
        case 2: sqlite3_result_int64(ctx, data->time); break;
        case 3: sqlite3_result_int(ctx, data->cpu_entry.cpu); break;
        case 4: sqlite3_result_int64(ctx, data->period); break;

        // common_* (common_type removed - use event_id from event_metadata table)
        case 5: sqlite3_result_int(ctx, data->raw.common.common_flags); break;
        case 6: sqlite3_result_int(ctx, data->raw.common.common_preempt_count); break;
        case 7: sqlite3_result_int(ctx, data->raw.common.common_pid); break;

        // event-specific fields
        default: {
            struct tp_private *priv = table->tp->private;
            struct tep_format_field *field = i < priv->nr_fields ? priv->fields[i - 8] : NULL;
            void *base = data->raw.data;
            long long val = 0;
            void *ptr;
            int len;

            if (!field)
                return SQLITE_ERROR;

            if ((field->flags & TEP_FIELD_IS_STRING)) {
                // TEXT: String fields (IS_STRING flag)
                if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                    // Dynamic string: __data_loc char[] field
                    ptr = base + *(unsigned short *)(base + field->offset);
                    len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
                } else {
                    // Fixed string: char field[N]
                    ptr = base + field->offset;
                    len = -1;
                }
                // Use SQLITE_STATIC for zero-copy: data valid during sqlite3_step()
                sqlite3_result_text(ctx, ptr, len, SQLITE_STATIC);
            } else if (field->flags & TEP_FIELD_IS_ARRAY) {
                // BLOB: Array fields without string semantics
                if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                    // Dynamic array: __data_loc __u8[] buf
                    ptr = base + *(unsigned short *)(base + field->offset);
                    len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
                } else {
                    // Fixed array: __u8 saddr[4], long sysctl_mem[3]
                    ptr = base + field->offset;
                    len = field->size;
                }
                // Use SQLITE_STATIC for zero-copy: data valid during sqlite3_step()
                sqlite3_result_blob(ctx, ptr, len, SQLITE_STATIC);
            } else {
                // INTEGER: Numeric fields
                // Must respect signedness to correctly bind values to SQLite:
                //   - unsigned char 255 should bind as 255, not -1
                //   - signed char -1 should bind as -1, not 255
                // Using proper type casts ensures correct sign/zero extension to int64.
                bool is_signed = field->flags & TEP_FIELD_IS_SIGNED;
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
                    sqlite3_result_int64(ctx, val);
                else
                    sqlite3_result_null(ctx);
            }
        }
        break;
    }
    return SQLITE_OK;
}

static int perf_tp_xRowid(sqlite3_vtab_cursor *pCursor, sqlite_int64 *pRowid)
{
    struct perf_tp_cursor *cursor = (void *)pCursor;
    *pRowid = cursor->curr->rowid;
    return SQLITE_OK;
}

static sqlite3_module perf_tp_module = {
    0,                       /* iVersion */
    perf_tp_xCreate,         /* xCreate */
    perf_tp_xConnect,        /* xConnect */
    perf_tp_xBestIndex,      /* xBestIndex */
    perf_tp_xDisconnect,     /* xDisconnect */
    perf_tp_xDisconnect,     /* xDestroy */
    perf_tp_xOpen,           /* xOpen - open a cursor */
    perf_tp_xClose,          /* xClose - close a cursor */
    perf_tp_xFilter,         /* xFilter - configure scan constraints */
    perf_tp_xNext,           /* xNext - advance a cursor */
    perf_tp_xEof,            /* xEof - check for end of scan */
    perf_tp_xColumn,         /* xColumn - read data */
    perf_tp_xRowid,          /* xRowid - read data */
    0,                       /* xUpdate */
    0,                       /* xBegin */
    0,                       /* xSync */
    0,                       /* xCommit */
    0,                       /* xRollback */
    0,                       /* xFindMethod */
    0,                       /* xRename */
    0,                       /* xSavepoint */
    0,                       /* xRelease */
    0                        /* xRollbackTo */
};

/*
 * Create regular tables for events where col_used != 0.
 *
 * Performance optimization: Virtual Table xNext/xEof/xColumn calls have overhead.
 * When query only needs specific columns (col_used != 0), create a regular table
 * with only those columns and use INSERT for better performance.
 *
 * col_used == 0 cases (continue using Virtual Table):
 *   - "select * from sched_wakeup" (all columns)
 *   - "select COUNT(*) from sched_wakeup" (no specific columns)
 *   - "select * from event_metadata" (different table)
 *   - SQLite < 3.10.0 (colUsed not available)
 */
static int sql_tp_mem_create_table(struct sql_tp_ctx *ctx)
{
    struct tp *tp;
    int i;
    const char *table_fmt = "DROP TABLE IF EXISTS %s; CREATE TABLE %s (%s);";
    const char *insert_fmt = "INSERT INTO %s VALUES(%s);";
    char buf[1024 + strlen(table_fmt)];
    char *errmsg = NULL;

    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tp_private *priv = (struct tp_private *)tp->private;
        struct tep_format_field **fields = priv->fields;
        char col_buf[1024];
        char ins_buf[512];
        int j, col_len = 0, ins_len = 0;

        /* If all columns selected or too many fields, fall back to Virtual Table */
        if (priv->nr_fields > BITS_PER_LONG ||
            priv->col_used == GENMASK(priv->nr_fields-1, 0))
            priv->col_used = 0;

        /* col_used == 0: continue using Virtual Table for this event */
        if (priv->col_used == 0)
            continue;

        #define COLUMN(i, name) \
        if (test_bit(i, &priv->col_used)) { \
            col_len += snprintf(col_buf + col_len, sizeof(col_buf) - col_len, "%s INTEGER, ", name); \
            if (!priv->insert_stmt) \
                ins_len += snprintf(ins_buf + ins_len, sizeof(ins_buf) - ins_len, "?, "); \
        }
        COLUMN(0, "_pid");
        COLUMN(1, "_tid");
        COLUMN(2, "_time");
        COLUMN(3, "_cpu");
        COLUMN(4, "_period");
        COLUMN(5, "common_flags");
        COLUMN(6, "common_preempt_count");
        COLUMN(7, "common_pid");
        #undef COLUMN

        for (j = 0; fields && fields[j]; j++) {
            if (!test_bit(8 + j, &priv->col_used))
                continue;

            if ((fields[j]->flags & TEP_FIELD_IS_STRING))
                col_len += snprintf(col_buf + col_len, sizeof(col_buf) - col_len,
                                "%s TEXT, ", fields[j]->name);
            else if (fields[j]->flags & TEP_FIELD_IS_ARRAY)
                col_len += snprintf(col_buf + col_len, sizeof(col_buf) - col_len,
                                "%s BLOB, ", fields[j]->name);
            else
                col_len += snprintf(col_buf + col_len, sizeof(col_buf) - col_len,
                                "%s INTEGER, ", fields[j]->name);
            if (!priv->insert_stmt)
                ins_len += snprintf(ins_buf + ins_len, sizeof(ins_buf) - ins_len,
                                "?, ");
        }
        if (col_len) col_len -= 2; // remove ", "
        if (ins_len) ins_len -= 2; // remove ", "
        col_buf[col_len] = '\0';
        ins_buf[ins_len] = '\0';

        snprintf(buf, sizeof(buf), table_fmt, priv->table_name, priv->table_name, col_buf);
        if (tp->dev->env->verbose)
            printf("CREATE SQL: %s\n", buf);
        if (sqlite3_exec(ctx->sql, buf, NULL, NULL, &errmsg) != SQLITE_OK) {
            fprintf(stderr, "Failed to create table %s: %s\n", priv->table_name, errmsg);
            sqlite3_free(errmsg);
            return -1;
        }
        priv->created_time = time(NULL);

        if (priv->insert_stmt)
            continue;

        snprintf(buf, sizeof(buf), insert_fmt, priv->table_name, ins_buf);
        if (tp->dev->env->verbose)
            printf("INSERT SQL: %s\n", buf);

    #ifdef USE_SQLITE_PREPARE_V3
        if (sqlite3_prepare_v3(ctx->sql, buf, -1, SQLITE_PREPARE_PERSISTENT, &priv->insert_stmt, NULL) != SQLITE_OK) {
    #else
        if (sqlite3_prepare_v2(ctx->sql, buf, -1, &priv->insert_stmt, NULL) != SQLITE_OK) {
    #endif
            fprintf(stderr, "Failed to prepare insert statement for %s: %s\n", priv->table_name, sqlite3_errmsg(ctx->sql));
            return -1;
        }
    }
    return 0;
}

/*
 * Memory mode sample handler.
 *
 * Two paths based on col_used:
 *   col_used == 0: Store raw event in linked list (Virtual Table access)
 *   col_used != 0: Parse and INSERT only needed columns (regular table)
 */
static int sql_tp_mem_sample(struct sql_tp_ctx *ctx, struct tp *tp, union perf_event *event)
{
    struct tp_private *priv = tp->private;
    struct sql_sample_type *data = (void *)event->sample.array;
    int idx = 1;
    int i, ret = -1;

    if (priv->col_used == 0) {
        /* Virtual Table path: store raw event for on-demand field extraction */
        struct tp_event *e = malloc(offsetof(struct tp_event, event) + event->header.size);
        if (e) {
            e->rowid = priv->rowid++;
            memcpy(&e->event, event, event->header.size);
            list_add_tail(&e->link, &priv->event_list);
            ret = 0;
        }
    } else {
        /* Regular table path: parse and bind only needed columns */
        sqlite3_reset(priv->insert_stmt);

        // Bind common fields
        if (test_bit(0, &priv->col_used))
            sqlite3_bind_int(priv->insert_stmt, idx++, data->tid_entry.pid);
        if (test_bit(1, &priv->col_used))
            sqlite3_bind_int(priv->insert_stmt, idx++, data->tid_entry.tid);
        if (test_bit(2, &priv->col_used))
            sqlite3_bind_int64(priv->insert_stmt, idx++, data->time);
        if (test_bit(3, &priv->col_used))
            sqlite3_bind_int(priv->insert_stmt, idx++, data->cpu_entry.cpu);
        if (test_bit(4, &priv->col_used))
            sqlite3_bind_int64(priv->insert_stmt, idx++, data->period);

        // common_* (common_type removed - use event_id from event_metadata table)
        if (test_bit(5, &priv->col_used))
            sqlite3_bind_int(priv->insert_stmt, idx++, data->raw.common.common_flags);
        if (test_bit(6, &priv->col_used))
            sqlite3_bind_int(priv->insert_stmt, idx++, data->raw.common.common_preempt_count);
        if (test_bit(7, &priv->col_used))
            sqlite3_bind_int(priv->insert_stmt, idx++, data->raw.common.common_pid);

        /* Parse and bind event-specific fields */
        for (i = 0; priv->fields && priv->fields[i]; i++) {
            struct tep_format_field *field = priv->fields[i];
            void *base = data->raw.data;
            long long val = 0;
            void *ptr;
            int len;

            if (!test_bit(8 + i, &priv->col_used))
                continue;

            if ((field->flags & TEP_FIELD_IS_STRING)) {
                // TEXT: String fields (IS_STRING flag)
                if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                    // Dynamic string: __data_loc char[] field
                    ptr = base + *(unsigned short *)(base + field->offset);
                    len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
                } else {
                    // Fixed string: char field[N]
                    ptr = base + field->offset;
                    len = -1;
                }
                // Use SQLITE_STATIC for zero-copy: data valid during sqlite3_step()
                sqlite3_bind_text(priv->insert_stmt, idx++, ptr, len, SQLITE_STATIC);
            } else if (field->flags & TEP_FIELD_IS_ARRAY) {
                // BLOB: Array fields without string semantics
                if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                    // Dynamic array: __data_loc __u8[] buf
                    ptr = base + *(unsigned short *)(base + field->offset);
                    len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
                } else {
                    // Fixed array: __u8 saddr[4], long sysctl_mem[3]
                    ptr = base + field->offset;
                    len = field->size;
                }
                // Use SQLITE_STATIC for zero-copy: data valid during sqlite3_step()
                sqlite3_bind_blob(priv->insert_stmt, idx++, ptr, len, SQLITE_STATIC);
            } else {
                // INTEGER: Numeric fields
                bool is_signed = field->flags & TEP_FIELD_IS_SIGNED;
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
                    sqlite3_bind_int64(priv->insert_stmt, idx++, val);
                else
                    sqlite3_bind_null(priv->insert_stmt, idx++);
            }
        }

        // Execute the insert statement
        if (sqlite3_step(priv->insert_stmt) != SQLITE_DONE) {
            if (tp->dev->env->verbose) {
                fprintf(stderr, "Failed to insert record into %s: %s\n",
                        priv->table_name, sqlite3_errmsg(ctx->sql));
            }
        } else
            ret = 0;
    }

    if (ret == 0) {
        priv->sample_count++;
        if (priv->first_sample_time == 0 || data->time < priv->first_sample_time)
            priv->first_sample_time = data->time;
        if (data->time > priv->last_sample_time)
            priv->last_sample_time = data->time;
    }
    return ret;
}

/* Memory mode reset: free all events from linked lists after each interval */
static void sql_tp_mem_reset(struct sql_tp_ctx *ctx)
{
    struct tp *tp;
    int i;

    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tp_private *priv = tp->private;
        struct tp_event *e, *n;

        list_for_each_entry_safe(e, n, &priv->event_list, link) {
            __list_del_entry(&e->link);
            free(e);
        }
        if (priv->insert_stmt) {
            sqlite3_finalize(priv->insert_stmt);
            priv->insert_stmt = NULL;
        }
        priv->rowid = 0;
        priv->created_time = time(NULL);
        priv->sample_count = 0;
        priv->first_sample_time = 0;
        priv->last_sample_time = 0;
    }

    // Recreate tables
    if (sql_tp_mem_create_table(ctx) < 0)
        fprintf(stderr, "Failed to recreate tables\n");
}

/*
 * Try to execute query to trigger xBestIndex and collect colUsed.
 *
 * Supports multi-statement queries separated by ';'. Failures are ignored
 * because some tables (like event_metadata) don't exist yet during init,
 * but event Virtual Tables are already available for colUsed collection.
 */
static int sql_tp_mem_try_exec(sqlite3 *sql, const char *query)
{
    sqlite3_stmt *stmt;
    const char *next_query;
    int ret = -1;

    while (1) {
    #ifdef USE_SQLITE_PREPARE_V3
        if (sqlite3_prepare_v3(sql, query, -1, SQLITE_PREPARE_PERSISTENT, &stmt, &next_query) == SQLITE_OK) {
    #else
        if (sqlite3_prepare_v2(sql, query, -1, &stmt, &next_query) == SQLITE_OK) {
    #endif
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            ret = 0;
        }
        /* Continue to next statement even if current one failed */
        if (*next_query) query = next_query;
        else break;
    }
    return ret;
}

/*
 * Initialize memory mode: events stored in linked list, accessed via Virtual Table.
 * Used when no --output2 is specified (in-memory database).
 *
 * Initialization flow:
 *   1. Create Virtual Tables for all events (enables xBestIndex calls)
 *   2. Set priv->init = 1 to enable colUsed collection
 *   3. Execute --query to trigger xBestIndex and collect colUsed
 *   4. Create regular tables for events with col_used != 0
 *   5. Set priv->init = 0 to stop colUsed collection
 *
 * After init, col_used is fixed for the session (--query doesn't change).
 */
struct sql_tp_ctx *sql_tp_mem(sqlite3 *sql, struct tp_list *tp_list, const char *query)
{
    struct sql_tp_ctx *ctx = sql_tp_common_init(sql, tp_list);
    const char *vtable_fmt = "CREATE VIRTUAL TABLE IF NOT EXISTS %s USING perf_tp";
    struct tp *tp;
    int i;
    char buf[128];
    char *errmsg;

    if (ctx) {
        /* Register perf_tp virtual table module */
        if (sqlite3_create_module(ctx->sql, "perf_tp", &perf_tp_module, ctx) != SQLITE_OK) {
            fprintf(stderr, "Failed to create perf_tp module: %s\n", sqlite3_errmsg(ctx->sql));
            goto failed;
        }
        /* Step 1-2: Create Virtual Tables and enable colUsed collection */
        for_each_real_tp(ctx->tp_list, tp, i) {
            struct tp_private *priv = (struct tp_private *)tp->private;

            snprintf(buf, sizeof(buf), vtable_fmt, priv->table_name);
            if (tp->dev->env->verbose)
                printf("CREATE VTABLE SQL: %s\n", buf);
            if (sqlite3_exec(ctx->sql, buf, NULL, NULL, &errmsg) != SQLITE_OK) {
                fprintf(stderr, "Failed to create vtable %s: %s\n", priv->table_name, errmsg);
                sqlite3_free(errmsg);
                goto failed;
            }
            priv->init = 1;  /* Enable colUsed collection in xBestIndex */
        }

        /* Step 3-4: Execute query to collect colUsed, then create optimized tables */
        if (query && query[0]) {
            sql_tp_mem_try_exec(ctx->sql, query);
            if (sql_tp_mem_create_table(ctx) < 0)
                goto failed;
        }

        /* Step 5: Disable colUsed collection */
        for_each_real_tp(ctx->tp_list, tp, i) {
            struct tp_private *priv = (struct tp_private *)tp->private;
            priv->init = 0;
            if (!tp->filter && priv->ftrace_filter) {
                tp->filter = strdup(priv->ftrace_filter);
                printf("%s:%s SQL Query planner filter: %s\n", tp->sys, tp->name, tp->filter);
            }
        }

        ctx->sample = sql_tp_mem_sample;
        ctx->reset = sql_tp_mem_reset;
        return ctx;
    }

failed:
    if (ctx)
        sql_tp_free(ctx);
    return NULL;
}

void sql_tp_free(struct sql_tp_ctx *ctx)
{
    struct tp *tp;
    int i;
    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tp_private *priv = tp->private;
        struct tp_event *e, *n;
        if (priv) {
            if (priv->fields)
                free(priv->fields);
            if (priv->function_list)
                free(priv->function_list);
            if (priv->ftrace_filter)
                sqlite3_free(priv->ftrace_filter);
            list_for_each_entry_safe(e, n, &priv->event_list, link) {
                __list_del_entry(&e->link);
                free(e);
            }
            if (priv->insert_stmt)
                sqlite3_finalize(priv->insert_stmt);
            free(priv);
        }
    }
    if (ctx->ksymbol)
        function_resolver_unref();
    rblist__exit(&ctx->symbolic_table);
    if (ctx->tep)
        tep__unref();
    free(ctx);
}
