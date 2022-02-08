#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <monitor.h>
#include <errno.h>
#include <linux/refcount.h>
#include <linux/rblist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>


static struct global_syms {
    struct ksyms *ksyms;
    struct syms_cache *syms_cache;
    refcount_t ksyms_ref;
    refcount_t syms_ref;
} ctx;

/*
 * ffffffff81ad6db9 system_call_fastpath+0x16 ([kernel.kallsyms])
 * 00007efd88d7ea20 __write_nocancel+0x7 (/usr/lib64/libc-2.17.so)
 * addr             symbol  +offset      (dso)
 *
 * addr symbol+offset (dso)...addr symbol+offset (dso)
 *                         ^                          ^
 *                         `seperate                  `end
**/
struct callchain_ctx {
    u64 kernel      : 1, /* need kernel symbols, /proc/kallsyms */
        user        : 1, /* need user symbols, /proc/pid/maps */
        addr        : 1, /* print addr */
        symbol      : 1, /* print symbol */
        offset      : 1, /* print +offset */
        dso         : 1, /* print (dso) */
        reverse     : 1, /* reverse, down to top */
        debug       : 1, /* debug, print PERF_CONTEXT_* */
        print2string_kernel : 1, /* convert to string, for kernel callchain */
        print2string_user   : 1; /* convert to string, for user callchain */
    char seperate;
    char end;
    FILE *fout;
};

static int global_syms_ref(bool kernel, bool user)
{
    if (kernel) {
        if (!ctx.ksyms) {
            ctx.ksyms = ksyms__load();
            if (!ctx.ksyms)
                return -1;
            refcount_set(&ctx.ksyms_ref, 1);
        } else
            refcount_inc(&ctx.ksyms_ref);
    }
    if (user) {
        if (!ctx.syms_cache) {
            ctx.syms_cache = syms_cache__new();
            if (!ctx.syms_cache)
                return -1;
            refcount_set(&ctx.syms_ref, 1);
        } else
            refcount_inc(&ctx.syms_ref);
    }
    return 0;
}

static void global_syms_unref(bool kernel, bool user)
{
    if (kernel && ctx.ksyms && refcount_dec_and_test(&ctx.ksyms_ref)) {
        ksyms__free(ctx.ksyms);
        ctx.ksyms = NULL;
    }
    if (user && ctx.syms_cache && refcount_dec_and_test(&ctx.syms_ref)) {
        syms_cache__free(ctx.syms_cache);
        ctx.syms_cache = NULL;
    }
}

static void callchain_ctx_debug_init(struct callchain_ctx *cc, bool kernel, bool user, FILE *fout)
{
    cc->kernel = kernel;
    cc->user   = user;
    cc->addr   = 1;
    cc->symbol = 1;
    cc->offset = 1;
    cc->dso    = 1;
    cc->reverse = 0;
    cc->debug  = 1;
    cc->seperate = '\n';
    cc->end = '\n';
    cc->fout = fout;
}

struct callchain_ctx *callchain_ctx_new(int flags, FILE *fout)
{
    struct callchain_ctx *cc;
    bool kernel = flags & CALLCHAIN_KERNEL;
    bool user   = flags & CALLCHAIN_USER;

    if (kernel == false && user == false)
        return NULL;

    if (global_syms_ref(kernel, user) < 0)
        return NULL;

    cc = calloc(1, sizeof(*cc));
    if (!cc)
        return NULL;

    cc->kernel = kernel;
    cc->user   = user;
    cc->addr   = 1;
    cc->symbol = 1;
    cc->offset = 1;
    cc->dso    = 1;
    cc->reverse = 0;
    cc->seperate = '\n';
    cc->end = '\n';
    cc->fout = fout;
    return cc;
}

void callchain_ctx_free(struct callchain_ctx *cc)
{
    if (!cc)
        return ;
    global_syms_unref(cc->kernel, cc->user);
    free(cc);
}

static void __print_callchain_kernel(struct callchain_ctx *cc, u64 ip, bool *printed)
{
    const struct ksym *ksym = cc->print2string_kernel ? NULL : ksyms__map_addr(ctx.ksyms, ip);
    if (*printed)
        fprintf(cc->fout, "%c", cc->seperate);
    if (cc->print2string_kernel)
        fprintf(cc->fout, "%s", (char *)ip);
    else {
        if (cc->addr)
            fprintf(cc->fout, "    %016lx", ip);
        if (cc->symbol)
            fprintf(cc->fout, "%s%s", cc->addr ? " " : "", ksym ? ksym->name : "Unknown");
        if (cc->offset)
            fprintf(cc->fout, "+0x%lx", ksym ? ip - ksym->addr : 0L);
        if (cc->dso)
            fprintf(cc->fout, "%s([kernel.kallsyms])", (cc->offset || cc->symbol || cc->addr) ? " " : "");
    }
    if (cc->addr || cc->symbol || cc->offset || cc->dso)
        *printed = true;
}

static void __print_callchain_user(struct callchain_ctx *cc, struct syms *syms, u64 ip, bool *printed)
{
    struct dso *dso;
    const char *symbol = "Unknown";
    u64 offset = 0L;
    const char *dso_name = "Unknown";

    if (!cc->print2string_user) {
        dso = syms__find_dso(syms, ip, &offset);
        if (dso) {
            const struct sym *sym = dso__find_sym(dso, offset);
            if (sym) {
                symbol = sym->name;
                offset = offset - sym->start;
                dso_name = dso__name(dso)?:"Unknown";
            }
        }
    }
    if (*printed)
        fprintf(cc->fout, "%c", cc->seperate);
    if (cc->print2string_user)
        fprintf(cc->fout, "%s", (char *)ip);
    else {
        if (cc->addr)
            fprintf(cc->fout, "    %016lx", ip);
        if (cc->symbol)
            fprintf(cc->fout, "%s%s", cc->addr ? " " : "", symbol);
        if (cc->offset)
            fprintf(cc->fout, "+0x%lx", offset);
        if (cc->dso)
            fprintf(cc->fout, "%s(%s)", (cc->offset || cc->symbol || cc->addr) ? " " : "", dso_name);
    }
    if (cc->addr || cc->symbol || cc->offset || cc->dso)
        *printed = true;
}

static bool __print_callchain(struct callchain_ctx *cc, struct callchain *callchain, u32 pid)
{
    u64 i;
    bool kernel = false, user = false, printed = false;
    struct syms *syms = NULL;

    for (i = 0; i < callchain->nr; i++) {
        u64 ip = callchain->ips[i];
        if (ip == PERF_CONTEXT_KERNEL) {
            kernel = cc->kernel;
            user = false;
            continue;
        } else if (ip == PERF_CONTEXT_USER) {
            kernel = false;
            user = cc->print2string_user;
            if (ctx.syms_cache && cc->user && !user) {
                syms = syms_cache__get_syms(ctx.syms_cache, pid);
                user = syms ? true : false;
            }
            continue;
        }
        if (kernel) {
            __print_callchain_kernel(cc, ip, &printed);
        } else if (user) {
            __print_callchain_user(cc, syms, ip, &printed);
        }
    }
    return printed;
}

static bool __print_callchain_reverse(struct callchain_ctx *cc, struct callchain *callchain, u32 pid)
{
    u64 i, kstart = 0, kend = 0, ustart = 0, uend = 0;
    struct syms *syms = NULL;
    bool printed = false;

    for (i = 0; i < callchain->nr; i++) {
        u64 ip = callchain->ips[i];
        if (ip == PERF_CONTEXT_KERNEL) {
            kstart = i + 1;
            kend = callchain->nr - 1;
            if (!cc->user)
                break;
        } else if (ip == PERF_CONTEXT_USER) {
            if (ctx.syms_cache && cc->user && !cc->print2string_user)
                syms = syms_cache__get_syms(ctx.syms_cache, pid);
            kend = i - 1;
            ustart = i + 1;
            uend = callchain->nr - 1;
            break;
        }
    }
    if (cc->user && ustart) {
        for (; uend >= ustart; uend--) {
            u64 ip = callchain->ips[uend];
            // There may be more than 1 PERF_CONTEXT_* tag.
            if (ip == PERF_CONTEXT_KERNEL ||
                ip == PERF_CONTEXT_USER)
                continue;
            __print_callchain_user(cc, syms, ip, &printed);
        }
    }
    if (cc->kernel && kstart) {
        for (; kend >= kstart; kend--) {
            u64 ip = callchain->ips[kend];
            // There may be more than 1 PERF_CONTEXT_* tag.
            if (ip == PERF_CONTEXT_KERNEL ||
                ip == PERF_CONTEXT_USER)
                continue;
            __print_callchain_kernel(cc, ip, &printed);
        }
    }
    return printed;
}

void print_callchain(struct callchain_ctx *cc, struct callchain *callchain, u32 pid)
{
    if (cc == NULL ||
        callchain == NULL || callchain->nr == 0)
        return ;
    if (ctx.ksyms == NULL &&
        ctx.syms_cache == NULL)
        return ;

    if ((cc->reverse ? __print_callchain_reverse : __print_callchain)(cc, callchain, pid))
        fprintf(cc->fout, "%c", cc->end);
}

void print_callchain_common(struct callchain_ctx *cc, struct callchain *callchain, u32 pid)
{
    __u64 i;
    bool kernel = false, user = false;
    struct syms *syms;

    if (cc == NULL ||
        callchain == NULL || callchain->nr == 0)
        return ;
    if (ctx.ksyms == NULL &&
        ctx.syms_cache == NULL)
        return ;

    for (i = 0; i < callchain->nr; i++) {
        __u64 ip = callchain->ips[i];
        if (ip == PERF_CONTEXT_KERNEL) {
            kernel = cc->kernel;
            user = false;
            if (cc->debug)
                fprintf(cc->fout, "    %016llx PERF_CONTEXT_KERNEL\n", ip);
            continue;
        } else if (ip == PERF_CONTEXT_USER) {
            kernel = false;
            user = false;
            if (ctx.syms_cache) {
                syms = syms_cache__get_syms(ctx.syms_cache, pid);
                if (syms)
                    user = cc->user;
            }
            if (cc->debug)
                fprintf(cc->fout, "    %016llx PERF_CONTEXT_USER\n", ip);
            continue;
        }
        if (kernel) {
            const struct ksym *ksym = ksyms__map_addr(ctx.ksyms, ip);
            fprintf(cc->fout, "    %016llx %s+0x%llx ([kernel.kallsyms])\n", ip, ksym ? ksym->name : "Unknown",
                                ksym ? ip - ksym->addr : 0L);
        } else if (user) {
            struct dso *dso;
            uint64_t offset;
            dso = syms__find_dso(syms, ip, &offset);
            if (dso) {
                const struct sym *sym = dso__find_sym(dso, offset);
                fprintf(cc->fout, "    %016llx %s+0x%lx (%s)\n", ip, sym ? sym->name : "Unknown",
                                sym ? offset - sym->start : 0L, dso__name(dso)?:"Unknown");
            } else
                fprintf(cc->fout, "    %016llx %s (%s)\n", ip, "Unknown", "Unknown");
        } else
            fprintf(cc->fout, "    %016llx\n", ip);
    }
}

static void print2string_callchain(struct callchain_ctx *cc, struct callchain *callchain, u32 pid,
                                          int *context_kernel_num, int *context_user_num)
{
    __u64 i;
    bool kernel = false, user = false;
    struct syms *syms = NULL;
    char buff[1024];
    int len = 0;

    if (cc == NULL ||
        callchain == NULL || callchain->nr == 0)
        return ;
    if (!cc->print2string_kernel && !cc->print2string_user)
        return ;
    if (ctx.ksyms == NULL &&
        ctx.syms_cache == NULL)
        return ;

    *context_kernel_num = 0;
    *context_user_num = 0;
    for (i = 0; i < callchain->nr; i++) {
        u64 ip = callchain->ips[i];
        if (ip == PERF_CONTEXT_KERNEL) {
            kernel = true;
            user = false;
            (*context_kernel_num) ++;
            continue;
        } else if (ip == PERF_CONTEXT_USER) {
            kernel = false;
            user = true;
            if (ctx.syms_cache) {
                syms = cc->user ? syms_cache__get_syms(ctx.syms_cache, pid) : NULL;
            }
            (*context_user_num) ++;
            continue;
        }
        if (kernel && cc->print2string_kernel) {
            const struct ksym *ksym = cc->kernel ? ksyms__map_addr(ctx.ksyms, ip) : NULL;
            len = 0;
            if (cc->addr)
                len += snprintf(buff+len, sizeof(buff)-len, "    %016lx", ip);
            if (cc->symbol)
                len += snprintf(buff+len, sizeof(buff)-len, "%s%s", cc->addr ? " " : "", ksym ? ksym->name : "Unknown");
            if (cc->offset)
                len += snprintf(buff+len, sizeof(buff)-len, "+0x%lx", ksym ? ip - ksym->addr : 0L);
            if (cc->dso)
                len += snprintf(buff+len, sizeof(buff)-len, "%s([kernel.kallsyms])", (cc->offset || cc->symbol || cc->addr) ? " " : "");
            // Convert to unique string.
            callchain->ips[i] = (__u64)(void *)unique_string(buff);
        } else if (user && cc->print2string_user) {
            struct dso *dso;
            const char *symbol = "Unknown";
            u64 offset = 0L;
            const char *dso_name = "Unknown";

            if (syms) {
                dso = syms__find_dso(syms, ip, &offset);
                if (dso) {
                    const struct sym *sym = dso__find_sym(dso, offset);
                    if (sym) {
                        symbol = sym->name;
                        offset = offset - sym->start;
                        dso_name = dso__name(dso)?:"Unknown";
                    }
                }
            }
            len = 0;
            if (cc->addr)
                len += snprintf(buff+len, sizeof(buff)-len, "    %016lx", ip);
            if (cc->symbol)
                len += snprintf(buff+len, sizeof(buff)-len, "%s%s", cc->addr ? " " : "", symbol);
            if (cc->offset)
                len += snprintf(buff+len, sizeof(buff)-len, "+0x%lx", offset);
            if (cc->dso)
                len += snprintf(buff+len, sizeof(buff)-len, "%s(%s)", (cc->offset || cc->symbol || cc->addr) ? " " : "", dso_name);
            // Convert to unique string.
            callchain->ips[i] = (__u64)(void *)unique_string(buff);
        }
    }
}


void task_exit_free_syms(union perf_event *event)
{
    if (ctx.syms_cache &&
        event->fork.pid == event->fork.tid) {
        syms_cache__free_syms(ctx.syms_cache, event->fork.pid);
    }
}

struct key_value {
    struct rb_node rbnode;
    unsigned int n;
    struct_key key;
    /* void *value; */
};

struct key_value_paires {
    struct rblist kv_pairs;
    int value_size;
};

static int key_value_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct key_value *kv = container_of(rbn, struct key_value, rbnode);
    const struct_key *key = entry;
    int i = 0, j = 0;

    /*
     * In the flame_graph_add_callchain function, the PERF_CONTEXT_FLAME_GRAPH
     * will be added, which can be sorted by time(ips[1]).
    **/
    for (; i < (int)kv->key.nr && j < (int)key->nr; i++, j++) {
        if (kv->key.ips[i] > key->ips[j])
            return 1;
        else if (kv->key.ips[i] < key->ips[j])
            return -1;
    }
    return (int)kv->key.nr - (int)key->nr;
}
static struct rb_node *key_value_node_new(struct rblist *rlist, const void *new_entry)
{
    struct key_value_paires *pairs = container_of(rlist, struct key_value_paires, kv_pairs);
    const struct_key *key = new_entry;
    struct key_value *kv = malloc(sizeof(struct key_value) + key->nr * sizeof(key->ips[0]) + pairs->value_size);
    if (kv) {
        RB_CLEAR_NODE(&kv->rbnode);
        kv->n = 0;
        kv->key.nr = key->nr;
        memcpy(kv->key.ips, key->ips, key->nr * sizeof(key->ips[0]));
        memset(&kv->key.ips[key->nr], 0, pairs->value_size);
        return &kv->rbnode;
    } else
        return NULL;
}

static void key_value_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct key_value *kv = container_of(rb_node, struct key_value, rbnode);
    free(kv);
}

struct key_value_paires *keyvalue_pairs_new(int value_size)
{
    struct key_value_paires *pairs;
    pairs = calloc(1, sizeof(*pairs));
    if (!pairs)
        return NULL;

    rblist__init(&pairs->kv_pairs);
    pairs->kv_pairs.node_cmp = key_value_node_cmp;
    pairs->kv_pairs.node_new = key_value_node_new;
    pairs->kv_pairs.node_delete = key_value_node_delete;
    pairs->value_size = value_size;
    return pairs;
}

void keyvalue_pairs_free(struct key_value_paires *pairs)
{
    if (!pairs)
        return ;
    rblist__exit(&pairs->kv_pairs);
    free(pairs);
}

void *keyvalue_pairs_add_key(struct key_value_paires *pairs, struct_key *key)
{
    struct rb_node *rbn;
    struct key_value *kv = NULL;
    void *value = NULL;

    rbn = rblist__findnew(&pairs->kv_pairs, key);
    if (rbn) {
        kv = container_of(rbn, struct key_value, rbnode);
        kv->n ++;
        value = pairs->value_size ? (void *)&kv->key.ips[kv->key.nr] : NULL;
    }
    return value;
}

void keyvalue_pairs_foreach(struct key_value_paires *pairs, foreach_keyvalue f, void *opaque)
{
    struct rblist *rblist = &pairs->kv_pairs;
    struct rb_node *pos, *next = rb_first_cached(&rblist->entries);
    struct key_value *kv = NULL;
    void *value = NULL;

    while (next) {
        pos = next;
        next = rb_next(pos);
        kv = container_of(pos, struct key_value, rbnode);
        value = pairs->value_size ? (void *)&kv->key.ips[kv->key.nr] : NULL;
        f(opaque, &kv->key, value, kv->n);
    }
}


struct unique_string {
    struct rb_node rbnode;
    unsigned int n, len;
    char str[0];
};

static int unique_string_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct unique_string *s = container_of(rbn, struct unique_string, rbnode);
    const char *str = entry;

    return strcmp(s->str, str);
}
static struct rb_node *unique_string_node_new(struct rblist *rlist, const void *new_entry)
{
    const char *str = new_entry;
    unsigned int len = strlen(str) + 1;
    struct unique_string *s = malloc(sizeof(struct unique_string) + len);
    if (s) {
        RB_CLEAR_NODE(&s->rbnode);
        s->n = 0;
        s->len = len;
        strncpy(s->str, str, len);
        return &s->rbnode;
    } else
        return NULL;
}
static void unique_string_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct unique_string *s = container_of(rb_node, struct unique_string, rbnode);
    free(s);
}

static struct rblist unique_strings = {
    .entries = RB_ROOT_CACHED,
    .nr_entries = 0,
    .node_cmp = unique_string_node_cmp,
    .node_new = unique_string_node_new,
    .node_delete = unique_string_node_delete,
};

const char *unique_string(const char *str)
{
    struct rb_node *rbn;
    struct unique_string *s = NULL;

    rbn = rblist__findnew(&unique_strings, str);
    if (rbn) {
        s = container_of(rbn, struct unique_string, rbnode);
        s->n ++;
        return s->str;
    }
    return NULL;
}

void unique_string_stat(FILE *fp)
{
    struct rb_node *pos, *next = rb_first_cached(&unique_strings.entries);
    struct unique_string *s = NULL;
    size_t str_len = 0, node_len = 0;

    while (next) {
        pos = next;
        next = rb_next(pos);
        s = container_of(pos, struct unique_string, rbnode);
        str_len += s->len * s->n;
        node_len += sizeof(*s);
    }
    fprintf(fp, "UNIQUE STRING STAT: strlen %lu, nodelen %lu\n", str_len, node_len);
}


struct flame_graph {
    struct callchain_ctx *cc;
    struct key_value_paires *kv_pairs;
};

struct flame_graph *flame_graph_new(int flags, FILE *fout)
{
    struct flame_graph *fg = malloc(sizeof(*fg));
    struct callchain_ctx *cc = callchain_ctx_new(flags, fout);
    struct key_value_paires *kv_pairs = keyvalue_pairs_new(0);

    if (!fg || !cc || !kv_pairs) {
        free(fg);
        callchain_ctx_free(cc);
        keyvalue_pairs_free(kv_pairs);
        return NULL;
    }

    cc->addr   = 0;
    cc->symbol = 1;
    cc->offset = 0;
    cc->dso    = 0;
    cc->reverse = 1;
    cc->print2string_kernel = 1;
    cc->print2string_user = 1;
    cc->seperate = ';';
    cc->end = ' ';

    fg->cc = cc;
    fg->kv_pairs = kv_pairs;
    return fg;
}

void flame_graph_free(struct flame_graph *fg)
{
    if (!fg)
        return ;

    callchain_ctx_free(fg->cc);
    keyvalue_pairs_free(fg->kv_pairs);
    free(fg);
}

void flame_graph_add_callchain_at_time(struct flame_graph *fg, struct callchain *callchain,
                                         u32 pid, const char *comm,
                                         u64 time, const char *time_str)
{
    struct {
        __u64   nr;
        __u64   ips[PERF_MAX_STACK_DEPTH + PERF_MAX_CONTEXTS_PER_STACK + 5];
    } key;
    char buff[128];
    int context_kernel_num = 0;
    int context_user_num = 0;

    if (!fg)
        return ;

    key.nr = 0;
    /*
     * The time is placed at the front of the stack.
     *   1. The flame graph can be sorted by time.
     *   2. The print_callchain function is not affected.
    **/
    if (time) {
        key.ips[key.nr++] = PERF_CONTEXT_FLAME_GRAPH;
        key.ips[key.nr++] = time;
    }

    memcpy(&key.ips[key.nr], callchain->ips, callchain->nr * sizeof(callchain->ips[0]));
    key.nr += callchain->nr;
    /*
     * convert callchain to unique string.
     * For user-mode stacks, symbols are freed after the process exits. Therefore,
     * the stack needs to be converted into a unique string first.
    **/
    print2string_callchain(fg->cc, (struct callchain *)&key, pid, &context_kernel_num, &context_user_num);
    /*
     * There may be more than 1 PERF_CONTEXT_* tag. So, pre-print the error message.
    **/
    if (context_kernel_num > 1 || context_user_num > 1) {
        struct callchain_ctx debug;
        callchain_ctx_debug_init(&debug, fg->cc->kernel, fg->cc->user, stderr);
        print_time(stderr);
        fprintf(stderr, "BUG: callchain error%s%s\n",
                context_kernel_num > 1 ? " PERF_CONTEXT_KERNEL >1" : "",
                context_user_num > 1 ? " PERF_CONTEXT_USER >1" : "");
        print_callchain_common(&debug, callchain, pid);
    }

    if (fg->cc->user && fg->cc->print2string_user) {
        /*
         * There is no user-mode stack in callchain, add PERF_CONTEXT_USER isolates
         * the user-mode and kernel-mode stacks.
        **/
        if (!context_user_num) {
            key.ips[key.nr++] = PERF_CONTEXT_USER;
            context_user_num++;
        }
        if (comm)
            snprintf(buff, sizeof(buff), "%s", comm);
        else
            snprintf(buff, sizeof(buff), "%d", pid);
        key.ips[key.nr++] = (__u64)(void *)unique_string(buff);
    }
    if (time && time_str) {
        if (!context_user_num) {
            key.ips[key.nr++] = PERF_CONTEXT_USER;
            context_user_num++;
        }
        key.ips[key.nr++] = (__u64)(void *)unique_string(time_str);
    }

    /*
     * Add to the storage pool with the stack as the key.
    **/
    keyvalue_pairs_add_key(fg->kv_pairs, (struct_key *)&key);
}

static void __flame_graph_print(void *opaque, struct_key *key, void *value, unsigned int n)
{
    struct flame_graph *fg = opaque;
    print_callchain(fg->cc, key, 0);
    fprintf(fg->cc->fout, "%u\n", n);
}

void flame_graph_output(struct flame_graph *fg)
{
    if (!fg)
        return ;

    keyvalue_pairs_foreach(fg->kv_pairs, __flame_graph_print, fg);
}

struct flame_graph *flame_graph_open(int flags, const char *path)
{
    char filename[PATH_MAX];
    FILE *fp;

    if (!path)
        return NULL;

    snprintf(filename, sizeof(filename), "%s.folded", path);
    if (access(filename, F_OK) == 0) {
        char filename_old[PATH_MAX];
        snprintf(filename_old, sizeof(filename_old), "%s.folded.old", path);
        rename(filename, filename_old);
    }
    fp = fopen(filename, "w+");
    if (!fp)
        return NULL;
    return flame_graph_new(flags, fp);
}

void flame_graph_close(struct flame_graph *fg)
{
    FILE *fp;

    if (!fg)
        return ;

    fp = fg->cc->fout;
    flame_graph_free(fg);
    fclose(fp);
}

