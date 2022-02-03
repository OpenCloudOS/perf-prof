#ifndef __STACK_HELPERS_H
#define __STACK_HELPERS_H

struct callchain {
    __u64   nr;
    __u64   ips[0];
};


struct callchain_ctx;
enum {
    CALLCHAIN_KERNEL = 1,
    CALLCHAIN_USER = 2,
};
struct callchain_ctx *callchain_ctx_new(int flags, FILE *fout);
void callchain_ctx_free(struct callchain_ctx *cc);
void print_callchain(struct callchain_ctx *cc, struct callchain *callchain, u32 pid);
void print_callchain_common(struct callchain_ctx *cc, struct callchain *callchain, u32 pid);
void print2string_callchain(struct callchain_ctx *cc, struct callchain *callchain, u32 pid);
void task_exit_free_syms(union perf_event *event);


typedef struct callchain struct_key;
struct key_value_paires;
struct key_value_paires *keyvalue_pairs_new(int value_size);
void keyvalue_pairs_free(struct key_value_paires *pairs);
void *keyvalue_pairs_add_key(struct key_value_paires *pairs, struct_key *key);
typedef void (*foreach_keyvalue)(struct_key *key, void *value, unsigned int n);
void keyvalue_pairs_foreach(struct key_value_paires *pairs, foreach_keyvalue f);


const char *unique_string(const char *str);
void unique_string_stat(FILE *fp);
#endif