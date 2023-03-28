#ifndef __LATENCY_HELPERS
#define __LATENCY_HELPERS

#include <linux/tdigest.h>

struct latency_node {
    struct rb_node rbnode;
    struct tdigest *td;
    u64 instance;
    u64 key;

    u64 min;
    u64 max;
    u64 n;
    u64 sum;
    u64 extra[0];
};

struct latency_dist;
struct latency_dist *latency_dist_new(bool perins, bool perkey, int extra_size);
struct latency_dist *latency_dist_new_quantile(bool perins, bool perkey, int extra_size);
void latency_dist_free(struct latency_dist *dist);
struct latency_node *latency_dist_input(struct latency_dist *dist, u64 instance, u64 key, u64 lat);
bool latency_dist_greater_than(struct latency_dist *dist, u64 than);
typedef void (*print_node)(void *opaque, struct latency_node *node);
void latency_dist_print(struct latency_dist *dist, print_node printnode, void *opaque);
void latency_dist_print_sorted(struct latency_dist *dist, print_node printnode, void *opaque);
struct latency_node *latency_dist_find(struct latency_dist *dist, u64 instance, u64 key);
bool latency_dist_empty(struct latency_dist *dist);
void latency_dist_reset(struct latency_dist *dist);

#endif

