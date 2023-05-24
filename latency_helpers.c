#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/const.h>
#include <linux/refcount.h>
#include <linux/rblist.h>
#include <monitor.h>
#include <latency_helpers.h>

struct latency_dist {
    struct rblist lat;
    bool perins;
    bool perkey;
    bool quantile;
    int extra_size;
};

struct letency_entry {
    struct latency_dist *dist;
    struct latency_node *node;
    u64 instance;
    u64 key;
};

static int latency_stat_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct latency_node *n = rb_entry(rbn, struct latency_node, rbnode);
    const struct letency_entry *e = entry;
    const struct latency_dist *dist = e->dist;

    if (dist->perins) {
        if (n->instance > e->instance)
            return 1;
        else if (n->instance < e->instance)
            return -1;
    }
    if (dist->perkey) {
        if (n->key > e->key)
            return 1;
        else if (n->key < e->key)
            return -1;
    }
    return 0;
}

static struct rb_node *latency_stat_node_new(struct rblist *rlist, const void *new_entry)
{
    struct latency_dist *dist = container_of(rlist, struct latency_dist, lat);
    const struct letency_entry *e = new_entry;
    struct latency_node *n = malloc(sizeof(*n) + dist->extra_size);

    if (n) {
        if (dist->quantile) {
            n->td = tdigest_new(100);
            if (!n->td) goto _err;
        } else
            n->td = NULL;

        RB_CLEAR_NODE(&n->rbnode);
        n->instance = e->instance;
        n->key = e->key;
        n->min = ~0UL;
        n->max = n->than = n->n = n->sum = 0;
        if (dist->extra_size)
            memset(n->extra, 0, dist->extra_size);
        return &n->rbnode;
    }

_err:
    if (n) free(n);
    return NULL;
}

static void latency_stat_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct latency_node *n = rb_entry(rb_node, struct latency_node, rbnode);
    if (n->td) tdigest_free(n->td);
    free(n);
}

static void empty(struct rblist *rblist, struct rb_node *rb_node)
{
}

static int latency_stat__sorted_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct latency_node *n = rb_entry(rbn, struct latency_node, rbnode);
    const struct letency_entry *en = entry;
    const struct latency_dist *dist = en->dist;
    const struct latency_node *e = en->node;

    if (dist->perins) {
        if (n->instance > e->instance)
            return 1;
        else if (n->instance < e->instance)
            return -1;
    }

    if (n->sum > e->sum)
        return -1;
    else if (n->sum < e->sum)
        return 1;

    if (dist->perkey) {
        if (n->key > e->key)
            return 1;
        else if (n->key < e->key)
            return -1;
    }
    return 0;

}

static struct rb_node *latency_stat__sorted_node_new(struct rblist *rlist, const void *new_entry)
{
    const struct letency_entry *en = new_entry;
    struct latency_node *n = en->node;

    RB_CLEAR_NODE(&n->rbnode);
    return &n->rbnode;
}


struct latency_dist *latency_dist_new(bool perins, bool perkey, int extra_size)
{
    struct latency_dist *dist;

    dist = malloc(sizeof(*dist));
    if (!dist)
        return NULL;

    rblist__init(&dist->lat);
    dist->lat.node_cmp = latency_stat_node_cmp;
    dist->lat.node_new = latency_stat_node_new;
    dist->lat.node_delete = latency_stat_node_delete;

    dist->perins = perins;
    dist->perkey = perkey;
    dist->quantile = false;
    dist->extra_size = extra_size;
    return dist;
}

struct latency_dist *latency_dist_new_quantile(bool perins, bool perkey, int extra_size)
{
    struct latency_dist *dist = latency_dist_new(perins, perkey, extra_size);

    if (dist)
        dist->quantile = true;

    return dist;
}

void latency_dist_free(struct latency_dist *dist)
{
    if (dist) {
        rblist__exit(&dist->lat);
        free(dist);
    }
}

struct latency_node *latency_dist_input(struct latency_dist *dist, u64 instance, u64 key, u64 lat, unsigned long greater_than)
{
    struct letency_entry e = {dist, NULL, instance, key};
    struct rb_node *rbn = NULL;
    struct latency_node *ln = NULL;

    if (!dist)
        return NULL;

    rbn = rblist__findnew(&dist->lat, &e);
    if (rbn) {
        ln = rb_entry(rbn, struct latency_node, rbnode);

        if (dist->quantile)
            tdigest_add(ln->td, lat, 1);

        if (lat < ln->min)
            ln->min = lat;
        if (lat > ln->max)
            ln->max = lat;
        if (greater_than && lat > greater_than)
            ln->than ++;
        ln->n ++;
        ln->sum += lat;
        return ln;
    }
    return NULL;
}

bool latency_dist_greater_than(struct latency_dist *dist, u64 than)
{
    struct rb_node *node = NULL, *next = NULL;
    struct latency_node *ln = NULL;

    if (!dist)
        return false;
    if (rblist__empty(&dist->lat))
        return false;

    for (node = rb_first_cached(&dist->lat.entries); node;
        node = next) {
        next = rb_next(node);
        ln = rb_entry(node, struct latency_node, rbnode);

        if (ln->max > than)
            return true;
    }
    return false;
}

void latency_dist_print(struct latency_dist *dist, print_node printnode, void *opaque)
{
    struct rb_node *node = NULL, *next = NULL;
    struct latency_node *ln = NULL;

    if (!dist)
        return;
    if (rblist__empty(&dist->lat))
        return;

    for (node = rb_first_cached(&dist->lat.entries); node;
        node = next) {
        next = rb_next(node);
        ln = rb_entry(node, struct latency_node, rbnode);

        printnode(opaque, ln);
        rblist__remove_node(&dist->lat, node);
    }
}

void latency_dist_print_sorted(struct latency_dist *dist, print_node printnode, void *opaque)
{
    struct rb_node *node = NULL, *next = NULL, *rbn;
    struct latency_node *ln = NULL;
    struct letency_entry entry = {dist,};
    struct rblist sorted;

    if (!dist)
        return;
    if (rblist__empty(&dist->lat))
        return;

    rblist__init(&sorted);
    sorted.node_cmp = latency_stat__sorted_node_cmp;
    sorted.node_new = latency_stat__sorted_node_new;
    sorted.node_delete = latency_stat_node_delete;
    dist->lat.node_delete = empty; //empty, not really delete

    /* sort, remove from `ctx.exit_reason_stat', add to `sorted'. */
    do {
        rbn = rblist__entry(&dist->lat, 0);
        entry.node = rb_entry(rbn, struct latency_node, rbnode);
        rblist__remove_node(&dist->lat, rbn);
        rblist__add_node(&sorted, &entry);
    } while (!rblist__empty(&dist->lat));

    for (node = rb_first_cached(&sorted.entries); node;
        node = next) {
        next = rb_next(node);
        ln = rb_entry(node, struct latency_node, rbnode);

        printnode(opaque, ln);
        rblist__remove_node(&sorted, node);
    }

    dist->lat.node_delete = latency_stat_node_delete;
}

struct latency_node *latency_dist_find(struct latency_dist *dist, u64 instance, u64 key)
{
    struct letency_entry e = {dist, NULL, instance, key};
    struct rb_node *rbn = NULL;
    struct latency_node *ln = NULL;

    if (!dist)
        return NULL;

    rbn = rblist__find(&dist->lat, &e);
    if (rbn) {
        ln = rb_entry(rbn, struct latency_node, rbnode);
        return ln;
    }
    return NULL;
}

bool latency_dist_empty(struct latency_dist *dist)
{
    if (!dist)
        return true;
    return rblist__empty(&dist->lat);
}

void latency_dist_reset(struct latency_dist *dist)
{
    if (!dist)
        return ;
    rblist__exit(&dist->lat);
}


