#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <values.h>
#include <math.h>
#include <linux/kernel.h>
#include <linux/tdigest.h>

static inline bool should_merge(struct tdigest *td)
{
    return (td->merged_nodes + td->unmerged_nodes) == td->cap;
}

static inline int next_node(struct tdigest *td)
{
    return td->merged_nodes + td->unmerged_nodes;
}

static inline struct centroid *first(struct tdigest *td)
{
    return &td->centroids[0];
}

static inline struct centroid *last(struct tdigest *td)
{
    return &td->centroids[td->merged_nodes - 1];
}

static inline double weighted_average_sorted(double x1, double w1, double x2, double w2)
{
    double x = (x1 * w1 + x2 * w2) / (w1 + w2);
    return max(x1, min(x, x2));
}

static inline double weighted_average(double x1, double w1, double x2, double w2)
{
    if (x1 <= x2)
        return weighted_average_sorted(x1, w1, x2, w2);
    else
        return weighted_average_sorted(x2, w2, x1, w1);
}

static int compare_centroids(const void *v1, const void *v2)
{
    struct centroid *c1 = (void *)v1;
    struct centroid *c2 = (void *)v2;

    if (c1->mean < c2->mean) return -1;
    else if (c1->mean > c2->mean) return 1;
    else return 0;
}

static void merge(struct tdigest *td)
{
    int i, N;
    double total_weight;
    double Z, normalizer, z;
    double count_so_far = 0;
    int cur = 0;

    if (td->unmerged_nodes == 0)
        return;

    N = td->merged_nodes + td->unmerged_nodes;
    qsort((void *)td->centroids, N, sizeof(struct centroid), &compare_centroids);

    total_weight = td->merged_weight + td->unmerged_weight;
    Z = 4 * log(total_weight / td->compression) + 24; // k2
    normalizer = td->compression / Z;
    z = total_weight / normalizer;

    for (i = 1; i < N; i++) {
        double proposed_count = td->centroids[cur].weight + td->centroids[i].weight;
        double q0 = count_so_far / total_weight;
        double q2 = (count_so_far + proposed_count) / total_weight;
        int add_this = proposed_count <= z * min(q0 * (1 - q0), q2 * (1 - q2));

        if (add_this) {
            td->centroids[cur].weight += td->centroids[i].weight;
            td->centroids[cur].mean += ((td->centroids[i].mean - td->centroids[cur].mean) *
                                       td->centroids[i].weight) /
                                       td->centroids[cur].weight;
        } else {
            count_so_far += td->centroids[cur].weight;
            cur++;
            td->centroids[cur] = td->centroids[i];
        }

        if (cur != i)
            td->centroids[i] = (struct centroid) {0, 0};
    }
    td->merged_nodes = cur + 1;
    td->merged_weight = total_weight;
    td->unmerged_nodes = 0;
    td->unmerged_weight = 0;
    td->min = min(td->min, first(td)->mean);
    td->max = max(td->max, last(td)->mean);
}

struct tdigest *tdigest_new(double compression)
{
    size_t memsize;
    struct tdigest *td;

    if (compression < 10)
        compression = 10;

    memsize = sizeof(struct tdigest);
    memsize += ((6 * (int)compression) + 10) * sizeof(struct centroid);
    td = malloc(memsize);
    if (!td) return NULL;

    memset(td, 0, memsize);
    td->compression = compression;
    td->cap = (memsize - sizeof(struct tdigest)) / sizeof(struct centroid);

    td->merged_weight = 0;
    td->unmerged_weight = 0;

    td->min = MAXDOUBLE;
    td->max = MINDOUBLE;

    return td;
}

void tdigest_free(struct tdigest *td)
{
    free(td);
}

void tdigest_add(struct tdigest *td, double mean, long weight)
{
    if (should_merge(td)) {
        merge(td);
    }
    td->centroids[next_node(td)] = (struct centroid) {
        .mean = mean,
        .weight = weight,
    };
    td->unmerged_nodes++;
    td->unmerged_weight += weight;
}

double tdigest_quantile(struct tdigest *td, double q)
{
    int i;
    double index;
    double weight_so_far, z1, z2;

    merge(td);

    if (q < 0 || q > 1 || td->merged_nodes == 0)
        return NAN;

    if (td->merged_nodes == 1)
        return td->centroids[0].mean;

    index = q * td->merged_weight;

    // beyond the boundaries, we return min or max
    // usually, the first centroid will have unit weight so this will make it moot
    if (index < 1) {
        return td->min;
    }

    // if the first centroid has more than one sample, we still know
    // that one sample occurred at min so we can do some interpolation
    if (first(td)->weight > 1 && index < first(td)->weight / 2) {
        // there is a single sample at min so we interpolate with less weight
        return td->min + (index - 1) / (first(td)->weight / 2 - 1) *
                         (first(td)->mean - td->min);
    }

    // usually the last centroid will have unit weight so this test will make it moot
    if (index > td->merged_weight - 1) {
        return td->max;
    }

    // if the last centroid has more than one sample, we still know
    // that one sample occurred at max so we can do some interpolation
    if (last(td)->weight > 1 && td->merged_weight - index <= last(td)->weight / 2) {
        return td->max - (td->merged_weight - index - 1) / (last(td)->weight / 2 - 1) *
                         (td->max - last(td)->mean);
    }

    // in between extremes we interpolate between centroids
    weight_so_far = first(td)->weight / 2;
    for (i = 0; i < td->merged_nodes - 1; i++) {
        double dw = (td->centroids[i].weight + td->centroids[i + 1].weight) / 2;
        if (weight_so_far + dw > index) {
            // centroids i and i+1 bracket our current point
            double leftUnit = 0;
            double rightUnit = 0;

            // check for unit weight
            if (td->centroids[i].weight == 1) {
                if (index - weight_so_far < 0.5) {
                    // within the singleton's sphere
                    return td->centroids[i].mean;
                }
                leftUnit = 0.5;
            }
            if (td->centroids[i + 1].weight == 1) {
                if (weight_so_far + dw - index <= 0.5) {
                    // no interpolation needed near singleton
                    return td->centroids[i + 1].mean;
                }
                rightUnit = 0.5;
            }
            z1 = index - weight_so_far - leftUnit;
            z2 = weight_so_far + dw - index - rightUnit;
            return weighted_average(td->centroids[i].mean, z2, td->centroids[i + 1].mean, z1);
        }
        weight_so_far += dw;
    }

    // weight_so_far = totalWeight - weight[n-1]/2 (very nearly)
    // so we interpolate out to max value ever seen
    z1 = index - td->merged_weight - last(td)->weight / 2.0;
    z2 = last(td)->weight / 2 - z1;
    return weighted_average(last(td)->mean, z1, td->max, z2);
}

