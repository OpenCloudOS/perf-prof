#ifndef __TDIGEST_H
#define __TDIGEST_H

/*
 * tdigest
 *
 * tdigest is an implementation of Ted Dunning's streaming quantile estimation
 * data structure.
 * This implementation is intended to be like the new MergingHistogram.
 *
 * The implementation is a direct descendent of
 *  https://github.com/tdunning/t-digest/
 *
 */

struct centroid    {
    double mean;
    double weight;
};

struct tdigest {
    // compression is a setting used to configure the size of centroids when merged.
    double compression;

    int cap;
    int merged_nodes;
    int unmerged_nodes;

    double merged_weight;
    double unmerged_weight;

    double min, max;

    struct centroid centroids[];
};

struct tdigest *tdigest_new(double compression);

void tdigest_free(struct tdigest *td);

void tdigest_add(struct tdigest *td, double mean, long weight);

// If q is not in [0, 1], NAN will be returned.
double tdigest_quantile(struct tdigest *h, double q);


#endif
