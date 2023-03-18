/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LIBPERF_MMAP_H
#define __LIBPERF_MMAP_H

#include <linux/types.h>
#include <perf/core.h>

struct perf_mmap;
union perf_event;

LIBPERF_API int perf_mmap__idx(struct perf_mmap *map);
LIBPERF_API void perf_mmap__consume(struct perf_mmap *map);
LIBPERF_API int perf_mmap__read_init(struct perf_mmap *map);
LIBPERF_API void perf_mmap__read_done(struct perf_mmap *map);
LIBPERF_API union perf_event *perf_mmap__read_event(struct perf_mmap *map);

struct perf_tsc_conversion {
	u16 time_shift;
	u32 time_mult;
	u64 time_zero;
	bool cap_user_time_zero;
};
LIBPERF_API int perf_mmap__read_tsc_conversion(struct perf_mmap *map, struct perf_tsc_conversion *tc);


#endif /* __LIBPERF_MMAP_H */
