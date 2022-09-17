/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CGROUP_H__
#define __CGROUP_H__

#include <linux/compiler.h>
#include <linux/refcount.h>
#include <linux/list.h>
#include <perf/threadmap.h>
#include <perf/event.h>

struct cgroup {
	struct list_head  list;
	char             *name;
	int               fd;
};

int cgroup_is_v2(const char *subsys);

struct cgroup *cgroup__new(const char *name);
struct cgroup *cgroup__findnew(const char *name);
void cgroup__delete(struct cgroup *cgroup);

int cgroup_list__open(const char *str);
void cgroup_list__delete(void);

struct perf_thread_map *thread_map__expand_cgroups(struct perf_thread_map *threads);

static inline struct perf_thread_map *thread_map__cgroups(const char *str)
{
	if (cgroup_list__open(str) < 0)
		return NULL;

	return thread_map__expand_cgroups(NULL);
}

#endif /* __CGROUP_H__ */
