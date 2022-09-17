// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#include <linux/zalloc.h>
#include <api/fs/fs.h>
#include <internal/threadmap.h>
#include <perf/internal.h>
#include <linux/cgroup.h>

#define __USE_XOPEN_EXTENDED
#include <ftw.h>

static int nr_cgroups = 0;

/* used to match cgroup name with patterns */
struct cgroup_name {
	struct list_head list;
	bool used;
	char name[];
};
static LIST_HEAD(cgroup_name_list);
static LIST_HEAD(cgroup_list);

static int open_cgroup(const char *name)
{
	char path[PATH_MAX + 1];
	char mnt[PATH_MAX + 1];
	int fd;

	if (cgroupfs_find_mountpoint(mnt, PATH_MAX + 1, "perf_event"))
		return -1;

	scnprintf(path, PATH_MAX, "%s/%s", mnt, name);

	fd = open(path, O_RDONLY);
	if (fd == -1)
		fprintf(stderr, "no access to cgroup %s\n", path);

	return fd;
}

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC  0x63677270
#endif

int cgroup_is_v2(const char *subsys)
{
	char mnt[PATH_MAX + 1];
	struct statfs stbuf;

	if (cgroupfs_find_mountpoint(mnt, PATH_MAX + 1, subsys))
		return -1;

	if (statfs(mnt, &stbuf) < 0)
		return -1;

	return (stbuf.f_type == CGROUP2_SUPER_MAGIC);
}

struct cgroup *cgroup__new(const char *name)
{
	struct cgroup *cgroup = zalloc(sizeof(*cgroup));

	if (cgroup != NULL) {
		cgroup->name = strdup(name);
		if (!cgroup->name)
			goto out_err;

		cgroup->fd = open_cgroup(name);
		if (cgroup->fd == -1)
			goto out_free_name;

		list_add_tail(&cgroup->list, &cgroup_list);
		nr_cgroups ++;
	}

	return cgroup;

out_free_name:
	zfree(&cgroup->name);
out_err:
	free(cgroup);
	return NULL;
}

struct cgroup *cgroup__findnew(const char *name)
{
	struct cgroup *cgroup;

	list_for_each_entry(cgroup, &cgroup_list, list) {
		if (strcmp(cgroup->name, name) == 0) {
			return cgroup;
		}
	}
	return cgroup__new(name);
}

void cgroup__delete(struct cgroup *cgroup)
{
	if (cgroup) {
		nr_cgroups --;
		list_del(&cgroup->list);
		if (cgroup->fd >= 0)
			close(cgroup->fd);
		zfree(&cgroup->name);
		free(cgroup);
	}
}

/* helper function for ftw() in match_cgroups and list_cgroups */
static int add_cgroup_name(const char *fpath, const struct stat *sb __maybe_unused,
			   int typeflag, struct FTW *ftwbuf __maybe_unused)
{
	struct cgroup_name *cn;

	if (typeflag != FTW_D)
		return 0;

	cn = malloc(sizeof(*cn) + strlen(fpath) + 1);
	if (cn == NULL)
		return -1;

	cn->used = false;
	strcpy(cn->name, fpath);

	list_add_tail(&cn->list, &cgroup_name_list);
	return 0;
}

static void release_cgroup_name_list(void)
{
	struct cgroup_name *cn;

	while (!list_empty(&cgroup_name_list)) {
		cn = list_first_entry(&cgroup_name_list, struct cgroup_name, list);
		list_del(&cn->list);
		free(cn);
	}
}

/* collect given cgroups only */
static int list_cgroups(const char *str)
{
	const char *p, *e, *eos = str + strlen(str);
	struct cgroup_name *cn;
	char *s;

	for (;;) {
		p = strchr(str, ',');
		e = p ? p : eos;

		if (e - str) {
			int ret;

			s = strndup(str, e - str);
			if (!s)
				return -1;
			/* pretend if it's added by ftw() */
			ret = add_cgroup_name(s, NULL, FTW_D, NULL);
			free(s);
			if (ret)
				return -1;
		} else {
			if (add_cgroup_name("", NULL, FTW_D, NULL) < 0)
				return -1;
		}

		if (!p)
			break;
		str = p+1;
	}

	/* these groups will be used */
	list_for_each_entry(cn, &cgroup_name_list, list)
		cn->used = true;

	return 0;
}

/* collect all cgroups first and then match with the pattern */
static int match_cgroups(const char *str)
{
	char mnt[PATH_MAX];
	const char *p, *e, *eos = str + strlen(str);
	struct cgroup_name *cn;
	regex_t reg;
	int prefix_len;
	char *s;

	if (cgroupfs_find_mountpoint(mnt, sizeof(mnt), "perf_event"))
		return -1;

	/* cgroup_name will have a full path, skip the root directory */
	prefix_len = strlen(mnt);

	/* collect all cgroups in the cgroup_list */
	if (nftw(mnt, add_cgroup_name, 20, 0) < 0)
		return -1;

	for (;;) {
		p = strchr(str, ',');
		e = p ? p : eos;

		/* allow empty cgroups, i.e., skip */
		if (e - str) {
			/* termination added */
			s = strndup(str, e - str);
			if (!s)
				return -1;
			if (regcomp(&reg, s, REG_NOSUB)) {
				free(s);
				return -1;
			}

			/* check cgroup name with the pattern */
			list_for_each_entry(cn, &cgroup_name_list, list) {
				char *name = cn->name + prefix_len;

				if (name[0] == '/' && name[1])
					name++;
				if (!regexec(&reg, name, 0, NULL, 0))
					cn->used = true;
			}
			regfree(&reg);
			free(s);
		} else {
			/* first entry to root cgroup */
			cn = list_first_entry(&cgroup_name_list, struct cgroup_name,
					      list);
			cn->used = true;
		}

		if (!p)
			break;
		str = p+1;
	}
	return prefix_len;
}
static bool has_pattern_string(const char *str)
{
	return !!strpbrk(str, "{}[]()|*+?^$");
}

int cgroup_list__open(const char *str)
{
	struct cgroup *cgrp = NULL;
	struct cgroup_name *cn;
	int ret = -1;
	int prefix_len;
	bool pattern = false;

	if (has_pattern_string(str)) {
		prefix_len = match_cgroups(str);
		pattern = true;
	} else
		prefix_len = list_cgroups(str);

	if (prefix_len < 0)
		goto out_err;

	list_for_each_entry(cn, &cgroup_name_list, list) {
		char *name;

		if (!cn->used)
			continue;

		/* cgroup_name might have a full path, skip the prefix */
		name = cn->name + prefix_len;
		if (name[0] == '/' && name[1])
			name++;
		cgrp = cgroup__findnew(name);
		if (cgrp == NULL)
			goto out_err;
	}

	ret = 0;
	if (pattern && nr_cgroups == 0) {
		ret = -1;
		fprintf(stderr, "The regular expression did not match any cgroups.\n");
	}

out_err:
	release_cgroup_name_list();

	return ret;
}

void cgroup_list__delete(void)
{
	struct cgroup *cgroup;

	while (!list_empty(&cgroup_list)) {
		cgroup = list_first_entry(&cgroup_list, struct cgroup, list);
		cgroup__delete(cgroup);
	}
}

struct perf_thread_map *thread_map__expand_cgroups(struct perf_thread_map *threads)
{
	int nr = 0;
	struct cgroup *cgroup;

	if (nr_cgroups == 0)
		return threads;

	if (perf_thread_map__pid(threads, 0) != -1)
		nr = perf_thread_map__nr(threads);

	threads = perf_thread_map__realloc(threads, nr + nr_cgroups);

	list_for_each_entry(cgroup, &cgroup_list, list) {
		perf_thread_map__set_pid(threads, nr, cgroup->fd);
		perf_thread_map__pid_cgroup(threads, nr);
		nr++;
	}

	threads->nr = nr;
	refcount_set(&threads->refcnt, 1);

	return threads;
}

