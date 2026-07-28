/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TRACE_HELPERS_H
#define __TRACE_HELPERS_H

#include <stdbool.h>


struct ksym {
	const char *name;
	const char *module;   /* NULL when the symbol is in the core kernel */
	unsigned long addr;
};

struct ksyms;

struct ksyms *ksyms__load(void);
void ksyms__free(struct ksyms *ksyms);
const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr);
/*
 * Look up a kernel symbol by name and (optional) module.
 *   module == NULL: match by name only, regardless of module.
 *   module != NULL: match only symbols in that specific module.
 */
const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name,
				     const char *module);
void ksym__register_unregister(struct ksyms *ksyms, struct perf_record_ksymbol *ksymbol);


struct sym {
	const char *name, *demangled;
	unsigned long start;
	unsigned long size;
};

struct syms;
struct dso;

void obj__stat(FILE *fp);

struct syms *syms__load_pid(int tgid);
struct syms *syms__load_file(const char *fname, int tgid);
void syms__free(struct syms *syms);
const struct sym *syms__map_addr(const struct syms *syms, unsigned long addr);
struct dso *syms__find_dso(const struct syms *syms, unsigned long addr,
				  uint64_t *offset);
const struct sym *dso__find_sym(struct dso *dso, uint64_t offset);
const char *dso__name(struct dso *dso);

#ifdef HAVE_LIBUNWIND
/*
 * DWARF unwind info accessors.
 * These provide access to cached .eh_frame_hdr and .eh_frame data
 * stored in struct object for DWARF-based stack unwinding.
 */
struct dso_unwind_data {
    void *eh_frame_hdr;         /* eh_frame_hdr segment data */
    uint64_t eh_frame_hdr_sz;
    uint64_t eh_frame_hdr_addr; /* ELF runtime address of eh_frame_hdr */
    void *eh_frame;             /* .eh_frame data */
    uint64_t eh_frame_sz;
    uint64_t eh_frame_addr;    /* ELF runtime address of .eh_frame */
};
bool dso__get_unwind_data(struct dso *dso, struct dso_unwind_data *data);
#endif

static inline const char *sym__name(const struct sym *sym) { return sym->demangled ?: sym->name; }
void syms__convert(FILE *fin, FILE *fout, char *binpath);
unsigned long syms__file_offset(const char *binpath, const char *func,
                                char **err_msg);

/*
 * Pin the parsed symbol table for `binpath` so a burst of
 * syms__file_offset() calls against the same binary share one ELF
 * parse instead of dropping the table between calls. `binpath` must
 * be the same string (same rblist key) that syms__file_offset()
 * will be called with -- callers typically pass tp->uprobe_path.
 * Each successful pin must be balanced by exactly one unpin.
 */
void syms__file_pin(const char *binpath);
void syms__file_unpin(const char *binpath);

struct syms_cache;

struct syms_cache *syms_cache__new(void);
struct syms *syms_cache__get_syms(struct syms_cache *syms_cache, int tgid);
void syms_cache__free(struct syms_cache *syms_cache);
void syms_cache__free_syms(struct syms_cache *syms_cache, int tgid);
void syms_cache__stat(struct syms_cache *syms_cache, FILE *fp);

struct partition {
	char *name;
	unsigned int dev;
};

struct partitions;

struct partitions *partitions__load(void);
void partitions__free(struct partitions *partitions);
const struct partition *
partitions__get_by_dev(const struct partitions *partitions, unsigned int dev);
const struct partition *
partitions__get_by_name(const struct partitions *partitions, const char *name);

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type);
void print_linear_hist(unsigned int *vals, int vals_size, unsigned int base,
		unsigned int step, const char *val_type);

unsigned long long get_ktime_ns(void);

bool is_kernel_module(const char *name);


/*
 * The name of a kernel function to be attached to may be changed between
 * kernel releases. This helper is used to confirm whether the target kernel
 * uses a certain function name before attaching.
 *
 * It is achieved by scaning
 * 	/sys/kernel/debug/tracing/available_filter_functions
 * If this file does not exist, it fallbacks to parse /proc/kallsyms,
 * which is slower.
 */
bool kprobe_exists(const char *name);

bool vmlinux_btf_exists(void);
bool module_btf_exists(const char *mod);

#endif /* __TRACE_HELPERS_H */
