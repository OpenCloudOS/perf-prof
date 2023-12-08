/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// Copyright (c) 2020 Wenbo Zhang
//
// Based on ksyms improvements from Andrii Nakryiko, add more helpers.
// 28-Feb-2020   Wenbo Zhang   Created this.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>
#include <linux/refcount.h>
#include <linux/rblist.h>
#include <linux/time64.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include <lzma.h>
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define min(x, y) ({                \
    typeof(x) _min1 = (x);          \
    typeof(y) _min2 = (y);          \
    (void) (&_min1 == &_min2);      \
    _min1 < _min2 ? _min1 : _min2; })

#define DISK_NAME_LEN   32

#define MINORBITS   20
#define MINORMASK   ((1U << MINORBITS) - 1)

#define MKDEV(ma, mi)   (((ma) << MINORBITS) | (mi))

struct ksyms {
    struct ksym *syms;
    int syms_sz;
    int syms_cap;
    char *strs;
    int strs_sz;
    int strs_cap;
};

static int ksyms__add_symbol(struct ksyms *ksyms, const char *name, unsigned long addr)
{
    size_t new_cap, name_len = strlen(name) + 1;
    struct ksym *ksym;
    void *tmp;

    if (ksyms->strs_sz + name_len > ksyms->strs_cap) {
        new_cap = ksyms->strs_cap * 4 / 3;
        if (new_cap < ksyms->strs_sz + name_len)
            new_cap = ksyms->strs_sz + name_len;
        if (new_cap < 1024)
            new_cap = 1024;
        tmp = realloc(ksyms->strs, new_cap);
        if (!tmp)
            return -1;
        ksyms->strs = tmp;
        ksyms->strs_cap = new_cap;
    }
    if (ksyms->syms_sz + 1 > ksyms->syms_cap) {
        new_cap = ksyms->syms_cap * 4 / 3;
        if (new_cap < 1024)
            new_cap = 1024;
        tmp = realloc(ksyms->syms, sizeof(*ksyms->syms) * new_cap);
        if (!tmp)
            return -1;
        ksyms->syms = tmp;
        ksyms->syms_cap = new_cap;
    }

    ksym = &ksyms->syms[ksyms->syms_sz];
    /* while constructing, re-use pointer as just a plain offset */
    ksym->name = (void *)(unsigned long)ksyms->strs_sz;
    ksym->addr = addr;

    memcpy(ksyms->strs + ksyms->strs_sz, name, name_len);
    ksyms->strs_sz += name_len;
    ksyms->syms_sz++;

    return 0;
}

static int ksym_cmp(const void *p1, const void *p2)
{
    const struct ksym *s1 = p1, *s2 = p2;

    if (s1->addr == s2->addr)
        return strcmp(s1->name, s2->name);
    return s1->addr < s2->addr ? -1 : 1;
}

struct ksyms *ksyms__load(void)
{
    char sym_type, sym_name[256];
    struct ksyms *ksyms;
    unsigned long sym_addr;
    int i, ret;
    FILE *f;

    f = fopen("/proc/kallsyms", "r");
    if (!f)
        return NULL;

    ksyms = calloc(1, sizeof(*ksyms));
    if (!ksyms)
        goto err_out;

    while (true) {
        ret = fscanf(f, "%lx %c %s%*[^\n]\n",
                 &sym_addr, &sym_type, sym_name);
        if (ret == EOF && feof(f))
            break;
        if (ret != 3)
            goto err_out;
        if (ksyms__add_symbol(ksyms, sym_name, sym_addr))
            goto err_out;
    }

    /* now when strings are finalized, adjust pointers properly */
    for (i = 0; i < ksyms->syms_sz; i++)
        ksyms->syms[i].name += (unsigned long)ksyms->strs;

    qsort(ksyms->syms, ksyms->syms_sz, sizeof(*ksyms->syms), ksym_cmp);

    fclose(f);
    return ksyms;

err_out:
    ksyms__free(ksyms);
    fclose(f);
    return NULL;
}

void ksyms__free(struct ksyms *ksyms)
{
    if (!ksyms)
        return;

    free(ksyms->syms);
    free(ksyms->strs);
    free(ksyms);
}

const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
                   unsigned long addr)
{
    int start = 0, end = ksyms->syms_sz - 1, mid;
    unsigned long sym_addr;

    /* find largest sym_addr <= addr using binary search */
    while (start < end) {
        mid = start + (end - start + 1) / 2;
        sym_addr = ksyms->syms[mid].addr;

        if (sym_addr <= addr)
            start = mid;
        else
            end = mid - 1;
    }

    if (start == end && ksyms->syms[start].addr <= addr)
        return &ksyms->syms[start];
    return NULL;
}

const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
                     const char *name)
{
    int i;

    for (i = 0; i < ksyms->syms_sz; i++) {
        if (strcmp(ksyms->syms[i].name, name) == 0)
            return &ksyms->syms[i];
    }

    return NULL;
}

/*
 * syms_cache --> syms --> dso --> object --> sym
 *            pid      maps    file       sym
**/

struct load_range {
    uint64_t start;
    uint64_t end;
    uint64_t file_off;
};

enum elf_type {
    EXEC,
    DYN,
    PERF_MAP,
    VDSO,
    UNKNOWN,
};

struct object {
    struct rb_node rbnode;
    refcount_t refcnt;
    char *name;
    /* Dyn's first text section virtual addr at execution */
    uint64_t sh_addr;
    /* Dyn's first text section file offset */
    uint64_t sh_offset;
    enum elf_type type;

    struct sym *syms;
    int syms_sz;
    int syms_cap;

    char *strs;
    int strs_sz;
    int strs_cap;
};

struct dso {
    struct load_range *ranges;
    int range_sz;
    struct object *obj;
};

struct map {
    uint64_t start_addr;
    uint64_t end_addr;
    uint64_t file_off;
    uint64_t dev_major;
    uint64_t dev_minor;
    uint64_t inode;
};

struct syms {
    struct dso *dsos;
    int dso_sz;
};

static bool is_file_backed(const char *mapname)
{
#define STARTS_WITH(mapname, prefix) \
    (!strncmp(mapname, prefix, sizeof(prefix) - 1))

    return mapname[0] && !(
        STARTS_WITH(mapname, "//anon") ||
        STARTS_WITH(mapname, "/dev/zero") ||
        STARTS_WITH(mapname, "/anon_hugepage") ||
        STARTS_WITH(mapname, "socket:") ||
        STARTS_WITH(mapname, "[stack") ||
        STARTS_WITH(mapname, "/SYSV") ||
        STARTS_WITH(mapname, "[heap]") ||
        STARTS_WITH(mapname, "[vsyscall]"));
}

static bool is_perf_map(const char *path)
{
    return false;
}

static bool is_vdso(const char *path)
{
    return !strcmp(path, "[vdso]");
}

static int get_elf_type(const char *path)
{
    GElf_Ehdr hdr;
    void *res;
    Elf *e;
    int fd;

    if (is_vdso(path))
        return -1;
    e = open_elf(path, &fd);
    if (!e)
        return -1;
    res = gelf_getehdr(e, &hdr);
    close_elf(e, fd);
    if (!res)
        return -1;
    return hdr.e_type;
}

static int get_elf_text_scn_info(const char *path, uint64_t *addr,
                 uint64_t *offset)
{
    Elf_Scn *section = NULL;
    int fd = -1, err = -1;
    GElf_Shdr header;
    size_t stridx;
    Elf *e = NULL;
    char *name;

    e = open_elf(path, &fd);
    if (!e)
        goto err_out;
    err = elf_getshdrstrndx(e, &stridx);
    if (err < 0)
        goto err_out;

    err = -1;
    while ((section = elf_nextscn(e, section)) != 0) {
        if (!gelf_getshdr(section, &header))
            continue;

        name = elf_strptr(e, stridx, header.sh_name);
        if (name && !strcmp(name, ".text")) {
            *addr = (uint64_t)header.sh_addr;
            *offset = (uint64_t)header.sh_offset;
            err = 0;
            break;
        }
    }

err_out:
    close_elf(e, fd);
    return err;
}

static int object_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct object *obj = container_of(rbn, struct object, rbnode);
    const char *name = entry;

    return strcmp(obj->name, name);
}

static struct rb_node *object_node_new(struct rblist *rlist, const void *new_entry)
{
    const char *name = new_entry;
    struct object *obj = malloc(sizeof(*obj));
    int type;

    if (obj) {
        memset(obj, 0, sizeof(*obj));
        RB_CLEAR_NODE(&obj->rbnode);
        obj->name = strdup(name);
        refcount_set(&obj->refcnt, 0);

        type = get_elf_type(name);
        if (type == ET_EXEC) {
            obj->type = EXEC;
        } else if (type == ET_DYN) {
            obj->type = DYN;
            if (get_elf_text_scn_info(name, &obj->sh_addr, &obj->sh_offset) < 0)
                return NULL;
        } else if (is_perf_map(name)) {
            obj->type = PERF_MAP;
        } else if (is_vdso(name)) {
            obj->type = VDSO;
        } else {
            obj->type = UNKNOWN;
        }
        return &obj->rbnode;
    } else
        return NULL;
}

static void object_node_delete(struct rblist *rblist, struct rb_node *rbn)
{
    struct object *obj = container_of(rbn, struct object, rbnode);

    free(obj->name);
    free(obj->syms);
    free(obj->strs);
    free(obj);
}

static struct rblist objects = {
    .entries = RB_ROOT_CACHED,
    .nr_entries = 0,
    .node_cmp = object_node_cmp,
    .node_new = object_node_new,
    .node_delete = object_node_delete,
};

static struct object *obj__get(const char *name)
{
    struct rb_node *rbnode;
    struct object *obj = NULL;

    rbnode = rblist__findnew(&objects, name);
    if (rbnode) {
        obj = container_of(rbnode, struct object, rbnode);
        if (refcount_read(&obj->refcnt) == 0)
            refcount_set(&obj->refcnt, 1);
        else
            refcount_inc(&obj->refcnt);
    }
    return obj;
}

static void obj__put(struct object *obj)
{
    if (obj && refcount_dec_and_test(&obj->refcnt))
        rblist__remove_node(&objects, &obj->rbnode);
}

void obj__stat(FILE *fp)
{
    static const char *str_type[] = {"EXEC", "DYN", "PERF_MAP", "VDSO", "UNKNOWN"};
    struct rb_node *node;
    struct object *obj;
    long used, size;

    if (rblist__nr_entries(&objects) == 0)
        return;

    fprintf(fp, "OBJECTS %u\n", rblist__nr_entries(&objects));
    fprintf(fp, "%-4s %-8s %-8s %-12s %-12s %s\n", "REF", "TYPE", "SYMS", "USED", "MEMS", "OBJECT");
    for (node = rb_first_cached(&objects.entries); node;
         node = rb_next(node)) {
        obj = container_of(node, struct object, rbnode);
        used = obj->syms_sz * sizeof(*obj->syms) + obj->strs_sz;
        size = obj->syms_cap * sizeof(*obj->syms) + obj->strs_cap;
        fprintf(fp, "%-4u %-8s %-8d %-12ld %-12ld %s\n", refcount_read(&obj->refcnt),
                str_type[obj->type], obj->syms_sz, used, size, obj->name);
    }
}

static int syms__add_dso(struct syms *syms, struct map *map, const char *name)
{
    struct dso *dso = NULL;
    int i;
    void *tmp;

    for (i = 0; i < syms->dso_sz; i++) {
        if (!strcmp(syms->dsos[i].obj->name, name)) {
            dso = &syms->dsos[i];
            break;
        }
    }

    if (!dso) {
        tmp = realloc(syms->dsos, (syms->dso_sz + 1) *
                  sizeof(*syms->dsos));
        if (!tmp)
            return -1;
        syms->dsos = tmp;
        dso = &syms->dsos[syms->dso_sz++];
        memset(dso, 0, sizeof(*dso));

        dso->obj = obj__get(name);
        if (!dso->obj)
            return -1;
    }

    tmp = realloc(dso->ranges, (dso->range_sz + 1) * sizeof(*dso->ranges));
    if (!tmp)
        return -1;
    dso->ranges = tmp;
    dso->ranges[dso->range_sz].start = map->start_addr;
    dso->ranges[dso->range_sz].end = map->end_addr;
    dso->ranges[dso->range_sz].file_off = map->file_off;
    dso->range_sz++;

    return 0;
}

static void dso__free_fields(struct dso *dso)
{
    if (!dso)
        return;

    obj__put(dso->obj);
    free(dso->ranges);
}

struct dso *syms__find_dso(const struct syms *syms, unsigned long addr,
                  uint64_t *offset)
{
    struct load_range *range;
    struct dso *dso;
    int i, j;

    for (i = 0; i < syms->dso_sz; i++) {
        dso = &syms->dsos[i];
        for (j = 0; j < dso->range_sz; j++) {
            range = &dso->ranges[j];
            if (addr <= range->start || addr >= range->end)
                continue;
            if (dso->obj->type == DYN || dso->obj->type == VDSO) {
                /* Offset within the mmap */
                *offset = addr - range->start + range->file_off;
                /* Offset within the ELF for dyn symbol lookup */
                *offset += dso->obj->sh_addr - dso->obj->sh_offset;
            } else {
                *offset = addr;
            }

            return dso;
        }
    }

    return NULL;
}

static int obj__load_sym_table_from_perf_map(struct object *obj)
{
    return -1;
}

static int obj__add_sym(struct object *obj, const char *name, uint64_t start,
            uint64_t size)
{
    struct sym *sym;
    size_t new_cap, name_len = strlen(name) + 1;
    void *tmp;

    if (obj->strs_sz + name_len > obj->strs_cap) {
        new_cap = obj->strs_cap * 4 / 3;
        if (new_cap < obj->strs_sz + name_len)
            new_cap = obj->strs_sz + name_len;
        if (new_cap < 1024)
            new_cap = 1024;
        tmp = realloc(obj->strs, new_cap);
        if (!tmp)
            return -1;
        obj->strs = tmp;
        obj->strs_cap = new_cap;
    }

    if (obj->syms_sz + 1 > obj->syms_cap) {
        new_cap = obj->syms_cap * 4 / 3;
        if (new_cap < 1024)
            new_cap = 1024;
        tmp = realloc(obj->syms, sizeof(*obj->syms) * new_cap);
        if (!tmp)
            return -1;
        obj->syms = tmp;
        obj->syms_cap = new_cap;
    }

    sym = &obj->syms[obj->syms_sz++];
    /* while constructing, re-use pointer as just a plain offset */
    sym->name = (void *)(unsigned long)obj->strs_sz;
    sym->start = start;
    sym->size = size;

    memcpy(obj->strs + obj->strs_sz, name, name_len);
    obj->strs_sz += name_len;
    return 0;
}

static int sym_cmp(const void *p1, const void *p2)
{
    const struct sym *s1 = p1, *s2 = p2;

    if (s1->start == s2->start)
        return strcmp(s1->name, s2->name);
    return s1->start < s2->start ? -1 : 1;
}

static int obj__add_syms(struct object *obj, Elf *e, Elf_Scn *section,
             size_t stridx, size_t symsize)
{
    Elf_Data *data = NULL;

    while ((data = elf_getdata(section, data)) != 0) {
        size_t i, symcount = data->d_size / symsize;

        if (data->d_size % symsize)
            return -1;

        for (i = 0; i < symcount; ++i) {
            const char *name;
            GElf_Sym sym;

            if (!gelf_getsym(data, (int)i, &sym))
                continue;
            if (!(name = elf_strptr(e, stridx, sym.st_name)))
                continue;
            if (name[0] == '\0')
                continue;

            if (sym.st_value == 0)
                continue;

            if (obj__add_sym(obj, name, sym.st_value, sym.st_size))
                goto err_out;
        }
    }

    return 0;

err_out:
    return -1;
}

static void obj__free_fields(struct object *obj)
{
    free(obj->syms);
    free(obj->strs);
    obj->syms_sz = 0;
    obj->syms_cap = 0;
    obj->strs_sz = 0;
    obj->syms_cap = 0;
}

#define MAGIC		"\xFD" "7zXZ\0" /* XZ file format.  */
#define MAGIC2		"\x5d\0"	/* Raw LZMA format.  */
static int unlzma(void *input, size_t input_size, void **output, size_t *output_size)
{
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_action action = LZMA_RUN;
    lzma_ret ret;
    void *buffer = NULL;
    size_t size = 0;

    *output = NULL;
    *output_size = 0;

    #define NOMAGIC(magic) \
      (input_size <= sizeof magic || \
       memcmp (input, magic, sizeof magic - 1))
    if (NOMAGIC (MAGIC) && NOMAGIC (MAGIC2))
        return -1;

    ret = lzma_stream_decoder(&strm, 1UL << 30, 0);
    if (ret != LZMA_OK)
        return -1;

    strm.next_in = input;
	strm.avail_in = input_size;

    do {
        if (strm.avail_out == 0) {
            ptrdiff_t pos = (void *) strm.next_out - buffer;
            size_t more = size ? size * 2 : input_size;
            char *b = realloc (buffer, more);
            while (unlikely (b == NULL) && more >= size + 1024)
                b = realloc (buffer, more -= 1024);
            if (unlikely (b == NULL)) {
                ret = LZMA_MEM_ERROR;
                break;
            }
            buffer = b;
            size = more;
            strm.next_out = buffer + pos;
            strm.avail_out = size - pos;
        }
    } while ((ret = lzma_code(&strm, action)) == LZMA_OK);

    size = strm.total_out;
    buffer = realloc (buffer, size) ?: size == 0 ? NULL : buffer;

    lzma_end(&strm);

    if (ret == LZMA_STREAM_END) {
        *output = buffer;
        *output_size = size;
        return 0;
    }

    free(buffer);
    return -1;
}

static int elf__load_sym_table(struct object *obj, Elf *e)
{
    Elf_Scn *section = NULL;
    size_t shstrndx;
    void *buffer = NULL;
    size_t size = 0;
    int added = 0;

    if (elf_getshdrstrndx(e, &shstrndx) < 0)
        return -1;

    while ((section = elf_nextscn(e, section)) != 0) {
        GElf_Shdr header;
        const char *name;

        if (!gelf_getshdr(section, &header))
            continue;

        name = elf_strptr(e, shstrndx, header.sh_name);
        if (name == NULL)
            continue;

        if (header.sh_type == SHT_SYMTAB ||
            header.sh_type == SHT_DYNSYM) {
            if (obj__add_syms(obj, e, section, header.sh_link,
                      header.sh_entsize))
                goto err_out;
            added ++;
            continue;
        }

        if (!strcmp (name, ".gnu_debugdata")) {
            /* Uncompress LZMA data found in a minidebug file.  The minidebug
             * format is described at
             * https://sourceware.org/gdb/current/onlinedocs/gdb/MiniDebugInfo.html.
             */
            Elf_Data *rawdata = elf_rawdata(section, NULL);
            if (rawdata != NULL &&
                unlzma(rawdata->d_buf, rawdata->d_size, &buffer, &size) == 0) {
                Elf *debuginfo = open_elf_memory(buffer, size);
                if (debuginfo &&
                    elf__load_sym_table(obj, debuginfo) == 0) {
                    close_elf(debuginfo, 0);
                }
                free(buffer);
            }
        }
    }

    return added ? 0 : -1;

err_out:
    return -1;
}

typedef struct
{
  uint32_t namesz;
  uint32_t descsz;
  uint32_t type;
  char name[1];
} b_elf_note;

#define NT_GNU_BUILD_ID 3
#define SYSTEM_BUILD_ID_DIR "/usr/lib/debug/.build-id/"

/*
 * Open a separate debug info file, using the build ID to find it.
 * The GDB manual says that the only place gdb looks for a debug file
 * when the build ID is known is in /usr/lib/debug/.build-id.
 * https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
 */
static Elf *open_elf_debugfile_by_buildid(Elf *e, int *debug_fd)
{
    const char * const prefix = SYSTEM_BUILD_ID_DIR;
    const size_t prefix_len = strlen (prefix);
    const char * const suffix = ".debug";
    const size_t suffix_len = strlen (suffix);
    size_t len;
    char *bd_filename, *t;
    size_t i;

    const char *buildid_data = NULL;
    uint32_t buildid_size;
    Elf_Scn *section = NULL;
    size_t shstrndx;
    Elf *debug = NULL;

    if (elf_getshdrstrndx(e, &shstrndx) < 0)
        return NULL;

    while ((section = elf_nextscn(e, section)) != 0) {
        GElf_Shdr header;
        const char *name;

        if (!gelf_getshdr(section, &header))
            continue;

        name = elf_strptr(e, shstrndx, header.sh_name);
        if (name == NULL)
            continue;

        if (!strcmp (name, ".note.gnu.build-id")) {
            const b_elf_note *note;
            Elf_Data *rawdata = elf_rawdata(section, NULL);

            note = (const b_elf_note *)rawdata->d_buf;
            if (note->type == NT_GNU_BUILD_ID &&
                note->namesz == 4 &&
                strncmp (note->name, "GNU", 4) == 0 &&
                header.sh_size <= 12 + ((note->namesz + 3) & ~3) + note->descsz)
            {
                buildid_data = &note->name[0] + ((note->namesz + 3) & ~3);
                buildid_size = note->descsz;
                goto found;
            }
        }
    }
    return NULL;

found:
    len = prefix_len + buildid_size * 2 + suffix_len + 2;
    bd_filename = malloc(len);
    if (bd_filename == NULL)
        return NULL;

    t = bd_filename;
    memcpy(t, prefix, prefix_len);
    t += prefix_len;
    for (i = 0; i < buildid_size; i++) {
        unsigned char b;
        unsigned char nib;

        b = (unsigned char) buildid_data[i];
        nib = (b & 0xf0) >> 4;
        *t++ = nib < 10 ? '0' + nib : 'a' + nib - 10;
        nib = b & 0x0f;
        *t++ = nib < 10 ? '0' + nib : 'a' + nib - 10;
        if (i == 0)
            *t++ = '/';
    }
    memcpy (t, suffix, suffix_len);
    t[suffix_len] = '\0';

    debug = open_elf(bd_filename, debug_fd);
    free(bd_filename);
    return debug;
}

static int obj__load_sym_table_from_elf(struct object *obj, int fd)
{
    Elf *e, *debug = NULL;
    int debug_fd = 0;
    int i, err = -1;
    void *tmp;

    e = fd > 0 ? open_elf_by_fd(fd) : open_elf(obj->name, &fd);
    if (!e)
        return err;

    debug = open_elf_debugfile_by_buildid(e, &debug_fd);

    if (!debug || elf__load_sym_table(obj, debug) < 0) {
        if (elf__load_sym_table(obj, e) < 0)
            goto err_out;
    }

    tmp = realloc(obj->strs, obj->strs_sz);
    if (!tmp)
        goto err_out;
    obj->strs = tmp;
    obj->strs_cap = obj->strs_sz;

    tmp = realloc(obj->syms, sizeof(*obj->syms) * obj->syms_sz);
    if (!tmp)
        goto err_out;
    obj->syms = tmp;
    obj->syms_cap = obj->syms_sz;

    /* now when strings are finalized, adjust pointers properly */
    for (i = 0; i < obj->syms_sz; i++)
        obj->syms[i].name += (unsigned long)obj->strs;

    qsort(obj->syms, obj->syms_sz, sizeof(*obj->syms), sym_cmp);

    err = 0;

out:
    close_elf(e, fd);
    if (debug)
        close_elf(debug, debug_fd);
    return err;

err_out:
    obj__free_fields(obj);
    goto out;
}

static int create_tmp_vdso_image(struct object *obj)
{
    uint64_t start_addr, end_addr;
    long pid = getpid();
    char buf[PATH_MAX];
    void *image = NULL;
    char tmpfile[128];
    int ret, fd = -1;
    uint64_t sz;
    char *name;
    FILE *f;

    snprintf(tmpfile, sizeof(tmpfile), "/proc/%ld/maps", pid);
    f = fopen(tmpfile, "r");
    if (!f)
        return -1;

    while (true) {
        ret = fscanf(f, "%lx-%lx %*s %*x %*x:%*x %*u%[^\n]",
                 &start_addr, &end_addr, buf);
        if (ret == EOF && feof(f))
            break;
        if (ret != 3)
            goto err_out;

        name = buf;
        while (isspace(*name))
            name++;
        if (!is_file_backed(name))
            continue;
        if (is_vdso(name))
            break;
    }

    sz = end_addr - start_addr;
    image = malloc(sz);
    if (!image)
        goto err_out;
    memcpy(image, (void *)start_addr, sz);

    snprintf(tmpfile, sizeof(tmpfile),
         "/tmp/libbpf_%ld_vdso_image_XXXXXX", pid);
    fd = mkostemp(tmpfile, O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "failed to create temp file: %s\n",
            strerror(errno));
        goto err_out;
    }
    /* Unlink the file to avoid leaking */
    if (unlink(tmpfile) == -1)
        fprintf(stderr, "failed to unlink %s: %s\n", tmpfile,
            strerror(errno));
    if (write(fd, image, sz) == -1) {
        fprintf(stderr, "failed to write to vDSO image: %s\n",
            strerror(errno));
        close(fd);
        fd = -1;
        goto err_out;
    }

err_out:
    fclose(f);
    free(image);
    return fd;
}

static int obj__load_sym_table_from_vdso_image(struct object *obj)
{
    int fd = create_tmp_vdso_image(obj);

    if (fd < 0)
        return -1;
    return obj__load_sym_table_from_elf(obj, fd);
}

static int obj__load_sym_table(struct object *obj)
{
    if (obj->type == UNKNOWN)
        return -1;
    if (obj->type == PERF_MAP)
        return obj__load_sym_table_from_perf_map(obj);
    if (obj->type == EXEC || obj->type == DYN)
        return obj__load_sym_table_from_elf(obj, 0);
    if (obj->type == VDSO)
        return obj__load_sym_table_from_vdso_image(obj);
    return -1;
}

static const struct sym *obj__find_sym(struct object *obj, uint64_t offset)
{
    unsigned long sym_addr;
    int start, end, mid;

    if (!obj)
        return NULL;
    if (!obj->syms && obj__load_sym_table(obj))
        return NULL;

    start = 0;
    end = obj->syms_sz - 1;

    /* find largest sym_addr <= addr using binary search */
    while (start < end) {
        mid = start + (end - start + 1) / 2;
        sym_addr = obj->syms[mid].start;

        if (sym_addr <= offset)
            start = mid;
        else
            end = mid - 1;
    }

    if (start == end &&
        obj->syms[start].start <= offset &&
        obj->syms[start].start + obj->syms[start].size >= offset)
        return &obj->syms[start];
    return NULL;
}

const struct sym *dso__find_sym(struct dso *dso, uint64_t offset)
{
    return obj__find_sym(dso->obj, offset);
}

const char *dso__name(struct dso *dso)
{
    return dso ? dso->obj->name : NULL;
}

static struct syms *__syms__load_file(FILE *f, char *line, int size, pid_t tgid)
{
    char buf[PATH_MAX], perm[5];
    char deleted[128];
    struct syms *syms;
    struct map map;
    char *s;
    char *name;
    int ret;

    syms = calloc(1, sizeof(*syms));
    if (!syms)
        goto err_out;

    if (tgid)
        snprintf(deleted, sizeof(deleted), "/proc/%ld/exe", (long)tgid);

    while (true) {
        s = fgets(line, size, f);
        if (!s || feof(f))
            break;

        ret = sscanf(s, "%lx-%lx %4s %lx %lx:%lx %lu%[^\n]\n",
                 &map.start_addr, &map.end_addr, perm,
                 &map.file_off, &map.dev_major,
                 &map.dev_minor, &map.inode, buf);

        if (ret != 8)   /* perf-<PID>.map */
            break;

        if (perm[2] != 'x')
            continue;

        name = buf;
        while (isspace(*name))
            name++;
        if (!is_file_backed(name))
            continue;

        if (tgid &&
            strncmp(name + strlen(name) - 10, " (deleted)", 10) == 0)
            name = deleted;

        if (syms__add_dso(syms, &map, name))
            goto err_out;
    }

    return syms;

err_out:
    syms__free(syms);
    return NULL;
}

struct syms *syms__load_file(const char *fname, pid_t tgid)
{
    FILE *f;
    struct syms *syms;
    char line[PATH_MAX];

    f = fopen(fname, "r");
    if (!f)
        return NULL;
    syms = __syms__load_file(f, line, PATH_MAX, tgid);
    fclose(f);
    return syms;
}

struct syms *syms__load_pid(pid_t tgid)
{
    char fname[128];

    snprintf(fname, sizeof(fname), "/proc/%ld/maps", (long)tgid);
    return syms__load_file(fname, tgid);
}

void syms__free(struct syms *syms)
{
    int i;

    if (!syms)
        return;

    for (i = 0; i < syms->dso_sz; i++)
        dso__free_fields(&syms->dsos[i]);
    free(syms->dsos);
    free(syms);
}

const struct sym *syms__map_addr(const struct syms *syms, unsigned long addr)
{
    struct dso *dso;
    uint64_t offset;

    dso = syms__find_dso(syms, addr, &offset);
    if (!dso)
        return NULL;
    return dso__find_sym(dso, offset);
}

/*
 * pprof --symbols <program>
 *  Maps addresses to symbol names.  In this mode, stdin should be a
 *  list of library mappings, in the same format as is found in the heap-
 *  and cpu-profile files (this loosely matches that of /proc/self/maps
 *  on linux), followed by a list of hex addresses to map, one per line.
 **/
void syms__convert(FILE *fin, FILE *fout)
{
    struct syms *syms;
    char line[PATH_MAX];
    char *s;
    int ret;
    unsigned long addr;

    syms = __syms__load_file(fin, line, PATH_MAX, 0);
    if (!syms)
        return;

    while (true) {
        ret = sscanf(line, "0x%lx\n", &addr);
        if (ret == 1) {
            struct dso *dso;
            uint64_t offset;
            dso = syms__find_dso(syms, addr, &offset);
            if (dso) {
                const struct sym *sym = dso__find_sym(dso, offset);
                if (sym) {
                    fprintf(fout, "%s+0x%lx\n", sym->name, offset - sym->start);
                    goto next_line;
                }
            }
        }
        fprintf(fout, "??\n");

next_line:
        s = fgets(line, PATH_MAX, fin);
        if (!s && feof(fin))
            break;
    }
    syms__free(syms);
}

struct syms_cache_node {
    struct rb_node rbnode;
    struct syms *syms;
    int tgid;
};
struct syms_cache {
    struct rblist cache;
};

static int syms_cache_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct syms_cache_node *node = container_of(rbn, struct syms_cache_node, rbnode);
    int tgid = *(const int *)entry;

    if (node->tgid > tgid)
        return 1;
    else if (node->tgid < tgid)
        return -1;
    else
        return 0;
}

static struct rb_node *syms_cache_node_new(struct rblist *rlist, const void *new_entry)
{
    int tgid = *(const int *)new_entry;
    struct syms_cache_node *node = malloc(sizeof(*node));

    if (node) {
        memset(node, 0, sizeof(*node));
        RB_CLEAR_NODE(&node->rbnode);
        node->tgid = tgid;
        node->syms = syms__load_pid(tgid);
        if (!node->syms) {
            free(node);
            return NULL;
        }
        return &node->rbnode;
    } else
        return NULL;
}

static void syms_cache_node_delete(struct rblist *rblist, struct rb_node *rbn)
{
    struct syms_cache_node *node = container_of(rbn, struct syms_cache_node, rbnode);

    syms__free(node->syms);
    free(node);
}

struct syms_cache *syms_cache__new(void)
{
    struct syms_cache *syms_cache;

    syms_cache = calloc(1, sizeof(*syms_cache));
    if (!syms_cache)
        return NULL;

    rblist__init(&syms_cache->cache);
    syms_cache->cache.node_cmp = syms_cache_node_cmp;
    syms_cache->cache.node_new = syms_cache_node_new;
    syms_cache->cache.node_delete = syms_cache_node_delete;
    return syms_cache;
}

void syms_cache__free(struct syms_cache *syms_cache)
{
    if (!syms_cache)
        return;

    rblist__exit(&syms_cache->cache);
    free(syms_cache);
}

struct syms *syms_cache__get_syms(struct syms_cache *syms_cache, int tgid)
{
    struct rb_node *rbn;
    struct syms_cache_node *node = NULL;
    struct syms *syms = NULL;

    rbn = rblist__findnew(&syms_cache->cache, &tgid);
    if (rbn) {
        node = container_of(rbn, struct syms_cache_node, rbnode);
        syms = node->syms;
    }
    return syms;
}

void syms_cache__free_syms(struct syms_cache *syms_cache, int tgid)
{
    struct rb_node *rbn;

    rbn = rblist__find(&syms_cache->cache, &tgid);
    if (rbn) {
        rblist__remove_node(&syms_cache->cache, rbn);
    }
}

struct partitions {
    struct partition *items;
    int sz;
};

static int partitions__add_partition(struct partitions *partitions,
                     const char *name, unsigned int dev)
{
    struct partition *partition;
    void *tmp;

    tmp = realloc(partitions->items, (partitions->sz + 1) *
        sizeof(*partitions->items));
    if (!tmp)
        return -1;
    partitions->items = tmp;
    partition = &partitions->items[partitions->sz];
    partition->name = strdup(name);
    partition->dev = dev;
    partitions->sz++;

    return 0;
}

struct partitions *partitions__load(void)
{
    char part_name[DISK_NAME_LEN];
    unsigned int devmaj, devmin;
    unsigned long long nop;
    struct partitions *partitions;
    char buf[64];
    FILE *f;

    f = fopen("/proc/partitions", "r");
    if (!f)
        return NULL;

    partitions = calloc(1, sizeof(*partitions));
    if (!partitions)
        goto err_out;

    while (fgets(buf, sizeof(buf), f) != NULL) {
        /* skip heading */
        if (buf[0] != ' ' || buf[0] == '\n')
            continue;
        if (sscanf(buf, "%u %u %llu %s", &devmaj, &devmin, &nop,
                part_name) != 4)
            goto err_out;
        if (partitions__add_partition(partitions, part_name,
                        MKDEV(devmaj, devmin)))
            goto err_out;
    }

    fclose(f);
    return partitions;

err_out:
    partitions__free(partitions);
    fclose(f);
    return NULL;
}

void partitions__free(struct partitions *partitions)
{
    int i;

    if (!partitions)
        return;

    for (i = 0; i < partitions->sz; i++)
        free(partitions->items[i].name);
    free(partitions->items);
    free(partitions);
}

const struct partition *
partitions__get_by_dev(const struct partitions *partitions, unsigned int dev)
{
    int i;

    for (i = 0; i < partitions->sz; i++) {
        if (partitions->items[i].dev == dev)
            return &partitions->items[i];
    }

    return NULL;
}

const struct partition *
partitions__get_by_name(const struct partitions *partitions, const char *name)
{
    int i;

    for (i = 0; i < partitions->sz; i++) {
        if (strcmp(partitions->items[i].name, name) == 0)
            return &partitions->items[i];
    }

    return NULL;
}

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
    int num_stars, num_spaces, i;
    bool need_plus;

    num_stars = min(val, val_max) * width / val_max;
    num_spaces = width - num_stars;
    need_plus = val > val_max;

    for (i = 0; i < num_stars; i++)
        printf("*");
    for (i = 0; i < num_spaces; i++)
        printf(" ");
    if (need_plus)
        printf("+");
}

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
    int stars_max = 40, idx_max = -1, idx0_max = -1;
    unsigned int val, val_max = 0;
    unsigned long long low, high;
    int stars, width, i;

    for (i = 0; i < vals_size; i++) {
        val = vals[i];
        if (val > 0)
            idx_max = i;
        if (val > val_max)
            val_max = val;
        if (idx_max < 0)
            idx0_max = i;
    }

    if (idx_max < 0)
        return;

    printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
        idx_max <= 32 ? 19 : 29, val_type);

    if (idx_max <= 32)
        stars = stars_max;
    else
        stars = stars_max / 2;

    for (i = 0; i <= idx_max; i++) {
        low = (1ULL << (i + 1)) >> 1;
        high = (1ULL << (i + 1)) - 1;
        if (low == high)
            low -= 1;
        if (idx0_max > i) {
            i = idx0_max;
            high = (1ULL << (i + 1)) - 1;
        }
        val = vals[i];
        width = idx_max <= 32 ? 10 : 20;
        printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
        print_stars(val, val_max, stars);
        printf("|\n");
    }
}

void print_linear_hist(unsigned int *vals, int vals_size, unsigned int base,
               unsigned int step, const char *val_type)
{
    int i, stars_max = 40, idx_min = -1, idx_max = -1;
    unsigned int val, val_max = 0;

    for (i = 0; i < vals_size; i++) {
        val = vals[i];
        if (val > 0) {
            idx_max = i;
            if (idx_min < 0)
                idx_min = i;
        }
        if (val > val_max)
            val_max = val;
    }

    if (idx_max < 0)
        return;

    printf("     %-13s : count     distribution\n", val_type);
    for (i = idx_min; i <= idx_max; i++) {
        val = vals[i];
        printf("        %-10d : %-8d |", base + i * step, val);
        print_stars(val, val_max, stars_max);
        printf("|\n");
    }
}

unsigned long long get_ktime_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

bool is_kernel_module(const char *name)
{
    bool found = false;
    char buf[64];
    FILE *f;

    f = fopen("/proc/modules", "r");
    if (!f)
        return false;

    while (fgets(buf, sizeof(buf), f) != NULL) {
        if (sscanf(buf, "%s %*s\n", buf) != 1)
            break;
        if (!strcmp(buf, name)) {
            found = true;
            break;
        }
    }

    fclose(f);
    return found;
}

bool kprobe_exists(const char *name)
{
    char sym_name[256];
    FILE *f;
    int ret;

    f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
    if (!f)
        goto slow_path;

    while (true) {
        ret = fscanf(f, "%s%*[^\n]\n", sym_name);
        if (ret == EOF && feof(f))
            break;
        if (ret != 1) {
            fprintf(stderr, "failed to read symbol from available_filter_functions\n");
            break;
        }
        if (!strcmp(name, sym_name)) {
            fclose(f);
            return true;
        }
    }

    fclose(f);
    return false;

slow_path:
    f = fopen("/proc/kallsyms", "r");
    if (!f)
        return false;

    while (true) {
        ret = fscanf(f, "%*x %*c %s%*[^\n]\n", sym_name);
        if (ret == EOF && feof(f))
            break;
        if (ret != 1) {
            fprintf(stderr, "failed to read symbol from kallsyms\n");
            break;
        }
        if (!strcmp(name, sym_name)) {
            fclose(f);
            return true;
        }
    }

    fclose(f);
    return false;
}

bool vmlinux_btf_exists(void)
{
    if (!access("/sys/kernel/btf/vmlinux", R_OK))
        return true;
    return false;
}

bool module_btf_exists(const char *mod)
{
    char sysfs_mod[80];

    if (mod) {
        snprintf(sysfs_mod, sizeof(sysfs_mod), "/sys/kernel/btf/%s", mod);
        if (!access(sysfs_mod, R_OK))
            return true;
    }
    return false;
}
