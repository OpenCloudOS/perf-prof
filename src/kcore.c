#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <gelf.h>
#include <linux/align.h>
#include <linux/bitops.h>
#include <linux/refcount.h>
#include "monitor.h"
#include "uprobe_helpers.h"
#include "trace_helpers.h"

extern struct env env;

struct segment {
    GElf_Off  p_offset;
    GElf_Addr p_vaddr;
    GElf_Addr p_vaend;
};

static struct kcore_info {
    refcount_t ref;
    int kcore_fd;
    int nr_load;
    struct segment load[0];
} *kcore = NULL;

static void kcore_open(void)
{
    int i, fd;
    Elf *e;
    GElf_Ehdr ehdr;
    GElf_Phdr phdr;
    size_t nhdrs;

    e = open_elf("/proc/kcore", &fd);
    if (!e)
        return;

    if (!gelf_getehdr(e, &ehdr))
        goto out;
    if (ehdr.e_type != ET_CORE)
        goto out;

    if (elf_getphdrnum(e, &nhdrs) != 0)
        goto out;

    kcore = calloc(1, sizeof(struct kcore_info) + nhdrs * sizeof(struct segment));
    if (!kcore)
        goto out;

    for (i = 0; i < (int)nhdrs; i++) {
        if (!gelf_getphdr(e, i, &phdr))
            continue;
        if (phdr.p_type != PT_LOAD)
            continue;
        kcore->load[kcore->nr_load].p_offset = phdr.p_offset;
        kcore->load[kcore->nr_load].p_vaddr = phdr.p_vaddr;
        kcore->load[kcore->nr_load].p_vaend = phdr.p_vaddr + phdr.p_memsz;
        kcore->nr_load++;
    }
    elf_end(e);

    refcount_set(&kcore->ref, 1);
    kcore->kcore_fd = fd;
    return;

out:
    close_elf(e, fd);
    return;
}

void kcore_ref(void)
{
    if (kcore)
        refcount_inc(&kcore->ref);
    else
        kcore_open();
}

void kcore_unref(void)
{
    if (kcore && refcount_dec_and_test(&kcore->ref)) {
        close(kcore->kcore_fd);
        free(kcore);
        kcore = NULL;
    }
}

ssize_t kcore_read(unsigned long kaddr, void *buf, size_t count)
{
    int i;

    if (kcore)
    for (i = 0; i < kcore->nr_load; i++) {
        struct segment *s = &kcore->load[i];
        if (s->p_vaddr <= kaddr && kaddr < s->p_vaend) {
            off_t offset = kaddr - s->p_vaddr + s->p_offset;
            return pread(kcore->kcore_fd, buf, count, offset);
        }
    }
    return -1;
}

static int kcore_argc_init(int argc, char *argv[])
{
    unsigned long long kaddr;
    char *kaddr_end;
    unsigned long count = 1;
    int print = 0;

    if (argc < 1) {
        fprintf(stderr, " <kaddr> needs to be specified.\n");
        help();
    }
    kcore_ref();

    kaddr = strtoull(argv[0], &kaddr_end, 0);
    if (kaddr_end == argv[0]) {
        struct ksyms *ksyms = ksyms__load();
        if (ksyms) {
            const struct ksym *ksym = ksyms__get_symbol(ksyms, argv[0]);
            if (ksym)
                kaddr = ksym->addr;
            ksyms__free(ksyms);
        }
    }
    if (argc > 1)
        count = strtoul(argv[1], NULL, 0);

    printf("%016llx: ", kaddr);
    if (!env.string) {
        int align = env.bytes ? 1<<(fls(env.bytes)-1) : 8;
        size_t size = count * align;
        unsigned char *mem = calloc(size, sizeof(char));
        unsigned char *data = mem;

        if (align != 1 && align != 2 && align != 4 && align != 8)
            align = 1;

        if (data &&
            kcore_read(kaddr, data, size) == size) {
            int i = 0, t = 0;
            char tailer[32];

            while (size) {
                switch (align) {
                   default:
                    case 1: printf("%02x ", *data); break;
                    case 2: printf("%04x ", *(unsigned short *)data); break;
                    case 4: printf("%08x ", *(unsigned int *)data); break;
                    case 8: printf("%016lx ", *(unsigned long *)data); break;
                }
                for (i = 0; i < align; i++)
                    tailer[t++] = isprint(data[i]) ? data[i] : '.';
                size -= align;
                kaddr += align;
                data += align;
                if (t == 16 && size) {
                    printf ("  %.*s\n%016llx: ", t, tailer, kaddr);
                    t = 0;
                }
            }
            if (t) printf ("  %*s%.*s", (16-t)*2 + (16-t)/align, "", t, tailer);
            print = 1;
        }
        free(mem);
    } else {
        unsigned char c;
        while (kcore_read(kaddr, &c, sizeof(c)) == sizeof(c) &&
               c != '\0') {
            print += printf("%c", c);
            kaddr += sizeof(c);
            if (c == '\n')
                printf("%016llx: ", kaddr);
        }
    }
    printf("%s\n", print ? "" : "not a kernel virtual address");

    kcore_unref();
    exit(0);
}

static const char *kcore_desc[] = PROFILER_DESC("kcore",
    "[OPTION...] [-1|-2|-4|-8] [--string] <kaddr|symbol> [count]",
    "Read kernel memory.", "",
    "SYNOPSIS",
    "    Read from /proc/kcore. Supports reading kernel memory by virtual address",
    "    or symbol name. The output includes hex dump with ASCII representation.",
    "",
    "    <kaddr|symbol>  Kernel virtual address (hex) or symbol name",
    "    [count]         Number of elements to read (default: 1)",
    "",
    "    -1, -2, -4, -8  Element size in bytes (default: 8)",
    "    --string        Read as null-terminated string",
    "",
    "EXAMPLES",
    "    "PROGRAME" kcore --string linux_banner",
    "    "PROGRAME" kcore -8 0xffffffff81ade0c0 1",
    "    "PROGRAME" kcore jiffies",
    "    "PROGRAME" kcore -4 loops_per_jiffy 1");
static const char *kcore_argv[] = PROFILER_ARGV("kcore",
    "OPTION:",
    "version", "verbose", "quiet", "help",
    PROFILER_ARGV_PROFILER,
    "string", "1", "2", "4", "8"
);
static profiler kcore_profiler = {
    .name = "kcore",
    .desc = kcore_desc,
    .argv = kcore_argv,
    .argc_init = kcore_argc_init,
};
PROFILER_REGISTER(kcore_profiler);

