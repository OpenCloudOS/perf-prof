#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <vcpu_info.h>

struct vcpu_info *vcpu_info_new(const char *vm)
{
    char buff[512];
    FILE *info = NULL;
    struct vcpu_info *vcpu = NULL;
    int nr_vcpu = 0;

    // Popen's process disable HEAPCHECK.
    // See: https://gperftools.github.io/gperftools/heap_checker.html
    unsetenv("HEAPCHECK");

    snprintf(buff, sizeof(buff), "virsh qemu-monitor-command %s --hmp info cpus", vm);
    info = popen(buff, "r");
    if (!info)
        goto cleanup;

    /*
     * This is the gross format we're about to parse :-{
     *
     * (qemu) info cpus
     * * CPU #0: pc=0x00000000000f0c4a thread_id=30019
     *   CPU #1: pc=0x00000000fffffff0 thread_id=30020
     *   CPU #2: pc=0x00000000fffffff0 (halted) thread_id=30021
     *
     */
    while (fgets(buff, sizeof(buff), info)) {
        char *offset = NULL;
        char *end = NULL;
        long int cpuid = -1;
        long int tid = 0;
        int len = strlen(buff);

        if (len == 0 || (len == 1 && buff[0] == '\n'))
            continue;

        /* extract cpu number */
        if ((offset = strstr(buff, "#")) == NULL)
            goto cleanup;

        cpuid = strtol(offset + strlen("#"), &end, 0);
        if (cpuid == LONG_MIN || cpuid == LONG_MAX)
            goto cleanup;
        if (end == NULL || *end != ':')
            goto cleanup;

        /* Extract host Thread ID */
        if ((offset = strstr(end, "thread_id=")) == NULL)
            goto cleanup;

        tid = strtol(offset + strlen("thread_id="), &end, 0);
        if (cpuid == LONG_MIN || cpuid == LONG_MAX)
            goto cleanup;
        if (end == NULL)
            goto cleanup;

        if (cpuid >= nr_vcpu) {
            vcpu = realloc(vcpu, sizeof(*vcpu) + sizeof(vcpu->vcpu[0]) * (cpuid + 32));
            if (!vcpu)
                goto cleanup;

            memset(&vcpu->vcpu[nr_vcpu], 0, sizeof(vcpu->vcpu[0]) * (cpuid + 32 - nr_vcpu));
            nr_vcpu = cpuid + 32;
        }

        vcpu->nr_vcpu = cpuid + 1;
        vcpu->vcpu[cpuid].thread_id = (int)tid;
    }
    pclose(info);


    snprintf(buff, sizeof(buff), "virsh vcpupin --live %s", vm);
    info = popen(buff, "r");
    if (!info)
        goto cleanup;

    /*
     * This is the gross format we're about to parse :-{
     *
     * VCPU: CPU Affinity
     * ----------------------------------
     *    0: 1,49
     *    1: 1,49
     *
     */
    vcpu->host_cpus = calloc(vcpu->nr_vcpu, sizeof(*vcpu->host_cpus));
    if (!vcpu->host_cpus)
        goto cleanup;
    while (fgets(buff, sizeof(buff), info)) {
        char *str = buff;
        char *end = NULL;
        long int cpuid = -1;
        int nr;

        while (*str != '\0' && isspace((unsigned char)*str))
            str++;

        if (*str == '\0')
            continue;
        if (str[0] == 'V' && str[1] == 'C' && str[2] == 'P' && str[3] == 'U')
            continue;
        if (str[0] == '-' && str[1] == '-')
            continue;

        cpuid = strtol(str, &end, 0);
        if (cpuid == LONG_MIN || cpuid == LONG_MAX)
            goto cleanup;
        if (end == NULL || *end != ':')
            goto cleanup;
        if (cpuid >= vcpu->nr_vcpu)
            goto cleanup;

        end ++;
        while (*end != '\0' && isspace((unsigned char)*end))
            end++;

        vcpu->host_cpus[cpuid] = perf_cpu_map__new(end);
        if (!vcpu->host_cpus[cpuid])
            goto cleanup;

        nr = perf_cpu_map__nr(vcpu->host_cpus[cpuid]);
        vcpu->vcpu[cpuid].host_cpu = perf_cpu_map__cpu(vcpu->host_cpus[cpuid], cpuid % nr);
    }
    pclose(info);

    return vcpu;

cleanup:
    if (info) pclose(info);
    if (vcpu) vcpu_info_free(vcpu);
    return NULL;
}

void vcpu_info_free(struct vcpu_info *vcpu)
{
    int i;

    if (!vcpu) return;
    if (vcpu->host_cpus) {
        for (i = 0; i < vcpu->nr_vcpu; i ++)
            perf_cpu_map__put(vcpu->host_cpus[i]);
        free(vcpu->host_cpus);
    }
    free(vcpu);
}

