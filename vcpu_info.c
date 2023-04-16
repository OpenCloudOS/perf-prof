#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include <vcpu_info.h>

struct vcpu_info *vcpu_info_new(const char *vm)
{
    char buff[512];
    FILE *info = NULL;
    struct vcpu_info *vcpu = NULL;
    int nr_vcpu = 0;

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
            vcpu = realloc(vcpu, sizeof(int) * (cpuid + 32));
            if (!vcpu)
                goto cleanup;

            memset(&vcpu->thread_id[nr_vcpu], 0, sizeof(int) * (cpuid + 32 - nr_vcpu));
            nr_vcpu = cpuid + 32;
        }

        vcpu->thread_id[cpuid] = (int)tid;
    }

    pclose(info);
    return vcpu;

cleanup:
    if (info) pclose(info);
    if (vcpu) free(vcpu);
    return NULL;
}

void vcpu_info_free(struct vcpu_info *vcpu)
{
    free(vcpu);
}

