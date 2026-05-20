#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <dirent.h>

#include <vcpu_info.h>

static struct list_head vm_list = LIST_HEAD_INIT(vm_list);

static void vcpu_info_free(struct vcpu_info *vcpu);


static struct vcpu_info *vcpu_info_hmp_info_cpus(const char *uuid)
{
    char buff[512];
    FILE *info = NULL;
    struct vcpu_info *vcpu = NULL;
    int nr_vcpu = 0;

    snprintf(buff, sizeof(buff), "virsh qemu-monitor-command %s --hmp info cpus", uuid);
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
    info = NULL;

    // Non-existent vm.
    if (!vcpu)
        goto cleanup;

    return vcpu;

cleanup:
    if (info) pclose(info);
    if (vcpu) free(vcpu);
    return NULL;
}

static int vcpu_info_vcpupin(struct vcpu_info *vcpu)
{
    char buff[512];
    FILE *info = NULL;

    snprintf(buff, sizeof(buff), "virsh vcpupin --live %s", vcpu->uuid);
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

    return 0;

cleanup:
    if (info) pclose(info);
    return -1;
}

static int vcpu_info_tgid(struct vcpu_info *vcpu)
{
    char path[256], line[256];
    FILE *fp;
    int pid = -1;

    /*
     * Read /proc/pid/status, get Tgid.
     */
    snprintf(path, sizeof(path), "/proc/%d/status", vcpu->vcpu[0].thread_id);
    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "Tgid: %d", &pid) == 1)
            break;
        pid = -1;
    }
    fclose(fp);

    if (pid == -1)
        return -1;

    vcpu->tgid = pid;
    return 0;
}

static int vcpu_info_kvm_vm_fd(struct vcpu_info *vcpu)
{
    char path[256];
    DIR *dir;
    struct dirent *entry;
    int kvm_vm_fd = -1;

    /*
     * Readdir /proc/pid/fd/, obtain the "anon_inode:kvm-vm" file descriptor.
     */
    snprintf(path, sizeof(path), "/proc/%d/fd/", vcpu->tgid);
    dir = opendir(path);
    if (dir == NULL)
        return -1;

    while ((entry = readdir(dir)) != NULL) {
        char link_target[256];
        char link_path[256];
        ssize_t len;
        int ret;

        if (entry->d_name[0] == '.')
            continue;

        ret = snprintf(link_path, sizeof(link_path), "%s/%s", path, entry->d_name);
        if (ret >= sizeof(link_path))
            continue;

        len = readlink(link_path, link_target, sizeof(link_target) - 1);
        if (len == -1)
            continue;

        link_target[len] = '\0';
        if (strstr(link_target, "kvm-vm")) {
            kvm_vm_fd = atoi(entry->d_name);
            break;
        }
    }
    closedir(dir);

    if (kvm_vm_fd == -1)
        return -1;

    vcpu->kvm_vm_fd = kvm_vm_fd;
    return 0;
}

static struct vcpu_info *vcpu_info_new(const char *uuid)
{
    struct vcpu_info *vcpu = NULL;

    // Popen's process disable HEAPCHECK.
    // See: https://gperftools.github.io/gperftools/heap_checker.html
    unsetenv("HEAPCHECK");

    vcpu = vcpu_info_hmp_info_cpus(uuid);
    if (!vcpu)
        return NULL;

    INIT_LIST_HEAD(&vcpu->vm_link);
    vcpu->uuid = uuid;
    refcount_set(&vcpu->ref, 1);

    if (vcpu_info_vcpupin(vcpu) < 0)
        goto cleanup;

    if (vcpu_info_tgid(vcpu) < 0)
        goto cleanup;

    if (vcpu_info_kvm_vm_fd(vcpu) < 0)
        goto cleanup;

    list_add(&vcpu->vm_link, &vm_list);

    return vcpu;

cleanup:
    vcpu_info_free(vcpu);
    return NULL;
}

static void vcpu_info_free(struct vcpu_info *vcpu)
{
    int i;

    if (vcpu->host_cpus) {
        for (i = 0; i < vcpu->nr_vcpu; i ++)
            perf_cpu_map__put(vcpu->host_cpus[i]);
        free(vcpu->host_cpus);
    }
    list_del(&vcpu->vm_link);
    free(vcpu);
}

struct vcpu_info *vcpu_info_get(const char *uuid)
{
    struct vcpu_info *vcpu;

    list_for_each_entry(vcpu, &vm_list, vm_link) {
        if (strcmp(vcpu->uuid, uuid) == 0) {
            if (refcount_inc_not_zero(&vcpu->ref))
                return vcpu;
        }
    }
    vcpu = vcpu_info_new(uuid);
    return vcpu;
}

void vcpu_info_put(struct vcpu_info *vcpu)
{
    if (!vcpu) return;
    if (refcount_dec_and_test(&vcpu->ref))
        vcpu_info_free(vcpu);
}

