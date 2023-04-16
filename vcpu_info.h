#ifndef __VCPU_INFO_H
#define __VCPU_INFO_H

struct vcpu_info {
    int thread_id[0]; // vcpu -> thread_id
};
struct vcpu_info *vcpu_info_new(const char *vm);
void vcpu_info_free(struct vcpu_info *vcpu);


#endif
