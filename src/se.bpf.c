#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, pid_t);     // pid_t
    __type(value, __u32);   // inode_t
} maps_deny SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm, int ret) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    unsigned long *target_inode = bpf_map_lookup_elem(&maps_deny, &pid);
    if (!target_inode || ret) return ret;

    // unsigned long inode = BPF_CORE_READ(bprm, executable, f_path.dentry, d_inode, i_ino);
    unsigned long inode = 0;

    if (*target_inode == inode) return -1;

    return ret;
}
