#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);     // ppid << 32 | inode
    __type(value, __u8);   // inode_t
} maps_deny SEC(".maps");

/*struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} rb SEC(".maps");*/

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm, int ret) {

    struct task_struct *ptask = (struct task_struct *) bpf_get_current_task();
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t ppid = BPF_CORE_READ(ptask, real_parent, tgid);
    unsigned long inode = BPF_CORE_READ(bprm, file, f_inode, i_ino);

    __u64 key = ((__u64)ppid << 32) | inode;
    __u8 *dummy = bpf_map_lookup_elem(&maps_deny, &key);
    if (dummy) return -1;

    /*__u64 *log = bpf_ringbuf_reserve(&rb, sizeof(__u64), 0);
    if (!log) return ret;
    *log = ((__u64)ppid << 32) | inode;
    bpf_ringbuf_submit(log, 0);*/
    return ret;
}

/* >>>>>>>>    File Permission Check     >>>>>>>>
 * This part will check the pid and control if this open is allowed.
 * <<<<<<<< End of File Permission Check <<<<<<<< */
SEC("lsm/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int flags, int ret) {

    struct task_struct *ptask = (struct task_struct *) bpf_get_current_task();
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t ppid = BPF_CORE_READ(ptask, real_parent, tgid);
    unsigned long ino = BPF_CORE_READ(inode, i_ino);

    __u64 key = ((__u64)ppid << 32) | ino;
    __u8 *dummy = bpf_map_lookup_elem(&maps_deny, &key);
    if (dummy && (flags & 0x4)) return -1;

    return ret;
}

char LICENSE[] SEC("license") = "GPL";
