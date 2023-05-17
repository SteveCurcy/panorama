/*
 * @author  Xu.Cao
 * @date    2023-03-03.
 * @details 通过追踪系统调用维护当前状态机的状态和当前进程上下文信息，通过内核函数获取更详细的信息
 *
 * @functions:
 *      这里只展示在代码中没有注释的系统调用函数集合，除了 exit_group 函数都对应一个入口和出口函数
 *
 *      int syscall__openat(struct pt_regs *ctx, int dirfd, const char __user *name, int FLAG)
 *      int syscall__openat_return(struct pt_regs *ctx)
 *      int syscall__read(struct pt_regs *ctx, int fd)
 *      int syscall__read_return(struct pt_regs *ctx)
 *      int syscall__write(struct pt_regs *ctx, int fd)
 *      int syscall__write_return(struct pt_regs *ctx)
 *      int syscall__close(struct pt_regs *ctx, int fd)
 *      int syscall__close_return(struct pt_regs *ctx)
 *      int syscall__unlinkat(struct pt_regs *ctx, int dirfd, const char __user *name, int FLAG)
 *      int syscall__unlinkat_return(struct pt_regs *ctx)
 *      int syscall__mkdirat(struct pt_regs *ctx, int dirfd, const char __user *name)
 *      int syscall__mkdirat_return(struct pt_regs *ctx)
 *      int syscall__renameat(struct pt_regs *ctx, int olddir, const char *oldname, int newdir, const char *newname)
 *      int syscall__renameat_return(struct pt_regs *ctx)
 *      int syscall__renameat2(struct pt_regs *ctx, int olddir, const char *oldname, int newdir, const char *newname, unsigned int FLAG)
 *      int syscall__renameat2_return(struct pt_regs *ctx)
 *      int syscall__dup3(struct pt_regs *ctx, int oldfd, int newfd, int FLAG)
 *      int syscall__dup3_return(struct pt_regs *ctx)
 *      int syscall__socket(struct pt_regs *ctx, int family, int type, int protocol)
 *      int syscall__socket_return(struct pt_regs *ctx)
 *      int syscall__connect(struct pt_regs *ctx, int fd, const struct sockaddr __user* addr, u32 addrlen)
 *      int syscall__connect_return(struct pt_regs *ctx)
 *      int syscall__accept(struct pt_regs *ctx, int sockfd, struct sockaddr __user* addr)
 *      int syscall__accept_return(struct pt_regs *ctx)
 *
 * @history
 *      <author>    <time>      <version>                       <description>
 *      Xu.Cao      2023-03-07  6.0.5                           规范化当前代码
 *      Xu.Cao      2023-04-17  6.0.6                           1. 修改了 do_entry 和 do_return 的 __always_inline 属性，
 *                                                                 防止出现 inline 导致的二进制爆炸问题.
 *                                                              2. 增加了对 close 系统调用 fd 的处理，将 fd 置为 -1
 *      Xu.Cao      2023-04-26  6.1.0                           将宏定义和代码剥离，由用户态程序完全控制
 */
#include <uapi/linux/ptrace.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include "include/ebpf_string.h"

#define NET_ARGS(f, t) ((u64)(f) << 32 | (t))

struct sys_t {
    u32 ppid, pid;
    char comm[32];
    char name[32], aux_name[32];
    u64 args;
    int fd, aux_fd;
    int sys_id;
    u32 local_ip, remote_ip;
    u16 local_port, remote_port;
};

BPF_HASH(syscall, u32, struct sys_t, 4096);
BPF_HASH(tmp_dentry, u32, struct dentry*, 32);      // save dentry info for vfs_mkdir temporarily
BPF_HASH(currsock, u32, struct sock *, 32);
BPF_PERF_OUTPUT(events);

/**
 * 系统调用专用的入口处理函数，根据当前的状态查看是否会引起状态转移；
 * 如果可能引起状态转移，则保存可能的目标状态，根据函数执行成功与否决定是否更新状态
 *
 * @param ctx 上下文结构体
 * @param call_args 系统调用和最重要参数，syscall << 40 | args
 * @param fd_to_cmp 用于和当前状态 fd 比较的 fd，如 read、write、dup3 等
 * @param fd_for_update 用于更新当前状态中 fd 的
 * @param flag 是否需要更新传入的 call_args 参数，比如 read 可能需要通过判断 fd 来确定参数
 * @return 恒为 0，由 eBPF 规定
 */
static int do_entry(struct pt_regs *ctx, int sys_id, u64 args, int fd_to_cmp, int fd_for_update) {

    struct sys_t b = {};
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 pre_state = 0, *state = NULL;

    b.pid = task->pid;
    b.ppid = task->real_parent->pid;
    bpf_get_current_comm(&(b.comm), 32);
    
    if (ebpf_strcmp(b.comm, COMMAND)) return 0;
    
    b.sys_id = sys_id;
    b.name[0] = b.aux_name[0] = '\0';
    b.args = args;
    b.aux_fd = fd_to_cmp;
    b.fd = fd_for_update;
    b.local_ip = b.remote_ip = 0;
    b.local_port = b.remote_port = 0;
    syscall.update(&b.pid, &b);
    
    return 0;
}

/**
 * 根据函数的返回值（函数是否执行成功）决定是否更新状态信息；
 * 如果需要更新，则先根据目标状态的 flag 来执行一定操作，
 * 如新旧状态的信息传递，网络信息的保存等
 *
 * @param ctx 当前进程上下文
 * @return 恒为 0，由 eBPF 决定
 */
static int do_return(struct pt_regs *ctx) {
    int ret_val = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sys_t *cur = syscall.lookup(&pid);
    
    if (0 == cur) {
        return 0;
    }
    syscall.delete(&pid);
    
    // !!! syscall execute error !!!
    if (ret_val < 0) {
        return 0;
    }
    
    if (ret_val > 0) {
        cur->fd = ret_val;
    }
    
    events.perf_submit(ctx, cur, sizeof(*cur));

    return 0;
}

int syscall__openat(struct pt_regs *ctx, int dirfd, const char __user *name, int FLAG) {
    return do_entry(ctx, 0, FLAG, -1, -1);
}

int syscall__openat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__read(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, 1, 0, fd, -1);
}

int syscall__read_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__write(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, 2, 0, fd, -1);
}

int syscall__write_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__close(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, 3, 0, fd, -1);
}

int syscall__close_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__unlinkat(struct pt_regs *ctx, int dirfd, const char __user *name, int FLAG) {
    return do_entry(ctx, 4, FLAG, -1, -1);
}

int syscall__unlinkat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__mkdirat(struct pt_regs *ctx, int dirfd, const char __user *name) {
    return do_entry(ctx, 5, 0, -1, -1);
}

int syscall__mkdirat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__mkdir(struct pt_regs *ctx, const char __user *name) {
    return do_entry(ctx, 5, 0, -1, -1);
}

int syscall__mkdir_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__rmdir(struct pt_regs *ctx, const char __user *name) {
    return do_entry(ctx, 14, 0, -1, -1);
}

int syscall__rmdir_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__rename(struct pt_regs *ctx,
                    const char __user *oldname,
                    const char __user *newname) {
    return do_entry(ctx, 13, 0, -1, -1);
}

int syscall__rename_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__renameat(struct pt_regs *ctx,
                      int olddir, const char *oldname,
                      int newdir, const char *newname) {
    return do_entry(ctx, 6, 0, -1, -1);
}

int syscall__renameat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__renameat2(struct pt_regs *ctx,
                       int olddir, const char *oldname,
                       int newdir, const char *newname,
                       unsigned int FLAG) {
    return do_entry(ctx, 7, FLAG, -1, -1);
}

int syscall__renameat2_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__dup2(struct pt_regs *ctx, int oldfd, int newfd, int FLAG) {
    return do_entry(ctx, 12, FLAG, oldfd, newfd);
}

int syscall__dup2_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__dup3(struct pt_regs *ctx, int oldfd, int newfd, int FLAG) {
    return do_entry(ctx, 8, FLAG, oldfd, newfd);
}

int syscall__dup3_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__socket(struct pt_regs *ctx,
                    int family, int type, int protocol) {
    return do_entry(ctx, 9, NET_ARGS(family, type), -1, -1);
}

int syscall__socket_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__connect(struct pt_regs *ctx, int fd,
                     const struct sockaddr __user* addr, u32 addrlen) {
    return do_entry(ctx, 10, 0, fd, -1);
}

int syscall__connect_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

// 保存当前的 accept 状态，用于在内核中获取更精准的套接字信息
int syscall__accept(struct pt_regs *ctx, int sockfd, struct sockaddr __user* addr) {
    return do_entry(ctx, 11, 0, sockfd, -1);
}

// 如果当前 accept 失败，则将保存的套接字信息删除
int syscall__accept_return(struct pt_regs *ctx) {
    return do_return(ctx);
}


/* 以下都是内核函数的监控，为了获取更详细的文件信息，如 inode，文件短名字等，因此不要随意改动 */
/* !!! ================ 禁止改动 ===================== !!! */

int do_vfs_open(struct pt_regs *ctx, const struct path *path, struct file *file) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sys_t *cur = syscall.lookup(&pid);

    if (NULL == cur) return 0;

    bpf_probe_read_kernel_str(cur->name, sizeof(cur->name), path->dentry->d_iname);

    return 0;
}

int do_vfs_unlink(struct pt_regs *ctx, struct user_namespace *mnt_userns, struct inode *dir,
                  struct dentry *dentry, struct inode **delegated_inode) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sys_t *cur = syscall.lookup(&pid);

    if (NULL == cur) return 0;
    
    bpf_probe_read_kernel_str(cur->name, sizeof(cur->name), dentry->d_iname);

    return 0;
}

/* vfs_rename */
/* here we can consider that the source and target inode will be the
 * same in the same disk */
int do_vfs_rename(struct pt_regs *ctx, struct renamedata *rd) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sys_t *cur = syscall.lookup(&pid);

    if (NULL == cur) return 0;
    
    bpf_probe_read_kernel_str(cur->aux_name, sizeof(cur->aux_name), rd->old_dentry->d_iname);
    bpf_probe_read_kernel_str(cur->name, sizeof(cur->name), rd->new_dentry->d_iname);

    return 0;
}

int do_vfs_mkdir(struct pt_regs *ctx, struct user_namespace *mnt_userns,
        struct inode *dir, struct dentry *dentry, umode_t mode) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sys_t *cur = syscall.lookup(&pid);

    if (!cur) return 0;
    
    tmp_dentry.update(&pid, &dentry);

    return 0;
}

int do_vfs_mkdir_return(struct pt_regs *ctx) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sys_t *cur = syscall.lookup(&pid);
    struct dentry **tmp = tmp_dentry.lookup(&pid);

    /* delete that tmp variable at first */
    if (tmp) tmp_dentry.delete(&pid);
    if (NULL == cur || NULL == tmp) return 0;
    
    bpf_probe_read_kernel_str(cur->name, sizeof(cur->name), (*tmp)->d_iname);

    return 0;
}

int do_vfs_rmdir(struct pt_regs *ctx, struct user_namespace *mnt_userns,
        struct inode *dir, struct dentry *dentry) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sys_t *cur = syscall.lookup(&pid);

    if (NULL == cur) return 0;
    
    bpf_probe_read_kernel_str(cur->name, sizeof(cur->name), dentry->d_iname);

    return 0;
}

int do_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    /* if you want to filter the container flows, use it */
//    if (container_should_be_filtered()) {
//        return 0;
//    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sys_t *cur = syscall.lookup(&pid);
    // stash the sock ptr for lookup on return
    if (NULL != cur) {
        currsock.update(&pid, &sk);
    }

    return 0;
}

int do_tcp_v4_connect_return(struct pt_regs *ctx) {

    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = currsock.lookup(&pid);
    struct sys_t *cur = syscall.lookup(&pid);
    
    if (NULL == skpp) {
        return 0;
    }
    currsock.delete(&pid);
    if (NULL == cur) {
        return 0;
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        return 0;
    }

    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;

    cur->remote_ip = skp->__sk_common.skc_daddr;
    cur->local_ip  = skp->__sk_common.skc_rcv_saddr;
    cur->remote_port = ntohs(dport);
    cur->local_port  = lport;

    return 0;
}

int kretprobe__inet_csk_accept(struct pt_regs *ctx) {

    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sys_t *cur = syscall.lookup(&pid);
    
    if (NULL == cur) return 0;

    // pull in details
    u16 lport = 0, dport;
    lport = newsk->__sk_common.skc_num;
    dport = newsk->__sk_common.skc_dport;
    dport = ntohs(dport);

    cur->local_ip = newsk->__sk_common.skc_rcv_saddr;
    cur->remote_ip = newsk->__sk_common.skc_daddr;
    cur->local_port = lport;
    cur->remote_port = dport;

    return 0;
}
