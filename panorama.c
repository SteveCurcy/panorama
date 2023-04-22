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
 *      int syscall_exit_group(struct pt_regs *ctx, int sig)
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
#include "include/panorama.h"

[MICRO_DEFINITIONS]

BPF_HASH(stt_behav, u64, u64, 4096);                // state transition table (stt) of behavior
BPF_HASH(state_behav, u32, struct behav_t, 4096);   // pid -> state, state of behavior
BPF_HASH(next_state, u32, struct behav_t, 4096);    // save the next possible state temporarily
BPF_HASH(accept_block, u32, struct peer_net_t, 1);       // save the latest connection request globally
BPF_HASH(tmp_dentry, u32, struct dentry*, 32);      // save dentry info for vfs_mkdir temporarily
BPF_HASH(currsock, u32, struct sock *, 32);
BPF_PERF_OUTPUT(behavior);                          // used to submit current state of behavior to user space and print it

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
static int do_entry(struct pt_regs *ctx, u64 call_args, int fd_to_cmp, int fd_for_update, u8 flag) {

    struct behav_t b = {}, *cur = NULL, *parent = NULL;
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 pre_state = 0, *state = NULL;

    b.pid = task->pid;
    b.ppid = task->real_parent->pid;
    cur = state_behav.lookup(&b.pid);

    /*
     * 查看当前是否已经记入状态机，如果已经记入，则将当前的状态更新到 b 中；
     * 如果还没有记入，则查看当前动作是否会引发状态转移，如果不会直接返回；
     * b 将用来保存可能的下一个状态，而 cur 当前状态暂时不予改变，只有当前
     * 动作完成并且没有报错再进行状态转移（在出口处理函数中）
     */
    if (!cur) {
        pre_state = call_args;
        state = stt_behav.lookup(&pre_state);
        if (!state) return 0;

        b.time = bpf_ktime_get_ns();
        b.uid = (u32) bpf_get_current_uid_gid();
        bpf_get_current_comm(&(b.comm), 32);
        b.fd = -1;
        b.detail.file.i_ino = 0;
        b.s.for_assign = 0;
    } else {
        bpf_probe_read(&b, sizeof(b), cur);
        b.time = bpf_ktime_get_ns();
    }

    /*
     * 查看当前是否需要进行参数的更新，如 read、write 等需要判断 fd 是否是之前打开的文件描述符；
     * 并根据 fd 更新参数，获得正确的状态转移条件
     */
    if (flag) {
        if (b.fd != -1 && fd_to_cmp == b.fd) {
            call_args |= ARGS_EQL_FD;
            if (call_args == SYS_CALL_CLOSE) {
                b.fd = -1;
            }
        }
        else if (fd_to_cmp == 0 || fd_to_cmp == 1) call_args |= ARGS_EQL_IO;
    }
    pre_state = ((u64)b.s.for_assign << 48) | call_args;

    state = stt_behav.lookup(&pre_state);
    if (!state) {
        return 0;
    }

    if (!(*state)) {
        b.s.for_assign = 0;
        next_state.update(&b.pid, &b);
        return 0;
    }

    b.s.for_assign = *state;

    if (fd_for_update >= 0 && CHECK_FLAG(b.s.for_assign, FLAG_FD)) {
        b.fd = fd_for_update;
    }

    next_state.update(&b.pid, &b);
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
    struct behav_t *cur = state_behav.lookup(&pid);
    struct behav_t *nex = next_state.lookup(&pid);

    if (!nex) return 0;
    next_state.delete(&pid);
    if (ret_val < 0) return 0;  // 如果函数执行错误，则不进行状态信息的更新
    if (cur && !nex->s.for_assign) {    // 有可能回到起始状态
        cur->s.for_assign = 0;
        return 0;
    }

    // update fd when it's not set yet or not be set in function do_entry.
    if (CHECK_FLAG(nex->s.for_assign, FLAG_FD)) {
        if (nex->fd == -1 || (cur && cur->fd == nex->fd))
            nex->fd = ret_val;
    }

    // 将当前进程的状态信息传给父进程并删除当前进程的信息
    struct behav_t *parent = state_behav.lookup(&(nex->ppid));
    if (parent && CHECK_FLAG(nex->s.for_assign, FLAG_PARENT)) {
        parent->detail.net.remote.addr = nex->detail.net.remote.addr;
        parent->detail.net.remote.port = nex->detail.net.remote.port;
        parent->detail.net.local.addr = nex->detail.net.local.addr;
        parent->detail.net.local.port = nex->detail.net.local.port;
        parent->s.for_assign = nex->s.for_assign;
        state_behav.delete(&pid);
        return 0;
    }

    // 将父进程保存的网络套接字信息传递给当前子进程
    if (CHECK_FLAG(nex->s.for_assign, FLAG_CHILD)) {
        struct task_struct *task = (struct task_struct *) bpf_get_current_task();
        task = task->real_parent;
        u32 ppid = 0;
        for (int i = 0; i < 4 && task; i++) {
            ppid = task->pid;
            if (ppid == 1) break;

            struct peer_net_t *net_info = accept_block.lookup(&ppid);
            if (!net_info) {
                task = task->real_parent;
                continue;
            }

            accept_block.delete(&ppid);
            nex->detail.net.remote.addr = net_info->remote.addr;
            nex->detail.net.remote.port = net_info->remote.port;
            nex->detail.net.local.addr = net_info->local.addr;
            nex->detail.net.local.port = net_info->local.port;
            bpf_get_current_comm(&(nex->comm), sizeof(nex->comm));
            break;
        }
    }

    // ssh 保存 accept 得到的套接字，防止被再次替换
    if (CHECK_FLAG(nex->s.for_assign, FLAG_ACCEPT)) {
        struct peer_net_t *net_info = accept_block.lookup(&(nex->ppid));

        if (net_info) {
            accept_block.delete(&(nex->ppid));
            // change the ownership
            accept_block.update(&(nex->pid), net_info);
        }
    }

    if (cur && CHECK_FLAG(nex->s.for_assign, FLAG_SMT_LST)) {
        behavior.perf_submit(ctx, cur, sizeof(*cur));
    } else if (CHECK_FLAG(nex->s.for_assign, FLAG_SMT_CUR)) {
        behavior.perf_submit(ctx, nex, sizeof(*nex));
    }

    // for debug and print the current state and behavior semantics context
//    if (nex->s.fr.state == 31) {
//        behavior.perf_submit(ctx, nex, sizeof(*nex));
//    }

    state_behav.update(&pid, nex);

    return 0;
}

int syscall__openat(struct pt_regs *ctx, int dirfd, const char __user *name, int FLAG) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_OPENAT, FLAG), -1, -1, 0);
}

int syscall__openat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__read(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_READ, 0), fd, -1, 1);
}

int syscall__read_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__write(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_WRITE, 0), fd, -1, 1);
}

int syscall__write_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__close(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_CLOSE, 0), fd, -1, 1);
}

int syscall__close_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__unlinkat(struct pt_regs *ctx, int dirfd, const char __user *name, int FLAG) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_UNLINKAT, FLAG), -1, -1, 0);
}

int syscall__unlinkat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__mkdirat(struct pt_regs *ctx, int dirfd, const char __user *name) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_MKDIRAT, 0), -1, -1, 0);
}

int syscall__mkdirat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__renameat(struct pt_regs *ctx,
                      int olddir, const char *oldname,
                      int newdir, const char *newname) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_RENAMEAT, 0), -1, -1, 0);
}

int syscall__renameat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__renameat2(struct pt_regs *ctx,
                       int olddir, const char *oldname,
                       int newdir, const char *newname,
                       unsigned int FLAG) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_RENAMEAT2, 0), -1, -1, 0);
}

int syscall__renameat2_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__dup3(struct pt_regs *ctx, int oldfd, int newfd, int FLAG) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_DUP3, 0), oldfd, newfd, 1);
}

int syscall__dup3_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__socket(struct pt_regs *ctx,
                    int family, int type, int protocol) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_SOCKET, NET_ARGS(family, type)), -1, -1, 0);
}

int syscall__socket_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__connect(struct pt_regs *ctx, int fd,
                     const struct sockaddr __user* addr, u32 addrlen) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_CONNECT, 0), fd, -1, 1);
}

int syscall__connect_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

// 保存当前的 accept 状态，用于在内核中获取更精准的套接字信息
int syscall__accept(struct pt_regs *ctx, int sockfd, struct sockaddr __user* addr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sockaddr_in *sa = (struct sockaddr_in*)addr;
    struct peer_net_t parent = {};


    parent.remote.addr = (sa->sin_addr).s_addr;
    parent.remote.port = sa->sin_port;
    parent.remote.port = ntohs(parent.remote.port);
    if (parent.remote.port && parent.remote.addr)
        accept_block.update(&pid, &parent);

    return 0;
}

// 如果当前 accept 失败，则将保存的套接字信息删除
int syscall__accept_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int ret_val = PT_REGS_RC(ctx);
    struct peer_net_t *daemon = accept_block.lookup(&pid);

    if (!daemon) return 0;

    if (ret_val < 0) {
        accept_block.delete(&pid);
        return 0;
    }

    return 0;
}

// 进程退出，删除当前进程的状态信息
int syscall_exit_group(struct pt_regs *ctx, int sig) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state_behav.lookup(&pid);

    if (!cur) return 0;
    state_behav.delete(&pid);

    return 0;
}

/* 以下都是内核函数的监控，为了获取更详细的文件信息，如 inode，文件短名字等，因此不要随意改动 */
/* !!! ================ 禁止改动 ===================== !!! */

int do_vfs_open(struct pt_regs *ctx, const struct path *path, struct file *file) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = next_state.lookup(&pid);

    if (!cur) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAG_FILE_NAME)) {
        cur->detail.file.i_ino = path->dentry->d_inode->i_ino;
        bpf_probe_read_kernel_str(cur->detail.file.name, sizeof(cur->detail.file.name), path->dentry->d_iname);
    }

    return 0;
}

int do_vfs_unlink(struct pt_regs *ctx, struct user_namespace *mnt_userns, struct inode *dir,
                  struct dentry *dentry, struct inode **delegated_inode) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = next_state.lookup(&pid);

    if (!cur) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAG_FILE_NAME)) {
        cur->detail.file.i_ino = dentry->d_inode->i_ino;
        bpf_probe_read_kernel_str(cur->detail.file.name, sizeof(cur->detail.file.name), dentry->d_iname);
    }

    return 0;
}

/* vfs_rename */
/* here we can consider that the source and target inode will be the
 * same in the same disk */
int do_vfs_rename(struct pt_regs *ctx, struct renamedata *rd) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = next_state.lookup(&pid);

    if (!cur) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAG_RNM_SRC)) {
        cur->detail.file.i_ino = rd->old_dentry->d_inode->i_ino;
        u16 tmp_op = cur->s.fr.operate;
        cur->s.fr.operate = OP_REMOVE;
        bpf_probe_read_kernel_str(cur->detail.file.name, sizeof(cur->detail.file.name), rd->old_dentry->d_iname);
        behavior.perf_submit(ctx, cur, sizeof(*cur));
        cur->s.fr.operate = tmp_op;
    }
    if (CHECK_FLAG(cur->s.for_assign, FLAG_FILE_NAME)) {
        bpf_probe_read_kernel_str(cur->detail.file.name, sizeof(cur->detail.file.name), rd->new_dentry->d_iname);
        if (rd->new_dentry->d_inode->i_ino) {
            // cover a file, so output the covered file
            cur->detail.file.i_ino = rd->new_dentry->d_inode->i_ino;
            // cur->s.for_assign = (cur->s.for_assign & 0xffffffffff00ffff) | ((u64)OP_COVER << 32);
            cur->s.fr.operate = OP_REMOVE;
            behavior.perf_submit(ctx, cur, sizeof(*cur));
            cur->s.fr.operate = OP_COVER;
        }
        cur->detail.file.i_ino = rd->old_dentry->d_inode->i_ino;
    }

    return 0;
}

int do_vfs_mkdir(struct pt_regs *ctx, struct user_namespace *mnt_userns,
        struct inode *dir, struct dentry *dentry, umode_t mode) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = next_state.lookup(&pid);

    if (!cur) return 0;
    tmp_dentry.update(&pid, &dentry);

    return 0;
}

int do_vfs_mkdir_return(struct pt_regs *ctx) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = next_state.lookup(&pid);
    struct dentry **tmp = tmp_dentry.lookup(&pid);

    /* delete that tmp variable at first */
    if (tmp) tmp_dentry.delete(&pid);
    if (!cur || !tmp) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAG_FILE_NAME)) {
        bpf_probe_read_kernel(&(cur->detail.file.i_ino), sizeof(u32), &((*tmp)->d_inode->i_ino));
        bpf_probe_read_kernel_str(cur->detail.file.name, sizeof(cur->detail.file.name), (*tmp)->d_iname);
    }

    return 0;
}

int do_vfs_rmdir(struct pt_regs *ctx, struct user_namespace *mnt_userns,
        struct inode *dir, struct dentry *dentry) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = next_state.lookup(&pid);

    if (!cur) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAG_FILE_NAME)) {
        cur->detail.file.i_ino = dentry->d_inode->i_ino;
        bpf_probe_read_kernel_str(cur->detail.file.name, sizeof(cur->detail.file.name), dentry->d_iname);
    }

    return 0;
}

int do_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    /* if you want to filter the container flows, use it */
//    if (container_should_be_filtered()) {
//        return 0;
//    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = next_state.lookup(&pid);
    // stash the sock ptr for lookup on return
    if (cur) {
        currsock.update(&pid, &sk);
    }

    return 0;
}

int do_tcp_v4_connect_return(struct pt_regs *ctx) {

    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = currsock.lookup(&pid);
    struct behav_t *cur = next_state.lookup(&pid);
    if (skpp == 0) {
        return 0;
    }
    currsock.delete(&pid);
    if (cur == 0) {
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

    cur->detail.net.remote.addr = skp->__sk_common.skc_daddr;
    cur->detail.net.local.addr  = skp->__sk_common.skc_rcv_saddr;
    cur->detail.net.remote.port = ntohs(dport);
    cur->detail.net.local.port  = lport;

    return 0;
}

int kretprobe__inet_csk_accept(struct pt_regs *ctx) {

    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct peer_net_t *net_info = accept_block.lookup(&pid);
    if (net_info == 0) {
        return 0;
    }

    // pull in details
    u16 lport = 0, dport;
    lport = newsk->__sk_common.skc_num;
    dport = newsk->__sk_common.skc_dport;
    dport = ntohs(dport);

    net_info->local.addr = newsk->__sk_common.skc_rcv_saddr;
    net_info->remote.addr = newsk->__sk_common.skc_daddr;
    net_info->local.port = lport;
    net_info->remote.port = dport;

    return 0;
}