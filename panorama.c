/*
 * @date    2023-03-03.
 * @version v6.0.5.230307_alpha_a1_Xu.C
 * @author  Xu.Cao
 * @details To maintain the state of system context by tracing syscalls, get details by tracing vfs_* kernel functions.
 *
 * @functions:
 *      __always_inline static int do_entry(struct pt_regs *ctx, u64 call_args, int fd0, int fd1, u64 net_info, u8 flag)
 *      __always_inline static int do_return(struct pt_regs *ctx)
 *      @details
 *          do_entry is to receive some essential arguments of syscalls and fill the next possible state.
 *          do_return will update the state if return-value is valid. besides, it will submit the state infos (log)
 *              by the state transition table.
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
 *      @details
 *          All `syscall__*` functions will be injected to trace the related syscall's context and maintain the state.
 *          Specially, syscall__exit_group is the exit point of a task, so will destruct the state struct.
 *
 *      int do_vfs_open(struct pt_regs *ctx, const struct path *path, struct file *file)
 *      int do_vfs_unlink(struct pt_regs *ctx, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
 *      int do_vfs_rename(struct pt_regs *ctx, struct renamedata *rd)
 *      int do_vfs_mkdir(struct pt_regs *ctx, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, umode_t mode)
 *      int do_vfs_mkdir_return(struct pt_regs *ctx)
 *      int do_vfs_rmdir(struct pt_regs *ctx, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry)
 *      @details
 *          All `do_vfs_*` functions will be injected to trace deeper kernel functions and get file names and inodes, etc.
 * @history
 *      <author>    <time>      <version>                       <description>
 *      Xu.Cao      2023-03-07  6.0.5.230307_alpha_a1_Xu.C     Format this code
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

BPF_HASH(stt_behav, u64, u64, 4096);                // state transition table (stt) of behavior
BPF_HASH(state_behav, u32, struct behav_t, 4096);   // pid -> state, state of behavior
BPF_HASH(next_state, u32, struct behav_t, 4096);    // save the next possible state temporarily
BPF_HASH(accept_block, u32, struct peer_net_t, 1);       // save the latest connection request globally
BPF_HASH(tmp_dentry, u32, struct dentry*, 32);      // save dentry info for vfs_mkdir temporarily
BPF_HASH(currsock, u32, struct sock *, 32);
BPF_PERF_OUTPUT(behavior);                          // used to submit current state of behavior to user space and print it

/*
 * @param ctx context of current task
 * @param call_args syscall << 40 | args
 * @param fd_to_cmp to compare with fd of current state, like `read, write, close`, etc.
 * @param fd_for_update to update the file's fd, for example, dup3 will update fd from `fd_to_cmp` to `fd_for_update`
 * @param net_info port << 32 | ip
 * @param flag whether compare with fd_to_cmp, some functions don't need comparison, so it will be set 0.
 * @return always 0, routine for ebpf
 */
__always_inline static int do_entry(struct pt_regs *ctx, u64 call_args,
                                    int fd_to_cmp, int fd_for_update, u8 flag) {

    struct behav_t b = {}, *cur = NULL, *parent = NULL;
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 pre_state = 0, *state = NULL;

    b.pid = task->pid;
    b.ppid = task->real_parent->pid;
    cur = state_behav.lookup(&b.pid);

    /*
     * check if current task's behavior semantic has been saved.
     * |- No + then check if current syscall and its arguments can cause state transition
     * |     |- No, which means current state is useless
     * |     +- Yes, which means this syscall can navigate current state to the next state by stt.
     * |            Then generate and save a new state, it will run in state machine.
     * +- Yes, back up the current behavior semantic, and try to get info for the next possible behavior semantic.
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

    /* check args of functions, like write(fd), connect(fd,...). */
    if (flag) {
        if (b.fd != -1 && fd_to_cmp == b.fd) call_args |= ARGS_EQL_FD;
        else if (fd_to_cmp == 0 || fd_to_cmp == 1) call_args |= ARGS_EQL_IO;
    }
    pre_state = ((u64)b.s.for_assign << 48) | call_args;

    state = stt_behav.lookup(&pre_state);
    if (!state) {
        return 0;
    }

    /* state0 means start, so just remain it. */
    if (!(*state)) {
        b.s.for_assign = 0;
        next_state.update(&b.pid, &b);
        return 0;
    }

    b.s.for_assign = *state;
//
//    if (CHECK_FLAG(*state, FLAG_SOCKET)) {
//        b.detail.sock.addr = (net_info & 0x00000000ffffffff);
//        b.detail.sock.port = (net_info >> 32) & 0x000000000000ffff;
//    }

    // if fd_for_update >= 0, means it is an argument of syscall and need to be updated
    if (fd_for_update >= 0 && CHECK_FLAG(b.s.for_assign, FLAG_FD)) {
        b.fd = fd_for_update;
    }

    next_state.update(&b.pid, &b);
    return 0;
}

/*
 * @param ctx context of task
 * @return always 0
 *
 * @details This function handles the next possible behavior semantic when function returns. If return-value is invalid,
 *          just abandon the possible behavior semantic.
 */
__always_inline static int do_return(struct pt_regs *ctx) {
    int ret_val = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state_behav.lookup(&pid);
    struct behav_t *nex = next_state.lookup(&pid);

    /* skip if no state recording or returning error */
    if (!nex) return 0;
    next_state.delete(&pid);
    if (ret_val < 0) return 0;
    if (cur && !nex->s.for_assign) {
        cur->s.for_assign = 0;
        return 0;
    }

    // update fd when it's not set yet or not be set in function do_entry.
    if (CHECK_FLAG(nex->s.for_assign, FLAG_FD)) {
        if (nex->fd == -1 || (cur && cur->fd == nex->fd))
            nex->fd = ret_val;
    }

    struct behav_t *parent = state_behav.lookup(&(nex->ppid));
    if (parent && CHECK_FLAG(nex->s.for_assign, FLAG_PARENT)) {
        parent->detail.remote.addr = nex->detail.remote.addr;
        parent->detail.remote.port = nex->detail.remote.port;
        parent->local.addr = nex->local.addr;
        parent->local.port = nex->local.port;
        parent->s.for_assign = nex->s.for_assign;
        state_behav.delete(&pid);
        return 0;
    }

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
            nex->detail.remote.addr = net_info->remote.addr;
            nex->detail.remote.port = net_info->remote.port;
            nex->local.addr = net_info->local.addr;
            nex->local.port = net_info->local.port;
            bpf_get_current_comm(&(nex->comm), sizeof(nex->comm));
            break;
        }
    }

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

// accept is listened by sshd as daemon, so should put it into state machine
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

int syscall__accept_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int ret_val = PT_REGS_RC(ctx);
    struct peer_net_t *daemon = accept_block.lookup(&pid);

    if (!daemon) return 0;

    if (ret_val < 0) {
        accept_block.delete(&pid);
        return 0;
    }

//    struct behav_t b = {};
//    bpf_get_current_comm(&b.comm, sizeof(b.comm));
//    b.detail.sock.addr = daemon->addr;
//    b.detail.sock.port = daemon->port;
//    b.s.fr.flags = FLAG_SMT_SOCK;
//    behavior.perf_submit(ctx, &b, sizeof(b));

    return 0;
}

int syscall_exit_group(struct pt_regs *ctx, int sig) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state_behav.lookup(&pid);

    if (!cur) return 0;
    state_behav.delete(&pid);

    return 0;
}

/* kernel function to get inode */

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

    cur->detail.remote.addr = skp->__sk_common.skc_daddr;
    cur->local.addr         = skp->__sk_common.skc_rcv_saddr;
    cur->detail.remote.port = ntohs(dport);
    cur->local.port         = lport;

    return 0;
}

int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
//    if (container_should_be_filtered()) {
//        return 0;
//    }

    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
//    u32 pid = bpf_get_current_pid_tgid() >> 32;
//
//    if (newsk == NULL)
//        return 0;
//
//    // check this is TCP
//    u16 protocol = 0;
//    // workaround for reading the sk_protocol bitfield:
//
//    // Following comments add by Joe Yin:
//    // Unfortunately,it can not work since Linux 4.10,
//    // because the sk_wmem_queued is not following the bitfield of sk_protocol.
//    // And the following member is sk_gso_max_segs.
//    // So, we can use this:
//    // bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&newsk->sk_gso_max_segs) - 3);
//    // In order to  diff the pre-4.10 and 4.10+ ,introduce the variables gso_max_segs_offset,sk_lingertime,
//    // sk_lingertime is closed to the gso_max_segs_offset,and
//    // the offset between the two members is 4
//
//    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
//    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);
//
//
//    // Since kernel v5.6 sk_protocol is its own u16 field and gso_max_segs
//    // precedes sk_lingertime.
//    if (sk_lingertime_offset - gso_max_segs_offset == 2)
//        protocol = newsk->sk_protocol;
//    else if (sk_lingertime_offset - gso_max_segs_offset == 4)
//        // 4.10+ with little endian
//#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
//        protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 3);
//    else
//        // pre-4.10 with little endian
//        protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 3);
//#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
//    // 4.10+ with big endian
//        protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 1);
//    else
//        // pre-4.10 with big endian
//        protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 1);
//#else
//# error "Fix your compiler's __BYTE_ORDER__?!"
//#endif
//
//    if (protocol != IPPROTO_TCP)
//        return 0;

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