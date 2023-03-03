/*
 * Created by Xu.Cao on 2023/1/23.
 * Version 2.0.0.230220_build_b0_Xu.C
 * Here I hope that `entry` calculates the next state if it's available in state transition table, and `return` updates
 * the state depending on return value.
 */
#include <uapi/linux/ptrace.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include "include/ebpf_string.h"
#include "include/panorama.h"

BPF_HASH(stt_behav, u64, u64, 4096);  // the first layer state transition table
BPF_HASH(state_behav, u32, struct behav_t, 4096);  // pid -> data
BPF_HASH(next_state, u32, struct behav_t, 4096);
BPF_HASH(accept_block, u32, struct net_t, 1); // store the latest accept request
/* the temporary variables' size can be set as 1,
 * but set as 32 for multithreading concurrency */
BPF_HASH(tmp_dentry, u32, struct dentry*, 32);
BPF_HASH(tmp_rndata, u32, struct renamedata*, 32);
BPF_PERF_OUTPUT(behavior);

/**
 * @param ctx context of current task
 * @param call_args syscall << 40 | args
 * @param fd0 used to compare, like old fd
 * @param fd1 used to assign
 * @param net_info port << 32 | ip
 * @param flag whether compare with fd0
 * @return always 0
 * @todo check if the current state will change the state and save the current util `return` context if it can
 */
__always_inline static int do_entry(struct pt_regs *ctx, u64 call_args, int fd0, int fd1, u64 net_info, u8 flag) {
    struct behav_t b = {}, *cur = NULL, *parent = NULL;
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 pre_state = 0, *state = NULL;

    /* get the pid and ppid and state */
    b.pid = task->pid;
    b.ppid = task->real_parent->pid;
    cur = state_behav.lookup(&b.pid);

//    if (CALL_ARGS(SYS_CALL_OPENAT, 02) == call_args) {
//        bpf_get_current_comm(&(b.comm), 32);
//        if (cur)
//            behavior.perf_submit(ctx, cur, sizeof(*cur));
//    }

    /* current task's state not found */
    if (!cur) {
        pre_state = call_args;
        /* check if this task will cause state transition */
        state = stt_behav.lookup(&pre_state);
        if (!state) return 0;

        /* initialize the state and redirect the pointer */
        b.time = bpf_ktime_get_ns();
        b.uid = (u32) bpf_get_current_uid_gid();
        bpf_get_current_comm(&(b.comm), 32);
        b.fd = -1;
        b.detail.file.i_ino = 0;
        b.s.for_assign = 0;
    } else {
        // clone the current state
        bpf_probe_read(&b, sizeof(b), cur);
        b.time = bpf_ktime_get_ns();
    }
    /* Here 'b' has been a copy of current state and take own of the handling for next state. */

    /* check args of functions, like write(fd), connect(fd,...). */
    if (flag) {  // read, write, etc., will set this flag by default
        if (b.fd != -1 && fd0 == b.fd) call_args |= ARGS_EQL_FD;
        else if (fd0 == 0 || fd0 == 1) call_args |= ARGS_EQL_IO;
    }
    pre_state = ((u64)b.s.for_assign << 48) | call_args;

    /* check the next state */
    state = stt_behav.lookup(&pre_state);
    if (!state) {
        return 0;
    }

    /* state0 means start, so just remain it. */
    if (!(*state)) {
        b.s.for_assign = 0;
        next_state.update(&b.pid, &b);  //
        return 0;
    }

    b.s.for_assign = *state;

    if (CHECK_FLAG(*state, FLAG_SOCKET)) {
        b.detail.sock.addr = (net_info & 0x00000000ffffffff);
        b.detail.sock.port = (net_info >> 32) & 0x000000000000ffff;
    }

    /* update fds from arguments */
    if (fd1 >= 0 && CHECK_FLAG(b.s.for_assign, FLAG_FD)) {
        b.fd = fd1;
    }

    next_state.update(&b.pid, &b);
    return 0;
}

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

    /* update the return value which is fd */
    if (CHECK_FLAG(nex->s.for_assign, FLAG_FD)) {
//    behavior.perf_submit(ctx, cur, sizeof(*cur));
        if (nex->fd == -1 || (cur && cur->fd == nex->fd))
            nex->fd = ret_val;
    }

    struct behav_t *parent = state_behav.lookup(&(nex->ppid));
    if (parent && CHECK_FLAG(nex->s.for_assign, FLAG_PARENT)) {
        parent->detail.sock.addr = nex->detail.sock.addr;
        parent->detail.sock.port = nex->detail.sock.port;
        parent->s.for_assign = nex->s.for_assign;
        state_behav.delete(&pid);
        return 0;
    }

    if (CHECK_FLAG(nex->s.for_assign, FLAG_ACCEPT)) {
        struct task_struct *task = (struct task_struct *) bpf_get_current_task();
        task = task->real_parent;
        u32 ppid = 0;
        for (int i = 0; i < 4 && task; i++) {
            ppid = task->pid;
            if (ppid == 1) break;

            struct net_t *net_info = accept_block.lookup(&ppid);
            if (!net_info) {
                task = task->real_parent;
                continue;
            }

            accept_block.delete(&ppid);
            nex->detail.sock.addr = net_info->addr;
            nex->detail.sock.port = net_info->port;
            bpf_get_current_comm(&(nex->comm), sizeof(nex->comm));
//            behavior.perf_submit(ctx, nex, sizeof(*nex));
            break;
        }
    }

    /* submit the event now? */
    if (cur && CHECK_FLAG(nex->s.for_assign, FLAG_SMT_LST)) {
        behavior.perf_submit(ctx, cur, sizeof(*cur));
    } else if (CHECK_FLAG(nex->s.for_assign, FLAG_SMT_CUR)) {
        behavior.perf_submit(ctx, nex, sizeof(*nex));
    }
    /* remove FLAG for storing after using */
//    nex->s.for_assign &= 0xfffff1ffffffffff;
//    if (nex->s.fr.state == 31) {
//        behavior.perf_submit(ctx, nex, sizeof(*nex));
//    }

    state_behav.update(&pid, nex);

    return 0;
}

int syscall__openat(struct pt_regs *ctx, int dirfd, const char __user *name, int FLAG) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_OPENAT, FLAG), -1, -1, 0, 0);
}

int syscall__openat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__read(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_READ, 0), fd, -1, 0, 1);
}

int syscall__read_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__write(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_WRITE, 0), fd, -1, 0, 1);
}

int syscall__write_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__close(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_CLOSE, 0), fd, -1, 0, 1);
}

int syscall__close_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__unlinkat(struct pt_regs *ctx, int dirfd, const char __user *name, int FLAG) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_UNLINKAT, FLAG), -1, -1, 0, 0);
}

int syscall__unlinkat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__mkdirat(struct pt_regs *ctx, int dirfd, const char __user *name) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_MKDIRAT, 0), -1, -1, 0, 0);
}

int syscall__mkdirat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__renameat(struct pt_regs *ctx,
                      int olddir, const char *oldname,
                      int newdir, const char *newname) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_RENAMEAT, 0), -1, -1, 0, 0);
}

int syscall__renameat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__renameat2(struct pt_regs *ctx,
                       int olddir, const char *oldname,
                       int newdir, const char *newname,
                       unsigned int FLAG) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_RENAMEAT2, 0), -1, -1, 0, 0);
}

int syscall__renameat2_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__dup3(struct pt_regs *ctx, int oldfd, int newfd, int FLAG) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_DUP3, 0), oldfd, newfd, 0, 1);
}

int syscall__dup3_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__socket(struct pt_regs *ctx,
                    int family, int type, int protocol) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_SOCKET, NET_ARGS(family, type)), -1, -1, 0, 0);
}

int syscall__socket_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__connect(struct pt_regs *ctx, int fd,
                     const struct sockaddr __user* addr, u32 addrlen) {
    struct sockaddr_in *sa = (struct sockaddr_in*)addr;
    u64 net_info = ((u64)sa->sin_port << 32) | (sa->sin_addr).s_addr;
    return do_entry(ctx, CALL_ARGS(SYS_CALL_CONNECT, 0), fd, -1, net_info, 1);
}

int syscall__connect_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

// accept is listened by sshd as daemon, so should put it into state machine
int syscall__accept(struct pt_regs *ctx, int sockfd, struct sockaddr __user* addr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sockaddr_in *sa = (struct sockaddr_in*)addr;
    struct net_t parent = {};


    u32 zero = 0;
    parent.addr = (sa->sin_addr).s_addr;
    parent.port = sa->sin_port;
    if (parent.port && parent.addr)
        accept_block.update(&pid, &parent);

    return 0;
}

int syscall__accept_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int ret_val = PT_REGS_RC(ctx);
    struct net_t *daemon = accept_block.lookup(&pid);

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


