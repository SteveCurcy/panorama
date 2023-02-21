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
/* the temporary variables' size can be set as 1,
 * but set as 32 for multithreading concurrency */
BPF_HASH(tmp_dentry, u32, struct dentry*, 32);
BPF_HASH(tmp_rndata, u32, struct renamedata*, 32);
BPF_PERF_OUTPUT(behavior);

/**
 * @param ctx context of current task
 * @param call_args syscall << 40 | args
 * @param name0 the first file's name
 * @param name1 the second file's name
 * @param fd0 used to compare, like old fd
 * @param fd1 used to assign
 * @param net_info port << 32 | ip
 * @param flag whether compare with fd0
 * @return always 0
 * @todo check if the current state will change the state and save the current util `return` context if it can
 */
__always_inline static int do_entry(struct pt_regs *ctx, u64 call_args, const char __user *name0,
        const char __user *name1, int fd0, int fd1, u64 net_info, u8 flag) {
    struct behav_t b = {}, *cur = NULL, *parent = NULL;
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 pre_state = 0, *state = NULL;

    /* get the pid and ppid and state */
    b.pid = task->pid;
    b.ppid = task->real_parent->pid;
    cur = state_behav.lookup(&b.pid);

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
        b.f0.i_ino = b.f1.i_ino = b.net.addr = b.net.port = 0;
        b.f0.fd = b.f1.fd = b.net.fd = -1;
        b.s.for_assign = 0;
        b.out_flag = 1;
    } else {
        // clone the current state
        bpf_probe_read(&b, sizeof(b), cur);
    }
    /* Here 'b' has been a copy of current state and take own of the handling for next state. */

    /* check args of functions, like write(fd), connect(fd,...). */
    if (flag) {  // read, write, etc., will set this flag by default
        if (b.f0.fd != -1 && fd0 == b.f0.fd) call_args |= ARGS_EQL_SRC;
        else if (b.f1.fd != -1 && fd0 == b.f1.fd) call_args |= ARGS_EQL_DST;
        else if (b.net.fd != -1 && fd0 == b.net.fd) call_args |= ARGS_EQL_NET;
        else if (fd0 == 0 || fd0 == 1) call_args |= ARGS_EQL_IO;
    }
    pre_state = ((u64)b.s.for_assign << 48) | call_args;
//    if (!ebpf_strcmp("vi", cur->comm)) {
//        // cur->s.for_assign = pre_state;
//        behavior.perf_submit(ctx, cur, sizeof(*cur));
//    }
//    if (cur->s.fr.state == 11) {
//        behavior.perf_submit(ctx, cur, sizeof(*cur));
//    }

    /* check the next state */
    state = stt_behav.lookup(&pre_state);
    if (!state) {
        /* check if the next state transition should be caused now.
         * restore the state back to START if not. */
        if (CHECK_FLAG(b.s.for_assign, FLAGS_NEXT)) {
            b.s.for_assign = 0;
            next_state.update(&b.pid, &b);
        }
        return 0;
    }

    /* state0 means start, so just remain it. */
    if (!(*state)) {
//        state_behav.delete(&b.pid);
        b.s.for_assign = 0;
        next_state.update(&b.pid, &b);  //
        return 0;
    }

    /* check if state need to be updated */
    b.s.for_assign = (*state & 0x0000000000800000) ?
            *state : (b.s.fr.operate ? (b.s.for_assign & 0x0000000000ff0000) |
                                          (*state & 0xffffffffff00ffff) : *state);

//    if (cur->s.fr.state == 21)
//    behavior.perf_submit(ctx, cur, sizeof(*cur));
    /* net info assignment */
    if (CHECK_FLAG(*state, FLAGS_NET)) {
        b.net.addr = (net_info & 0x00000000ffffffff);
        b.net.port = (net_info >> 32) & 0x000000000000ffff;
        /* upload the state and delete current one if parent exists */
        /* This work saved for `return` to finish */
        /*if (parent && CHECK_FLAG(*state, FLAGS_PARENT)) {
            parent->net.addr = cur->net.addr;
            parent->net.port = cur->net.port;
            parent->s.for_assign = cur->s.for_assign;
            state_behav.delete(&b.pid);
            return 0;
        }*/
    }

    /* update fds from arguments */
    if (fd1 >= 0) {
        if (CHECK_FLAG(b.s.for_assign, FLAGS_MAY_FD)) {
            b.f0.fd = fd1;
        } else if (CHECK_FLAG(b.s.for_assign, FLAGS_MIN_FD)) {
            b.f1.fd = fd1;
        } else if (CHECK_FLAG(b.s.for_assign, FLAGS_NET_FD)) {
            b.net.fd = fd1;
        }
    }

    /* copy the filename and check if it needs to be delay */
    if (CHECK_FLAG(*state, FLAGS_MAYOR)) {
        bpf_probe_read_user_str(b.f0.name, sizeof(b.f0.name), name0);
    }
    if (CHECK_FLAG(*state, FLAGS_MINOR)) {
        bpf_probe_read_user_str(b.f1.name, sizeof(b.f1.name), name1);
    }

    if (CHECK_FLAG(*state, FLAGS_CLR_MAY)) {
        b.f0.fd = -1;
        b.f0.i_ino = 0;
        b.f0.name[0] = '\0';
//        bpf_probe_read(&cur->f0.name, 32, NULL);
    }
    if (CHECK_FLAG(*state, FLAGS_CLR_MIN)) {
        b.f1.fd = -1;
        b.f1.i_ino = 0;
        b.f1.name[0] = '\0';
//        bpf_probe_read(&cur->f1.name, 32, NULL);
    }

//    cur->out_flag = 1;
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
//    if (ret_val < 0) {
//        cur->out_flag = 0;
//        /* suppress the final error output temporarily */
//        cur->s.for_assign &= ~((u64)FLAGS_FINAL << 32);
//        return 0;
//    }
    if (cur && !nex->s.for_assign) {
        cur->s.for_assign = 0;
        return 0;
    }

    /* update the return value which is fd */
    if (CHECK_FLAG(nex->s.for_assign, FLAGS_MAY_FD)) {
//    behavior.perf_submit(ctx, cur, sizeof(*cur));
        if (nex->f0.fd == -1 || (cur && cur->f0.fd == nex->f0.fd))
            nex->f0.fd = ret_val;
    } else if (CHECK_FLAG(nex->s.for_assign, FLAGS_MIN_FD)) {
        if (nex->f1.fd == -1 || (cur && cur->f1.fd == nex->f1.fd))
            nex->f1.fd = ret_val;
    } else if (CHECK_FLAG(nex->s.for_assign, FLAGS_NET_FD)) {
        if (nex->net.fd == -1 || (cur && cur->net.fd == nex->net.fd))
            nex->net.fd = ret_val;
    }

    struct behav_t *parent = state_behav.lookup(&(nex->ppid));
    if (parent && CHECK_FLAG(nex->s.for_assign, FLAGS_PARENT)) {
        parent->net.addr = nex->net.addr;
        parent->net.port = nex->net.port;
        parent->s.for_assign = nex->s.for_assign;
        state_behav.delete(&pid);
        return 0;
    }

    /* submit the event now? */
    if (cur && CHECK_FLAG(nex->s.for_assign, FLAGS_SMT_LST)) {
        behavior.perf_submit(ctx, cur, sizeof(*cur));
    } else if (CHECK_FLAG(nex->s.for_assign, FLAGS_SMT_CUR)) {
        behavior.perf_submit(ctx, nex, sizeof(*nex));
    }
    /* remove flags for storing after using */
//    nex->s.for_assign &= 0xfffff1ffffffffff;
//    if (nex->s.fr.state == 43) {
//        behavior.perf_submit(ctx, nex, sizeof(*nex));
//    }

    state_behav.update(&pid, nex);

    return 0;
}

int syscall__openat(struct pt_regs *ctx, int dirfd, const char __user *name, int flags) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_OPENAT, flags), name, name, -1, -1, 0, 0);
}

int syscall__openat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__read(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_READ, 0), NULL, NULL, fd, -1, 0, 1);
}

int syscall__read_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__write(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_WRITE, 0), NULL, NULL, fd, -1, 0, 1);
}

int syscall__write_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__close(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_CLOSE, 0), NULL, NULL, fd, -1, 0, 1);
}

int syscall__close_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__unlinkat(struct pt_regs *ctx, int dirfd, const char __user *name, int flags) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_UNLINKAT, flags), name, name, -1, -1, 0, 0);
}

int syscall__unlinkat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__mkdirat(struct pt_regs *ctx, int dirfd, const char __user *name) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_MKDIRAT, 0), name, name, -1, -1, 0, 0);
}

int syscall__mkdirat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__renameat(struct pt_regs *ctx,
                      int olddir, const char *oldname,
                      int newdir, const char *newname) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_RENAMEAT, 0), oldname, newname, -1, -1, 0, 0);
}

int syscall__renameat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__renameat2(struct pt_regs *ctx,
                       int olddir, const char *oldname,
                       int newdir, const char *newname,
                       unsigned int flags) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_RENAMEAT2, 0), oldname, newname, -1, -1, 0, 0);
}

int syscall__renameat2_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__dup3(struct pt_regs *ctx, int oldfd, int newfd, int flags) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_DUP3, 0), NULL, NULL, oldfd, newfd, 0, 1);
}

int syscall__dup3_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__socket(struct pt_regs *ctx,
                    int family, int type, int protocol) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_SOCKET, NET_ARGS(family, type)), NULL, NULL, -1, -1, 0, 0);
}

int syscall__socket_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__connect(struct pt_regs *ctx, int fd,
                     const struct sockaddr __user* addr, u32 addrlen) {
    struct sockaddr_in *sa = (struct sockaddr_in*)addr;
    u64 net_info = ((u64)sa->sin_port << 32) | (sa->sin_addr).s_addr;
    return do_entry(ctx, CALL_ARGS(SYS_CALL_CONNECT, 0), NULL, NULL, fd, -1, net_info, 1);
}

int syscall__connect_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall_exit_group(struct pt_regs *ctx, int sig) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state_behav.lookup(&pid);

    if (!cur) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_SMT_EXT))
        behavior.perf_submit(ctx, cur, sizeof(*cur));
    state_behav.delete(&pid);

    return 0;
}

/* kernel function to get inode */

int do_vfs_open(struct pt_regs *ctx, const struct path *path, struct file *file) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = next_state.lookup(&pid);

    if (!cur) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_MAYOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MAY_FD)) {
        cur->f0.i_ino = path->dentry->d_inode->i_ino;
    } else if (CHECK_FLAG(cur->s.for_assign, FLAGS_MINOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MIN_FD)) {
        cur->f1.i_ino = path->dentry->d_inode->i_ino;
    }

    return 0;
}

int do_vfs_unlink(struct pt_regs *ctx, struct user_namespace *mnt_userns, struct inode *dir,
                  struct dentry *dentry, struct inode **delegated_inode) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = next_state.lookup(&pid);

    if (!cur) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_MAYOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MAY_FD)) {
        cur->f0.i_ino = dentry->d_inode->i_ino;
    } else if (CHECK_FLAG(cur->s.for_assign, FLAGS_MINOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MIN_FD)) {
        cur->f1.i_ino = dentry->d_inode->i_ino;
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
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_MAYOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MAY_FD)) {
        cur->f0.i_ino = rd->old_dentry->d_inode->i_ino;
    }
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_MINOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MIN_FD)) {
        cur->f1.i_ino = rd->old_dentry->d_inode->i_ino;
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
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_MAYOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MAY_FD)) {
        bpf_probe_read_kernel(&cur->f0.i_ino, sizeof(u32), &((*tmp)->d_inode->i_ino));
    } else if (CHECK_FLAG(cur->s.for_assign, FLAGS_MINOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MIN_FD)) {
        bpf_probe_read_kernel(&cur->f1.i_ino, sizeof(u32), &((*tmp)->d_inode->i_ino));
    }

    return 0;
}

int do_vfs_rmdir(struct pt_regs *ctx, struct user_namespace *mnt_userns,
        struct inode *dir, struct dentry *dentry) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = next_state.lookup(&pid);

    if (!cur) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_MAYOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MAY_FD)) {
        cur->f0.i_ino = dentry->d_inode->i_ino;
    } else if (CHECK_FLAG(cur->s.for_assign, FLAGS_MINOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MIN_FD)) {
        cur->f1.i_ino = dentry->d_inode->i_ino;
    }

    return 0;
}


