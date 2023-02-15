//
// Created by steve on 2023/1/23.
//
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
BPF_HASH(delay0, u32, const char*, 512);
BPF_HASH(delay1, u32, const char*, 512);
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
 */
__always_inline static int do_entry(struct pt_regs *ctx, u64 call_args, const char *name0,
        const char *name1, int fd0, int fd1, u64 net_info, u8 flag) {
    struct behav_t b = {}, *cur = NULL, *parent = NULL;
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 pre_state = 0, *state = NULL;

    /* get the pid and ppid and state */
    b.pid = task->pid;
    b.ppid = task->real_parent->pid;
//    if (b.ppid == 1) return 0;  // filter the system routines
    cur = state_behav.lookup(&b.pid);
    parent = state_behav.lookup(&b.ppid);

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
        b.f0.i_ino = b.f1.i_ino = 0;
        b.f0.fd = b.f1.fd = -1;
        b.s.for_assign = 0;
        b.out_flag = 1;
        cur = &b;
    }
    if (!cur) return 0;

    /* check args of functions, like write(fd), connect(fd,...). */
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_COM_IO)) {  // higher priority
        switch ((call_args >> 40) & 0x00ff) {
            case SYS_CALL_READ:
                if (0 == fd0) call_args |= ARGS_EQL_IO;
                break;
            case SYS_CALL_WRITE:
                if (1 == fd0) call_args |= ARGS_EQL_IO;
                break;
        }
    } else if (flag) {  // read, write, etc., will set this flag by default
        if (cur->f0.fd != -1 && fd0 == cur->f0.fd) call_args |= ARGS_EQL_SRC;
        else if (cur->f1.fd != -1 && fd0 == cur->f1.fd) call_args |= ARGS_EQL_DST;
        else if (cur->net.fd != -1 && fd0 == cur->net.fd) call_args |= ARGS_EQL_NET;
    }
    pre_state = ((u64)cur->s.for_assign << 48) | call_args;
//    if (!ebpf_strcmp("vi", cur->comm)) {
//        // cur->s.for_assign = pre_state;
//        behavior.perf_submit(ctx, cur, sizeof(*cur));
//    }
//    if (cur->s.fr.state == 11) {
//        behavior.perf_submit(ctx, cur, sizeof(*cur));
//    }

    /* remember the last state */
    if (cur != &b) {
        /* they are not the same and used to remember last one */
        bpf_probe_read(&b, sizeof(b), cur);
    }

    /* check the next state */
    state = stt_behav.lookup(&pre_state);
    if (!state) {
        /* check if the next state transition should be caused now.
         * restore the state back to START if not. */
        if (CHECK_FLAG(cur->s.for_assign, FLAGS_NEXT)) {
            cur->s.for_assign = 0;
        }
        return 0;
    }

    /* state0 means start, so just remain it. */
    if (!(*state)) {
//        state_behav.delete(&b.pid);
        cur->s.for_assign = 0;
        return 0;
    }

    /* check if state need to be updated */
    cur->s.for_assign = (*state & 0x0000000000800000) ?
            *state : (cur->s.fr.operate ? (cur->s.for_assign & 0x0000000000ff0000) |
                                          (*state & 0xffffffffff00ffff) : *state);

//    if (cur->s.fr.state == 21)
//    behavior.perf_submit(ctx, cur, sizeof(*cur));
    /* net info assignment */
    if (CHECK_FLAG(*state, FLAGS_NET)) {
        cur->net.addr = (net_info & 0x00000000ffffffff);
        cur->net.port = (net_info >> 32) & 0x000000000000ffff;
        /* upload the state and delete current one if parent exists */
        if (parent && CHECK_FLAG(*state, FLAGS_PARENT)) {
            parent->net.addr = cur->net.addr;
            parent->net.port = cur->net.port;
            parent->s.for_assign = cur->s.for_assign;
            state_behav.delete(&b.pid);
            return 0;
        }
    }

    /* update fds from arguments */
    if (fd1 >= 0) {
        if (CHECK_FLAG(cur->s.for_assign, FLAGS_MAY_FD)) {
            cur->f0.fd = fd1;
        } else if (CHECK_FLAG(cur->s.for_assign, FLAGS_MIN_FD)) {
            cur->f1.fd = fd1;
        } else if (CHECK_FLAG(cur->s.for_assign, FLAGS_NET_FD)) {
            cur->net.fd = fd1;
        }
    }

    /* copy the filename and check if it needs to be delay */
    if (CHECK_FLAG(*state, FLAGS_DELAY)) {
        if (CHECK_FLAG(*state, FLAGS_MAYOR)) {
            delay0.update(&b.pid, &name0);
        }
        if (CHECK_FLAG(*state, FLAGS_MINOR)) {
            delay1.update(&b.pid, &name1);
        }
    } else {
        if (CHECK_FLAG(*state, FLAGS_MAYOR)) {
            bpf_probe_read_user_str(&(cur->f0.name), 32, name0);
        }
        if (CHECK_FLAG(*state, FLAGS_MINOR)) {
            bpf_probe_read_user_str(&(cur->f1.name), 32, name1);
        }
    }

    if (CHECK_FLAG(*state, FLAGS_CLR_MAY)) {
        cur->f0.fd = -1;
        cur->f0.i_ino = 0;
        cur->f0.name[0] = '\0';
//        bpf_probe_read(&cur->f0.name, 32, NULL);
    }
    if (CHECK_FLAG(*state, FLAGS_CLR_MIN)) {
        cur->f1.fd = -1;
        cur->f1.i_ino = 0;
        cur->f1.name[0] = '\0';
//        bpf_probe_read(&cur->f1.name, 32, NULL);
    }

    /* submit the event now? */
    if (CHECK_FLAG(*state, FLAGS_SUBMIT) && cur->out_flag) {
        behavior.perf_submit(ctx, cur, sizeof(*cur));
    } else if (cur != &b && CHECK_FLAG(*state, FLAGS_LST_SMT) && cur->out_flag) {
        behavior.perf_submit(ctx, &b, sizeof(b));
    }

    cur->out_flag = 1;
    state_behav.update(&b.pid, cur);
    return 0;
}

__always_inline static int do_return(struct pt_regs *ctx) {
    int ret_val = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state_behav.lookup(&pid);
    const char** name0 = delay0.lookup(&pid);
    const char** name1 = delay1.lookup(&pid);
    if (name0) delay0.delete(&pid);
    if (name1) delay1.delete(&pid);

    /* skip if no state recording or returning error */
    if (!cur) return 0;
    if (ret_val < 0) {
        cur->out_flag = 0;
        /* suppress the final error output temporarily */
        cur->s.for_assign &= ~((u64)FLAGS_FINAL << 32);
        return 0;
    }

    /* copy filename now if `delay` flag was set */
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_DELAY)) {
        if (name0) {
            if (CHECK_FLAG(cur->s.for_assign, FLAGS_MAYOR)) {
                bpf_probe_read_user_str(&cur->f0.name, 32, *name0);
            }
        }
        if (name1) {
            if (CHECK_FLAG(cur->s.for_assign, FLAGS_MINOR)) {
                bpf_probe_read_user_str(&cur->f1.name, 32, *name1);
            }
        }
    }

    /* update the return value which is fd */
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_MAY_FD)) {
//    behavior.perf_submit(ctx, cur, sizeof(*cur));
        cur->f0.fd = ret_val;
    } else if (CHECK_FLAG(cur->s.for_assign, FLAGS_MIN_FD)) {
        cur->f1.fd = ret_val;
    } else if (CHECK_FLAG(cur->s.for_assign, FLAGS_NET_FD)) {
        cur->net.fd = ret_val;
    }

    /* submit the event now? */
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_DLY_SMT)) {
        behavior.perf_submit(ctx, cur, sizeof(*cur));
    }
    /* remove flags for storing after using */
    cur->s.for_assign &= 0xffffff01ffffffff;

    return 0;
}

int do_open_entry(struct pt_regs *ctx, const char *name, int flags) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_OPEN, flags), name, name, -1, -1, 0, 0);
}

int do_open_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_openat_entry(struct pt_regs *ctx, int dirfd, const char *name, int flags) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_OPENAT, flags), name, name, -1, -1, 0, 0);
}

int do_openat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_read_entry(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_READ, 0), NULL, NULL, fd, -1, 0, 1);
}

int do_write_entry(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_WRITE, 0), NULL, NULL, fd, -1, 0, 1);
}

int do_close_entry(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_CLOSE, 0), NULL, NULL, fd, fd, 0, 1);
}

int do_unlinkat_entry(struct pt_regs *ctx, int dirfd, const char __user *name) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_UNLINKAT, 0), name, name, -1, -1, 0, 0);
}

int do_unlinkat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_mkdir_entry(struct pt_regs *ctx, const char __user *name) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_MKDIR, 0), name, name, -1, -1, 0, 0);
}

int do_mkdir_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_rmdir_entry(struct pt_regs *ctx, const char __user *name) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_RMDIR, 0), name, NULL, -1, -1, 0, 0);
}

int do_rmdir_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_rename_entry(struct pt_regs *ctx,
                    const char __user* oldname, const char __user* newname) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_RENAME, 0), oldname, newname, -1, -1, 0, 0);
}

int do_rename_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_renameat2_entry(struct pt_regs *ctx,
                       int olddir, const char *oldname,
                       int newdir, const char *newname,
                       unsigned int flags) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_RENAMEAT2, 0), oldname, newname, -1, -1, 0, 0);
}

int do_renameat2_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_dup2_entry(struct pt_regs *ctx, int oldfd, int newfd) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_DUP2, 0), NULL, NULL, oldfd, newfd, 0, 1);
}

int do_socket_entry(struct pt_regs *ctx,
                    int family, int type, int protocol) {
    return do_entry(ctx, CALL_ARGS(SYS_CALL_SOCKET, NET_ARGS(family, type)), NULL, NULL, -1, -1, 0, 0);
}

int do_socket_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_connect_entry(struct pt_regs *ctx, int fd,
                     const struct sockaddr __user* addr, u32 addrlen) {
    struct sockaddr_in *sa = (struct sockaddr_in*)addr;
    u64 net_info = ((u64)sa->sin_port << 32) | (sa->sin_addr).s_addr;
    return do_entry(ctx, CALL_ARGS(SYS_CALL_CONNECT, 0), NULL, NULL, fd, -1, net_info, 1);
}

int do_exit_entry(struct pt_regs *ctx, int sig) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state_behav.lookup(&pid);

    if (!cur) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_FINAL))
        behavior.perf_submit(ctx, cur, sizeof(*cur));
    state_behav.delete(&pid);

    return 0;
}

/* kernel function to get inode */

int do_vfs_open(struct pt_regs *ctx, const struct path *path, struct file *file) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state_behav.lookup(&pid);

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
    struct behav_t *cur = state_behav.lookup(&pid);

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
    struct behav_t *cur = state_behav.lookup(&pid);

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
    struct behav_t *cur = state_behav.lookup(&pid);

    if (!cur) return 0;
    tmp_dentry.update(&pid, &dentry);

    return 0;
}

int do_vfs_mkdir_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state_behav.lookup(&pid);
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
    struct behav_t *cur = state_behav.lookup(&pid);

    if (!cur) return 0;
    if (CHECK_FLAG(cur->s.for_assign, FLAGS_MAYOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MAY_FD)) {
        cur->f0.i_ino = dentry->d_inode->i_ino;
    } else if (CHECK_FLAG(cur->s.for_assign, FLAGS_MINOR) || CHECK_FLAG(cur->s.for_assign, FLAGS_MIN_FD)) {
        cur->f1.i_ino = dentry->d_inode->i_ino;
    }

    return 0;
}


