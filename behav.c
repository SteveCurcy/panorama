/*
 * Author: Xu.Cao
 * Created by steve on 1/8/23.
 */

#include <uapi/linux/ptrace.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include "include/ebpf_string.h"
#include "include/al.h"

// 10240 by default
BPF_HASH(STT_fir, u64, u64, 4096);  // the first layer state transition table
BPF_HASH(state_fir, u32, struct omni_data_t, 4096);  // pid -> data
BPF_HASH(file_delay, u32, const char*, 2048);
BPF_HASH(aux_file_delay, u32, const char*, 2048);
BPF_PERF_OUTPUT(perf_fir);

__always_inline static int do_entry(struct pt_regs *ctx, u64 call_args, const char *name,
        const char *aux_name, u64* net_info, int fd, int aux_fd, u64 flag) {
    // get the pid and ppid by `struct task_struct`
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u32 pid = task->pid;
    u32 ppid = task->real_parent->tgid;
    u64 pre_state = 0;
    u64 *state;
    struct omni_data_t data = {};
    struct omni_data_t *ret = state_fir.lookup(&pid);
    struct omni_data_t *parent = state_fir.lookup(&ppid);

    if (!ret) {
        pre_state = call_args;

        state = STT_fir.lookup(&pre_state);

        if (!state) return 0;

        init(&data, pid, ppid);
        ret = &data;
    }
    if (!ret) return 0;

    if (flag == AL_FLAG_COMPARE_MAYOR_FD) {
        if (fd == ret->fd) call_args |= AL_ARGS_EQL_SRC;
        else if (fd == ret->aux_fd) call_args |= AL_ARGS_EQL_DST;
    } else if (flag == AL_FLAG_COMPARE_MINOR_FD) {
        if (aux_fd == ret->fd) call_args |= AL_ARGS_EQL_SRC;
        else if (aux_fd == ret->aux_fd) call_args |= AL_ARGS_EQL_DST;
    }
    pre_state = STATE_KEY(ret->state, call_args);
//    if ((ret->state & 0xffff) == 28) {
//        ret->time = pre_state;
//        perf_fir.perf_submit(ctx, ret, sizeof(struct omni_data_t));
//    }

    state = STT_fir.lookup(&pre_state);
    if (!state) {
        return 0;
    }

    if (!(*state)) {
        state_fir.delete(&pid);
        return 0;
    }

    // if higher priority, op will be replaced, or remain
    ret->state = (*state & 0x0000000000800000) ?
                 *state : ((ret->state & 0x0000000000ff0000) ? (ret->state & 0x0000000000ff0000) |
                                                               (*state & 0xffffffffff00ffff) : *state);

    if (STATE_FLAG_CHECK(*state, AL_FLAG_ADDR)) {
        // fill the net_info
        (ret->aux).net_info = *net_info;
        // fill the parent
        if (STATE_FLAG_CHECK(*state, AL_FLAG_PARENT) && parent) {
            (parent->aux).net_info = *net_info;
            parent->state = ret->state;
        }
    }

    if (STATE_FLAG_CHECK(*state, AL_FLAG_ARG_MAYOR_FD)) {
        ret->fd = fd;
    }
    if (STATE_FLAG_CHECK(*state, AL_FLAG_ARG_MAYOR_FD)) {
        ret->aux_fd = aux_fd;
    }

    if (STATE_FLAG_CHECK(*state, AL_FLAG_DELAY)) {
        if (STATE_FLAG_CHECK(*state, AL_FLAG_MAYOR_NAME)) {
            // fill the mayor name or fd
            file_delay.update(&pid, &name);
        }
        if (STATE_FLAG_CHECK(*state, AL_FLAG_MINOR_NAME)) {
            // fill the minor name or fd
            aux_file_delay.update(&pid, &aux_name);
        }
    } else {
        if (STATE_FLAG_CHECK(*state, AL_FLAG_MAYOR_NAME)) {
            // fill the mayor name or fd
            bpf_probe_read_user(&(ret->name), 32, name);

        }
        if (STATE_FLAG_CHECK(*state, AL_FLAG_MINOR_NAME)) {
            // fill the minor name or fd
            bpf_probe_read_user(&((ret->aux).name), 32, aux_name);
        }
    }

    if (STATE_FLAG_CHECK(*state, AL_FLAG_PSH)) {
        perf_fir.perf_submit(ctx, ret, sizeof(struct omni_data_t));
    }
    state_fir.update(&pid, ret);

    return 0;
}

__always_inline static int do_return(struct pt_regs *ctx) {
    int ret_val = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct omni_data_t *ret = state_fir.lookup(&pid);

    if (!ret) return 0;
    if (STATE_FLAG_CHECK(ret->state, AL_FLAG_CHK) && ret_val == -1) {
        state_fir.delete(&pid);
        return 0;
    }

    if (STATE_FLAG_CHECK(ret->state, AL_FLAG_DELAY) && ret_val != -1) {
        const char** filename = file_delay.lookup(&pid);
        const char** aux_filename = aux_file_delay.lookup(&pid);
        if (STATE_FLAG_CHECK(ret->state, AL_FLAG_MAYOR_NAME) && filename) {
            bpf_probe_read_user(&(ret->name), 32, *filename);
            file_delay.delete(&pid);

        }
        if (STATE_FLAG_CHECK(ret->state, AL_FLAG_MINOR_NAME) && aux_filename) {
            bpf_probe_read_user(&((ret->aux).name), 32, *aux_filename);
            aux_file_delay.delete(&pid);
        }
    }

    if (STATE_FLAG_CHECK(ret->state, AL_FLAG_RET_MAYOR_FD)) {
        ret->fd = ret_val;
    } else if (STATE_FLAG_CHECK(ret->state, AL_FLAG_RET_MINOR_FD)) {
        ret->aux_fd = ret_val;
    }
//    perf_fir.perf_submit(ctx, ret, sizeof(*ret));

    return 0;
}

int do_open_entry(struct pt_regs *ctx,
                  const char *filename, int flags, mode_t mode) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_OPEN, flags), filename, filename, NULL, -1, -1, 0);
}

int do_open_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_openat_entry(struct pt_regs *ctx, int dirfd,
                    const char *filename, int flags, mode_t mode) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_OPENAT, flags), filename, filename, NULL, -1, -1, 0);
}

int do_openat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_dup2_entry(struct pt_regs *ctx, int oldfd, int newfd) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_DUP2, 0), NULL, NULL, NULL, newfd, oldfd, 0);
}

int do_rename_entry(struct pt_regs *ctx,
                    const char __user* oldname, const char __user* newname) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_RENAME, 0), oldname, newname, NULL, -1, -1, 0);
}

int do_renameat2_entry(struct pt_regs *ctx,
                       int olddir, const char *oldname,
                       int newdir, const char *newname,
                       unsigned int flags) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_RENAMEAT2, 0), oldname, newname, NULL, -1, -1, 0);
}

int do_renameat2_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_read_entry(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_READ, 0), NULL, NULL, NULL, fd, -1, AL_FLAG_COMPARE_MAYOR_FD);
}

int do_write_entry(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_WRITE, 0), NULL, NULL, NULL, fd, -1, AL_FLAG_COMPARE_MAYOR_FD);
}

int do_close_entry(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_CLOSE, 0), NULL, NULL, NULL, fd, -1, AL_FLAG_COMPARE_MAYOR_FD);
}

int do_unlinkat_entry(struct pt_regs *ctx, int dirfd,
                      const char __user* pathname) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_UNLINKAT, 0), pathname, NULL, NULL, -1, -1, 0);
}

int do_mkdir_entry(struct pt_regs *ctx, const char *pathname) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_MKDIR, 0), pathname, NULL, NULL, -1, -1, 0);
}

int do_rmdir_entry(struct pt_regs *ctx, const char *pathname) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_RMDIR, 0), pathname, NULL, NULL, -1, -1, 0);
}

int do_socket_entry(struct pt_regs *ctx,
                    int family, int type, int protocol) {
    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_SOCKET, NET_ARGS(family, type)), NULL, NULL, NULL, -1, -1, 0);
}

int do_socket_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int do_connect_entry(struct pt_regs *ctx, int fd,
                     const struct sockaddr __user* addr, u32 addrlen) {
    struct sockaddr_in *sa = (struct sockaddr_in*)addr;
    u64 net_info = ((u64)sa->sin_port << 32) | (sa->sin_addr).s_addr;

    return do_entry(ctx, CALL_ARGS(AL_SYS_CALL_CONNECT, 0), NULL, NULL, &net_info, fd, -1, AL_FLAG_COMPARE_MAYOR_FD);
}

int do_exit_entry(struct pt_regs *ctx, int sig) {
    do_entry(ctx, CALL_ARGS(AL_SYS_CALL_EXIT, 0), NULL, NULL, NULL, -1, -1, 0);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct omni_data_t *ret = state_fir.lookup(&pid);
    if (!ret) return 0;

    if (STATE_FLAG_CHECK(ret->state, AL_FLAG_FINAL_MEMO))
        perf_fir.perf_submit(ctx, ret, sizeof(struct omni_data_t));

    return 0;
}
