/**
 * @file panorama.bpf.c
 * @author Xu.Cao
 * @version v1.5.1
 * @date 2023-10-30
 * @details 本源文件定义了将被插入到内核中的钩子函数，分别在系统调用和
 * 	内核函数入口和出口处进行监控。（说明：入口指函数开始位置；出口指函数
 * 	的返回位置）
 * 
 * 	- 系统调用主要用于控制进程行为状态的走向；使用 tracepoint，即静态
 *      跟踪点监控，因为该接口通常为内核开发者预留，较稳定，且执行速度快。
 * 	- 内核函数主要用于采集文件相关的详细信息（如 inode、文件名、类型等）；
 *      使用 kprobe 内核探针监控，因为内核开发者通常不会为这些函数预留
 *      检测点，只能使用探针插入监控函数。
 * 	对于简单的系统调用，本文件提供统一的入口/出口处理函数；
 * 	对于复杂的系统调用，具体的状态转移和信息保存则由钩子函数自行处理。
 * 
 * 	对于所有系统调用和内核函数，都将在出口处判断函数执行情况。如果函数
 * 	执行失败，则不会对进程的当前状态产生影响，否则将导致状态转移。
 * 
 *  本源文件中的所有钩子函数都将被动态加载到内核中。本文件属于内核态代码；
 *  panorama.c 则是对应的用户态代码，本文件中的函数由 panorama.c 加载
 *  至内核中。
 * @see panorama.c
 * @history
 *  <author>    <time>    <version>    <desc>
 *  Xu.Cao      23/10/30    1.5.1    Format and Standardize this source
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "panorama.h"
#include "config.h"

/* 状态转移表，BPF_HASH;
 * state transition table 简写 stt,
 * <old_code><event>, <new_code>
 * - old_code 为旧状态码 -- 32bit；
 * - event 为触发状态转移的事件 -- 32bit；
 * - new_code 为新的状态码，即状态转移之后的状态码 -- 32bit */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, u32);
} maps_stt SEC(".maps");

/* 保存当前的和可能的下一个状态信息。
 * maps_nex 类似一个临时变量，保存当前系统调用导致
 * 转移到的下一个状态，当函数执行成功时，maps_cur
 * 中的状态将被该状态代替，并且从 maps_nex 中移除。*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, pid_t);
    __type(value, struct p_state_t);
} maps_cur SEC(".maps"), maps_nex SEC(".maps");

/* 保存临时 sock 结构体，将保存入口处提供的 socket 参数，在出口使用 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, pid_t);
    __type(value, struct sock*);
} maps_temp_sock SEC(".maps");

/* 存储临时的 fd 信息，保存函数入口参数中的 fd 信息，在出口使用 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, __u64);
} maps_temp_fd SEC(".maps");

/* 存储临时的文件信息，通常在内核函数的入口处保存，出口处使用并删除 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, struct p_finfo_t);
} maps_temp_file SEC(".maps");

/* 临时保存 dentry 信息 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, struct dentry*);
} maps_temp_dentry SEC(".maps");

/* 用于保存进程打开的文件的相关信息，包括文件名、inode、读写数量等
 * 使用 pid << 32 | fd 来作为 key 唯一标识一个文件, fd 全 1 代表临时存储 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct p_finfo_t);
} maps_files SEC(".maps");

/* 用于保存需要过滤的进程的哈希值 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u8);
} maps_filter_hash SEC(".maps");

/* 事件类型，将日志信息传输到用户空间 */
#ifdef __KERNEL_VERSION
#if __KERNEL_VERSION<508
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} rb SEC(".maps");
#else
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} rb SEC(".maps");
#endif
#endif

#ifndef fill_log
#define fill_log(log, _ppid, _pid, _state_code, _life)\
    do {										\
    __builtin_memset(&(log), 0, sizeof (log));  \
    (log).ppid = (_ppid);   					\
    (log).pid = (_pid);  						\
    (log).uid = (u32) bpf_get_current_uid_gid();\
    (log).state = (_state_code); 				\
    (log).life = _life; 						\
    bpf_get_current_comm(&(log).comm, 32);  	\
    } while (0)
#endif

/**
 * @brief  清理结束的进程打开过的文件信息
 * @note   用于清理进程打开的文件信息，防止内存泄露。在
 *         进程结束时被调用，用于清理残留信息。
 * @param  pid: 结束的进程号，即希望进行信息清理的进程
 * @retval None
 * @see    tracepoint__syscalls__sys_enter_exit_group
 */
static void clear_rest_files(pid_t pid) {
    u64 key = (u64) pid << 32;
    int err = 0;
#pragma unroll(1024)
    for (int i = 0; i < 1024; i++) {
        key = (key & 0xffffffff00000000) | i;
        err = bpf_map_delete_elem(&maps_files, &key);
    }
    bpf_map_delete_elem(&maps_cur, &pid);
}

/**
 * @brief  检查当前进程是否需要被忽略
 * @note   有一些系统例程会导致大量冗余日志，因此需要查看当前
 *         进程是否在“被忽略列表”中
 * @retval bool 返回是否需要被忽略，需要则返回 true
 */
__always_inline static bool ignore_proc() {
    char comm[32];
    bpf_get_current_comm(&comm, 32);
    __u64 hash_value = str_hash(comm);

    __u8 *dummy = bpf_map_lookup_elem(&maps_filter_hash, &hash_value);
    return (0 != dummy);
}

/**
 * @brief  系统调用入口的统一处理函数
 * @note   只根据当前的事件编号进行状态转移，如果当前进程不在“被忽略
 *         列表”中，则根据进程状态和当前事件编号计算下一个可能的状态。
 * @param  event: 触发状态转移的事件
 * @retval 永远为 0
 */
static int tracepoint__syscalls__sys_enter(__u32 event) {
    
    if (ignore_proc()) return 0;

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_cur = bpf_map_lookup_elem(&maps_cur, &pid), state_tmp;
    struct task_struct *ptask = (struct task_struct *) bpf_get_current_task();
    pid_t ppid = BPF_CORE_READ(ptask, real_parent, tgid);
    FILL_STATE(state_tmp, ppid, 0);

    if (!pstate_cur) pstate_cur = &state_tmp;
    if (!pstate_cur) return 0;          // 验证器需要，要在使用前检查，确保指针不为空

    __u64 trigger_key = STT_KEY(pstate_cur->state_code, event);
    __u32 *state_code_next = bpf_map_lookup_elem(&maps_stt, &trigger_key);
    if (!state_code_next) return 0;

    state_tmp.state_code = *state_code_next;
    bpf_map_update_elem(&maps_nex, &pid, &state_tmp, BPF_ANY);
    
    return pid;
}

/**
 * @brief  系统调用入口的统一处理函数
 * @note   根据系统调用的返回值完成状态转移的最终处理：
 *         - 如果执行成功，则将预期状态更新为当前状态，删除临时状态信息；
 *         - 如果执行失败，则直接删除临时状态信息，然后返回
 * @param  ret: 系统调用的返回值
 * @retval 永远为 0
 * @TODO   下一步应该修改输入参数，为 bool 类型，即调用是否成功，因为不同
 *         调用的返回值含意不同，应分别判断。
 */
static int tracepoint__syscalls__sys_exit(long ret) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);

    bpf_map_delete_elem(&maps_nex, &pid);
    if (!pstate_next || ret < 0) return 0;

    bpf_map_update_elem(&maps_cur, &pid, pstate_next, BPF_ANY);

    return pid;
}

/**
 * @brief  监控 openat 系统调用入口，保存打开文件信息
 * @note   int openat(int dfd, const char *filename, int flags, umode_t mode)
 *         由于文件打开较为重要，并且关系到具体的文件操作，应单独编写。
 *         flags 参数标识文件打开方式，我们通过该参数获得对文件的操作方式，如读、写、创建等。
 * @param  ctx: 进程上下文，可以用于获取调用参数
 * @retval 永远为 0
 */
SEC("tp/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {

    int flags = BPF_CORE_READ(ctx, args[2]);
    if (ignore_proc()) return 0;

    /* 如果一个文件的打开方式为 O_CLOEXEC 则大概率是一个库文件，将其过滤 */
    if (flags == O_CLOEXEC) return 0;

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    __u32 pid = BPF_CORE_READ(task, tgid);
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    struct p_state_t *pstate_cur = bpf_map_lookup_elem(&maps_cur, &pid), state_tmp;
    struct p_finfo_t finfo_tmp;
    __u32 pevent_code = 0;

    FILL_STATE(state_tmp, ppid, 0);
    __builtin_memset(&finfo_tmp, 0, sizeof(finfo_tmp));

    pevent_code = get_open_evnt(flags);
    switch (pevent_code) {
    case PEVENT_OPEN_READ:
        finfo_tmp.operation = OP_READ;
        break;
    case PEVENT_OPEN_WRITE:
        finfo_tmp.operation = OP_WRITE;
        break;
    case PEVENT_OPEN_COVER:
        finfo_tmp.operation = OP_COVER;
        finfo_tmp.op_cnt = 1;
        break;
    case PEVENT_OPEN_RDWR:
        finfo_tmp.operation = OP_RDWR;
        break;
    case PEVENT_OPEN_CREAT:
        finfo_tmp.operation = OP_CREATE;
        finfo_tmp.op_cnt = 1;
        break;
    case PEVENT_OPEN_DIR:
        finfo_tmp.operation = OP_OPEN;
        break;
    default:
        break;
    }
    finfo_tmp.open_time = bpf_ktime_get_ns();	// bpf_ktime_get_boot_ns 不可用，改用 bpf_ktime_get_ns

    if (!pstate_cur) pstate_cur = &state_tmp;
    if (!pstate_cur) return 0;

    __u64 stt_key = STT_KEY(pstate_cur->state_code, pevent_code);
    __u32 *state_code_next = bpf_map_lookup_elem(&maps_stt, &stt_key);
    if (!state_code_next) return 0;

    __u64 file_key = (__u64) pid << 32 | 0xffffffff;
    bpf_map_update_elem(&maps_files, &file_key, &finfo_tmp, BPF_ANY);

    state_tmp.state_code = *state_code_next;
    bpf_map_update_elem(&maps_nex, &pid, &state_tmp, BPF_ANY);

    return 0;
}

/**
 * @brief  监控 openat 系统调用出口，更新进程状态
 * @param  ctx: 进程上下文，用于获取返回值
 * @retval 永远为 0
 */
SEC("tp/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    __u64 file_key = ((__u64) pid << 32) | 0xffffffff;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);
    struct p_finfo_t *pfinfo_new = bpf_map_lookup_elem(&maps_files, &file_key);
    long ret = BPF_CORE_READ(ctx, ret), err = 0;

    /* 必须要删除的临时变量放在指针非空判断之前，
     * 防止因逻辑错误或者忘记删除而导致的资源浪费 */
    bpf_map_delete_elem(&maps_files, &file_key);
    bpf_map_delete_elem(&maps_nex, &pid);
    if (!pstate_next || !pfinfo_new || ret < 0) return 0;

    file_key = ((__u64) pid << 32) | ret;
    err = bpf_map_update_elem(&maps_files, &file_key, pfinfo_new, BPF_ANY);

    err = bpf_map_update_elem(&maps_cur, &pid, pstate_next, BPF_ANY);

    return 0;
}

/**
 * @brief  更新文件读取统计信息
 * @note   ssize_t read(int fd, char *buf, size_t count)
 *         read 系统调用不参与状态转移，因此需要自行编写。更新参数
 *         fd 对应的文件的统计信息
 * @param  ctx: 进程上下文信息
 * @retval 永远为 0
 */
SEC("tp/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct p_state_t *pstate_cur = bpf_map_lookup_elem(&maps_cur, &pid);
    if (!pstate_cur) return 0;

    int fd = BPF_CORE_READ(ctx, args[0]);
    bpf_map_update_elem(&maps_temp_fd, &pid, &fd, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int *fd = (int *) bpf_map_lookup_elem(&maps_temp_fd, &pid);
    struct p_state_t *pstate_cur = bpf_map_lookup_elem(&maps_cur, &pid);
    ssize_t read_size = BPF_CORE_READ(ctx, ret);

    bpf_map_delete_elem(&maps_temp_fd, &pid);
    if (!fd || !pstate_cur) return 0;

    __u64 file_key = ((__u64) pid << 32) | *fd;
    struct p_finfo_t *pfinfo = bpf_map_lookup_elem(&maps_files, &file_key);
    if (!pfinfo)
        return 0;

    pfinfo->rx += read_size;
    pfinfo->op_cnt++;

    return 0;
}

/* ssize_t write(int fd, const char *buf, size_t count) */
SEC("tp/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int fd = BPF_CORE_READ(ctx, args[0]);

    __u64 file_key = ((__u64) pid << 32) | fd;
    struct p_finfo_t *pfinfo = bpf_map_lookup_elem(&maps_files, &file_key);
    if (!pfinfo) return 0;

    bpf_map_update_elem(&maps_temp_fd, &pid, &fd, BPF_ANY);

    tracepoint__syscalls__sys_enter(PEVENT_WRITE);

    return 0;
}
SEC("tp/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct trace_event_raw_sys_exit *ctx) {

    ssize_t ret = BPF_CORE_READ(ctx, ret);
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int *fd = bpf_map_lookup_elem(&maps_temp_fd, &pid);

    bpf_map_delete_elem(&maps_temp_fd, &pid);
    if (!fd) return 0;

    __u64 file_key = ((__u64) pid << 32) | *fd;
    struct p_finfo_t *pfinfo = bpf_map_lookup_elem(&maps_files, &file_key);
    if (!pfinfo) return 0;

    pfinfo->tx += ret;
    pfinfo->op_cnt++;

    pid = tracepoint__syscalls__sys_exit(ret);
    
    return 0;
}

/* int close(int fd) */
SEC("tp/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int fd = BPF_CORE_READ(ctx, args[0]);
    
    __u64 file_key = ((__u64) pid << 32) | fd;
    struct p_finfo_t *pfinfo = bpf_map_lookup_elem(&maps_files, &file_key);
    if (!pfinfo) return 0;

    bpf_map_update_elem(&maps_temp_fd, &pid, &fd, BPF_ANY);

    tracepoint__syscalls__sys_enter(PEVENT_CLOSE);

    return 0;
}

/**
 * @brief  输出并删除进程打开的文件信息
 * @note   所有打开的文件都会通过 close 系统调用关闭，因此所有文件的输出都
 *         在关闭时输出，以确保统计信息的尽可能完整。没有被操作过的文件没有
 *         必要输出，会被直接清除。
 * @param  *ctx: 
 * @retval 
 */
SEC("tp/syscalls/sys_exit_close")
int tracepoint__syscalls__sys_exit_close(struct trace_event_raw_sys_exit *ctx) {

    long ret = BPF_CORE_READ(ctx, ret);
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int *fd = bpf_map_lookup_elem(&maps_temp_fd, &pid);

    bpf_map_delete_elem(&maps_temp_fd, &pid);
    if (!fd || ret < 0) return 0;

    __u64 file_key = (__u64) pid << 32 | *fd;
    struct p_finfo_t *pfinfo = bpf_map_lookup_elem(&maps_files, &file_key);
    if (!pfinfo) return 0;

    tracepoint__syscalls__sys_exit(ret);

    struct p_state_t *pstate_cur = bpf_map_lookup_elem(&maps_cur, &pid);
    if (!pstate_cur) return 0;

    bpf_map_delete_elem(&maps_files, &file_key);

    if (pfinfo->op_cnt) {   // 只有文件被操作过，才有必要输出
#ifdef __KERNEL_VERSION
#if __KERNEL_VERSION<508
        struct p_log_t log, *plog = &log;
        __builtin_memset(plog, 0, sizeof(log));
#else
        struct p_log_t *plog = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
        if (!log) return 0;
#endif

        fill_log(*plog, pstate_cur->ppid,
                pid, pstate_cur->state_code,
                bpf_ktime_get_ns() - pfinfo->open_time);
        bpf_core_read(&(plog->info), sizeof(*pfinfo), pfinfo);

#if __KERNEL_VERSION<508
        bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, plog, sizeof(*plog));
#else
        bpf_ringbuf_submit(plog, 0);
#endif
#endif
    }

    return 0;
}

/* int unlink(const char *pathname) */
SEC("tp/syscalls/sys_enter_unlink")
int tracepoint__syscalls__sys_enter_unlink(struct trace_event_raw_sys_enter *ctx) {

    tracepoint__syscalls__sys_enter(PEVENT_UNLINK_FILE);

    return 0;
}

SEC("tp/syscalls/sys_exit_unlink")
int tracepoint__syscalls__sys_exit_unlink(struct trace_event_raw_sys_exit *ctx) {

    long ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ret);

    return 0;
}

/* int unlinkat(int dfd, const char *pathname, int flag) */
SEC("tp/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {

    int flags = BPF_CORE_READ(ctx, args[2]);
    tracepoint__syscalls__sys_enter(flags == AT_REMOVEDIR ? PEVENT_UNLINK_DIR : PEVENT_UNLINK_FILE);

    return 0;
}

SEC("tp/syscalls/sys_exit_unlinkat")
int tracepoint__syscalls__sys_exit_unlinkat(struct trace_event_raw_sys_exit *ctx) {

    int ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ret);

    return 0;
}

/* int mkdir(const char *pathname, umode_t mode) */
SEC("tp/syscalls/sys_enter_mkdir")
int tracepoint__syscalls__sys_enter_mkdir(struct trace_event_raw_sys_enter *ctx) {

    tracepoint__syscalls__sys_enter(PEVENT_MKDIR);

    return 0;
}

SEC("tp/syscalls/sys_exit_mkdir")
int tracepoint__syscalls__sys_exit_mkdir(struct trace_event_raw_sys_exit *ctx) {

    int ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ret);

    return 0;
}

/* int mkdirat(int dfd, const char *pathname, umode_t mode) */
SEC("tp/syscalls/sys_enter_mkdirat")
int tracepoint__syscalls__sys_enter_mkdirat(struct trace_event_raw_sys_enter *ctx) {

    tracepoint__syscalls__sys_enter(PEVENT_MKDIR);

    return 0;
}

SEC("tp/syscalls/sys_exit_mkdirat")
int tracepoint__syscalls__sys_exit_mkdirat(struct trace_event_raw_sys_exit *ctx) {

    int ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ret);

    return 0;
}

/* int rmdir(const char *pathname) */
SEC("tp/syscalls/sys_enter_rmdir")
int tracepoint__syscalls__sys_enter_rmdir(struct trace_event_raw_sys_enter *ctx) {

    tracepoint__syscalls__sys_enter(PEVENT_UNLINK_DIR);

    return 0;
}

SEC("tp/syscalls/sys_exit_rmdir")
int tracepoint__syscalls__sys_exit_rmdir(struct trace_event_raw_sys_exit *ctx) {

    int ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ret);

    return 0;
}

/* int rename(const char *oldname, const char *newname) */
SEC("tp/syscalls/sys_enter_rename")
int tracepoint__syscalls__sys_enter_rename(struct trace_event_raw_sys_enter *ctx) {

    tracepoint__syscalls__sys_enter(PEVENT_RENAME);

    return 0;
}

SEC("tp/syscalls/sys_exit_rename")
int tracepoint__syscalls__sys_exit_rename(struct trace_event_raw_sys_exit *ctx) {

    int ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ret);

    return 0;
}

/* int renameat(int olddfd, const char *oldname, int newdfd, const char *newname) */
SEC("tp/syscalls/sys_enter_renameat")
int tracepoint__syscalls__sys_enter_renameat(struct trace_event_raw_sys_enter *ctx) {

    tracepoint__syscalls__sys_enter(PEVENT_RENAME);

    return 0;
}

SEC("tp/syscalls/sys_exit_renameat")
int tracepoint__syscalls__sys_exit_renameat(struct trace_event_raw_sys_exit *ctx) {

    int ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ret);

    return 0;
}

/* int renameat2(int olddfd, const char *oldname, int newdfd, const char *newname, int flag) */
SEC("tp/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {

    // int flag = BPF_CORE_READ(ctx, args[4]);
    tracepoint__syscalls__sys_enter(PEVENT_RENAME);

    return 0;
}

SEC("tp/syscalls/sys_exit_renameat2")
int tracepoint__syscalls__sys_exit_renameat2(struct trace_event_raw_sys_exit *ctx) {

    int ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ret);

    return 0;
}

/**
 * @brief  dup2/3 入口处理函数，更新文件对应的 fd
 * @note   由于我们通过 fd 查找对应的文件信息，因此本函数将更新
 *         BPF_MAP 中 fd 到文件信息的映射，以便后续更新统计信息
 * @param  ctx: 进程上下文信息
 * @retval 永远为 0
 */
static int enter_dup(struct trace_event_raw_sys_enter *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_cur = bpf_map_lookup_elem(&maps_cur, &pid);
    if (!pstate_cur) return 0;

    int oldfd = BPF_CORE_READ(ctx, args[0]);
    int newfd = BPF_CORE_READ(ctx, args[1]);
    __u64 pair_fds = (__u64) oldfd << 32 | newfd;
    bpf_map_update_elem(&maps_temp_fd, &pid, &pair_fds, BPF_ANY);

    return 0;
}

/* dup2/3 出口处理函数 */
static int exit_dup(struct trace_event_raw_sys_exit *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_cur = bpf_map_lookup_elem(&maps_cur, &pid);
    __u64 *ppair_fds = bpf_map_lookup_elem(&maps_temp_fd, &pid);
    long ret = BPF_CORE_READ(ctx, ret);

    bpf_map_delete_elem(&maps_temp_fd, &pid);
    if (!ppair_fds || !pstate_cur || ret < 0) return 0;

    __u64 file_key = ((__u64) pid << 32) | (*ppair_fds >> 32);
    struct p_finfo_t *pfinfo = bpf_map_lookup_elem(&maps_files, &file_key);
    if (!pfinfo) return 0;

    bpf_map_delete_elem(&maps_files, &file_key);
    file_key = ((__u64) pid << 32) | (*ppair_fds & 0xffffffff);
    pfinfo->op_cnt++;
    long err = bpf_map_update_elem(&maps_files, &file_key, pfinfo, BPF_ANY);

    return 0;
}

/* int dup2(int oldfd, int newfd) */
SEC("tp/syscalls/sys_enter_dup2")
int tracepoint__syscalls__sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    return enter_dup(ctx);
}

SEC("tp/syscalls/sys_exit_dup2")
int tracepoint__syscalls__sys_exit_dup2(struct trace_event_raw_sys_exit *ctx) {
    return exit_dup(ctx);
}

/* int dup3(int oldfd, int newfd, int flags) */
SEC("tp/syscalls/sys_enter_dup3")
int tracepoint__syscalls__sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    return enter_dup(ctx);
}

SEC("tp/syscalls/sys_exit_dup3")
int tracepoint__syscalls__sys_exit_dup3(struct trace_event_raw_sys_exit *ctx) {
    return exit_dup(ctx);
}

/* int connect(int fd, struct sockaddr *uservaddr, int addrlen) */
SEC("tp/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_cur = bpf_map_lookup_elem(&maps_cur, &pid);
    if (!pstate_cur) return 0;

    __u64 state_code_cur = STT_KEY(pstate_cur->state_code, PEVENT_CONNECT);
    __u32 *pstate_code_next = bpf_map_lookup_elem(&maps_stt, &state_code_cur);
    if (!pstate_code_next) return 0;

    int fd = BPF_CORE_READ(ctx, args[0]);
    struct p_finfo_t finfo_sock;

    struct p_state_t state_tmp;
    FILL_STATE(state_tmp, pstate_cur->ppid, *pstate_code_next);
    long err = bpf_map_update_elem(&maps_nex, &pid, &state_tmp, BPF_ANY);
    if (err < 0) return 0;

    __builtin_memset(&finfo_sock, 0, sizeof(finfo_sock));
    finfo_sock.type = fd;	// 使用 type 字段暂存 fd
    finfo_sock.operation = OP_TRANSMIT;
    finfo_sock.open_time = bpf_ktime_get_ns();

    __u64 file_key = (__u64) pid << 32 | 0xffffffff;
    bpf_map_update_elem(&maps_files, &file_key, &finfo_sock, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {

    long ret = BPF_CORE_READ(ctx, ret);
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    __u64 file_key = ((__u64) pid << 32) | 0xffffffff;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);
    struct p_finfo_t *pfinfo_sock = bpf_map_lookup_elem(&maps_files, &file_key);

    bpf_map_delete_elem(&maps_files, &file_key);
    bpf_map_delete_elem(&maps_nex, &pid);
    if (!pfinfo_sock || !pstate_next || ret < 0) return 0;

    int fd = pfinfo_sock->type;
    file_key = ((__u64) pid << 32) | fd;
    pfinfo_sock->type = S_IFSOCK;
    pfinfo_sock->op_cnt++;

    long err = bpf_map_update_elem(&maps_files, &file_key, pfinfo_sock, BPF_ANY);
    if (err < 0) return 0;

    bpf_map_update_elem(&maps_cur, &pid, pstate_next, BPF_ANY);

    return 0;
}

/* long accept(int fd, struct sockaddr *upeer_sockaddr, int upeer_addrlen) */
SEC("tp/syscalls/sys_enter_accept")
int tracepoint__syscalls__sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    
    tracepoint__syscalls__sys_enter(PEVENT_RENAME);
    return 0;
}

SEC("tp/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    
    long ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ret);
    return 0;
}

/* long exit_group(int error_code) */
SEC("tp/syscalls/sys_enter_exit_group")
int tracepoint__syscalls__sys_enter_exit_group(struct trace_event_raw_sys_enter *ctx) {
    
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    clear_rest_files(pid);

    return 0;
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, const struct path *path, struct file *file) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 file_key = (u64) pid << 32 | 0xffffffff;
    struct p_finfo_t *pfinfo_regular = bpf_map_lookup_elem(&maps_files, &file_key);

    if (!pfinfo_regular) return 0;

    pfinfo_regular->fp.regular.i_ino = BPF_CORE_READ(path, dentry, d_inode, i_ino);
    BPF_CORE_READ_STR_INTO(&(pfinfo_regular->fp.regular.name), path, dentry, d_iname);
    pfinfo_regular->type = get_file_type_by_path(path);

    return 0;
}

#ifdef __KERNEL_VERSION
SEC("kprobe/vfs_unlink")
#if __KERNEL_VERSION<600
int BPF_KPROBE(vfs_unlink, struct inode *dir,
               struct dentry *dentry, struct inode **delegated_inode) {
#elif __KERNEL_VERSION<603
int BPF_KPROBE(vfs_unlink, struct user_namespace *mnt_userns, struct inode *dir,
               struct dentry *dentry, struct inode **delegated_inode) {
#else
int BPF_KPROBE(vfs_unlink, struct mnt_idmap *idmap, struct inode *dir,
               struct dentry *dentry, struct inode **delegated_inode) {
#endif

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);
    struct p_finfo_t finfo;

    if (!pstate_next) return 0;

    __builtin_memset(&finfo, 0, sizeof(finfo));
    __u32 i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    bpf_core_read(&(finfo.fp.regular.i_ino), sizeof(__u32), &i_ino);
    BPF_CORE_READ_STR_INTO(&(finfo.fp.regular.name), dentry, d_iname);
    finfo.operation = OP_REMOVE;
    finfo.type = get_file_type_by_dentry(dentry);

    bpf_map_update_elem(&maps_temp_file, &pid, &finfo, BPF_ANY);

    return 0;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(vfs_unlink_exit, long ret) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);
    struct p_finfo_t *pfinfo = (struct p_finfo_t *) bpf_map_lookup_elem(&maps_temp_file, &pid);

    bpf_map_delete_elem(&maps_temp_file, &pid);
    if (!pstate_next || !pfinfo || ret < 0) return 0;

#if __KERNEL_VERSION<508
    struct p_log_t log, *plog = &log;
    __builtin_memset(plog, 0, sizeof(log));
#else
    struct p_log_t *plog = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
    if (!plog) return 0;
#endif

    fill_log(*plog, pstate_next->ppid, pid, pstate_next->state_code, 0);
    bpf_core_read(&(plog->info), sizeof(plog->info), pfinfo);

#if __KERNEL_VERSION<508
    bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, plog, sizeof(*plog));
#else
    bpf_ringbuf_submit(plog, 0);
#endif

    return 0;
}
#endif	// SEC("kprobe/vfs_unlink")

#ifdef __KERNEL_VERSION
SEC("kprobe/vfs_rename")
#if __KERNEL_VERSION<512
int BPF_KPROBE(vfs_rename, struct inode *old_dir, struct dentry *old_dentry,
                  struct inode *new_dir, struct dentry *new_dentry,
                  struct inode **delegated_inode, unsigned int flags) {
#else
int BPF_KPROBE(vfs_rename, struct renamedata *rd) {
    struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
    struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);
#endif

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);

    if (!pstate_next) return 0;

    struct p_finfo_t finfo;
    __builtin_memset(&finfo, 0, sizeof(finfo));
    finfo.fp.regular.i_ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
    BPF_CORE_READ_STR_INTO(&(finfo.fp.regular.name), old_dentry, d_iname);
    finfo.operation = OP_RENAMED;
    finfo.type = get_file_type_by_dentry(old_dentry);

    bpf_map_update_elem(&maps_temp_dentry, &pid, &new_dentry, BPF_ANY); // 目标文件
    bpf_map_update_elem(&maps_temp_file, &pid, &finfo, BPF_ANY);        // 源文件

    return 0;
}

SEC("kretprobe/vfs_rename")
int BPF_KRETPROBE(vfs_rename_exit, long ret) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);

    struct p_finfo_t *pfinfo = bpf_map_lookup_elem(&maps_temp_file, &pid);
    struct dentry **pnew_dentry = bpf_map_lookup_elem(&maps_temp_dentry, &pid);

    bpf_map_delete_elem(&maps_temp_file, &pid);
    bpf_map_delete_elem(&maps_temp_dentry, &pid);
    if (!pstate_next || !pfinfo || !pnew_dentry || ret < 0) return 0;

    struct dentry *new_dentry = *pnew_dentry;

    /* 输出源路径信息 */
#if __KERNEL_VERSION<508
    struct p_log_t log, *plog = &log;
    __builtin_memset(plog, 0, sizeof(log));
#else
    struct p_log_t *plog = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
    if (!plog) return 0;
#endif

    fill_log(*plog, pstate_next->ppid, pid, pstate_next->state_code, 0);
    bpf_core_read(&(plog->info), sizeof(plog->info), pfinfo);

#if __KERNEL_VERSION<508
    bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, plog, sizeof(*plog));
#else
    bpf_ringbuf_submit(plog, 0);
#endif

    /* 输出被覆盖路径信息 */
#if __KERNEL_VERSION<508
    // __builtin_memset(plog, 0, sizeof(log));
#else
    struct p_log_t *plog = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
    if (!plog) return 0;
#endif

    fill_log(*plog, pstate_next->ppid, pid, pstate_next->state_code, 0);
    plog->info.fp.regular.i_ino = BPF_CORE_READ(new_dentry, d_inode, i_ino);

    if (plog->info.fp.regular.i_ino) {
        /* 说明是移动覆盖的形式，输出被覆盖的文件信息 */
        BPF_CORE_READ_STR_INTO(&(plog->info.fp.regular.name), new_dentry, d_iname);
        plog->info.operation = OP_COVER;
        plog->info.type = get_file_type_by_dentry(new_dentry);
#if __KERNEL_VERSION<508
        bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, plog, sizeof(*plog));
#else
        bpf_ringbuf_submit(plog, 0);
#endif
    } else {
#if __KERNEL_VERSION>=508
        bpf_ringbuf_discard(plog, 0);
#endif
    }


    /* 输出目的路径信息 */
    BPF_CORE_READ_STR_INTO(&(pfinfo->fp.regular.name), new_dentry, d_iname);
    pfinfo->operation = OP_RENAMETO;
#if __KERNEL_VERSION<508
    // __builtin_memset(plog, 0, sizeof(log));
#else
    log = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
    if (!log) return 0;
#endif
    fill_log(*plog, pstate_next->ppid, pid, pstate_next->state_code, 0);
    bpf_core_read(&(plog->info), sizeof(plog->info), pfinfo);
#if __KERNEL_VERSION<508
    bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, plog, sizeof(*plog));
#else
    bpf_ringbuf_submit(plog, 0);
#endif

    return 0;
}
#endif	// SEC("kprobe/vfs_rename")

#ifdef __KERNEL_VERSION
SEC("kprobe/vfs_mkdir")
#if __KERNEL_VERSION<600
int BPF_KPROBE(vfs_mkdir, struct inode *dir,
               struct dentry *dentry, umode_t mode) {
#elif __KERNEL_VERSION<603
int BPF_KPROBE(vfs_mkdir, struct user_namespace *mnt_userns,
               struct inode *dir, struct dentry *dentry, umode_t mode) {
#else
int BPF_KPROBE(vfs_mkdir, struct mnt_idmap *idmap,
                 struct inode *dir, struct dentry *dentry, umode_t mode) {
#endif

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);

    if (!pstate_next) return 0;
    bpf_map_update_elem(&maps_temp_dentry, &pid, &dentry, BPF_ANY);

    return 0;
}

SEC("kretprobe/vfs_mkdir")
int BPF_KRETPROBE(vfs_mkdir_exit, long ret) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);
    struct dentry **pdentry = bpf_map_lookup_elem(&maps_temp_dentry, &pid), *dentry;

    bpf_map_delete_elem(&maps_temp_dentry, &pid);
    if (!pstate_next || !pdentry || ret < 0) return 0;

    dentry = *pdentry;
#if __KERNEL_VERSION<508
    struct p_log_t log, *plog = &log;
    __builtin_memset(plog, 0, sizeof(log));
#else
    struct p_log_t *plog = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
    if (!plog) return 0;
#endif

    fill_log(*plog, pstate_next->ppid, pid, pstate_next->state_code, 0);
    plog->info.fp.regular.i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    BPF_CORE_READ_STR_INTO(&(plog->info.fp.regular.name), dentry, d_iname);
    plog->info.operation = OP_CREATE;
    plog->info.type = get_file_type_by_dentry(dentry);

#if __KERNEL_VERSION<508
    bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, plog, sizeof(*plog));
#else
    bpf_ringbuf_submit(plog, 0);
#endif

    return 0;
}
#endif	// SEC("kprobe/vfs_mkdir")

#ifdef __KERNEL_VERSION
SEC("kprobe/vfs_rmdir")
#if __KERNEL_VERSION<600
int BPF_KPROBE(vfs_rmdir, struct inode *dir, struct dentry *dentry) {
#elif __KERNEL_VERSION<603
int BPF_KPROBE(vfs_rmdir, struct user_namespace *mnt_userns,
               struct inode *dir, struct dentry *dentry) {
#else
int BPF_KPROBE(vfs_rmdir, struct mnt_idmap *idmap,
               struct inode *dir, struct dentry *dentry) {
#endif

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);
    struct p_finfo_t finfo;

    if (!pstate_next) return 0;

    __builtin_memset(&finfo, 0, sizeof(finfo));
    __u32 i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    bpf_core_read(&(finfo.fp.regular.i_ino), sizeof(__u32), &i_ino);
    BPF_CORE_READ_STR_INTO(&(finfo.fp.regular.name), dentry, d_iname);
    finfo.operation = OP_REMOVE;
    finfo.type = get_file_type_by_dentry(dentry);

    bpf_map_update_elem(&maps_temp_file, &pid, &finfo, BPF_ANY);

    return 0;
}

SEC("kretprobe/vfs_rmdir")
int BPF_KRETPROBE(vfs_rmdir_exit, long ret) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);
    struct p_finfo_t *pfinfo = (struct p_finfo_t *) bpf_map_lookup_elem(&maps_temp_file, &pid);

    bpf_map_delete_elem(&maps_temp_file, &pid);
    if (!pstate_next || !pfinfo || ret < 0) return 0;

#if __KERNEL_VERSION<508
    struct p_log_t log, *plog = &log;
    __builtin_memset(plog, 0, sizeof(log));
#else
    struct p_log_t *plog = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
    if (!plog) return 0;
#endif

    fill_log(*plog, pstate_next->ppid, pid, pstate_next->state_code, 0);
    bpf_core_read(&(plog->info), sizeof(plog->info), pfinfo);

#if __KERNEL_VERSION<508
    bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, plog, sizeof(*plog));
#else
    bpf_ringbuf_submit(plog, 0);
#endif

    return 0;
}
#endif

/* int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);

    if (pstate_next) {
        bpf_map_update_elem(&maps_temp_sock, &pid, &sk, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, long ret) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    __u64 file_key = ((__u64) pid << 32) | 0xffffffff;
    struct sock **psock = bpf_map_lookup_elem(&maps_temp_sock, &pid);
    struct p_finfo_t *pfinfo_sock = bpf_map_lookup_elem(&maps_files, &file_key);
    
    bpf_map_delete_elem(&maps_temp_sock, &pid);
    if (!psock || !pfinfo_sock) return 0;
    struct sock *sk = *psock;

    pfinfo_sock->fp.socket.from_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    pfinfo_sock->fp.socket.to_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    pfinfo_sock->fp.socket.from_ip = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
    pfinfo_sock->fp.socket.to_ip = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));

    return 0;
}

/**
 * __be32	skc_daddr;		// 外部 IPv4 地址，大端
 * __be32	skc_rcv_saddr;	// 本地 IPv4 地址，大端
 * __be16	skc_dport;		// 外部端口，大端
 * __u16	skc_num;		// 本地端口，小端
 */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_exit, struct sock *newsk) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    long err = 0;

    struct p_state_t *pstate_next = bpf_map_lookup_elem(&maps_nex, &pid);
    if (!pstate_next) return 0;

    u16 lport = 0, dport;
    lport = BPF_CORE_READ(newsk, __sk_common.skc_num);
    dport = BPF_CORE_READ(newsk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

#if __KERNEL_VERSION<508
    struct p_log_t log, *plog = &log;
    __builtin_memset(plog, 0, sizeof(log));
#else
    struct p_log_t *plog = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
    if (!plog) return 0;
#endif
    fill_log(*plog, 1, pid, 0, 1000000);

    plog->info.fp.socket.to_ip = bpf_ntohl(BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr));
    plog->info.fp.socket.from_ip = bpf_ntohl(BPF_CORE_READ(newsk, __sk_common.skc_daddr));
    plog->info.fp.socket.to_port = lport;
    plog->info.fp.socket.from_port = dport;
    plog->info.operation = OP_RECEIVE;
    plog->info.type = S_IFSOCK;

#if __KERNEL_VERSION<508
    bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, plog, sizeof(*plog));
#else
    bpf_ringbuf_submit(plog, 0);
#endif

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
