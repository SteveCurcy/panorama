/**
 * @file 	genor.bpf.c
 * @author 	Xu.Cao
 * @version v1.5.3
 * @date 	2023-11-01
 * @details 从 genor.c 中获取关心的命令，监控其文件操作相关的系统调用序列并输出对应事件
 * @see 	genor.c
 * @history
 *  <author>    <time>    <version>    <desc>
 *  Xu.Cao      23/11/01    1.5.3    Format and Standardize this source
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>
#include "panorama.h"
#include "genor.h"

/* 是否希望进行捕获该进程，保存其名称哈希值 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} maps_cap_hash SEC(".maps");

/* 保存打开的文件 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} maps_file_opend SEC(".maps");

/* 保存系统调用中涉及的文件 fd */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, pid_t);
    __type(value, __u64);
} maps_fds SEC(".maps");

/* 保存状态转移事件 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, pid_t);
    __type(value, __u32);
} maps_pevents SEC(".maps");

/* 保存上一个系统调用编号 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, pid_t);
    __type(value, __u16);
} maps_last_sysid SEC(".maps");

#if LINUX_VERSION < KERNEL_VERSION(5, 8, 0)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} rb SEC(".maps");
#else
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 64);     // 指明 max_entries，并且要大于 4096B
} rb SEC(".maps");
#endif


/**
 * @brief  查看当前进程是否需要被捕获
 * @note   由于会检测到很多无关的进程，因此首先判断是否需要被捕获
 * @retval bool 是否需要被捕获
 */
__always_inline static bool need_capture() {

    char comm[32];
    bpf_get_current_comm(&comm, 32);
    __u64 hash_value = str_hash(comm);

    __u32 *dummy = bpf_map_lookup_elem(&maps_cap_hash, &hash_value);
    return dummy;
}

/**
 * @brief  函数入口的统一的状态存储
 * @note   获取当前系统调用对应的事件编号，并暂存到 BPF map 中
 * @param  pevent: 系统调用对应的事件编号
 * @retval pid_t 当前进程号，为 0 则说明进程被忽略
 */
static pid_t tracepoint__syscalls__sys_enter(__u32 pevent) {
    
    if (!need_capture()) return 0;

    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_update_elem(&maps_pevents, &pid, &pevent, BPF_ANY);
    
    return pid;
}

/**
 * @brief  函数出口的统一的状态输出
 * @note   获取暂存的状态转移事件，将其输出
 * @param  ctx: 进程执行上下文，在低版本内核中，输出事件需要上下文
 * @param  ret: 函数执行返回值
 * @param  syscall_id: 系统调用编号
 * @retval pid_t 进程号，如果为 0 则说明不能构成状态转移
 */
static pid_t tracepoint__syscalls__sys_exit(struct trace_event_raw_sys_exit *ctx, long ret, __u16 syscall_id) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *ppevent = bpf_map_lookup_elem(&maps_pevents, &pid);
    __u16 *psysid = bpf_map_lookup_elem(&maps_last_sysid, &pid), sysid = 0xffff;

    if (!psysid) psysid = &sysid;

    bpf_map_delete_elem(&maps_pevents, &pid);
    if (!ppevent || !psysid || ret < 0) return 0;

    if (*psysid == syscall_id && syscall_id == SYSCALL_WRITE) return 0;

    *psysid = syscall_id;
    bpf_map_update_elem(&maps_last_sysid, &pid, psysid, BPF_ANY);

#if LINUX_VERSION < KERNEL_VERSION(5, 8, 0)
    struct sf_t sf_ptr;
    __builtin_memset(&sf_ptr, 0, sizeof(sf_ptr));

    bpf_get_current_comm(&(sf_ptr.comm), 32);
    sf_ptr.event = *ppevent;
    sf_ptr.pid = pid;

    bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, &sf_ptr, sizeof(sf_ptr));
#else
    struct sf_t *sf_ptr = bpf_ringbuf_reserve(&rb, sizeof(struct sf_t), 0);
    if (!sf_ptr) return 0;	// 申请内存空间失败

    bpf_get_current_comm(&(sf_ptr->comm), 32);
    sf_ptr->event = *ppevent;
    sf_ptr->pid = pid;

    bpf_ringbuf_output(sf_ptr, 0);
#endif
    return pid;
}

SEC("tp/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 pevent = 0;

    int flags = BPF_CORE_READ(ctx, args[2]);

    /* 如果一个文件的打开方式为 O_CLOEXEC 则大概率是一个库文件，将其过滤 */
    if (flags == O_CLOEXEC) return 0;

    pevent = get_open_evnt(flags);

    tracepoint__syscalls__sys_enter(pevent);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {

    long ret = BPF_CORE_READ(ctx, ret), err = 0;

    pid_t pid = tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_OPENAT);
    if (!pid) return 0;

    __u8 zero = 0;
    __u64 dummy_key = ((__u64) pid << 32) | ret;
    err = bpf_map_update_elem(&maps_file_opend, &dummy_key, &zero, BPF_ANY);

    return 0;
}

/* ssize_t write(int fd, const char *buf, size_t count) */
SEC("tp/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int fd = BPF_CORE_READ(ctx, args[0]);

    __u64 dummy_key = ((__u64) pid << 32) | fd;
    __u8 *dummy = bpf_map_lookup_elem(&maps_file_opend, &dummy_key);
    if (!dummy) return 0;

    tracepoint__syscalls__sys_enter(PEVENT_WRITE);

    return 0;
}

SEC("tp/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct trace_event_raw_sys_exit *ctx) {

    long ret = BPF_CORE_READ(ctx, ret), err = 0;

    pid_t pid = tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_WRITE);
    
    return 0;
}

/* int close(int fd) */
SEC("tp/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int fd = BPF_CORE_READ(ctx, args[0]);
    
    __u64 dummy_key = ((__u64) pid << 32) | fd;
    __u8 *dummy = bpf_map_lookup_elem(&maps_file_opend, &dummy_key);
    if (!dummy) return 0;

    bpf_map_update_elem(&maps_fds, &pid, &fd, BPF_ANY);
    tracepoint__syscalls__sys_enter(PEVENT_CLOSE);

    return 0;
}

SEC("tp/syscalls/sys_exit_close")
int tracepoint__syscalls__sys_exit_close(struct trace_event_raw_sys_exit *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int *fd_ptr = bpf_map_lookup_elem(&maps_fds, &pid);
    long ret = BPF_CORE_READ(ctx, ret), err = 0;

    if (ret >= 0 && fd_ptr) {
        __u64 dummy_key = ((__u64) pid << 32) | *fd_ptr;
        bpf_map_delete_elem(&maps_file_opend, &dummy_key);
    }

    bpf_map_delete_elem(&maps_fds, &pid);
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_CLOSE);

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
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_UNLINK);

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
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_UNLINKAT);

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
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_MKDIR);

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
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_MKDIRAT);

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
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_RMDIR);

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
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_RENAME);

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
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_RENAMEAT);

    return 0;
}

/* int renameat2(int olddfd, const char *oldname, int newdfd, const char *newname, int flag) */
SEC("tp/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {

    int flag = BPF_CORE_READ(ctx, args[4]);
    tracepoint__syscalls__sys_enter(PEVENT_RENAME);

    return 0;
}
SEC("tp/syscalls/sys_exit_renameat2")
int tracepoint__syscalls__sys_exit_renameat2(struct trace_event_raw_sys_exit *ctx) {

    int ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_RENAMEAT2);

    return 0;
}

static void enter_dup(struct trace_event_raw_sys_enter *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    int oldfd = BPF_CORE_READ(ctx, args[0]);
    int newfd = BPF_CORE_READ(ctx, args[1]);
    __u64 fds = (__u64) oldfd << 32 | newfd;
    bpf_map_update_elem(&maps_fds, &pid, &fds, BPF_ANY);
}

static void exit_dup(struct trace_event_raw_sys_exit *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *pfds = bpf_map_lookup_elem(&maps_fds, &pid);
    long ret = BPF_CORE_READ(ctx, ret);

    bpf_map_delete_elem(&maps_fds, &pid);
    if (!pfds || ret < 0) return;

    __u64 dummy_key = ((__u64) pid << 32) | (*pfds >> 32);
    __u8 *dummy = bpf_map_lookup_elem(&maps_file_opend, &dummy_key);
    if (!dummy) return;

    bpf_map_delete_elem(&maps_file_opend, &dummy_key);
    dummy_key = ((__u64) pid << 32) | (*pfds & 0xffffffff);
    long err = bpf_map_update_elem(&maps_file_opend, &dummy_key, dummy, BPF_ANY);
}

/* int dup2(int oldfd, int newfd) */
SEC("tp/syscalls/sys_enter_dup2")
int tracepoint__syscalls__sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {

    enter_dup(ctx);

    return 0;
}

SEC("tp/syscalls/sys_exit_dup2")
int tracepoint__syscalls__sys_exit_dup2(struct trace_event_raw_sys_exit *ctx) {

    exit_dup(ctx);

    return 0;
}

/* int dup3(int oldfd, int newfd, int flags) */
SEC("tp/syscalls/sys_enter_dup3")
int tracepoint__syscalls__sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {

    enter_dup(ctx);

    return 0;
}

SEC("tp/syscalls/sys_exit_dup3")
int tracepoint__syscalls__sys_exit_dup3(struct trace_event_raw_sys_exit *ctx) {

    exit_dup(ctx);

    return 0;
}

/* int connect(int fd, struct sockaddr *uservaddr, int addrlen) */
SEC("tp/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {

    tracepoint__syscalls__sys_enter(PEVENT_CONNECT);

    return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {

    int ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_CONNECT);

    return 0;
}

/* long accept(int fd, struct sockaddr *upeer_sockaddr, int upeer_addrlen) */
SEC("tp/syscalls/sys_enter_accept")
int tracepoint__syscalls__sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {

    tracepoint__syscalls__sys_enter(PEVENT_ACCEPT);

    return 0;
}

SEC("tp/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {

    int ret = BPF_CORE_READ(ctx, ret);
    tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_ACCEPT);

    return 0;
}

/* long exit_group(int error_code) */
SEC("tp/syscalls/sys_enter_exit_group")
int tracepoint__syscalls__sys_enter_exit_group(struct trace_event_raw_sys_enter *ctx) {
    
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&maps_fds, &pid);

    char comm[32];
    bpf_get_current_comm(&comm, 32);
    __u64 comm_hash = str_hash(comm);
    
    __u32 *cnt = bpf_map_lookup_elem(&maps_cap_hash, &comm_hash);
    if (!cnt) return 0;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
