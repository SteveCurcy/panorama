/* 
 * License-Identifier: BSD-3
 * Copyright (c) 2023 Steve.Curcy
 * 
 * 我们需要明确工作：
 * 对于 openat 来说，它的调用顺序对于识别一个行为来说至关重要，
 * 因此如果它不能引起状态转移，则应该不保存信息。
 * 对于 write/close 来说，它可以影响状态，但是有时也可以出于
 * 对状态机的缩减从而进行省略，因此只要对应的文件信息被记录过，
 * 则应该先保证文件信息的更新，然后再判断是否能够进行状态转移。
 * 对于 read 来说，它何时调用并不会影响一个行为，因此，它只
 * 负责文件信息的更新，而不参与状态转移。
 * 对于其他的系统调用，比如 unlink/rename 等都指示了一些程序
 * 的行为，因此如果不符合状态机，则不保存文件信息。
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "panorama.h"
#include "config.h"

/* 状态转移表，BPF_HASH;
 * state_transition_table 简写 stt,
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
/* 保存当前的和可能的下一个状态信息 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, pid_t);
	__type(value, struct p_state_t);
} maps_cur SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, pid_t);
	__type(value, struct p_state_t);
} maps_nex SEC(".maps");

/* 存放 accept 获取的连接块的信息，最多支持同时 64 个连接请求;
 * 放在 QUEUE 结构中，请求的线程依次从中获取 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 64);
	__type(value, struct p_socket_t);
} maps_accept_block SEC(".maps");
/* 保存临时 sock 结构体 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, pid_t);
	__type(value, struct sock*);
} maps_temp_sock SEC(".maps");
/* 存储临时的 fd 信息 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, __u64);
} maps_temp_fd SEC(".maps");
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
/* 低版本中缺少 struct renamedata 数据结构，
 * 因此为了获取源和目的 dentry 开启辅助临时变量 */
#ifdef __KERNEL_VERSION
#if __KERNEL_VERSION<512
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, void*);
} maps_temp_ddentry SEC(".maps");
#endif
#endif
/* 用于保存进程打开的文件的相关信息，包括文件名、inode、读写数量等
 * 使用 pid << 32 | fd 来作为 key 唯一标识一个文件 */
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

/* 填充一个 log 类型，然后发送到用户空间 */
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
 * @brief 用于清理进程相关的状态，确保不会有多余的文件信息占用 Hash 表
 * @param  pid 想要清理的进程号
 * @author Xu.Cao
 */
static void clear_state(pid_t pid) {
    u64 key = (u64) pid << 32;
	int err = 0;
#pragma unroll(1024)
    for (int i = 0; i < 1024; i++) {
        key = (key & 0xffffffff00000000) | i;
        err = bpf_map_delete_elem(&maps_files, &key);
    }
    bpf_map_delete_elem(&maps_cur, &pid);
}

__always_inline static bool if_filt() {
	char comm[32];
	bpf_get_current_comm(&comm, 32);
	__u64 hash_value = str_hash(comm);

	__u8 *dummy = bpf_map_lookup_elem(&maps_filter_hash, &hash_value);
	return (dummy != 0);
}

/**
 * 用于处理状态机的转移事件，不做其他事件的处理；
 * 关于相关函数的细节处理放在对应的系统调用监控程序中，
 * 避免当前函数调用过于冗长，并且可能判断本不属于该调用的事件，造成性能损失
 * 
 * @param event 触发状态转移的事件
 * @return 返回 pid，如果执行出错则返回 0
 */
static int tracepoint__syscalls__sys_enter(__u32 event) {
	
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct p_state_t *cur_state_ptr = bpf_map_lookup_elem(&maps_cur, &pid), s;
	struct task_struct *task = (struct task_struct *) bpf_get_current_task();
	pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);
	NEW_STATE(s, ppid, 0);

	if (!cur_state_ptr) cur_state_ptr = &s;
	if (!cur_state_ptr) return 0;
	if (if_filt()) return 0;

	/* 查看是否会引起状态转移，如果不能则直接返回 */
	__u64 trigger_key = STT_KEY(cur_state_ptr->state_code, event);
	__u32 *next_state_code = bpf_map_lookup_elem(&maps_stt, &trigger_key);
	if (!next_state_code) return 0;

	/* 存储下一个可能的状态 */
	s.state_code = *next_state_code;
	bpf_map_update_elem(&maps_nex, &pid, &s, BPF_ANY);
	
	return pid;
}
static int tracepoint__syscalls__sys_exit(long ret) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);

	bpf_map_delete_elem(&maps_nex, &pid);
	if (!next_state_ptr || ret < 0) return 0;

	/* 如果当前系统调用成功，则更新对应的状态信息 */
	bpf_map_update_elem(&maps_cur, &pid, next_state_ptr, BPF_ANY);

	return pid;
}

/**
 * 为了尽量保证程序的性能，对于系统调用监控，我们选用 tracepoint 进行实现
 * int openat(int dfd, const char *filename, int flags, umode_t mode);
 * 
 * 进入后，首先判断当前的状态码能否引起状态转移，（第一次调用时，状态码为 0），
 * 如果可以，则将状态保存到 maps_nex 中，其中存储可能的下一个状态（因为可能有调用失败的情况）
 */
SEC("tp/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {

	struct task_struct *task = (struct task_struct *) bpf_get_current_task();
	__u32 pid = BPF_CORE_READ(task, tgid), ppid = BPF_CORE_READ(task, real_parent, tgid);
	struct p_state_t *cur_state_ptr = bpf_map_lookup_elem(&maps_cur, &pid), s;
	struct p_finfo_t new_file_info;
	__u32 stt_flags = 0;
	/* 从上下文中获取系统调用参数 */
	int flags = BPF_CORE_READ(ctx, args[2]);
	NEW_STATE(s, ppid, 0);

	/* 如果一个文件的打开方式为 O_CLOEXEC 则大概率是一个库文件，将其过滤 */
	if (flags == O_CLOEXEC) return 0;
	if (if_filt()) return 0;

	/* 根据打开方式获取状态转移标志字段 */
	__builtin_memset(&new_file_info, 0, sizeof(new_file_info));
	stt_flags = get_open_evnt(flags);
	switch (stt_flags)
	{
	case PEVENT_OPEN_READ: new_file_info.operation = OP_READ; break;
	case PEVENT_OPEN_WRITE: new_file_info.operation = OP_WRITE; break;
	case PEVENT_OPEN_COVER: new_file_info.operation = OP_COVER; new_file_info.op_cnt = 1; break;
	case PEVENT_OPEN_RDWR: new_file_info.operation = OP_RDWR; break;
	case PEVENT_OPEN_CREAT: new_file_info.operation = OP_CREATE, new_file_info.op_cnt = 1; break;
	case PEVENT_OPEN_DIR: new_file_info.operation = OP_OPEN; break;
	default:
		break;
	}
	new_file_info.open_time = bpf_ktime_get_ns();	// bpf_ktime_get_boot_ns 不可用，改用 bpf_ktime_get_ns

	if (!cur_state_ptr) cur_state_ptr = &s;
	if (!cur_state_ptr) return 0;

	/* 获取下一个状态的状态码，无法获取说明不能进行状态转移，直接返回 */
	__u64 trigger_key = STT_KEY(cur_state_ptr->state_code, stt_flags);
	__u32 *next_state_code = bpf_map_lookup_elem(&maps_stt, &trigger_key);
	if (!next_state_code) return 0;

	/* 暂存文件信息结构，通过内核函数将其补充完整 */
	__u64 file_key = (__u64) pid << 32 | 0xffffffff;
	bpf_map_update_elem(&maps_files, &file_key, &new_file_info, BPF_ANY);

	/* 更新下一个可能的状态信息 */
	s.state_code = *next_state_code;
	bpf_map_update_elem(&maps_nex, &pid, &s, BPF_ANY);

	return 0;
}
SEC("tp/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u64 finfo_key = ((__u64) pid << 32) | 0xffffffff;
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);
	struct p_finfo_t *new_finfo_ptr = bpf_map_lookup_elem(&maps_files, &finfo_key);
	long ret = BPF_CORE_READ(ctx, ret), err = 0;

	/* 必须要删除的临时变量放在指针非空判断之前，
	 * 防止因逻辑错误或者忘记删除而导致的资源浪费 */
	bpf_map_delete_elem(&maps_files, &finfo_key);	// 删除临时的文件信息
	bpf_map_delete_elem(&maps_nex, &pid);			// 删除下一个可能的状态
	if (!next_state_ptr || !new_finfo_ptr || ret < 0) return 0;

	/* 更新文件信息 */
	finfo_key = ((__u64) pid << 32) | ret;
	err = bpf_map_update_elem(&maps_files, &finfo_key, new_finfo_ptr, BPF_ANY);

	/* 更新状态信息 */
	err = bpf_map_update_elem(&maps_cur, &pid, next_state_ptr, BPF_ANY);

	return 0;
}

/* ssize_t read(int fd, char *buf, size_t count) */
SEC("tp/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	struct p_state_t *cur_state_ptr = bpf_map_lookup_elem(&maps_cur, &pid);
	if (!cur_state_ptr) return 0;

	int fd = BPF_CORE_READ(ctx, args[0]);
	bpf_map_update_elem(&maps_temp_fd, &pid, &fd, BPF_ANY);

	return 0;
}
SEC("tp/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int *fd = (int *) bpf_map_lookup_elem(&maps_temp_fd, &pid);
	struct p_state_t *cur_state_ptr = bpf_map_lookup_elem(&maps_cur, &pid);
	ssize_t read_size = BPF_CORE_READ(ctx, ret);

	bpf_map_delete_elem(&maps_temp_fd, &pid);
	if (!fd || !cur_state_ptr) return 0;

	__u64 finfo_key = ((__u64) pid << 32) | *fd;
	struct p_finfo_t *finfo_ptr = bpf_map_lookup_elem(&maps_files, &finfo_key);
	if (!finfo_ptr)
		return 0;

	finfo_ptr->rx += read_size;
	finfo_ptr->op_cnt++;

	return 0;
}

/* ssize_t write(int fd, const char *buf, size_t count) */
SEC("tp/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int fd = BPF_CORE_READ(ctx, args[0]);
	/* 确保保存了相关的文件信息才能进行状态机的匹配；
	 * 如果没保存，说明在 openat 就没有匹配到 */
	__u64 finfo_key = ((__u64) pid << 32) | fd;
	struct p_finfo_t *finfo_ptr = bpf_map_lookup_elem(&maps_files, &finfo_key);
	if (!finfo_ptr) return 0;

	/* 不管是否会引起状态转移都保存，确保能更新文件信息 */
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

	__u64 finfo_key = ((__u64) pid << 32) | *fd;
	struct p_finfo_t *finfo_ptr = bpf_map_lookup_elem(&maps_files, &finfo_key);
	if (!finfo_ptr) return 0;

	finfo_ptr->tx += ret;
	finfo_ptr->op_cnt++;

	pid = tracepoint__syscalls__sys_exit(ret);
	
	return 0;
}

/* int close(int fd) */
SEC("tp/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int fd = BPF_CORE_READ(ctx, args[0]);
	
	/* 如果没保存该文件的信息则不进行状态机匹配 */
	__u64 finfo_key = ((__u64) pid << 32) | fd;
	struct p_finfo_t *finfo_ptr = bpf_map_lookup_elem(&maps_files, &finfo_key);
	if (!finfo_ptr) return 0;

	bpf_map_update_elem(&maps_temp_fd, &pid, &fd, BPF_ANY);

	tracepoint__syscalls__sys_enter(PEVENT_CLOSE);

	return 0;
}
SEC("tp/syscalls/sys_exit_close")
int tracepoint__syscalls__sys_exit_close(struct trace_event_raw_sys_exit *ctx) {

	long ret = BPF_CORE_READ(ctx, ret);
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int *fd = bpf_map_lookup_elem(&maps_temp_fd, &pid);

	bpf_map_delete_elem(&maps_temp_fd, &pid);
	if (!fd || ret < 0) return 0;

	__u64 finfo_key = (__u64) pid << 32 | *fd;
	/* 文件关闭，将对应的文件信息删除 */
	struct p_finfo_t *finfo_ptr = bpf_map_lookup_elem(&maps_files, &finfo_key);
	if (!finfo_ptr) return 0;

	/* 确定有对应文件再进行状态转移 */
	tracepoint__syscalls__sys_exit(ret);

	struct p_state_t *cur_state_ptr = bpf_map_lookup_elem(&maps_cur, &pid);
	if (!cur_state_ptr) return 0;

	bpf_map_delete_elem(&maps_files, &finfo_key);
	// if (!(finfo_ptr->op_cnt) && cur_state_ptr->state_code == STATE_CAT) {
	// 	/* 如果打开文件又关闭，但是没有操作过，并且状态码是 cat，直接返回初始状态 */
	// 	cur_state_ptr->state_code = 0;
	// }

	/* 如果文件没有被操作过，那么没有必要输出 */
	if (finfo_ptr->op_cnt) {
#ifdef __KERNEL_VERSION
#if __KERNEL_VERSION<508
		struct p_log_t log, *log_ptr = &log;
		__builtin_memset(log_ptr, 0, sizeof(log));
#else
		struct p_log_t *log_ptr = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
		if (!log) return 0;
#endif

		fill_log(*log_ptr, cur_state_ptr->ppid,
				pid, cur_state_ptr->state_code,
				bpf_ktime_get_ns() - finfo_ptr->open_time);
		bpf_core_read(&(log_ptr->info), sizeof(*finfo_ptr), finfo_ptr);
#if __KERNEL_VERSION<508
		bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, log_ptr, sizeof(*log_ptr));
#else
		bpf_ringbuf_submit(log_ptr, 0);
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

/* dup2/3 入口处理函数 */
static int enter_dup(struct trace_event_raw_sys_enter *ctx) {
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	struct p_state_t *cur_state_ptr = bpf_map_lookup_elem(&maps_cur, &pid);
	if (!cur_state_ptr) return 0;

	int oldfd = BPF_CORE_READ(ctx, args[0]);
	int newfd = BPF_CORE_READ(ctx, args[1]);
	__u64 tmpfds = (__u64) oldfd << 32 | newfd;
	bpf_map_update_elem(&maps_temp_fd, &pid, &tmpfds, BPF_ANY);

	return 0;
}

/* dup2/3 出口处理函数 */
static int exit_dup(struct trace_event_raw_sys_exit *ctx) {
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct p_state_t *cur_state_ptr = bpf_map_lookup_elem(&maps_cur, &pid);
	__u64 *tmpfds = bpf_map_lookup_elem(&maps_temp_fd, &pid);
	long ret = BPF_CORE_READ(ctx, ret);

	bpf_map_delete_elem(&maps_temp_fd, &pid);
	if (!tmpfds || !cur_state_ptr || ret < 0) return 0;

	// 取出原 fd 对应的文件信息
	__u64 finfo_key = ((__u64) pid << 32) | (*tmpfds >> 32);
	struct p_finfo_t *finfo_value = bpf_map_lookup_elem(&maps_files, &finfo_key);
	if (!finfo_value) return 0;

	// 将文件信息更新到新 fd 上
	bpf_map_delete_elem(&maps_files, &finfo_key);
	finfo_key = ((__u64) pid << 32) | (*tmpfds & 0xffffffff);
	finfo_value->op_cnt++;
	long err = bpf_map_update_elem(&maps_files, &finfo_key, finfo_value, BPF_ANY);

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
	struct p_state_t *cur_state_ptr = bpf_map_lookup_elem(&maps_cur, &pid);
	if (!cur_state_ptr) return 0;

	/* 首先查看能否引起状态转移 */
	__u64 cur_state = STT_KEY(cur_state_ptr->state_code, PEVENT_CONNECT);
	__u32 *next_state_code = bpf_map_lookup_elem(&maps_stt, &cur_state);
	if (!next_state_code) return 0;

	/* 创建一个临时的套接字文件信息，通过内核函数获取具体详细信息；
	 * 获取系统调用参数 fd 并临时保存 */
	int fd = BPF_CORE_READ(ctx, args[0]);
	struct p_finfo_t new_sock_info;

	struct p_state_t s;
	NEW_STATE(s, cur_state_ptr->ppid, *next_state_code);
	long err = bpf_map_update_elem(&maps_nex, &pid, &s, BPF_ANY);
	if (err < 0) return 0;

	__builtin_memset(&new_sock_info, 0, sizeof(new_sock_info));
	new_sock_info.type = fd;	// 使用 type 字段暂存 fd
	new_sock_info.operation = OP_TRANSMIT;
	new_sock_info.open_time = bpf_ktime_get_ns();

	__u64 finfo_key = (__u64) pid << 32 | 0xffffffff;
	bpf_map_update_elem(&maps_files, &finfo_key, &new_sock_info, BPF_ANY);

	return 0;
}
SEC("tp/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {

	/* 查看返回值是否为负值（调用失败）；
	 * 如果失败，则将对应的文件信息删除；否则更新状态信息 */
	long ret = BPF_CORE_READ(ctx, ret);
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u64 finfo_key = ((__u64) pid << 32) | 0xffffffff;
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);
	struct p_finfo_t *sock_info_ptr = bpf_map_lookup_elem(&maps_files, &finfo_key);

	bpf_map_delete_elem(&maps_files, &finfo_key);
	bpf_map_delete_elem(&maps_nex, &pid);
	if (!sock_info_ptr || !next_state_ptr || ret < 0) return 0;

	/* 将暂存的 fd 取出，然后将文件类型设置为 socket */
	int fd = sock_info_ptr->type;
	finfo_key = ((__u64) pid << 32) | fd;
	sock_info_ptr->type = S_IFSOCK;
	sock_info_ptr->op_cnt++;
	/* 更新文件信息到正确的 fd */
	long err = bpf_map_update_elem(&maps_files, &finfo_key, sock_info_ptr, BPF_ANY);
	if (err < 0) return 0;

	bpf_map_update_elem(&maps_cur, &pid, next_state_ptr, BPF_ANY);

	return 0;
}

/**
 * accept 系统调用仅用来控制 socket 连接信息的输出；
 * 对于 accept 捕获的 socket 连接无法进一步统计 socket
 * 传输统计信息，因为该调用获得的 socket fd 通常会交给
 * 子进程处理，导致无法统计传输信息。
 * long accept(int fd, struct sockaddr *upeer_sockaddr, int upeer_addrlen)
 */
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
	clear_state(pid);

	return 0;
}

/**
 * 由于内核开发者通常不会预留内核函数的 tracepoint，因此使用 kprobe 来监测内核函数；
 * 对于 vfs_open 和网络连接来说，它所打开的文件在后续操作中可能被读写，因此需要长期保存其文件信息；
 * 但是对于删除、重命名、创建和删除文件等操作，都只是一次性的操作，不会有后续的读写访问。
 * 
 * 因此，对于 vfs_open 和网络连接打开的文件信息需要保存，并返回给系统调用监测函数进行后续处理；
 * 而对于其他的内核函数，在保证其调用成功的前提下，可以自行决定输出，而不受系统调用约束。
 */
SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, const struct path *path, struct file *file) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	u64 key = (u64) pid << 32 | 0xffffffff;
	struct p_finfo_t *file_info = bpf_map_lookup_elem(&maps_files, &key);

	if (!file_info) return 0;

	file_info->fp.file.i_ino = BPF_CORE_READ(path, dentry, d_inode, i_ino);
	BPF_CORE_READ_STR_INTO(&(file_info->fp.file.name), path, dentry, d_iname);
	file_info->type = get_file_type_by_path(path);

	return 0;
}

#ifdef __KERNEL_VERSION
SEC("kprobe/vfs_unlink")
#if __KERNEL_VERSION<600	// kernel version < 6.2
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
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);
	struct p_finfo_t finfo;

	if (!next_state_ptr) return 0;

	__builtin_memset(&finfo, 0, sizeof(finfo));
	__u32 i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	bpf_core_read(&(finfo.fp.file.i_ino), sizeof(__u32), &i_ino);
	BPF_CORE_READ_STR_INTO(&(finfo.fp.file.name), dentry, d_iname);
	finfo.operation = OP_REMOVE;
	finfo.type = get_file_type_by_dentry(dentry);

	bpf_map_update_elem(&maps_temp_file, &pid, &finfo, BPF_ANY);

	return 0;
}
SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(vfs_unlink_exit, long ret) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);
	struct p_finfo_t *finfo_ptr = (struct p_finfo_t *) bpf_map_lookup_elem(&maps_temp_file, &pid);

	bpf_map_delete_elem(&maps_temp_file, &pid);
	if (!next_state_ptr || !finfo_ptr || ret < 0) return 0;

#ifdef __KERNEL_VERSION
#if __KERNEL_VERSION<508
	struct p_log_t log, *log_ptr = &log;
	__builtin_memset(log_ptr, 0, sizeof(log));
#else
	struct p_log_t *log_ptr = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
	if (!log_ptr) return 0;
#endif

	fill_log(*log_ptr, next_state_ptr->ppid, pid, next_state_ptr->state_code, 0);
	bpf_core_read(&(log_ptr->info), sizeof(log_ptr->info), finfo_ptr);

#if __KERNEL_VERSION<508
	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, log_ptr, sizeof(*log_ptr));
#else
	bpf_ringbuf_submit(log_ptr, 0);
#endif
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
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);

	if (!next_state_ptr) return 0;

	/* 获取源文件信息 */
	struct p_finfo_t finfo;
	__builtin_memset(&finfo, 0, sizeof(finfo));
	finfo.fp.file.i_ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
	BPF_CORE_READ_STR_INTO(&(finfo.fp.file.name), old_dentry, d_iname);
	finfo.operation = OP_RENAMED;
	finfo.type = get_file_type_by_dentry(old_dentry);

	bpf_map_update_elem(&maps_temp_dentry, &pid, &new_dentry, BPF_ANY);
	bpf_map_update_elem(&maps_temp_file, &pid, &finfo, BPF_ANY);

	return 0;
}
SEC("kretprobe/vfs_rename")
int BPF_KRETPROBE(vfs_rename_exit, long ret) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);
/**
 * 为了方便支持不同版本的内核，统一使用 old_dentry,new_dentry
 * 来保存<源>和<目的>文件信息；
 * 
 * 由于不同内核版本之间的区别只在于参数传递和变量定义，监控函数
 * 体内的内容相似，因此只更改入口和变量定义，以便代码复用
 */
	struct p_finfo_t *finfo_ptr = bpf_map_lookup_elem(&maps_temp_file, &pid);
	struct dentry **new = bpf_map_lookup_elem(&maps_temp_dentry, &pid);

	bpf_map_delete_elem(&maps_temp_file, &pid);
	bpf_map_delete_elem(&maps_temp_dentry, &pid);
	if (!next_state_ptr || !finfo_ptr || !new || ret < 0) return 0;

	struct dentry *new_dentry = *new;

	/* 输出源路径信息 */
#if __KERNEL_VERSION<508
	struct p_log_t log, *log_ptr = &log;
	__builtin_memset(log_ptr, 0, sizeof(log));
#else
	struct p_log_t *log_ptr = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
	if (!log_ptr) return 0;
#endif

	fill_log(*log_ptr, next_state_ptr->ppid, pid, next_state_ptr->state_code, 0);
	bpf_core_read(&(log_ptr->info), sizeof(log_ptr->info), finfo_ptr);

#if __KERNEL_VERSION<508
	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, log_ptr, sizeof(*log_ptr));
#else
	bpf_ringbuf_submit(log_ptr, 0);
#endif

	/* 输出被覆盖路径信息 */
#if __KERNEL_VERSION<508
	// __builtin_memset(log_ptr, 0, sizeof(log));
#else
	struct p_log_t *log_ptr = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
	if (!log_ptr) return 0;
#endif

	fill_log(*log_ptr, next_state_ptr->ppid, pid, next_state_ptr->state_code, 0);
	log_ptr->info.fp.file.i_ino = BPF_CORE_READ(new_dentry, d_inode, i_ino);

	if (log_ptr->info.fp.file.i_ino) {
		/* 说明是移动创建的形式，输出被覆盖的文件信息 */
		BPF_CORE_READ_STR_INTO(&(log_ptr->info.fp.file.name), new_dentry, d_iname);
		log_ptr->info.operation = OP_COVER;
		log_ptr->info.type = get_file_type_by_dentry(new_dentry);
#if __KERNEL_VERSION<508
		bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, log_ptr, sizeof(*log_ptr));
#else
		bpf_ringbuf_submit(log_ptr, 0);
#endif
	} else {
#if __KERNEL_VERSION>=508
		bpf_ringbuf_discard(log_ptr, 0);
#endif
	}


	/* 输出目的路径信息 */
	BPF_CORE_READ_STR_INTO(&(finfo_ptr->fp.file.name), new_dentry, d_iname);
	finfo_ptr->operation = OP_RENAMETO;
#if __KERNEL_VERSION<508
	// __builtin_memset(log_ptr, 0, sizeof(log));
#else
	log = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
	if (!log) return 0;
#endif
	fill_log(*log_ptr, next_state_ptr->ppid, pid, next_state_ptr->state_code, 0);
	bpf_core_read(&(log_ptr->info), sizeof(log_ptr->info), finfo_ptr);
#if __KERNEL_VERSION<508
	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, log_ptr, sizeof(*log_ptr));
#else
	bpf_ringbuf_submit(log_ptr, 0);
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
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);

	if (!next_state_ptr) return 0;
	bpf_map_update_elem(&maps_temp_dentry, &pid, &dentry, BPF_ANY);

	return 0;
}
SEC("kretprobe/vfs_mkdir")
int BPF_KRETPROBE(vfs_mkdir_exit, long ret) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);
	struct dentry **dentry_ptr = bpf_map_lookup_elem(&maps_temp_dentry, &pid), *dentry;

	bpf_map_delete_elem(&maps_temp_dentry, &pid);
	if (!next_state_ptr || !dentry_ptr || ret < 0) return 0;

	/* 输出创建目录信息 */
	dentry = *dentry_ptr;
#if __KERNEL_VERSION<508
	struct p_log_t log, *log_ptr = &log;
	__builtin_memset(log_ptr, 0, sizeof(log));
#else
	struct p_log_t *log_ptr = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
	if (!log_ptr) return 0;
#endif

	fill_log(*log_ptr, next_state_ptr->ppid, pid, next_state_ptr->state_code, 0);
	log_ptr->info.fp.file.i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	BPF_CORE_READ_STR_INTO(&(log_ptr->info.fp.file.name), dentry, d_iname);
	log_ptr->info.operation = OP_CREATE;
	log_ptr->info.type = get_file_type_by_dentry(dentry);

#if __KERNEL_VERSION<508
	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, log_ptr, sizeof(*log_ptr));
#else
	bpf_ringbuf_submit(log_ptr, 0);
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
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);
	struct p_finfo_t finfo;

	if (!next_state_ptr) return 0;

	__builtin_memset(&finfo, 0, sizeof(finfo));
	__u32 i_ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	bpf_core_read(&(finfo.fp.file.i_ino), sizeof(__u32), &i_ino);
	BPF_CORE_READ_STR_INTO(&(finfo.fp.file.name), dentry, d_iname);
	finfo.operation = OP_REMOVE;
	finfo.type = get_file_type_by_dentry(dentry);

	bpf_map_update_elem(&maps_temp_file, &pid, &finfo, BPF_ANY);

	return 0;
}
SEC("kretprobe/vfs_rmdir")
int BPF_KRETPROBE(vfs_rmdir_exit, long ret) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);
	struct p_finfo_t *finfo_ptr = (struct p_finfo_t *) bpf_map_lookup_elem(&maps_temp_file, &pid);

	bpf_map_delete_elem(&maps_temp_file, &pid);
	if (!next_state_ptr || !finfo_ptr || ret < 0) return 0;

#if __KERNEL_VERSION<508
	struct p_log_t log, *log_ptr = &log;
	__builtin_memset(log_ptr, 0, sizeof(log));
#else
	struct p_log_t *log_ptr = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
	if (!log_ptr) return 0;
#endif

	fill_log(*log_ptr, next_state_ptr->ppid, pid, next_state_ptr->state_code, 0);
	bpf_core_read(&(log_ptr->info), sizeof(log_ptr->info), finfo_ptr);

#if __KERNEL_VERSION<508
	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, log_ptr, sizeof(*log_ptr));
#else
	bpf_ringbuf_submit(log_ptr, 0);
#endif

	return 0;
}
#endif

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);

	if (next_state_ptr) {
		/* 如果需要获取更多信息，则暂存 sock 指针 */
		bpf_map_update_elem(&maps_temp_sock, &pid, &sk, BPF_ANY);
	}

	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, long ret) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u64 finfo_key = ((__u64) pid << 32) | 0xffffffff;
	struct sock **sk_ptr = bpf_map_lookup_elem(&maps_temp_sock, &pid);
	struct p_finfo_t *sock_info_ptr = bpf_map_lookup_elem(&maps_files, &finfo_key);
	
	bpf_map_delete_elem(&maps_temp_sock, &pid);
	if (!sk_ptr || !sock_info_ptr) return 0;
	struct sock *sk = *sk_ptr;

	/* 获取套接字的详细信息 */
    sock_info_ptr->fp.socket.from_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    sock_info_ptr->fp.socket.to_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	sock_info_ptr->fp.socket.from_ip = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
	sock_info_ptr->fp.socket.to_ip = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
	// sock_info_ptr->type = S_IFSOCK;

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
    struct p_socket_t *net_info;
	struct p_finfo_t new_sock;
	long err = 0;

	/* 通过状态机控制是否输出当前的连接请求 */
	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);
	if (!next_state_ptr) return 0;

    // pull in details
    u16 lport = 0, dport;
    lport = BPF_CORE_READ(newsk, __sk_common.skc_num);
    dport = BPF_CORE_READ(newsk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

#if __KERNEL_VERSION<508
	struct p_log_t log, *log_ptr = &log;
	__builtin_memset(log_ptr, 0, sizeof(log));
#else
	struct p_log_t *log_ptr = bpf_ringbuf_reserve(&rb, sizeof(struct p_log_t), 0);
	if (!log_ptr) return 0;
#endif
	fill_log(*log_ptr, 1, pid, 0, 1000000);

	__builtin_memset(&new_sock, 0, sizeof(new_sock));
    new_sock.fp.socket.to_ip = bpf_ntohl(BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr));
    new_sock.fp.socket.from_ip = bpf_ntohl(BPF_CORE_READ(newsk, __sk_common.skc_daddr));
    new_sock.fp.socket.to_port = lport;
    new_sock.fp.socket.from_port = dport;
	new_sock.operation = OP_RECEIVE;
	new_sock.type = S_IFSOCK;
	log_ptr->info = new_sock;

#if __KERNEL_VERSION<508
	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, log_ptr, sizeof(*log_ptr));
#else
	bpf_ringbuf_submit(log_ptr, 0);
#endif

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
