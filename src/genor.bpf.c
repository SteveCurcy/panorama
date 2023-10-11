/* 
 * License-Identifier: BSD-3
 * Copyright (c) 2023 Steve.Curcy
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "panorama.h"
#include "config.h"

/* 默认情况下，0 是起始状态，改变量保存下一个可以使用的最新状态码 */
static volatile int new_state_code = 1;

struct sf_t {
	char comm[32];
	__u32 event;
	pid_t pid;
};

/* 保存想要捕获的进程名的哈希值，以及对应的最终状态码 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u32);
} maps_cap_hash SEC(".maps");
/* 保存进程打开的文件的 fd */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} maps_pid_fd SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, pid_t);
	__type(value, __u64);
} maps_tmp_fd SEC(".maps");
/* 保存状态转移表中的 flag */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, pid_t);
	__type(value, __u32);
} maps_flags SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, pid_t);
	__type(value, __u16);
} maps_sysid SEC(".maps");
/* 输出事件 */
/* 输出事件如果使用 perf_event 一定要指定 key_size, value_size；
 * 如果使用 ring_buffer 则最好指明 max_entries，并且要大于 4096B */
#ifdef __KERNEL_VERSION
#if __KERNEL_VERSION<508
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	// __uint(max_entries, 4096 * 64);
} rb SEC(".maps");
#else	// linux v5.8 开始支持 ring buffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096 * 64);
} rb SEC(".maps");
#endif
#endif	// end of __KERNEL_VERSION

/* 判断当前进程是否是关心命令，是否需要加入状态机中 */
__always_inline static bool if_capture() {
	char comm[32];
	bpf_get_current_comm(&comm, 32);
	__u64 hash_value = str_hash(comm);

	__u32 *dummy = bpf_map_lookup_elem(&maps_cap_hash, &hash_value);
	return (dummy != 0);
}

/**
 * 保存操作系统对应的 flags
 * @param flags 系统调用的标志
 * @return 返回 pid，如果执行出错则返回 0
 */
static pid_t tracepoint__syscalls__sys_enter(__u32 flags) {
	
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (!if_capture()) return 0;
	bpf_map_update_elem(&maps_flags, &pid, &flags, BPF_ANY);
	
	return pid;
}
static pid_t tracepoint__syscalls__sys_exit(struct trace_event_raw_sys_exit *ctx, long ret, __u16 syscall_id) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u32 *flags = bpf_map_lookup_elem(&maps_flags, &pid);
	__u16 *sysid_ptr = bpf_map_lookup_elem(&maps_sysid, &pid), sysid = 0xffff;

	if (!sysid_ptr) sysid_ptr = &sysid;

	bpf_map_delete_elem(&maps_flags, &pid);
	if (!flags || !sysid_ptr || ret < 0) return 0;

	/* 如果当前的系统调用是写操作，并且与上一个系统调用相同，则放弃更新
	 * 过滤掉重复的系统调用序列 */
	if (*sysid_ptr == syscall_id && syscall_id == SYSCALL_WRITE) return 0;
	/* 更新当前的系统调用 */
	*sysid_ptr = syscall_id;
	bpf_map_update_elem(&maps_sysid, &pid, sysid_ptr, BPF_ANY);

#ifdef __KERNEL_VERSION
#if __KERNEL_VERSION<508
	struct sf_t sf_ptr;
	__builtin_memset(&sf_ptr, 0, sizeof(sf_ptr));
	bpf_get_current_comm(&(sf_ptr.comm), 32);
	sf_ptr.event = *flags;
	sf_ptr.pid = pid;

	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, &sf_ptr, sizeof(sf_ptr));
#else	// 内核 5.8 开始支持
	struct sf_t *sf_ptr = bpf_ringbuf_reserve(&rb, sizeof(struct sf_t), 0);
	if (!sf_ptr) return 0;	// 申请内存空间失败

	bpf_get_current_comm(&(sf_ptr->comm), 32);
	sf_ptr->event = *flags;
	sf_ptr->pid = pid;

	bpf_ringbuf_output(sf_ptr, 0);
#endif
#endif // __KERNEL_VERSION
	return pid;
}

/* 为了尽量保证程序的性能，对于系统调用监控，我们选用 tracepoint 进行实现 */
/**
 * int openat(int dfd, const char *filename, int flags, umode_t mode);
 * 
 * 进入后，首先判断当前的状态码能否引起状态转移，（第一次调用时，状态码为 0），
 * 如果可以，则将状态保存到 maps_nex 中，其中存储可能的下一个状态（因为可能有调用失败的情况）
 */
SEC("tp/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u32 stt_flags = 0;
	/* 从上下文中获取系统调用参数 */
	int flags = BPF_CORE_READ(ctx, args[2]);

	/* 如果一个文件的打开方式为 O_CLOEXEC 则大概率是一个库文件，将其过滤 */
	if (flags == O_CLOEXEC) return 0;

	stt_flags = get_open_evnt(flags);

	tracepoint__syscalls__sys_enter(stt_flags);

	return 0;
}
SEC("tp/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {

	long ret = BPF_CORE_READ(ctx, ret), err = 0;

	pid_t pid = tracepoint__syscalls__sys_exit(ctx, ret, SYSCALL_OPENAT);
	if (!pid) return 0;

	__u8 zero = 0;
	__u64 dummy_key = ((__u64) pid << 32) | ret;
	err = bpf_map_update_elem(&maps_pid_fd, &dummy_key, &zero, BPF_ANY);

	return 0;
}

/* ssize_t read(int fd, char *buf, size_t count) */
// SEC("tp/syscalls/sys_enter_read")
// int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
// 	return 0;
// }
// SEC("tp/syscalls/sys_exit_read")
// int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
// 	return 0;
// }

/* ssize_t write(int fd, const char *buf, size_t count) */
SEC("tp/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int fd = BPF_CORE_READ(ctx, args[0]);
	/* 确保保存了相关的文件信息才能进行状态机的匹配；
	 * 如果没保存，说明在 openat 就没有匹配到 */
	__u64 dummy_key = ((__u64) pid << 32) | fd;
	__u8 *dummy = bpf_map_lookup_elem(&maps_pid_fd, &dummy_key);
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
	__u8 *dummy = bpf_map_lookup_elem(&maps_pid_fd, &dummy_key);
	if (!dummy) return 0;

	bpf_map_update_elem(&maps_tmp_fd, &pid, &fd, BPF_ANY);
	tracepoint__syscalls__sys_enter(PEVENT_CLOSE);

	return 0;
}
SEC("tp/syscalls/sys_exit_close")
int tracepoint__syscalls__sys_exit_close(struct trace_event_raw_sys_exit *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int *fd_ptr = bpf_map_lookup_elem(&maps_tmp_fd, &pid);
	long ret = BPF_CORE_READ(ctx, ret), err = 0;

	if (ret >= 0 && fd_ptr) {
		__u64 dummy_key = ((__u64) pid << 32) | *fd_ptr;
		bpf_map_delete_elem(&maps_pid_fd, &dummy_key);
	}

	bpf_map_delete_elem(&maps_tmp_fd, &pid);
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

/* int dup2(int oldfd, int newfd) */
SEC("tp/syscalls/sys_enter_dup2")
int tracepoint__syscalls__sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	int oldfd = BPF_CORE_READ(ctx, args[0]);
	int newfd = BPF_CORE_READ(ctx, args[1]);
	__u64 tmpfds = (__u64) oldfd << 32 | newfd;
	bpf_map_update_elem(&maps_tmp_fd, &pid, &tmpfds, BPF_ANY);

	return 0;
}
SEC("tp/syscalls/sys_exit_dup2")
int tracepoint__syscalls__sys_exit_dup2(struct trace_event_raw_sys_exit *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u64 *tmpfds = bpf_map_lookup_elem(&maps_tmp_fd, &pid);
	long ret = BPF_CORE_READ(ctx, ret);

	bpf_map_delete_elem(&maps_tmp_fd, &pid);
	if (!tmpfds || ret < 0) return 0;

	// 取出原 fd 对应的文件信息
	__u64 finfo_key = ((__u64) pid << 32) | (*tmpfds >> 32);
	__u8 *dummy = bpf_map_lookup_elem(&maps_pid_fd, &finfo_key);
	if (!dummy) return 0;

	// 将文件信息更新到新 fd 上
	bpf_map_delete_elem(&maps_pid_fd, &finfo_key);
	finfo_key = ((__u64) pid << 32) | (*tmpfds & 0xffffffff);
	long err = bpf_map_update_elem(&maps_pid_fd, &finfo_key, dummy, BPF_ANY);

	return 0;
}

/* int dup3(int oldfd, int newfd, int flags) */
SEC("tp/syscalls/sys_enter_dup3")
int tracepoint__syscalls__sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	int oldfd = BPF_CORE_READ(ctx, args[0]);
	int newfd = BPF_CORE_READ(ctx, args[1]);
	__u64 tmpfds = (__u64) oldfd << 32 | newfd;
	bpf_map_update_elem(&maps_tmp_fd, &pid, &tmpfds, BPF_ANY);

	return 0;
}
SEC("tp/syscalls/sys_exit_dup3")
int tracepoint__syscalls__sys_exit_dup3(struct trace_event_raw_sys_exit *ctx) {

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u64 *tmpfds = bpf_map_lookup_elem(&maps_tmp_fd, &pid);
	long ret = BPF_CORE_READ(ctx, ret);

	bpf_map_delete_elem(&maps_tmp_fd, &pid);
	if (!tmpfds || ret < 0) return 0;

	// 取出原 fd 对应的文件信息
	__u64 finfo_key = ((__u64) pid << 32) | (*tmpfds >> 32);
	__u8 *dummy = bpf_map_lookup_elem(&maps_pid_fd, &finfo_key);
	if (!dummy) return 0;

	// 将文件信息更新到新 fd 上
	bpf_map_delete_elem(&maps_pid_fd, &finfo_key);
	finfo_key = ((__u64) pid << 32) | (*tmpfds & 0xffffffff);
	long err = bpf_map_update_elem(&maps_pid_fd, &finfo_key, dummy, BPF_ANY);

	return 0;
}

/**
 * int socket(int family, int type, int protocol)
 * 由于 socket 函数并没有提供套接字相关的信息，因此我们考虑暂时弃用 socket 系统调用；
 * 通过 socket 获取的 fd 如果没有 connect 是没有意义的，因此不予处理也是合理的；
 * 对于 socket 获取的 fd 通过 connect 连接，则相关信息可以通过 connect 系统调用获取。
 *//*
SEC("tp/syscalls/sys_enter_socket")
int tracepoint__syscalls__sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
	return 0;
}
SEC("tp/syscalls/sys_exit_socket")
int tracepoint__syscalls__sys_exit_socket(struct trace_event_raw_sys_exit *ctx) {
	return 0;
}
*/

/* int connect(int fd, struct sockaddr *uservaddr, int addrlen) */
// SEC("tp/syscalls/sys_enter_connect")
// int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {

// 	pid_t pid = bpf_get_current_pid_tgid() >> 32;
// 	struct p_state_t *cur_state_ptr = bpf_map_lookup_elem(&maps_cur, &pid);
// 	if (!cur_state_ptr) return 0;

// 	/* 首先查看能否引起状态转移 */
// 	__u64 cur_state = STT_KEY(cur_state_ptr->state_code, SYSCALL_CONNECT, 0);
// 	__u32 *next_state_code = bpf_map_lookup_elem(&maps_stt, &cur_state);
// 	if (!next_state_code) return 0;

// 	/* 创建一个临时的套接字文件信息，通过内核函数获取具体详细信息；
// 	 * 获取系统调用参数 fd 并临时保存 */
// 	int fd = BPF_CORE_READ(ctx, args[0]);
// 	struct p_finfo_t new_sock_info;

// 	struct p_state_t s;
// 	NEW_STATE(s, cur_state_ptr->ppid, *next_state_code);
// 	long err = bpf_map_update_elem(&maps_nex, &pid, &s, BPF_ANY);
// 	if (err < 0) return 0;

// 	__builtin_memset(&new_sock_info, 0, sizeof(new_sock_info));
// 	new_sock_info.type = fd;	// 使用 type 字段暂存 fd
// 	new_sock_info.operation = OP_TRANSMIT;
// 	new_sock_info.open_time = bpf_ktime_get_boot_ns();

// 	__u64 finfo_key = (__u64) pid << 32 | 0xffffffff;
// 	bpf_map_update_elem(&maps_files, &finfo_key, &new_sock_info, BPF_ANY);

// 	return 0;
// }
// SEC("tp/syscalls/sys_exit_connect")
// int tracepoint__syscalls__sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {

// 	/* 查看返回值是否为负值（调用失败）；
// 	 * 如果失败，则将对应的文件信息删除；否则更新状态信息 */
// 	long ret = BPF_CORE_READ(ctx, ret);
// 	pid_t pid = bpf_get_current_pid_tgid() >> 32;
// 	__u64 finfo_key = ((__u64) pid << 32) | 0xffffffff;
// 	struct p_state_t *next_state_ptr = bpf_map_lookup_elem(&maps_nex, &pid);
// 	struct p_finfo_t *sock_info_ptr = bpf_map_lookup_elem(&maps_files, &finfo_key);

// 	bpf_map_delete_elem(&maps_files, &finfo_key);
// 	bpf_map_delete_elem(&maps_nex, &pid);
// 	if (!sock_info_ptr || !next_state_ptr || ret < 0) return 0;

// 	/* 将暂存的 fd 取出，然后将文件类型设置为 socket */
// 	int fd = sock_info_ptr->type;
// 	finfo_key = ((__u64) pid << 32) | ret;
// 	sock_info_ptr->op_cnt++;
// 	/* 更新文件信息到正确的 fd */
// 	long err = bpf_map_update_elem(&maps_files, &finfo_key, sock_info_ptr, BPF_ANY);
// 	if (err < 0) return 0;

// 	bpf_map_update_elem(&maps_cur, &pid, next_state_ptr, BPF_ANY);

// 	return 0;
// }

/* long accept(int fd, struct sockaddr *upeer_sockaddr, int upeer_addrlen) */
// SEC("tp/syscalls/sys_enter_accept")
// int tracepoint__syscalls__sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
// 	return 0;
// }
// SEC("tp/syscalls/sys_exit_accept")
// int tracepoint__syscalls__sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
// 	return 0;
// }

/* long exit_group(int error_code) */
SEC("tp/syscalls/sys_enter_exit_group")
int tracepoint__syscalls__sys_enter_exit_group(struct trace_event_raw_sys_enter *ctx) {
	
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&maps_tmp_fd, &pid);

	char comm[32];
	bpf_get_current_comm(&comm, 32);
	__u64 comm_hash = str_hash(comm);
	
	__u32 *cnt = bpf_map_lookup_elem(&maps_cap_hash, &comm_hash);
	if (!cnt) return 0;
	*cnt -= 1;
	if (*cnt <= 0) {
		bpf_map_delete_elem(&maps_cap_hash, &comm_hash);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
