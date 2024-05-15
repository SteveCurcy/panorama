// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ssl.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* 暂时存储字符串等指针变量 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, const void *);
} tmp_buf SEC(".maps");

/* 暂时存储ssl等指针变量 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, const void *);
} tmp_ssl SEC(".maps");

/* 暂时存储 pid+fd => socket 的映射关系 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct ssl_socket);
} tmp_fd_sock SEC(".maps");

/* 暂存 指针（通常为ssl结构体） => socket 的映射关系 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, const void *);
	__type(value, struct ssl_socket);
} tmp_ssl_sock SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * 暂存进程用于网络连接的 socket fd 和网络信息结构体
 *
 * @param pid 	目标进程的 id
 * @param fd 	socket 文件描述符
 */
static void ssl_stash_socket(const pid_t pid, const int fd)
{
	struct ssl_socket sock;
	__builtin_memset(&sock, 0, sizeof(sock));
	sock.local_ip = fd;

	__u64 key = ((__u64)pid << 32) | 0xffffffff;
	bpf_map_update_elem(&tmp_fd_sock, &key, &sock, BPF_ANY);
}

/**
 * 关闭 socket 连接，清理 fd 对应的 socket 信息，由于 connect/accept
 * 打开的 socket 可能不用于 ssl 加密通信，因此需要在 close 处关闭
 *
 * @param pid 	目标进程 id
 * @param fd 	关闭的 socket 对应的 fd
 */
static void ssl_close_socket(const pid_t pid, const int fd)
{
	__u64 key = ((__u64)pid << 32) | fd;
	bpf_map_delete_elem(&tmp_fd_sock, &key);
}

/**
 * 更新 fd 对应的 socket 信息
 *
 * @param pid 	目标进程的 pid
 * @param sk	存储网络套接字的内核数据结构
 * @return int 	更新成功则返回 0，否则返回 1
 */
static int ssl_update_fd_socket(const pid_t pid, const struct sock *sk)
{
	__u64 key = ((__u64)pid << 32) | 0xffffffff;
	struct ssl_socket *sock = bpf_map_lookup_elem(&tmp_fd_sock, &key);

	bpf_map_delete_elem(&tmp_fd_sock, &key);
	if (!sock)
	{
		return 1;
	}

	key = ((__u64)pid << 32) | (sock->local_ip);

	sock->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	sock->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	sock->local_ip = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
	sock->remote_ip = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));

	bpf_map_update_elem(&tmp_fd_sock, &key, sock, BPF_ANY);
	return 0;
}

/**
 * 更新 socket 映射关系信息，将 fd 对应的 socket 信息更新到 ssl 的映射中
 *
 * @param pid	目标进程的 pid
 * @param fd	socket 文件对应的文件描述符 fd
 * @param ssl	SSL 结构体指针
 * @return		返回 0 则执行成功，否则说明没有 fd 对应的 socket
 */
static int ssl_update_ssl_socket(const pid_t pid, const int fd, const void **ssl)
{
	__u64 key = ((__u64)pid << 32) | fd;
	struct ssl_socket *sock = bpf_map_lookup_elem(&tmp_fd_sock, &key);

	bpf_map_delete_elem(&tmp_fd_sock, &key);
	if (!sock)
	{
		return 1;
	}

	bpf_map_update_elem(&tmp_ssl_sock, ssl, sock, BPF_ANY);
	return 0;
}

/* 关闭 ssl 连接，清除对应的 socket 信息 */
static __always_inline int ssl_delete_socket(const void **ssl)
{
	return bpf_map_delete_elem(&tmp_ssl_sock, ssl);
}

/**
 * 将该进程，ssl 连接监控到的消息内容 buf 上传到用户态处理
 *
 * @param pid 	目标进程的 pid
 * @param ssl 	进程的哪一个 ssl 连接
 * @param buf 	该 ssl 连接[接收/发送]的消息内容
 * @param size	消息长度
 * @param direct 流量/消息方向，接收/发送，0 接收，1 发送
 * @return int 	0 为上传成功，否则失败
 */
static int ssl_submit_packet(const pid_t pid, const void **ssl,
							 const void **buf, const int size, const int direct)
{
	struct ssl_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct ssl_event), 0);
	if (!e)
		return 0;

	struct ssl_socket *sock = bpf_map_lookup_elem(&tmp_ssl_sock, ssl);
	if (!sock) // 如果 sock 为空，则说明没有对应的连接或者出错
	{
		bpf_ringbuf_discard(e, 0);
		return 1;
	}

	e->sock.local_ip = sock->local_ip;
	e->sock.local_port = sock->local_port;
	e->sock.remote_ip = sock->remote_ip;
	e->sock.remote_port = sock->remote_port;
	// 这里的 SSL_LEN_MASK 是为了确保 ret 不会导致数组越界
	// 从而可以通过 eBPF 验证器
	bpf_probe_read_user(e->content, size & SSL_LEN_MASK, *buf);
	e->from = direct;
	e->size = size;
	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("tp/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int fd = BPF_CORE_READ(ctx, args[0]);

	ssl_close_socket(pid, fd);

	return 0;
}

/* int connect(int fd, struct sockaddr *uservaddr, int addrlen) */
SEC("tp/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int fd = BPF_CORE_READ(ctx, args[0]);

	ssl_stash_socket(pid, fd);

	return 0;
}

/* long accept(int fd, struct sockaddr *upeer_sockaddr, int upeer_addrlen) */
SEC("tp/syscalls/sys_enter_accept")
int tracepoint__syscalls__sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int fd = BPF_CORE_READ(ctx, args[0]);

	ssl_stash_socket(pid, fd);

	return 0;
}

/* int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&tmp_ssl, &pid, &sk, BPF_ANY);

	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, long ret)
{

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (ret < 0)
		return 0;

	struct sock **psk = bpf_map_lookup_elem(&tmp_ssl, &pid);
	if (!psk)
	{
		return 0;
	}

	struct sock *sk = *psk;
	if (!sk)
	{
		return 0;
	}

	ssl_update_fd_socket(pid, sk);

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_exit, struct sock *sk)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	ssl_update_fd_socket(pid, sk);

	return 0;
}

// >>>>>>>>>>>>>>>>> Begin of libssl.so* >>>>>>>>>>>>>>>>>>>>>>>

SEC("uprobe")
int BPF_KPROBE(uprobe_ssl_read, void *ssl, const void *buf, int num)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&tmp_buf, &pid, &buf, BPF_ANY);
	bpf_map_update_elem(&tmp_ssl, &pid, &ssl, BPF_ANY);

	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_ssl_read, int ret)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	const void **buf = bpf_map_lookup_elem(&tmp_buf, &pid);
	const void **pssl = bpf_map_lookup_elem(&tmp_ssl, &pid);

	bpf_map_delete_elem(&tmp_buf, &pid);
	bpf_map_delete_elem(&tmp_ssl, &pid);
	if (!buf || !pssl || ret <= 0)
	{
		return 0;
	}

	ssl_submit_packet(pid, pssl, buf, ret, 0);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num)
{
	if (num <= 0)
		return 0;

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	ssl_submit_packet(pid, &ssl, &buf, num, 1);

	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_ssl_set_fd, void *ssl, int fd)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	ssl_update_ssl_socket(pid, fd, &ssl);

	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_ssl_shutdown, void *ssl)
{

	ssl_delete_socket(&ssl);

	return 0;
}

// <<<<<<<<<<<<<<<<<<<< End of libssl.so* <<<<<<<<<<<<<<<<<<<<<

SEC("uprobe")
int BPF_KPROBE(uprobe_pr_read, void *fd, const void *buf, int amount)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&tmp_buf, &pid, &buf, BPF_ANY);

	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_pr_read, int ret)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	const void **buf = bpf_map_lookup_elem(&tmp_buf, &pid);
	if (!buf)
	{
		return 0;
	}
	const char *data = *buf;
	if (!data)
	{
		return 0;
	}

	bpf_map_delete_elem(&tmp_buf, &pid);
	if (ret <= 0)
	{
		return 0;
	}

	struct ssl_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct ssl_event), 0);
	if (!e)
		return 0;

	bpf_probe_read_user(e->content, ret & SSL_LEN_MASK, data);
	e->from = 2;
	e->size = ret;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_pr_write, void *fd, const void *buf, int amount)
{
	if (amount <= 0)
		return 0;

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	struct ssl_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct ssl_event), 0);
	if (!e)
		return 0;

	bpf_probe_read_user(e->content, amount & SSL_LEN_MASK, buf);
	e->from = 3;
	e->size = amount;
	bpf_ringbuf_submit(e, 0);

	return 0;
}
