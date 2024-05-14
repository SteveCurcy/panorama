// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ssl.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, const void *);
} tmp_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, const void *);
} tmp_ssl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct ssl_socket);
} tmp_fd_sock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, const void *);
	__type(value, struct ssl_socket);
} tmp_ssl_sock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* int connect(int fd, struct sockaddr *uservaddr, int addrlen) */
SEC("tp/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int fd = BPF_CORE_READ(ctx, args[0]);
    struct ssl_socket sock;
    __builtin_memset(&sock, 0, sizeof(sock));
	sock.from_ip = fd;

	__u64 key = ((__u64) pid << 32) | 0xffffffff;

    bpf_map_update_elem(&tmp_fd_sock, &key, &sock, BPF_ANY);

    return 0;
}

/* int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&tmp_ssl, &pid, &sk, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, long ret) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u64 key = ((__u64) pid << 32) | 0xffffffff;
    struct ssl_socket *sock = bpf_map_lookup_elem(&tmp_fd_sock, &key);
	struct sock **psk = bpf_map_lookup_elem(&tmp_ssl, &pid);

	bpf_map_delete_elem(&tmp_ssl, &pid);
	bpf_map_delete_elem(&tmp_fd_sock, &key);
    if (!sock || !psk) {
		return 0;
	}

	struct sock *sk = *psk;
	if (!sk) {
		return 0;
	}
	key = ((__u64) pid << 32) | (sock->from_ip);
	
	sock->from_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    sock->to_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    sock->from_ip = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
    sock->to_ip = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));

	bpf_map_update_elem(&tmp_fd_sock, &key, sock, BPF_ANY);

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
	const void ** buf = bpf_map_lookup_elem(&tmp_buf, &pid);
	const void ** pssl = bpf_map_lookup_elem(&tmp_ssl, &pid);

	bpf_map_delete_elem(&tmp_buf, &pid);
	bpf_map_delete_elem(&tmp_ssl, &pid);
	if (!buf || !pssl) {
		return 0;
	}
	const char *data = *buf;
	const void *ssl = *pssl;
	if (!data || !ssl) {
		return 0;
	}
	if (ret <= 0) {
		return 0;
	}

	struct ssl_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct ssl_event), 0);
	if (!e)
		return 0;

	struct ssl_socket *sock = bpf_map_lookup_elem(&tmp_ssl_sock, &ssl);
	if (!sock) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	e->sock.from_ip = sock->from_ip;
	e->sock.from_port = sock->from_port;
	e->sock.to_ip = sock->to_ip;
	e->sock.to_port = sock->to_port;
	// 这里的 SSL_LEN_MASK 是为了确保 ret 不会导致数组越界
	// 从而可以通过 eBPF 验证器
	bpf_probe_read_user(e->content, ret & SSL_LEN_MASK, data);
	e->from = 0;
	e->size = ret;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num)
{
	if (num <= 0) return 0;

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	struct ssl_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct ssl_event), 0);
	if (!e)
		return 0;

	struct ssl_socket *sock = bpf_map_lookup_elem(&tmp_ssl_sock, &ssl);
	if (!sock) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	e->sock.from_ip = sock->from_ip;
	e->sock.from_port = sock->from_port;
	e->sock.to_ip = sock->to_ip;
	e->sock.to_port = sock->to_port;
	bpf_probe_read_user(e->content, num & SSL_LEN_MASK, buf);
	e->from = 1;
	e->size = num;
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_ssl_set_fd, void *ssl, int fd)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u64 key = ((__u64)pid << 32) | fd;
	struct ssl_socket *sock = bpf_map_lookup_elem(&tmp_fd_sock, &key);

	bpf_map_delete_elem(&tmp_fd_sock, &key);
	if (!sock) {
		return 0;
	}

	bpf_map_update_elem(&tmp_ssl_sock, &ssl, sock, BPF_ANY);

	return 0;
}

// <<<<<<<<<<<<<<<<<<<< End of libssl.so* <<<<<<<<<<<<<<<<<<<<<

SEC("uprobe")
int BPF_KPROBE(uprobe_pr_read, void *fd, const void* buf, int amount)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&tmp_buf, &pid, &buf, BPF_ANY);
	
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_pr_read, int ret)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	const void ** buf = bpf_map_lookup_elem(&tmp_buf, &pid);
	if (!buf) {
		return 0;
	}
	const char *data = *buf;
	if (!data) {
		return 0;
	}

	bpf_map_delete_elem(&tmp_buf, &pid);
	if (ret <= 0) {
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
int BPF_KPROBE(uprobe_pr_write, void *fd, const void* buf, int amount)
{
	if (amount <= 0) return 0;

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
