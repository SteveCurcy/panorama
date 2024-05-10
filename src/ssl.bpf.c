// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ssl.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, const void *);
} tmp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe")
int BPF_KPROBE(uprobe_ssl_read, void *ssl, const void *buf, int num)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&tmp, &pid, &buf, BPF_ANY);
	
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_ssl_read, int ret)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	const void ** buf = bpf_map_lookup_elem(&tmp, &pid);
	if (!buf) {
		return 0;
	}
	const char *data = *buf;
	if (!data) {
		return 0;
	}

	bpf_map_delete_elem(&tmp, &pid);
	if (ret <= 0) {
		return 0;
	}

	struct ssl_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct ssl_event), 0);
	if (!e)
		return 0;

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

	bpf_probe_read_user(e->content, num & SSL_LEN_MASK, buf);
	e->from = 1;
	e->size = num;
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_pr_read, void *fd, const void* buf, int amount)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&tmp, &pid, &buf, BPF_ANY);
	
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_pr_read, int ret)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	const void ** buf = bpf_map_lookup_elem(&tmp, &pid);
	if (!buf) {
		return 0;
	}
	const char *data = *buf;
	if (!data) {
		return 0;
	}

	bpf_map_delete_elem(&tmp, &pid);
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
