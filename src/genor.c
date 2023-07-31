/* 
 * License-Identifier: BSD-3
 * Copyright (c) 2023 Steve.Curcy
 */
#include <pwd.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include "panorama.h"
#include "genor.skel.h"

struct __entry {
	const char *key;
	__u32 val;
} cap_entries[] = {
	{"cat", 1},
	{"touch", 1},
	{"rm", 1},
	{"mkdir", 1},
	{"rmdir", 1},
	{"gzip", 2},
	{"zip", 2},
	{"unzip", 1},
	{"split", 1},
	{"cp", 2},
	{"mv", 2}
};

/* 保存当前程序是否正运行 */
static volatile bool is_running = true;
static void sig_handler(int sig) {
	is_running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

__always_inline static const char *get_syscall_str(__u32 sysid) {
	switch (sysid) {
	case SYSCALL_OPENAT: return "openat";
	case SYSCALL_DUP2: return "dup2";
	case SYSCALL_DUP3: return "dup3";
	case SYSCALL_READ: return "read";
	case SYSCALL_WRITE: return "write";
	case SYSCALL_CLOSE: return "close";
	case SYSCALL_UNLINK: return "unlink";
	case SYSCALL_UNLINKAT: return "unlinkat";
	case SYSCALL_MKDIR: return "mkdir";
	case SYSCALL_MKDIRAT: return "mkdirat";
	case SYSCALL_RMDIR: return "rmdir";
	case SYSCALL_RENAME: return "rename";
	case SYSCALL_RENAMEAT: return "renameat";
	case SYSCALL_RENAMEAT2: return "renameat2";
	case SYSCALL_EXIT_GROUP: return "exit_group";
	default:
		return "nil";
	}
}

struct sf_t {
	char comm[32];
	__u16 sysid;
	__u32 flags;
	pid_t pid;
};

static FILE *fp = NULL;

static int event_handler(void *ctx, void *data, size_t data_sz) {
	struct sf_t *sf_ptr = (struct sf_t *)data;
	fprintf(fp, "%u %s %u %u\n", sf_ptr->pid, sf_ptr->comm, sf_ptr->sysid, sf_ptr->flags);
	
	return 0;
}

int main(int argc, char **argv) {
	struct genor_bpf *skel;
	struct ring_buffer *rb = NULL;
	long err = 0;

	/* 设置 libbpf 打印错误和调试信息的回调函数 */
	libbpf_set_print(libbpf_print_fn);

	/* 处理用户的终止命令 Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	fp = fopen("/var/log/genor.log", "w");
	if (fp == NULL) {
		fprintf(stderr, "Log file open failed!\n");
		return 2;
	}

	/* Load and verify BPF application */
	skel = genor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* 将需要过滤的进程哈希更新到 map 中 */
	long cap_size = sizeof(cap_entries) / sizeof(struct __entry);
	for (int i = 0; i < cap_size; i++) {
		__u64 hash_value = str_hash(cap_entries[i].key);
		err = bpf_map__update_elem(skel->maps.maps_cap_hash, &hash_value, sizeof(__u64), &(cap_entries[i].val), sizeof(__u32), BPF_NOEXIST);
		if (err < 0) {
			fprintf(stderr, "Fialed to update maps\n");
			return 2;
		}
	}

	/* Attach tracepoint handler */
	err = genor_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Bpf programs have been attached successfully!\n");

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), event_handler, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (is_running) {
		/**
		 * eBPF 提供了 ring_buffer__poll 和 ring_buffer__consume 两个函数：
		 * - ring_buffer__poll 通过 epoll 来获取事件，如果没有事件到达则等待；
		 * - ring_buffer__consume 通过轮询的方式来获取事件，实时性更高但是性能损耗也更高；
		 * 为了平衡性能和实时性，采用 ring_buffer__poll 方式将更好。 
		 */
		err = ring_buffer__poll(rb, 100 /* 超时时间，100 ms */);
		/* Ctrl-C 会导致 -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:

	genor_bpf__destroy(skel);
	return -err;
}
