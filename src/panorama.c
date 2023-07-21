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
#include "config.h"
#include "panorama.h"
#include "panorama.skel.h"

/* 保存当前程序是否正运行 */
static volatile bool is_running = true;
static void sig_handler(int sig) {
	is_running = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

/* 状态转移表 */
struct __entry {
	__u64 key;
	__u32 val;
} stt[] = {
	/* cat */
	{STT_KEY(0, SYSCALL_OPENAT, 0), 1},
	{STT_KEY(1, SYSCALL_CLOSE, 0), STATE_CAT},
	{STT_KEY(STATE_CAT, SYSCALL_OPENAT, 0), 1},
	/* touch */
	{STT_KEY(0, SYSCALL_OPENAT, FLAG_CREATE), 2},
	{STT_KEY(2, SYSCALL_CLOSE, 0), STATE_TOUCH},
	{STT_KEY(STATE_TOUCH, SYSCALL_OPENAT, FLAG_CREATE), 2},
	/* mkdir */
	{STT_KEY(0, SYSCALL_MKDIR, 0), STATE_MKDIR},
	{STT_KEY(STATE_MKDIR, SYSCALL_MKDIR, 0), STATE_MKDIR},
	/* rmdir */
	{STT_KEY(0, SYSCALL_RMDIR, 0), STATE_RMDIR},
	{STT_KEY(STATE_RMDIR, SYSCALL_RMDIR, 0), STATE_RMDIR},
	/* rm */
	{STT_KEY(0, SYSCALL_UNLINKAT, 0), STATE_RM},
	{STT_KEY(STATE_RM, SYSCALL_UNLINKAT, 0), STATE_RM},
	/* gzip */
	{STT_KEY(1, SYSCALL_OPENAT, FLAG_CREATE), 3},
	{STT_KEY(3, SYSCALL_WRITE, 0), 4},
	{STT_KEY(3, SYSCALL_CLOSE, 0), 5},
	{STT_KEY(4, SYSCALL_CLOSE, 0), 5},
	{STT_KEY(5, SYSCALL_UNLINKAT, 0), STATE_GZIP},
	{STT_KEY(STATE_GZIP, SYSCALL_OPENAT, FLAG_READ), 1},
};

static int event_handler(void *ctx, void *data, size_t data_sz) {
	const struct p_log_t *log = data;
	struct tm *tm_t;
    struct timeval time;
	struct passwd *user_info;

    gettimeofday(&time, NULL);
	/* 将 tm 结构体转换为时间戳并计算得到文件打开的时间 */
	__u64 timestap = time.tv_sec * 1000000 + time.tv_usec - log->life / 1000;
	char date_time[24];	// 存储日期时间 yyyy-MM-dd hh-mm-ss.nnn
	time.tv_sec = timestap / 1000000;
	time.tv_usec = timestap % 1000000;
	/* 对计算得到的时间转换为 Date-Time 的形式 */
    tm_t = localtime(&(time.tv_sec));
	sprintf(date_time, "%4d-%02d-%02d %02d:%02d:%02d.%03d",
			tm_t->tm_year + 1900, tm_t->tm_mon + 1, tm_t->tm_mday,
			tm_t->tm_hour, tm_t->tm_min, tm_t->tm_sec, time.tv_usec / 1000);

	char file_info_str[45];
	/* 格式化事件中的文件信息 */
	switch (log->info.type) {
	case S_IFSOCK:{
			unsigned char *from_ips = (unsigned char *) &(log->info.fp.socket.from_ip);
			unsigned char *to_ips = (unsigned char *) &(log->info.fp.socket.to_ip);
			sprintf(file_info_str, "%u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
			from_ips[3], from_ips[2], from_ips[1], from_ips[0], log->info.fp.socket.from_port,
			to_ips[3], to_ips[2], to_ips[1], to_ips[0], log->info.fp.socket.to_port);
		}
		break;
	default:
		sprintf(file_info_str, "%s:%u", log->info.fp.file.name, log->info.fp.file.i_ino);
		break;
	}

	user_info = getpwuid(log->uid);

	printf("%s %6u %6u %10s %32s(%s)\n  %44s %10s %8s %ld/%ld\n",
			date_time, log->ppid, log->pid, user_info->pw_name, log->comm, get_true_behave(log->state),
			file_info_str, get_filetype_str(log->info.type),
			get_operation_str(log->info.operation), log->info.rx, log->info.tx);
	
	return 0;
}

int main(int argc, char **argv) {
	struct panorama_bpf *skel;
	struct ring_buffer *rb = NULL;
	long err = 0;

	/* 设置 libbpf 打印错误和调试信息的回调函数 */
	libbpf_set_print(libbpf_print_fn);

	/* 处理用户的终止命令 Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = panorama_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* 将本程序的 pid 传入，防止监控自身行为 */
	__u16 index = 0;
	pid_t pid = getpid();
	err = bpf_map__update_elem(skel->maps.maps_self_pid, &index, sizeof(__u16), &pid,
				   sizeof(pid_t), BPF_NOEXIST);
	if (err < 0) {
		fprintf(stderr, "Error updating map with pid: %s\n", strerror(err));
		goto cleanup;
	}
	/* 将状态转移表更新到 bpf map 中 */
	long stt_size = sizeof(stt) / sizeof(struct __entry);
	for (int i = 0; i < stt_size; i++) {
		err = bpf_map__update_elem(skel->maps.maps_stt, &stt[i].key, sizeof(__u64), &stt[i].val,
					sizeof(__u32), BPF_NOEXIST);
		if (err < 0) {
			fprintf(stderr, "Error updating map, there may be duplicated stt items.\n");
			goto cleanup;
		}
	}
	/* 将需要过滤的进程哈希更新到 map 中 */
	long filter_size = sizeof(filter_entrys) / sizeof(const char *);
	__u8 dummy = 0;
	for (int i = 0; i < filter_size; i++) {
		__u64 hash_value = str_hash(filter_entrys[i]);
		bpf_map__update_elem(skel->maps.maps_filter_hash, &hash_value, sizeof(__u64), &dummy, sizeof(__u8), BPF_NOEXIST);
	}

	/* Attach tracepoint handler */
	err = panorama_bpf__attach(skel);
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
	panorama_bpf__destroy(skel);
	printf("\n");
	return -err;
}
