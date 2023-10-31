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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "config.h"
#include "process.h"
#include "panorama.h"
#include "panorama.skel.h"

static FILE* fp = NULL;

/* 保存当前程序是否正运行 */
static volatile bool is_running = true;
static void sig_handler(int sig) {
	is_running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

/* 状态转移表 */
struct __entry {
	__u64 key;
	__u32 val;
};

#ifdef __KERNEL_VERSION
#if __KERNEL_VERSION<508
static void event_handler(void *ctx, int cpu, void *data, unsigned int data_sz) {
#else
static int event_handler(void *ctx, void *data, size_t data_sz) {
#endif
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
	sprintf(date_time, "%4d-%02d-%02d %02d:%02d:%02d.%03ld",
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
		sprintf(file_info_str, "%s:%u", log->info.fp.regular.name,
										log->info.fp.regular.i_ino);
		break;
	}

	user_info = getpwuid(log->uid);
	/* 获取当前进程对应的行为，如果无法判断则不输出，否则输出为 proc(behavior) */
	char behavior[20] = {0};
	const char *true_behav = get_true_behave(log->state);
	if (true_behav[0] != '\0') {
		sprintf(behavior, "(%s)", true_behav);
	}
	/* 输出格式为：
	 * time ppid pid proccess[(behave)] operate type file:inode read/write */
	fprintf(fp, "%s %u %u %s %s%s %s %s %s %ld/%ld\n",
			date_time, log->ppid, log->pid, user_info->pw_name, log->comm,
			behavior, get_operation_str(log->info.operation),
			get_filetype_str(log->info.type), file_info_str,
			log->info.rx, log->info.tx);

#if __KERNEL_VERSION>=508
	return 0;
#endif
}
#endif	// __KERNEL_VERSION

#ifdef __KERNEL_VERSION
int main(int argc, char **argv) {
	struct panorama_bpf *skel;
#if __KERNEL_VERSION<508
	struct perf_buffer *rb = NULL;
#else
	struct ring_buffer *rb = NULL;
#endif
	long err = 0;

	/* 设置 libbpf 打印错误和调试信息的回调函数 */
	libbpf_set_print(libbpf_print_fn);

	/* 处理用户的终止命令 Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	#ifdef __DEBUG_MOD
	fp = stdout;
	#else
	fp = fopen("/var/log/panorama.log", "w");
	if (fp == NULL) {
		fprintf(stderr, "Log file open failed!\n");
		return 2;
	}
	#endif

	/* Load and verify BPF application */
	skel = panorama_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* 将状态转移表二进制文件中的内容读取并更新到 bpf map 中 */
	int stt_fd = open("stateTransitionTable.stt", O_RDONLY);
	if (-1 == stt_fd) {
		fprintf(stderr, "Failed to load the state transition table! No such file named stateTransitionTable.stt!\n");
		err = -1;
		goto cleanup;
	}
	struct __entry stt_entry;
	while ((err = read(stt_fd, &stt_entry, sizeof(stt_entry)))) {
		if (err == -1) {
			goto cleanup;
		}
		err = bpf_map__update_elem(skel->maps.maps_stt,
								   &stt_entry.key,
								   sizeof(__u64),
								   &stt_entry.val,
								   sizeof(__u32), BPF_NOEXIST);
		if (err < 0) {
			fprintf(stderr, "Error updating map, there may be duplicated stt items.\n");
			goto cleanup;
		}
	}
	close(stt_fd);
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

#if __KERNEL_VERSION<508
	rb = perf_buffer__new(bpf_map__fd(skel->maps.rb), 4, event_handler, NULL, NULL, NULL);
#else
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), event_handler, NULL, NULL);
#endif
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
#if __KERNEL_VERSION<508
		err = perf_buffer__poll(rb, 100 /* 超时时间，100 ms */);
#else
		err = ring_buffer__poll(rb, 100);
#endif
		/* Ctrl-C 会导致 -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %ld\n", err);
			break;
		}
	}

cleanup:
	panorama_bpf__destroy(skel);
	printf("\n");
	#ifndef __DEBUG_MOD
	fclose(fp);
	#endif
	return -err;
}
#endif
