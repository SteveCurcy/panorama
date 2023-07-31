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
} stt[] = {
	/* cat */
	// {STT_KEY(0, SYSCALL_OPENAT, 0), 1},
	// {STT_KEY(1, SYSCALL_CLOSE, 0), STATE_CAT},
	// {STT_KEY(STATE_CAT, SYSCALL_OPENAT, 0), 1},
	// /* touch */
	// {STT_KEY(0, SYSCALL_OPENAT, FLAG_CREATE), 2},
	// {STT_KEY(2, SYSCALL_CLOSE, 0), STATE_TOUCH},
	// {STT_KEY(STATE_TOUCH, SYSCALL_OPENAT, FLAG_CREATE), 2},
	// /* mkdir */
	// {STT_KEY(0, SYSCALL_MKDIR, 0), STATE_MKDIR},
	// {STT_KEY(STATE_MKDIR, SYSCALL_MKDIR, 0), STATE_MKDIR},
	// /* rmdir */
	// {STT_KEY(0, SYSCALL_RMDIR, 0), STATE_RMDIR},
	// {STT_KEY(STATE_RMDIR, SYSCALL_RMDIR, 0), STATE_RMDIR},
	// /* rm */
	// {STT_KEY(0, SYSCALL_UNLINKAT, 0), STATE_RM},
	// {STT_KEY(STATE_RM, SYSCALL_UNLINKAT, 0), STATE_RM},
	// /* gzip */
	// {STT_KEY(1, SYSCALL_OPENAT, FLAG_CREATE), 3},
	// {STT_KEY(3, SYSCALL_WRITE, 0), 4},
	// {STT_KEY(3, SYSCALL_CLOSE, 0), 5},
	// {STT_KEY(4, SYSCALL_CLOSE, 0), 5},
	// {STT_KEY(5, SYSCALL_UNLINKAT, 0), STATE_GZIP},
	// {STT_KEY(STATE_GZIP, SYSCALL_OPENAT, FLAG_READ), 1},
	// /* zip */
	// {STT_KEY(STATE_TOUCH, SYSCALL_UNLINK, 0), 6},
	// {STT_KEY(6, SYSCALL_OPENAT, FLAG_CREATE), 7},
	// {STT_KEY(7, SYSCALL_OPENAT, FLAG_READ), 8},
	// {STT_KEY(8, SYSCALL_CLOSE, 0), 9},
	// {STT_KEY(9, SYSCALL_OPENAT, FLAG_READ), 8},
	// {STT_KEY(9, SYSCALL_RENAME, 0), STATE_ZIP},
	{STT_KEY(0, SYSCALL_OPENAT, 0), 1},
{STT_KEY(1, SYSCALL_CLOSE, 0), 2},
{STT_KEY(2, SYSCALL_OPENAT, 0), 3},
{STT_KEY(3, SYSCALL_OPENAT, 3), 4},
{STT_KEY(4, SYSCALL_CLOSE, 0), 5},
{STT_KEY(5, SYSCALL_CLOSE, 0), 6},
{STT_KEY(6, SYSCALL_OPENAT, 0), 7},
{STT_KEY(7, SYSCALL_OPENAT, 3), 8},
{STT_KEY(8, SYSCALL_WRITE, 0), 9},
{STT_KEY(9, SYSCALL_CLOSE, 0), 10},
{STT_KEY(10, SYSCALL_CLOSE, 0), STATE_CP},
{STT_KEY(3, SYSCALL_OPENAT, 1), 11},
{STT_KEY(11, SYSCALL_CLOSE, 0), 12},
{STT_KEY(12, SYSCALL_CLOSE, 0), 13},
{STT_KEY(13, SYSCALL_OPENAT, 0), 14},
{STT_KEY(14, SYSCALL_OPENAT, 1), 15},
{STT_KEY(15, SYSCALL_WRITE, 0), 16},
{STT_KEY(16, SYSCALL_CLOSE, 0), 17},
{STT_KEY(17, SYSCALL_CLOSE, 0), STATE_CP},
{STT_KEY(3, SYSCALL_UNLINK, 0), 18},
{STT_KEY(18, SYSCALL_OPENAT, 1), 19},
{STT_KEY(19, SYSCALL_WRITE, 0), 20},
{STT_KEY(20, SYSCALL_CLOSE, 0), 21},
{STT_KEY(21, SYSCALL_OPENAT, 1), 22},
{STT_KEY(22, SYSCALL_WRITE, 0), 23},
{STT_KEY(23, SYSCALL_CLOSE, 0), 24},
{STT_KEY(24, SYSCALL_CLOSE, 0), STATE_UNZIP},
{STT_KEY(3, SYSCALL_CLOSE, 0), 25},
{STT_KEY(25, SYSCALL_OPENAT, 0), 26},
{STT_KEY(26, SYSCALL_CLOSE, 0), 27},
{STT_KEY(27, SYSCALL_OPENAT, 4), 28},
{STT_KEY(28, SYSCALL_CLOSE, 0), 29},
{STT_KEY(29, SYSCALL_OPENAT, 1), 30},
{STT_KEY(30, SYSCALL_OPENAT, 0), 31},
{STT_KEY(31, SYSCALL_OPENAT, 0), 32},
{STT_KEY(32, SYSCALL_CLOSE, 0), 33},
{STT_KEY(33, SYSCALL_WRITE, 0), 34},
{STT_KEY(34, SYSCALL_OPENAT, 0), 35},
{STT_KEY(35, SYSCALL_WRITE, 0), 36},
{STT_KEY(36, SYSCALL_CLOSE, 0), 37},
{STT_KEY(37, SYSCALL_WRITE, 0), 38},
{STT_KEY(38, SYSCALL_OPENAT, 0), 39},
{STT_KEY(39, SYSCALL_WRITE, 0), 40},
{STT_KEY(40, SYSCALL_CLOSE, 0), 41},
{STT_KEY(41, SYSCALL_WRITE, 0), 42},
{STT_KEY(42, SYSCALL_CLOSE, 0), 43},
{STT_KEY(43, SYSCALL_CLOSE, 0), 44},
{STT_KEY(44, SYSCALL_UNLINK, 0), 45},
{STT_KEY(45, SYSCALL_RENAME, 0), STATE_ZIP},
{STT_KEY(2, SYSCALL_OPENAT, 1), 46},
{STT_KEY(46, SYSCALL_CLOSE, 0), 47},
{STT_KEY(47, SYSCALL_UNLINK, 0), 48},
{STT_KEY(48, SYSCALL_OPENAT, 1), 49},
{STT_KEY(49, SYSCALL_OPENAT, 0), 50},
{STT_KEY(50, SYSCALL_CLOSE, 0), 51},
{STT_KEY(51, SYSCALL_WRITE, 0), 52},
{STT_KEY(52, SYSCALL_OPENAT, 0), 53},
{STT_KEY(53, SYSCALL_WRITE, 0), 54},
{STT_KEY(54, SYSCALL_CLOSE, 0), 55},
{STT_KEY(55, SYSCALL_WRITE, 0), 56},
{STT_KEY(56, SYSCALL_CLOSE, 0), 57},
{STT_KEY(57, SYSCALL_RENAME, 0), STATE_ZIP},
{STT_KEY(11, SYSCALL_WRITE, 0), 58},
{STT_KEY(58, SYSCALL_CLOSE, 0), 59},
{STT_KEY(59, SYSCALL_OPENAT, 1), 60},
{STT_KEY(60, SYSCALL_WRITE, 0), 61},
{STT_KEY(61, SYSCALL_CLOSE, 0), 62},
{STT_KEY(62, SYSCALL_OPENAT, 1), 63},
{STT_KEY(63, SYSCALL_WRITE, 0), 64},
{STT_KEY(64, SYSCALL_CLOSE, 0), 65},
{STT_KEY(65, SYSCALL_OPENAT, 1), 66},
{STT_KEY(66, SYSCALL_WRITE, 0), 67},
{STT_KEY(67, SYSCALL_CLOSE, 0), 68},
{STT_KEY(68, SYSCALL_CLOSE, 0), STATE_SPLIT},
{STT_KEY(1, SYSCALL_OPENAT, 1), 69},
{STT_KEY(69, SYSCALL_WRITE, 0), 70},
{STT_KEY(70, SYSCALL_CLOSE, 0), 71},
{STT_KEY(71, SYSCALL_CLOSE, 0), 72},
{STT_KEY(72, SYSCALL_UNLINKAT, 0), 73},
{STT_KEY(73, SYSCALL_OPENAT, 0), 74},
{STT_KEY(74, SYSCALL_OPENAT, 1), 75},
{STT_KEY(75, SYSCALL_CLOSE, 0), 76},
{STT_KEY(76, SYSCALL_CLOSE, 0), 77},
{STT_KEY(77, SYSCALL_UNLINKAT, 0), STATE_GZIP},
{STT_KEY(47, SYSCALL_OPENAT, 1), 78},
{STT_KEY(78, SYSCALL_CLOSE, 0), STATE_TOUCH},
{STT_KEY(2, SYSCALL_RENAMEAT2, 1), 79},
{STT_KEY(79, SYSCALL_RENAMEAT2, 1), STATE_MV},
{STT_KEY(2, SYSCALL_RENAME, 0), 80},
{STT_KEY(80, SYSCALL_RENAME, 0), STATE_MV},
{STT_KEY(2, SYSCALL_UNLINKAT, 0), 81},
{STT_KEY(81, SYSCALL_UNLINKAT, 0), STATE_RM},
{STT_KEY(2, SYSCALL_MKDIR, 0), 82},
{STT_KEY(82, SYSCALL_MKDIR, 0), STATE_MKDIR},
{STT_KEY(2, SYSCALL_RMDIR, 0), 83},
{STT_KEY(83, SYSCALL_RMDIR, 0), STATE_RMDIR},
{STT_KEY(75, SYSCALL_WRITE, 0), 84},
{STT_KEY(84, SYSCALL_CLOSE, 0), 85},
{STT_KEY(85, SYSCALL_CLOSE, 0), 86},
{STT_KEY(86, SYSCALL_UNLINKAT, 0), STATE_GZIP}
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

	fprintf(fp, "%s %6u %6u %10s %32s(%s)\n  %44s %10s %8s %ld/%ld\n",
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

	/* 将状态转移表更新到 bpf map 中 */
	long stt_size = sizeof(stt) / sizeof(struct __entry);
	for (int i = 0; i < stt_size; i++) {
		err = bpf_map__update_elem(skel->maps.maps_stt, &stt[i].key, sizeof(__u64), &stt[i].val,
					sizeof(__u32), BPF_NOEXIST);
		if (err < 0) {
			fprintf(stderr, "Error updating map, there may be duplicated stt items(%d).\n", i);
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
	#ifdef __DEBUG_MOD
	fclose(fp);
	#endif
	return -err;
}
