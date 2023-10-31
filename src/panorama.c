/**
 * @file 	panorama.bpf.c
 * @author 	Xu.Cao
 * @version v1.5.1
 * @date 	2023-10-31
 * @details 本源文件为 eBPF 的用户态程序源代码，负责将 panorama.bpf.c 文件
 * 	的钩子处理函数动态插入到内核中；还将内核程序捕获的日志读取并输出到指定的终端
 * 	或文件中。
 * 	
 * 	本程序将配置文件中希望忽略的进程名、状态转移表等更新到内核 eBPF MAP 数据结
 * 	构中。今后可能将完成一些对采集程序的控制工作。
 * @see 	panorama.bpf.c
 * @history
 *  <author>    <time>    <version>    <desc>
 *  Xu.Cao      23/10/31    1.5.1    Format and Standardize this source
 */
#include <pwd.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/version.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "config.h"
#include "process.h"
#include "panorama.h"
#include "panorama.skel.h"

FILE *fp = NULL;

volatile bool is_running = true;
static void sig_handler(int sig) {
    is_running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

struct __entry {
    __u64 key;
    __u32 val;
};

#if LINUX_VERSION < KERNEL_VERSION(5, 8, 0)
static void event_handler(void *ctx, int cpu, void *data, unsigned int data_sz) {
#else
static int event_handler(void *ctx, void *data, size_t data_sz) {
#endif
    const struct p_log_t *plog = data;
    struct tm *ptm;
    struct timeval time_open;
    struct passwd *pwd_info;

    gettimeofday(&time_open, NULL);
    
    __u64 timestap_open = time_open.tv_sec * 1000000 + time_open.tv_usec - plog->life / 1000;
    char sdate_time[24];	// 存储日期时间 yyyy-MM-dd hh-mm-ss.nnn
    time_open.tv_sec = timestap_open / 1000000;
    time_open.tv_usec = timestap_open % 1000000;

    ptm = localtime(&(time_open.tv_sec));
    sprintf(sdate_time, "%4d-%02d-%02d %02d:%02d:%02d.%03ld",
            ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
            ptm->tm_hour, ptm->tm_min, ptm->tm_sec, time_open.tv_usec / 1000);

    char sfinfo[45];
    switch (plog->info.type) {
    case S_IFSOCK: {
        unsigned char *from_ips = (unsigned char *) &(plog->info.fp.socket.from_ip);
        unsigned char *to_ips = (unsigned char *) &(plog->info.fp.socket.to_ip);
        sprintf(sfinfo, "%u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
                from_ips[3], from_ips[2], from_ips[1], from_ips[0],
                plog->info.fp.socket.from_port, to_ips[3], to_ips[2],
                to_ips[1], to_ips[0], plog->info.fp.socket.to_port);
    }   break;
    default:
        sprintf(sfinfo, "%s:%u", plog->info.fp.regular.name,
                                 plog->info.fp.regular.i_ino);
        break;
    }

    pwd_info = getpwuid(plog->uid);

    char sbehav[20] = {0};
    const char *sbehav_output = get_true_behave(plog->state);
    if (sbehav_output[0] != '\0') {
        sprintf(sbehav, "(%s)", sbehav_output);
    }

    fprintf(fp, "%s %u %u %s %s%s %s %s %s %ld/%ld\n",
            sdate_time, plog->ppid, plog->pid, pwd_info->pw_name, plog->comm,
            sbehav, get_operation_str(plog->info.operation),
            get_filetype_str(plog->info.type), sfinfo,
            plog->info.rx, plog->info.tx);

#if LINUX_VERSION >= KERNEL_VERSION(5, 8, 0)
    return 0;
#endif
}

int main(int argc, char **argv) {

    struct panorama_bpf *skel;
#if LINUX_VERSION < KERNEL_VERSION(5, 8, 0)
    struct perf_buffer *rb = NULL;
#else
    struct ring_buffer *rb = NULL;
#endif
    long err = 0;

    libbpf_set_print(libbpf_print_fn);  /* 设置 libbpf 打印错误和调试信息的回调函数 */

    signal(SIGINT, sig_handler);        /* 处理用户的终止命令 Ctrl-C */
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

    skel = panorama_bpf__open_and_load();   /* Load and verify BPF application */
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

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

    long filter_size = sizeof(filter_entrys) / sizeof(const char *);
    __u8 dummy = 0;
    for (int i = 0; i < filter_size; i++) {
        __u64 hash_value = str_hash(filter_entrys[i]);
        bpf_map__update_elem(skel->maps.maps_filter_hash, &hash_value, sizeof(__u64), &dummy, sizeof(__u8), BPF_NOEXIST);
    }

    err = panorama_bpf__attach(skel);   /* Attach tracepoint handler */
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Bpf programs have been attached successfully!\n");

#if LINUX_VERSION < KERNEL_VERSION(5, 8, 0)
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
#if LINUX_VERSION < KERNEL_VERSION(5, 8, 0)
        err = perf_buffer__poll(rb, 100 /* 超时时间，100 ms */);
#else
        err = ring_buffer__poll(rb, 100);
#endif
        if (err == -EINTR) {    /* Ctrl-C 会导致 -EINTR */
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
