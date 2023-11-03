/**
 * @file 	panorama.c
 * @author 	Xu.Cao
 * @version v1.5.1
 * @date 	2023-10-31
 * @details 本源文件为 eBPF 的用户态程序源代码，负责将 panorama.bpf.c 文件
 * 	的钩子处理函数动态插入到内核中；还将内核程序捕获的日志读取并输出到指定的终端
 * 	或文件中。
 * 	
 * 	本程序将配置文件中希望忽略的进程名、状态转移表等更新到内核 eBPF MAP 数据结
 * 	构中。今后可能将完成一些对采集程序的控制工作。
 * @see 	panorama.bpf.c, sttGenor.cpp
 * @history
 *  <author>    <time>    <version>    <desc>
 *  Xu.Cao      23/10/31    1.5.1    Format and Standardize this source
 *  Xu.Cao      23/11/01    1.5.3    更新配置文件读取，实现简单配置文件处理
 *  Xu.Cao      23/11/03    1.5.4    更新了状态转移表元数据的读取，不再使用 process.h（因为会导致重新编译）
 */
#include <pwd.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/version.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
// #include "process.h"
#include "panorama.h"
#include "panorama.skel.h"

/* g_ 表示全局变量，pfh 表示文件句柄指针 */
FILE *g_pfh_log = NULL;
bool g_debug_mod = false;
volatile bool g_is_running = true;
char **g_behav_strs = NULL;
int g_behav_strs_len = 0;

static void sig_handler(int sig) {
    g_is_running = false;
}

/**
 * @brief  处理 libbpf 输出的回调函数
 * @param  level: 输出级别：警告、信息等
 * @param  format: 输出格式化模板
 * @param  args: 打印参数
 * @retval int 输出是否成功
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

/**
 * @brief  获取状态码对应的行为
 * @param  state_code: 状态码
 * @retval 行为字符串
 */
inline static const char *get_true_behave(__u32 state_code) {
    
    int idx = (int)(state_code & 0x7fffffff);
    if (idx < g_behav_strs_len) {
        return g_behav_strs[idx];
    }
    return NULL;
}

/**
 * @brief  处理内核 perf_event，格式化并输出日志
 * @note   日志格式主要包含：时间、进程号、用户名、进程名、行为、操作、文件类型、文件信息、读写数量
 * @param  ctx: 进程上下文
 * @param  cpu: perf_event 来自哪个 CPU
 * @param  data: 数据内容
 * @param  data_sz: 数据大小
 * @retval None
 */
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
    if (sbehav_output) {
        sprintf(sbehav, "(%s)", sbehav_output);
    }

    fprintf(g_pfh_log, "%s %u %u %s %s%s %s %s %s %ld/%ld\n",
            sdate_time, plog->ppid, plog->pid, pwd_info->pw_name, plog->comm,
            sbehav, get_operation_str(plog->info.operation),
            get_filetype_str(plog->info.type), sfinfo,
            plog->info.rx, plog->info.tx);

#if LINUX_VERSION >= KERNEL_VERSION(5, 8, 0)
    return 0;
#endif
}

int main(int argc, char **argv) {

    long err = 0;

    libbpf_set_print(libbpf_print_fn);  /* 设置 libbpf 打印错误和调试信息的回调函数 */

    signal(SIGINT, sig_handler);        /* 处理用户的终止命令 Ctrl-C */
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    struct panorama_bpf *skel = panorama_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    int fd_stt = open("stateTransitionTable.stt", O_RDONLY);
    if (fd_stt < 0) {
        fprintf(stderr, "Failed to load the state transition table! "\
                "No such file named stateTransitionTable.stt!\n");
        err = fd_stt;
        goto cleanup;
    }

    struct {
        __u64 key;
        __u32 val;
    } stt_entry;
    while ((err = read(fd_stt, &stt_entry, sizeof(stt_entry)))) {
        if (err == -1) {
            break;
        }
        err = bpf_map__update_elem(skel->maps.maps_stt, &stt_entry.key,
                                   sizeof(__u64), &stt_entry.val,
                                   sizeof(__u32), BPF_NOEXIST);
        if (err < 0) {
            fprintf(stderr, "Error updating map, there may be duplicated stt items.\n");
            break;
        }
    }
    close(fd_stt);
    if (err) {
        goto cleanup;
    }

    int fd_meta = open("meta.stt", O_RDONLY);
    if (fd_meta < 0) {
        fprintf(stderr, "Failed to load the stt meta file! \
                No such file named stateTransitionTable.stt!\n");
        err = fd_stt;
        goto cleanup;
    }

    read(fd_meta, &g_behav_strs_len, sizeof(g_behav_strs_len));
    g_behav_strs = (char **) malloc(sizeof(char *) * g_behav_strs_len);

    for (int i = 0; i < g_behav_strs_len; i++) {
        __u32 end_state;
        unsigned char str_len;
        read(fd_meta, &end_state, sizeof(end_state));
        read(fd_meta, &str_len, 1);

        int idx = (int)(end_state & 0x7fffffff);
        g_behav_strs[idx] = (char *) malloc(str_len + 1);
        memset(g_behav_strs[idx], 0, str_len + 1);
        read(fd_meta, g_behav_strs[idx], str_len);
    }
    close(fd_meta);

    /* 一定要确保自身不会被监控 */
    __u64 hash_value = str_hash("panorama");
    __u8 dummy = 0;
    bpf_map__update_elem(skel->maps.maps_filter_hash, &hash_value, sizeof(__u64),
                         &dummy, sizeof(__u8), BPF_NOEXIST);

    FILE *pfh_cfg = fopen("./panorama.ini", "r");
    if (!pfh_cfg) {
        pfh_cfg = fopen("../src/panorama.ini", "r");
    }

    if (pfh_cfg) {   /* 存在配置文件，则直接暴力读取即可，因为只有几类参数，没必要单独写一个库 */
        char sline[64] = {0};
        while (fgets(sline, 64, pfh_cfg)) {

            int len_line = strlen(sline);
            if (sline[len_line - 1] == '\n') {
                sline[len_line - 1] = '\0';
            }

            if (sline[0] == ';' || sline[0] == '#') {   // 忽略注释行
                continue;
            } else if (sline[0] == 'd' && sline[1] == 'e' && sline[2] == 'b'
                       && sline[3] == 'u' && sline[4] == 'g' && sline[5] == '=') {
                if (sline[6] == 't' && sline[7] == 'r'
                    && sline[8] == 'u' && sline[9] == 'e') {
                    g_debug_mod = true;
                }
            } else if (sline[0] == 'f' && sline[1] == 'i' && sline[2] == 'l'
                       && sline[3] == 't' && sline[4] == 'e' && sline[5] == 'r'
                       && sline[6] == '[' && sline[7] == ']' && sline[8] == '=') {
                hash_value = str_hash(sline + 9);
                err = bpf_map__update_elem(skel->maps.maps_filter_hash, &hash_value, 
                                           sizeof(__u64), &dummy, sizeof(__u8), BPF_NOEXIST);
                if (err < 0) {
                    fprintf(stderr, "Error updating map, ingnored process name not be updated.\n");
                    goto cleanup;
                }
            }
        }
        fclose(pfh_cfg);
    }

    if (g_debug_mod) {
        g_pfh_log = stdout;
    } else {
        g_pfh_log = fopen("/var/log/panorama.log", "w");
        if (!g_pfh_log) {
            fprintf(stderr, "Failed to open log file!\n");
            err = 2;
            goto cleanup;
        }
    }

    err = panorama_bpf__attach(skel);   /* Attach tracepoint handler */
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton!\n");
        goto cleanup;
    }

#if LINUX_VERSION < KERNEL_VERSION(5, 8, 0)
    struct perf_buffer *rb = NULL;
    rb = perf_buffer__new(bpf_map__fd(skel->maps.rb), 4, event_handler, NULL, NULL, NULL);
#else
    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), event_handler, NULL, NULL);
#endif
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Bpf programs have been attached successfully!\n");

    while (g_is_running) {
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

    if (!g_debug_mod && g_pfh_log) {
        fclose(g_pfh_log);
    }

    if (g_behav_strs) {
        for (int i = 0; i < g_behav_strs_len; i++) {
            free(g_behav_strs[i]);
        }
        free(g_behav_strs);
    }
    return -err;
}
