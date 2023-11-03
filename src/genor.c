/**
 * @file 	genor.c
 * @author 	Xu.Cao
 * @version v1.5.3
 * @date 	2023-11-01
 * @details 本程序根据配置文件，捕获指定命令集的操作事件序列。
 *  事件序列将是生成状态转移表的基础，可以通过 sttGenor 生成
 *  对应的状态转移表。
 * @see 	genor.bpf.c, sttGenor.cpp
 * @history
 *  <author>    <time>    <version>    <desc>
 *  Xu.Cao      23/11/01    1.5.3    Format and Standardize this source
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
#include <linux/version.h>
#include "panorama.h"
#include "genor.skel.h"
#include "genor.h"

FILE *g_pfh_log = NULL;
bool g_debug_mod = false;
volatile bool g_is_running = true;

static void sig_handler(int sig) {
    g_is_running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

#if LINUX_VERSION < KERNEL_VERSION(5, 8, 0)
static void event_handler(void *ctx, int cpu, void *data, unsigned int data_sz) {
#else
static int event_handler(void *ctx, void *data, size_t data_sz) {
#endif
    struct sf_t *sf_ptr = (struct sf_t *)data;
    fprintf(g_pfh_log, "%u %s %u\n", sf_ptr->pid, sf_ptr->comm, sf_ptr->event);

#if LINUX_VERSION >= KERNEL_VERSION(5, 8, 0)
    return 0;
#endif
}

int main(int argc, char **argv) {
    struct genor_bpf *skel;
#if LINUX_VERSION < KERNEL_VERSION(5, 8, 0)
    struct perf_buffer *rb = NULL;
#else
    struct ring_buffer *rb = NULL;
#endif
    long err = 0;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = genor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    __u64 hash_value = 0;
    __u8 dummy = 0;
    FILE *pfh_cfg = fopen("./genor.ini", "r");
    if (!pfh_cfg) {
        pfh_cfg = fopen("../src/genor.ini", "r");
    }

    if (pfh_cfg) {
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
            } else if (sline[0] == 'c' && sline[1] == 'o' && sline[2] == 'n'
                       && sline[3] == 'c' && sline[4] == 'e' && sline[5] == 'r'
                       && sline[6] == 'n' && sline[7] == '[' && sline[8] == ']'
                       && sline[9] == '=') {
                hash_value = str_hash(sline + 10);
                err = bpf_map__update_elem(skel->maps.maps_cap_hash, &hash_value, sizeof(__u64), &dummy, sizeof(__u8), BPF_NOEXIST);
                if (err < 0) {
                    fprintf(stderr, "Error updating map, concerned process name not be updated.\n");
                    goto cleanup;
                }
            }
        }
        fclose(pfh_cfg);
    }

    if (g_debug_mod) {
        g_pfh_log = stdout;
    } else {
        g_pfh_log = fopen("/var/log/genor.log", "w");
        if (!g_pfh_log) {
            fprintf(stderr, "Failed to open log file!\n");
            err = 2;
            goto cleanup;
        }
    }

    err = genor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

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

    printf("Bpf programs have been attached successfully!\n");

    while (g_is_running) {
#if LINUX_VERSION < KERNEL_VERSION(5, 8, 0)
        err = perf_buffer__poll(rb, 100 /* 超时时间，100 ms */);
#else
        err = ring_buffer__poll(rb, 100);
#endif
        
        if (err == -EINTR) {	/* Ctrl-C 会导致 -EINTR */
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %ld\n", err);
            break;
        }
    }

cleanup:
    genor_bpf__destroy(skel);
    printf("\n");
    return -err;
}
