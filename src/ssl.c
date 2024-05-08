// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "ssl.h"
#include "ssl.skel.h"

typedef unsigned char   FMT_Byte;
typedef size_t          FMT_Size;
typedef size_t          FMT_Pos;

const char * const from[] = {"SSL_read", "SSL_write", "PR_Read", "PR_Write"};

void display(const FMT_Byte * const content, const FMT_Size len) {

    FMT_Pos index = 0;
	FMT_Size tmp_size = 0;
    while (index < len) {
        if (!(index & 0xf)) {
			tmp_size = 8;
			if (index > 0) {
				for (int i = index - 16; i < index; i++) {
					if (content[i] >= 32 && content[i] < 126) {
						printf("%c", content[i]);
					} else {
						printf(".");
					}
				}
				printf("\n");
			}
			printf("%06d  ", index);
		}
		printf("%02X", content[index]);
		tmp_size += 2;
		switch (index & 0x3)
		{
		case 0:
		case 2:
			printf("");
			break;
		case 1:
			printf(" ");
			tmp_size++;
			break;
		case 3:
			printf("  ");
			tmp_size += 2;
			break;
		}
		index++;
    }

	FMT_Size rest = index & 0xf;
	for (int i = 0; i < (52 - tmp_size); i++) printf(" ");
	for (int i = index - rest; i < index; i++) {
		if (content[i] >= 32 && content[i] < 126) {
			printf("%c", content[i]);
		} else {
			printf(".");
		}
	}
	printf("\n");
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct ssl_event *d = data;
	printf("[INFO] Get Data From Func \"%s\"\n", from[d->from]);
	display(d->content, d->size);
	return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct ssl_bpf *skel;
	int err, i;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = ssl_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Attach tracepoint handler */
	uprobe_opts.func_name = "SSL_read";
	uprobe_opts.retprobe = false;
	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. libbpf will automatically find the offset for us if we provide the
	 * function name. If the function name is not specified, libbpf will try
	 * to use the function offset instead.
	 */
	skel->links.uprobe_ssl_read = bpf_program__attach_uprobe_opts(skel->progs.uprobe_ssl_read,
								 -1 /* self pid */, "/usr/lib64/libssl.so.3",
								 0 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.uprobe_ssl_read) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	uprobe_opts.func_name = "SSL_write";
	uprobe_opts.retprobe = false;
	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. libbpf will automatically find the offset for us if we provide the
	 * function name. If the function name is not specified, libbpf will try
	 * to use the function offset instead.
	 */
	skel->links.uprobe_ssl_write = bpf_program__attach_uprobe_opts(skel->progs.uprobe_ssl_write,
								 -1 /* self pid */, "/usr/lib64/libssl.so.3",
								 0 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.uprobe_ssl_write) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	uprobe_opts.func_name = "PR_Read";
	uprobe_opts.retprobe = false;
	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. libbpf will automatically find the offset for us if we provide the
	 * function name. If the function name is not specified, libbpf will try
	 * to use the function offset instead.
	 */
	skel->links.uprobe_pr_recv = bpf_program__attach_uprobe_opts(skel->progs.uprobe_pr_recv,
								 -1 /* self pid */, "/usr/lib64/libnspr4.so",
								 0 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.uprobe_pr_recv) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	uprobe_opts.func_name = "PR_Write";
	uprobe_opts.retprobe = false;
	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. libbpf will automatically find the offset for us if we provide the
	 * function name. If the function name is not specified, libbpf will try
	 * to use the function offset instead.
	 */
	skel->links.uprobe_pr_send = bpf_program__attach_uprobe_opts(skel->progs.uprobe_pr_send,
								 -1 /* self pid */, "/usr/lib64/libnspr4.so",
								 0 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.uprobe_pr_send) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	uprobe_opts.func_name = "SSL_read";
	uprobe_opts.retprobe = true;
	skel->links.uretprobe_ssl_read = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_ssl_read, -1 /* self pid */, "/usr/lib64/libssl.so.3",
		0 /* offset for function */, &uprobe_opts /* opts */);
	if (!skel->links.uretprobe_ssl_read) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	uprobe_opts.func_name = "PR_Read";
	uprobe_opts.retprobe = true;
	skel->links.uretprobe_pr_recv = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_pr_recv, -1 /* self pid */, "/usr/lib64/libnspr4.so",
		0 /* offset for function */, &uprobe_opts /* opts */);
	if (!skel->links.uretprobe_pr_recv) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = ssl_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started!\n\n");

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
		sleep(1);
	}

cleanup:
	ring_buffer__free(rb);
	ssl_bpf__destroy(skel);
	return -err;
}
