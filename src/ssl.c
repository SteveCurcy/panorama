// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
/**
 * The libssl.so* of openssl will be used as follows:
 * 
 * +----------+							+----------+
 * |  Client  |							|  Server  |
 * +----------+							+----------+
 * 		|								      |
 * 		|-------[ client_fd=connect() ]------>|  +----------+
 * 		|<------[ server_fd=accept()  ]-------|	-| syscalls |
 * 		|									  |	 +----------+
 *     [         SSL sub-process begin         ]
 * 		|									  |
 * 		|----[ Client initialize SSL env ]--->|		 +-------------------------------+
 * 		|<---[ Server initialize SSL env ]----|------| SSL_library_init();			 |
 * 		|									  |      | OpenSSL_add_all_algorithms(); |
 * 		|									  |      | SSL_load_error_strings();	 |
 * 		|----[ Client Create SSL session ]--->|		 +-------------------------------+
 * 		|<---[ Server Create SSL session ]----|\    +--------------------------------+
 * 		|									  | `---| SSL_CTX_new(method);			 |
 * 		|									  |     | SSL_CTX_use_certificate_file.. |
 * 		|									  |		| SSL_new(ctx), SSL_set_fd...	 |
 * 		|--[ SSL_connect() for shake hands ]->|		+--------------------------------+
 * 		|<-[ SSL_accept() for shake hands  ]--|
 * 		|									  |
 * 	   [         SSL sub-process ends          ]
 * 		|									  |
 * 		|--------[ SSL_write(data) ]--------->|
 * 		|<-------[ SSL_read(data)  ]----------|
 * 		|----------[ SSL_shutdown ]---------->|
 * 		|<---------[ SSL_shutdown ]-----------|
 * 		|--------------[ close ]------------->|
 * 		|<-------------[ close ]--------------|
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "ssl.h"
#include "ssl.skel.h"

typedef unsigned char FMT_Byte;
typedef size_t FMT_Size;
typedef size_t FMT_Pos;

const char *const from[] = {"SSL_read", "SSL_write", "PR_Read", "PR_Write"};

void display(const FMT_Byte *const content, const FMT_Size len)
{

	FMT_Pos index = 0;
	FMT_Size tmp_size = 0;
	while (index < len)
	{
		if (!(index & 0xf))
		{
			tmp_size = 8;
			if (index > 0)
			{
				for (int i = index - 16; i < index; i++)
				{
					if (content[i] >= 32 && content[i] < 126)
					{
						printf("%c", content[i]);
					}
					else
					{
						printf(".");
					}
				}
				printf("\n");
			}
			printf("%06ld  ", index);
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
	for (int i = 0; i < (52 - tmp_size); i++)
		printf(" ");
	for (int i = index - rest; i < index; i++)
	{
		if (content[i] >= 32 && content[i] < 126)
		{
			printf("%c", content[i]);
		}
		else
		{
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
	unsigned char *local_ips = (unsigned char *) &(d->sock.local_ip);
	unsigned char *remote_ips = (unsigned char *) &(d->sock.remote_ip);
	printf("[INFO] \033[32m%u.%u.%u.%u:%u\033[0m %s \033[33m%u.%u.%u.%u:%u\033[0m \033[34m%dB\033[0m\n", local_ips[3], local_ips[2], local_ips[1], local_ips[0], d->sock.local_port, d->from ? "\033[32m=>\033[0m" : "\033[33m<=\033[0m", remote_ips[3], remote_ips[2], remote_ips[1], remote_ips[0], d->sock.remote_port, d->size);
	display(d->content, d->size);
	return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

#define LIB_CNT 2

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct ssl_bpf *skel;
	int err, i;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	/* 先查找库文件，如果找不到则不监控 */
    /* 每个库可能存在多个副本，对所有链接库都 attach */
	FILE *fp;
	const char *const cmds[] = {"find /usr/lib* /lib* -name libssl.so*", "find /usr/lib* /lib* -name libnspr4.so"};
    int lib_copy_cnt[LIB_CNT] = {0};
	char lib_names[LIB_CNT][3][256] = {0};
	for (int i = 0; i < LIB_CNT; i++)
	{
		if ((fp = popen(cmds[i], "r")) == NULL)
		{
			perror("popen error");
			return 1;
		}
		while (1)
		{
			if (lib_copy_cnt[i] >= 3 || fgets(lib_names[i][lib_copy_cnt[i]], 256, fp) == NULL)
				break;
            size_t len = strlen(lib_names[i][lib_copy_cnt[i]]);
            if (len <= 3) {
                printf("[ERROR] Cannot find the relative library!\n");
                pclose(fp);
                return 2;
            }
            lib_names[i][lib_copy_cnt[i]][len - 1] = '\0';
            lib_copy_cnt[i]++;
		}
		if (pclose(fp) < 0)
		{
			perror("pclose error");
			return 1;
		}
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = ssl_bpf__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Attach tracepoint handler */
    /* Attach for libssl.so* */
    for (int i = 0; i < lib_copy_cnt[0]; i++)
    {
        uprobe_opts.func_name = "SSL_read";
        uprobe_opts.retprobe = false;
        skel->links.uprobe_ssl_read = bpf_program__attach_uprobe_opts(skel->progs.uprobe_ssl_read,
                                                                    -1, lib_names[0][i],
                                                                    0, &uprobe_opts);
        if (!skel->links.uprobe_ssl_read)
        {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }

        uprobe_opts.func_name = "SSL_read";
        uprobe_opts.retprobe = true;
        skel->links.uretprobe_ssl_read = bpf_program__attach_uprobe_opts(skel->progs.uretprobe_ssl_read,
                                                                        -1, lib_names[0][i],
                                                                        0, &uprobe_opts);
        if (!skel->links.uretprobe_ssl_read)
        {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }

        uprobe_opts.func_name = "SSL_write";
        uprobe_opts.retprobe = false;
        skel->links.uprobe_ssl_write = bpf_program__attach_uprobe_opts(skel->progs.uprobe_ssl_write,
                                                                    -1, lib_names[0][i],
                                                                    0, &uprobe_opts);
        if (!skel->links.uprobe_ssl_write)
        {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }

        uprobe_opts.func_name = "SSL_set_fd";
        uprobe_opts.retprobe = false;
        skel->links.uprobe_ssl_set_fd = bpf_program__attach_uprobe_opts(skel->progs.uprobe_ssl_set_fd,
                                                                    -1, lib_names[0][i],
                                                                    0, &uprobe_opts);
        if (!skel->links.uprobe_ssl_set_fd)
        {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }

        uprobe_opts.func_name = "SSL_shutdown";
        uprobe_opts.retprobe = false;
        skel->links.uprobe_ssl_shutdown = bpf_program__attach_uprobe_opts(skel->progs.uprobe_ssl_shutdown,
                                                                    -1, lib_names[0][i],
                                                                    0, &uprobe_opts);
        if (!skel->links.uprobe_ssl_shutdown)
        {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }
    }

    /* Attach for libnspr4.so */
    for (int i = 0; i < lib_copy_cnt[1]; i++)
    {
        uprobe_opts.func_name = "PR_Connect";
        uprobe_opts.retprobe = false;
        skel->links.uprobe_pr_connect = bpf_program__attach_uprobe_opts(skel->progs.uprobe_pr_connect,
                                                                    -1, lib_names[1][i],
                                                                    0, &uprobe_opts);
        if (!skel->links.uprobe_pr_connect)
        {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }

        uprobe_opts.func_name = "PR_Shutdown";
        uprobe_opts.retprobe = false;
        skel->links.uprobe_pr_shutdown = bpf_program__attach_uprobe_opts(skel->progs.uprobe_pr_shutdown,
                                                                    -1, lib_names[1][i],
                                                                    0, &uprobe_opts);
        if (!skel->links.uprobe_pr_shutdown)
        {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }

        uprobe_opts.func_name = "PR_Read";
        uprobe_opts.retprobe = false;
        skel->links.uprobe_pr_read = bpf_program__attach_uprobe_opts(skel->progs.uprobe_pr_read,
                                                                    -1 /* self pid */, lib_names[1][i],
                                                                    0 /* offset for function */,
                                                                    &uprobe_opts /* opts */);
        if (!skel->links.uprobe_pr_read)
        {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }

        uprobe_opts.func_name = "PR_Read";
        uprobe_opts.retprobe = true;
        skel->links.uretprobe_pr_read = bpf_program__attach_uprobe_opts(skel->progs.uretprobe_pr_read,
                                                                        -1 /* self pid */, lib_names[1][i],
                                                                        0 /* offset for function */,
                                                                        &uprobe_opts /* opts */);
        if (!skel->links.uretprobe_pr_read)
        {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }

        uprobe_opts.func_name = "PR_Write";
        uprobe_opts.retprobe = false;
        skel->links.uprobe_pr_write = bpf_program__attach_uprobe_opts(skel->progs.uprobe_pr_write,
                                                                    -1 /* self pid */, lib_names[1][i],
                                                                    0 /* offset for function */,
                                                                    &uprobe_opts /* opts */);
        if (!skel->links.uprobe_pr_write)
        {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }
    }

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = ssl_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started!\n\n");

	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
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
