#include <bpf/libbpf.h>
#include <unistd.h>
#include "se.skel.h"
#include <stdio.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[]) {
    struct se_bpf *skel;
    long err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    // Loads and verifies the BPF program
    skel = se_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Attaches the loaded BPF program to the LSM hook
    err = se_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("LSM loaded! ctrl+c to exit.\n");

    // The BPF link is not pinned, therefore exiting will remove program
    // for (;;) {
    //     fprintf(stderr, ".");
    //     sleep(1);
    // }
    pid_t pid;
    unsigned long inode;
    while (true) {
        printf("Enter malicious pid and inode of file not to be executed: ");
        scanf("%d%lu", &pid, &inode);
        err = bpf_map__update_elem(skel->maps.maps_deny,
                                   &pid, sizeof(pid),
                                   &inode, sizeof(inode), BPF_NOEXIST);
    }

cleanup:
    se_bpf__destroy(skel);
    return err;
}