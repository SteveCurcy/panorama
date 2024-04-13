#include <bpf/libbpf.h>
#include "se.skel.h"
#include "se.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

static int event_handler(void *ctx, void *data, size_t data_sz) {
    unsigned long long *log = data;
    printf("%u %u\n", *log >> 32, *log);
    return 0;
}

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

    pid_t pid = 0;
    char path[256];
    char permission[8];
    unsigned char dummy = 0;
    while (true) {
        printf("Enter malicious pid, target and permission: ");
        memset(path, 0, 256);   // Ensure the path will never be overwritten.
        memset(permission, 0, 8);
        scanf("%d %s %s", &pid, path, permission);

        struct stat st;
        if (stat(path, &st) == -1) {
            printf("There is no such file: %s\n", path);
            continue;
        }

        if (permission[3] != '\0') {
            printf("The permission of file can be 'rwx' at most!\n");
            continue;
        }

        // check every permission of input
        unsigned char real_permission = 0;
        unsigned char is_valid = 1;
        int per_len = strlen(permission);
        for (int i = 0; i < per_len; i++) {
            switch (permission[i]) {
            case 'r': real_permission |= MAY_READ; break;
            case 'w': real_permission |= MAY_WRITE; break;
            case 'x': real_permission |= MAY_EXEC; break;
            default:
                printf("No such permission named %c, only r/w/x is supported!\n", permission[i]);
                is_valid = 0;
                break;
            }
            if (!is_valid) break;
        }
        if (!is_valid) continue;
        
        // printf("%d,%s:%lu\n", pid, path, st.st_ino);
        unsigned long long key = ((unsigned long long)pid << 32) | st.st_ino;
        err = bpf_map__update_elem(skel->maps.maps_deny,
                                   &key, sizeof(key),
                                   &real_permission, sizeof(real_permission),
                                   BPF_ANY);    // add this rule even if overwrite
    	if (err < 0) {
    	    printf("Add the pid and inode failed!\n");
    	}
    }

    // >>>>>>>>> this part is for debugging >>>>>>>>>>
    /*struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), event_handler, NULL, NULL);
    if (!rb) {
	printf("Failed to create ring buffer!\n");
	goto cleanup;
    }

    while (1) {
    	err = ring_buffer__poll(rb, 100);
    	if (err == -EINTR) {
    	    err = 0;
    	    break;
    	}
    }*/
    // <<<<<<<<<<< end of debugging part <<<<<<<<<<<<<<<


cleanup:
    se_bpf__destroy(skel);
    return err;
}
