/*
 * Author: Xu.Cao
 * Created by steve on 1/8/23.
 */

#ifndef ADVANCED_LOGGER_EBPF_STRING_H
#define ADVANCED_LOGGER_EBPF_STRING_H

#define LENGTH_MAX 32   // equal to DNAME_INLINE_LEN

static int ebpf_strlen(const char* s);
static int hash_code(const char *s);
static void ebpf_strcat(char* dst, const char* src);
static void ebpf_strcpy(char* dst, const char* src);
static int ebpf_strcmp(const char *buff1, const char *buff2);

static int ebpf_strlen(const char* s) {
#pragma unroll(LENGTH_MAX)
    for (int i = 0; i < LENGTH_MAX; i++) {
        if (s[i] == '\0') {
            return i;
        }
    }
    return LENGTH_MAX;
}

static int hash_code(const char *s) {
    int h = 0;
    for (int i = 0; i < ebpf_strlen(s); i++) {
        h = (h << 5) - h + s[i];
    }
    return h;
}

static void ebpf_strcat(char* dst, const char* src) {
    int srclen = ebpf_strlen(src);
    int dstlen = ebpf_strlen(dst);

    if (srclen + dstlen >= sizeof(dst)) return;

    memcpy(dst + dstlen, src, LENGTH_MAX);
}

static void ebpf_strcpy(char* dst, const char* src) {
    int srclen = ebpf_strlen(src);
    memcpy(dst, src, srclen);
}

static int ebpf_strcmp(const char *buff1, const char *buff2) {
#pragma unroll (LENGTH_MAX)
    for (int i = 0; i < LENGTH_MAX; i++) {
        if (buff1[i] != buff2[i] || buff1[i] == '\0') {
            return (buff1[i] - buff2[i]);
        }
    }
    return 0;
}

#endif //ADVANCED_LOGGER_EBPF_STRING_H
