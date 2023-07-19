/* 
 * License-Identifier: BSD-3
 * Copyright (c) 2023 Steve.Curcy
 */
#ifndef PANORAMA_H
#define PANORAMA_H

#define STATE_START 0x0000
#define STATE_TOUCH 0x8000
#define STATE_RM 0x8001
#define STATE_MKDIR 0x8002
#define STATE_RMDIR 0x8003
#define STATE_CAT 0x8004
#define STATE_MV 0x8005
#define STATE_CP 0x8006
#define STATE_GZIP 0x8007
#define STATE_ZIP 0x8008
#define STATE_UNZIP 0x8009
#define STATE_SPLIT 0x800a
#define STATE_VI 0x800b
#define STATE_SSH 0x800c
#define STATE_SCP 0x800d

#define SYSCALL_OPENAT 0x00
#define SYSCALL_DUP2 0x01
#define SYSCALL_DUP3 0x02
#define SYSCALL_READ 0x03
#define SYSCALL_WRITE 0x04
#define SYSCALL_CLOSE 0x05
#define SYSCALL_UNLINK 0x06
#define SYSCALL_UNLINKAT 0x07
#define SYSCALL_MKDIR 0x08
#define SYSCALL_MKDIRAT 0x09
#define SYSCALL_RMDIR 0x0a
#define SYSCALL_RENAME 0x0b
#define SYSCALL_RENAMEAT 0x0c
#define SYSCALL_RENAMEAT2 0x0d
// #define SYSCALL_SOCKET 0x0e
#define SYSCALL_CONNECT 0x0f
/* 标识当前的内核版本号，必须指定，否则会报错；
 * xxxx 的形式指定，前两位为主版本号，后两位为此版本号 */
#define __KERNEL_VERSION 418

/* 补充 fcntl 中的标志位 */
#ifndef O_RDONLY
#define O_RDONLY	00000000
#endif
#ifndef O_WRONLY
#define O_WRONLY	00000001
#endif
#ifndef ORDWR
#define O_RDWR		00000002
#endif
#ifndef O_CREAT
#define O_CREAT		00000100	/* not fcntl */
#endif
#ifndef O_EXCL
#define O_EXCL		00000200	/* not fcntl */
#endif
#ifndef O_NOCTTY
#define O_NOCTTY	00000400	/* not fcntl */
#endif
#ifndef O_TRUNC
#define O_TRUNC		00001000	/* not fcntl */
#endif
#ifndef O_APPEND
#define O_APPEND	00002000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK	00004000
#endif
#ifndef O_DSYNC
#define O_DSYNC		00010000	/* used to be O_SYNC, see below */
#endif
#ifndef FASYNC
#define FASYNC		00020000	/* fcntl, for BSD compatibility */
#endif
#ifndef O_DIRECT
#define O_DIRECT	00040000	/* direct disk access hint */
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE	00100000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY	00200000	/* must be a directory */
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW	00400000	/* don't follow links */
#endif
#ifndef O_NOATIME
#define O_NOATIME	01000000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC	02000000	/* set close_on_exec */
#endif

/* 对文件的操作 */
#define OP_READ     0
#define OP_CREATE   1
#define OP_WRITE    2
#define OP_RDWR     3
#define OP_COVER    4   // 文件被覆盖，通常出现在移动操作中
#define OP_REMOVE   5
#define OP_TRANSMIT 6
#define OP_RECEIVE  7
#define OP_RXTX     8
#define OP_OPEN     9   // 用于目录打开

/* 状态转移表中的 flags 字段取值 */
/* openat 系统调用部分标志 */
#define FLAG_READ     0
#define FLAG_CREATE   1
#define FLAG_WRITE    2
#define FLAG_COVER    3   // 文件被覆盖，通常出现在移动操作中
#define FLAG_RDWR     4
#define FLAG_DIR	  5

/* 用于记录当前状态信息，使用位域来减少存储 */
struct p_state_t {
    __u32 state_code;   // 状态码，在状态机中的位置
    __u32 ppid;         // 父进程 pid，保存以节省再次获取的函数调用开销
};

/* 保存一个对等层的会话 socket，
 * 记录对等层的会话建立方向 */
struct p_socket_t {
    __u32 from_ip;
    __u32 to_ip;
    __u16 from_port;
    __u16 to_port;
};

/* 保存文件名及 inode 信息 */
struct p_common_file_t {
    char name[32];
    __u32 i_ino;
};

/* 用于保存通用文件形式；包括普通文件和网络文件 */
union p_file_t {
    struct p_common_file_t file;
    struct p_socket_t socket;
};

/* 保存文件信息，包括文件结构体
 * 收发的字节数，文件类型 */
struct p_finfo_t {
    union p_file_t fp;
    ssize_t rx, tx;
    __u64 open_time;
    __u32 operation;
    __u32 type;
    __u32 op_cnt;   // 被操作的次数
};

/* 日志类型，用于输出到用户空间并进行保存 */
struct p_log_t {
    __u64 life;
    __u32 ppid, pid;
    __u32 uid;
    __u32 state;
    char comm[32];
    struct p_finfo_t info;
};

/**
 * @param s 要计算哈希的字符串
 * @return 返回计算得到的哈希值
 */
static __u64 str_hash(const char *s) {
    __u64 _hash_value = 0;
#pragma unroll(32)
    for (int i = 0; i < 32; i++) {
        if (s[i] == '\0') break;
        _hash_value = _hash_value * 31 + s[i];
    }
    return _hash_value;
}

#define NEW_STATE(_s, _ppid, _code) \
    __builtin_memset(&(_s), 0, sizeof((_s)));   \
    (_s).ppid = (_ppid);                        \
    (_s).state_code = (_code)

#define STT_KEY(_oldcode, _sysid, _flags)\
    (((__u64) (_oldcode) << 32) |        \
    ((__u64) (_sysid) << 22) | (_flags) )

/* 文件类型，与 i_mode 中的文件类型表述相同 */
#define S_IFMT     0170000   // bit mask for the file type bit field
#define S_IFSOCK   0140000   // socket
#define S_IFLNK    0120000   // symbolic link
#define S_IFREG    0100000   // regular file
#define S_IFBLK    0060000   // block device
#define S_IFDIR    0040000   // directory
#define S_IFCHR    0020000   // character device
#define S_IFIFO    0010000   // FIFO
#define get_file_type_by_dentry(__dentry) \
    (S_IFMT & (BPF_CORE_READ((__dentry), d_inode, i_mode)))
#define get_file_type_by_path(__path) \
    (S_IFMT & (BPF_CORE_READ((__path), dentry, d_inode, i_mode)))

/* 通过操作字段获得操作名称的字符串 */
__always_inline static const char *get_operation_str(__u32 _operation_id) {
	switch (_operation_id) {
	case OP_CREATE: return "created";
	case OP_READ: return "read";
	case OP_WRITE: return "write";
	case OP_RDWR: return "rd&wr";
	case OP_COVER: return "covered";
	case OP_REMOVE: return "removed";
	case OP_TRANSMIT: return "transmit";
	case OP_RECEIVE: return "receive";
	case OP_RXTX: return "rx&tx";
	case OP_OPEN: return "open";
	default:
		break;
	}
    return "unkown";
}

__always_inline static const char *get_filetype_str(__u32 _filetype) {
	switch (_filetype) {
	case S_IFSOCK: return "socket";
	case S_IFLNK: return "soft link";
	case S_IFREG: return "regular";
	case S_IFBLK: return "block";
	case S_IFDIR: return "directory";
	case S_IFCHR: return "character";
	case S_IFIFO: return "fifo";
	default:
		break;
	}
    return "unkown";
}

__always_inline static const char *get_true_behave(__u32 state_code) {
	switch (state_code)
	{
	case STATE_CAT: return "cat";
	case STATE_TOUCH: return "touch";
	case STATE_RM: return "rm";
	case STATE_MKDIR: return "mkdir";
	case STATE_RMDIR: return "rmdir";
	case STATE_MV: return "mv";
	case STATE_CP: return "cp";
	case STATE_GZIP: return "gzip";
	case STATE_ZIP: return "zip";
	case STATE_UNZIP: return "unzip";
	case STATE_SPLIT: return "split";
	case STATE_VI: return "vi/vim";
	case STATE_SSH: return "ssh";
	case STATE_SCP: return "scp";
	default:
		break;
	}
    return "unkown";
}

static int bpf_strcmp(const char *s1, const char *s2) {
    int ret = 0;
#pragma unroll(32)
    for (int i = 0; i < 32; i++) {
        if (s1[i] == s2[i]) continue;
        return s1[i] - s2[i];
    }
    return 0;
}

#endif // PANORAMA_H
