/* 
 * License-Identifier: BSD-3
 * Copyright (c) 2023 Steve.Curcy
 */
#ifndef PANORAMA_H
#define PANORAMA_H

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
#define SYSCALL_ACCEPT 0x0e
#define SYSCALL_CONNECT 0x0f
#define SYSCALL_EXIT_GROUP 0x10

/* 补充 fcntl 中的标志位 */
#ifndef O_RDONLY
#define O_RDONLY	00000000
#endif
#ifndef O_WRONLY
#define O_WRONLY	00000001
#endif
#ifndef O_RDWR
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
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200      /* unlinkat remove dir */
#endif

/* 状态转移触发事件，不再根据系统调用和参数的组合；
 * 根据系统调用和参数计算事件类型，根据类型转移，32bit */
#define PEVENT_OPEN_READ    0x00000000  // 只读
#define PEVENT_OPEN_WRITE   0x00000001  // 只写
#define PEVENT_OPEN_COVER   0x00000002  // 覆盖
#define PEVENT_OPEN_RDWR    0x00000003  // 既读又写
#define PEVENT_OPEN_CREAT   0x00000004  // 创建
#define PEVENT_OPEN_DIR     0x00000005  // 打开目录

/* 根据打开方式获取上述事件类型 */
static __u32 get_open_evnt(int flags) {
    if (flags & O_DIRECTORY) return PEVENT_OPEN_DIR;
    if (flags & O_CREAT) return PEVENT_OPEN_CREAT;
    if (flags & O_TRUNC) return PEVENT_OPEN_COVER;
    if (flags & O_WRONLY) return PEVENT_OPEN_WRITE;
    if (flags & O_RDWR) return PEVENT_OPEN_RDWR;
    return PEVENT_OPEN_READ;
}

#define PEVENT_READ         0x00000006
#define PEVENT_WRITE        0x00000007
#define PEVENT_CLOSE        0x00000008
#define PEVENT_UNLINK_FILE  0x00000009  // 删除文件，unlink 或 unlinkat 0
#define PEVENT_UNLINK_DIR   0x0000000a  // 删除目录，unlinkat 0x00 或 rmdir
#define PEVENT_MKDIR        0x0000000b  // 创建目录
#define PEVENT_RENAME       0x0000000c  // 重命名或移动
#define PEVENT_DUP          0x0000000d  // 复制文件描述符 dup
#define PEVENT_CONNECT      0x0000000e  // 连接建立
#define PEVENT_ACCEPT       0x0000000f  // 接受连接

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
#define OP_RENAMED  10  // 用于被重命名
#define OP_RENAMETO 11  // 用于重命名目标

/* 状态转移表中的 flags 字段取值 */
/* openat 系统调用部分标志 */
#define FLAG_READ     0
#define FLAG_CREATE   1
#define FLAG_WRITE    2
#define FLAG_COVER    3   // 文件被覆盖，通常出现在移动操作中
#define FLAG_RDWR     4
#define FLAG_DIR	  5

/* 用于记录当前状态信息 */
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

#define STT_KEY(_oldcode, _event)\
    (((__u64) (_oldcode) << 32) | (_event))

#define DE_KEY(_key, _oldcode, _event)\
    (_oldcode) = (_key) >> 32; \
    (_event) = (_key) & 0xffffffff

/* 文件类型，与 i_mode 中的文件类型表述相同 */
#ifndef S_IFMT
#define S_IFMT     0170000   // bit mask for the file type bit field
#endif
#ifndef S_IFSOCK
#define S_IFSOCK   0140000   // socket
#endif
#ifndef S_IFLNK
#define S_IFLNK    0120000   // symbolic link
#endif
#ifndef S_IFREG
#define S_IFREG    0100000   // regular file
#endif
#ifndef S_IFBLK
#define S_IFBLK    0060000   // block device
#endif
#ifndef S_IFDIR
#define S_IFDIR    0040000   // directory
#endif
#ifndef S_IFCHR
#define S_IFCHR    0020000   // character device
#endif
#ifndef S_IFIFO
#define S_IFIFO    0010000   // FIFO
#endif
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
    case OP_RENAMED: return "renamed";
    case OP_RENAMETO: return "rename-to";
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
