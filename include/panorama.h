/*
 * Author: Xu.Cao
 * Created by steve on 1/8/23.
 */

#ifndef LOGGER_H
#define LOGGER_H

#define FLAGS_SUBMIT    0x00000001  // submit to the user space
#define FLAGS_DELAY     0x00000002  // copy the file name in `exit` but not `enter`
#define FLAGS_MAYOR     0x00000004  // copy the first file name
#define FLAGS_MINOR     0x00000008  // copy the second file name
#define FLAGS_MAY_FD    0x00000010  // copy the first file fd
#define FLAGS_MIN_FD    0x00000020  // copy the second file fd
#define FLAGS_NET_FD    0x00000040  // copy the socket fd
#define FLAGS_NET       0x00000080  // copy the net info
#define FLAGS_PARENT    0x00000100  // copy the net info to parent data and update
                                    // parent task's state
#define FLAGS_FINAL     0x00000200  // cope in `exit`
#define FLAGS_NEXT      0x00000400  // the next state transition must be caused
                                    // by the next sys_call.
//#define FLAGS_COM_FD    0x00000400  // compare with state's fds
#define FLAGS_COM_IO    0x00000800  // compare with standard input 0 and output 1
                                    // next time
#define FLAGS_CLR_MAY   0x00001000  // clear mayor info
#define FLAGS_CLR_MIN   0x00002000  // clear minor info
#define FLAGS_DLY_SMT   0x00004000  // submit at return
#define FLAGS_LST_SMT   0x00008000  // submit the last state

/* according to behaviors in the paper */
#define OP_CREATE   0x01
#define OP_REMOVE   0x02
#define OP_READ     0x03
#define OP_WRITE    0x04
#define OP_COVER    0x05
#define OP_SAVE     0x06
#define OP_COMPR    0x07
#define OP_UNZIP    0x08
#define OP_SPLIT    0x09
#define OP_MKDIR    0x0a
#define OP_RMDIR    0x0b
#define OP_LOGIN    0x0c
#define OP_UPLOAD   0x0d
// higher priority operation flags
#define OP_CREATE_PRI 0x81
#define OP_REMOVE_PRI 0x82
#define OP_READ_PRI   0x83
#define OP_WRITE_PRI  0x84
#define OP_COVER_PRI  0x85
#define OP_SAVE_PRI   0x86
#define OP_COMPR_PRI  0x87  // archive, like zip, unzip, gzip, etc.
#define OP_UNZIP_PRI  0x88
#define OP_SPLIT_PRI  0x89  // split the file
#define OP_MKDIR_PRI  0x8a
#define OP_RMDIR_PRI  0x8b
#define OP_LOGIN_PRI  0x8c
#define OP_UPLOAD_PRI 0x8d

#define STATE_START  0x0000
#define STATE_TOUCH  0x8000
#define STATE_RM     0x8001
#define STATE_MKDIR  0x8002
#define STATE_RMDIR  0x8003
#define STATE_CAT    0x8004
#define STATE_MV     0x8005
#define STATE_CP     0x8006
#define STATE_GZIP   0x8007
#define STATE_ZIP    0x8008
#define STATE_UNZIP  0x8009
#define STATE_SPLIT  0x800a
#define STATE_VI     0x800b
#define STATE_SSH    0x800c
#define STATE_SCP    0x800d

#define SYS_CALL_OPEN       0x00
#define SYS_CALL_OPENAT     0x01
#define SYS_CALL_DUP2       0x02
#define SYS_CALL_RENAME     0x03
#define SYS_CALL_RENAMEAT2  0x04
#define SYS_CALL_READ       0x05
#define SYS_CALL_WRITE      0x06
#define SYS_CALL_CLOSE      0x07
#define SYS_CALL_UNLINK     0x08
#define SYS_CALL_UNLINKAT   0x09
#define SYS_CALL_MKDIR      0x0a
#define SYS_CALL_RMDIR      0x0b
#define SYS_CALL_EXIT       0x0c
#define SYS_CALL_SOCKET     0x0d
#define SYS_CALL_CONNECT    0x0e

#define ARGS_EQL_SRC  0x0000000001
#define ARGS_EQL_DST  0x0000000002
#define ARGS_EQL_NET  0x0000000003
#define ARGS_EQL_IO   0x0000000004

#define FILL_STATE(stat, s, o, f) ({ \
    stat.state = s;                  \
    stat.operate = o;                \
    stat.flags = f;                  \
})
#define STATE(s, o, f) ( \
    (__u64)f << 32 |     \
    (__u64)o << 16 |     \
    s)
#define CALL_ARGS(c, a) ((u64)(c) << 40 | (a))
#define NET_ARGS(f, t) ((u64)(f) << 32 | t)
#define CHECK_FLAG(s, f) (!(((f) & ((s) >> 32)) ^ (f)))

struct file_t {
    int fd;
    __u32 i_ino;
    char name[32];
}; // 40B

union state_t {
    struct for_read_t {
        __u64 state: 16;    // current state of behavior
        __u64 operate: 8;   // this behavior runs in which way
        __u64 reserve: 8;   // reserve for latter use
        __u64 flags: 32;    // flags to show what to do after state transition
    } fr;
    __u64 for_assign;       // for a whole assignation
};  // 8B

struct net_t {
    int fd;
    u32 addr; // ip
    u32 port; // port
};  // 12B

struct behav_t {
    __u64 time; // time the last access
    __u32 ppid, pid;
    __u32 uid;  // which one do this behavior
    char comm[32];  // locate the task

    union state_t s;

    struct file_t f0, f1;

    struct net_t net;
    __u32 out_flag; // silence the next submit (push) if set 0
};  // 156B

#endif // LOGGER_H
