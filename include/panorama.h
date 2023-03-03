/*
 * Author: Xu.Cao
 * Created by steve on 1/8/23.
 */

#ifndef LOGGER_H
#define LOGGER_H


#define FLAG_FILE_NAME  0x00000001  // copy the file name
#define FLAG_SOCKET     0x00000002  // copy the socket
#define FLAG_FD         0x00000004  // copy the socket_fd
#define FLAG_PARENT     0x00000008  // copy the net info to parent data and update
                                    // parent task's state
#define FLAG_SMT_CUR    0x00000010  // submit at return
#define FLAG_SMT_LST    0x00000020  // submit the last state
#define FLAG_SMT_SOCK   0x00000040  // 1 for net, 0 for file
#define FLAG_RNM_SRC    0x00000080  // whether output source name of rename
                                    // 'cause it is a special case
#define FLAG_ACCEPT     0x00000100  // get a accept request from map

/* according to behaviors in the paper */
#define OP_CREATE   0x01
#define OP_REMOVE   0x02
#define OP_READ     0x03
#define OP_WRITE    0x04
#define OP_COVER    0x05
#define OP_SAVE     0x06
#define OP_MKDIR    0x07
#define OP_RMDIR    0x08
#define OP_CONNECT  0x09
#define OP_ACCEPT   0x0a

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

#define SYS_CALL_OPENAT     0x00
#define SYS_CALL_DUP3       0x01
#define SYS_CALL_RENAMEAT   0x02
#define SYS_CALL_RENAMEAT2  0x03
#define SYS_CALL_READ       0x04
#define SYS_CALL_WRITE      0x05
#define SYS_CALL_CLOSE      0x06
#define SYS_CALL_UNLINKAT   0x07
#define SYS_CALL_MKDIRAT    0x08
#define SYS_CALL_EXIT_GROUP 0x09
#define SYS_CALL_SOCKET     0x0a
#define SYS_CALL_CONNECT    0x0b

#define ARGS_EQL_FD 0x0000000001
#define ARGS_EQL_IO 0x0000000002

#define CALL_ARGS(c, a) ((u64)(c) << 40 | (a))
#define NET_ARGS(f, t) ((u64)(f) << 32 | t)
#define CHECK_FLAG(s, f) (!(((f) & ((s) >> 32)) ^ (f)))

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
    u32 addr; // ip
    u16 port; // port
};

union detail_t {
    struct file_t {
        __u32 i_ino;
        char name[32];
    } file; // 40B
    struct net_t sock;  // 12B
};

struct behav_t {
    __u64 time; // time the last access
    __u32 ppid, pid;
    __u32 uid;  // which one do this behavior
    char comm[32];  // locate the task

    union state_t s;
    int fd;
    union detail_t detail;
};  // 156B

#endif // LOGGER_H
