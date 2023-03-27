/*
 * @date    2023-03-03.
 * @version v6.0.5.230307_alpha_a1_Xu.C
 * @author  Xu.Cao
 * @details define the state struct to save the behavior's semantics.
 *
 * @structures
 *      `struct state_t` is to save the state code, it represents the behavior's semantic state.
 *          `struct for_read_t` is easy to get the items in state.
 *      `struct net_t` is to save a socket, which is '(IP, port)'.
 *      `struct file_t` is to save a file's info, includes name and inode.
 *      `union detail_t` will save the object which task handles, and only save one of the file or socket.
 *      `struct behav_t` saves behavior's semantics, which includes resources info, task info, user info and state info.
 * @history
 *      <author>    <time>      <version>                       <description>
 *      Xu.Cao      2023-03-07  6.0.5.230307_alpha_a1_Xu.C     Add this comment
 */

#ifndef LOGGER_H
#define LOGGER_H


#define FLAG_FILE_NAME  0x00000001  // copy the file name
#define FLAG_SOCKET     0x00000002  // copy the socket
#define FLAG_FD         0x00000004  // copy the socket_fd
#define FLAG_PARENT     0x00000008  // copy the net info to parent data and update parent task's state
#define FLAG_SMT_CUR    0x00000010  // submit current state
#define FLAG_SMT_LST    0x00000020  // submit last state
#define FLAG_SMT_SOCK   0x00000040  // print network info (user space) if it is set and print file infos if not
#define FLAG_RNM_SRC    0x00000080  // whether output source name of rename will be print
#define FLAG_ACCEPT     0x00000100  // get a connection request from ebpf map and take over its ownership
#define FLAG_CHILD      0x00000200  // get a connection from ancestor

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
    __u64 for_assign;       // for easier assignation
};  // 8B

struct net_t {
    u32 addr; // ip
    u16 port; // port
};

struct peer_net_t {
    struct net_t local, remote;
};

union detail_t {
    struct file_t {
        __u32 i_ino;
        char name[32];
    } file; // 40B
    struct net_t remote;  // 12B
};

struct behav_t {
    __u64 time;     // time every time to operate the resource (file or socket)
    __u32 ppid, pid;
    __u32 uid;
    int fd;
    char comm[32];  // task / process name

    union state_t s;
    union detail_t detail;
    struct net_t local;
};  // 156B

#endif // LOGGER_H
