/*
 * @author  Xu.Cao
 * @date    2023-03-03.
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
 *      Xu.Cao      2023-03-07  6.0.5                           规范化注释文档
 *      Xu.Cao      2023-04-19  6.0.6                           修改了现有数据结构，修复了数据定义 bug
 *      Xu.Cao      2023-04-26  6.1.0                           删除宏定义部分，将宏定义交由用户空间程序决定
 */

#ifndef LOGGER_H
#define LOGGER_H

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
}; // 6B

struct peer_net_t {
    struct net_t local, remote;
};

union detail_t {
    struct file_t {
        __u32 i_ino;
        char name[32];
    } file; // 36B
    struct peer_net_t net;  // 12B
};

struct behav_t {
    __u64 time;     // time every time to operate the resource (file or socket)
    __u32 ppid, pid;
    __u32 uid;
    int fd;
    char comm[32];  // task / process name

    union state_t s;
    union detail_t detail;
};  // 156B

#endif // LOGGER_H
