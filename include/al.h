/*
 * Author: Xu.Cao
 * Created by steve on 1/8/23.
 */

#ifndef ADVANCED_LOGGER_AL_H
#define ADVANCED_LOGGER_AL_H

//#include <uapi/linux/ptrace.h>
//#include <linux/dcache.h>

//#ifndef _LINUX_TYPES_H
//    typedef unsigned long long u64;
//    typedef unsigned long u32;
//    typedef unsigned short u16;
//    typedef unsigned char u8;
//#endif

/*
 * STT key (8B, u64)
 * +-------+----------+------+
 * |  2B   |    1B    |  5B  |
 * +-------+----------+------+
 * | STATE | SYS_CALL | ARGS |
 * +-------+----------+------+
 * STT value (8B, u64)
 * +---------+-------+-----------+-------+
 * |   1B    |  4B   |     1B    |   2B  |
 * +---------+-------+-----------+-------+
 * | RESERVE | FLAGS | OPERATION | STATE |
 * +---------+-------+-----------+-------+
 * RESERVE: reserve for former using.
 */
#define AL_FLAG_PSH              0x00000001 // push, urgent, debug, submit to userspace immediately.
#define AL_FLAG_CHK              0x00000002 // check, if the return value need to be checked, and delete data if invalid.
#define AL_FLAG_MAYOR_NAME       0x00000004 // get mayor name from args.
#define AL_FLAG_MINOR_NAME       0x00000008 // get minor name from args.
#define AL_FLAG_ARG_MAYOR_FD     0x00000010 // get mayor fd from args.
#define AL_FLAG_ARG_MINOR_FD     0x00000020 // get minor fd from args.
#define AL_FLAG_RET_MAYOR_FD     0x00000040 // get mayor fd from return value.
#define AL_FLAG_RET_MINOR_FD     0x00000080 // get minor fd from return value.
#define AL_FLAG_DELAY            0x00000100 // the name will be assigned when return.
#define AL_FLAG_ADDR             0x00000200 // get the address and port
#define AL_FLAG_PARENT           0x00000400 // copy the address and port to parent data.
#define AL_FLAG_FINAL_MEMO       0x00000800 // if this event be memoized in `exit()`

#define AL_FLAG_COMPARE_MAYOR_FD 0x00000001 // compare with mayor fd in args.
#define AL_FLAG_COMPARE_MINOR_FD 0x00000002 // compare with minor fd in args.

// definition of operations
#define AL_OP_CREATE 0x01
#define AL_OP_REMOVE 0x02
#define AL_OP_READ   0x03
#define AL_OP_WRITE  0x04
#define AL_OP_COVER  0x05
#define AL_OP_SAVE   0x06
#define AL_OP_COMPR   0x07
#define AL_OP_UNZIP 0x08
#define AL_OP_SPLIT  0x09
#define AL_OP_LOGIN  0x0a
#define AL_OP_UPLOAD 0x0b
// higher priority operation flags
#define AL_OP_CREATE_PRI 0x81
#define AL_OP_REMOVE_PRI 0x82
#define AL_OP_READ_PRI   0x83
#define AL_OP_WRITE_PRI  0x84
#define AL_OP_COVER_PRI  0x85
#define AL_OP_SAVE_PRI   0x86
#define AL_OP_COMPR_PRI   0x87  // archive, like zip, unzip, gzip, etc.
#define AL_OP_UNZIP_PRI   0x88
#define AL_OP_SPLIT_PRI  0x89  // split the file
#define AL_OP_LOGIN_PRI  0x8a
#define AL_OP_UPLOAD_PRI 0x8b
// end of definition of operations

// definition of states
#define AL_STATE_START  0x0000
#define AL_STATE_TOUCH  0x8000
#define AL_STATE_RM     0x8001
#define AL_STATE_MKDIR  0x8002
#define AL_STATE_RMDIR  0x8003
#define AL_STATE_CAT    0x8004
#define AL_STATE_MV     0x8005
#define AL_STATE_CP     0x8006
#define AL_STATE_GZIP   0x8007
#define AL_STATE_ZIP    0x8008
#define AL_STATE_UNZIP  0x8009
#define AL_STATE_SPLIT  0x800a
#define AL_STATE_VI     0x800b
#define AL_STATE_SSH    0x800c
#define AL_STATE_SCP    0x800d
// end of definition of states

// definition of id of sys_call
#define AL_SYS_CALL_OPEN    0x00
#define AL_SYS_CALL_OPENAT  0x01
#define AL_SYS_CALL_DUP2    0x02
#define AL_SYS_CALL_RENAME  0x03
#define AL_SYS_CALL_RENAMEAT2 0x04
#define AL_SYS_CALL_READ    0x05
#define AL_SYS_CALL_WRITE   0x06
#define AL_SYS_CALL_CLOSE   0x07
#define AL_SYS_CALL_UNLINK  0x08
#define AL_SYS_CALL_UNLINKAT 0x09
#define AL_SYS_CALL_MKDIR   0x0a
#define AL_SYS_CALL_RMDIR   0x0b
#define AL_SYS_CALL_EXIT    0x0c
#define AL_SYS_CALL_SOCKET  0x0d
#define AL_SYS_CALL_CONNECT 0x0e
// end of definition of sys_call's id

#define AL_ARGS_EQL_SRC  0x0000000001
#define AL_ARGS_EQL_DST  0x0000000002

#define NET_ARGS(p, t) (((u64)(p) << 32) | t)
#define STATE_KEY(s, c_a) (((u64)(s) << 48) | c_a)
#define STATE_FLAG_CHECK(s, f) (!(((f) & ((s) >> 24)) ^ (f)))
#define CALL_ARGS(c, a) (((u64)(c) << 40) | a)

struct omni_data_t {
    // These fields can be ascertained in INIT, which is called "fixed field".
    u64 time;       // time structure being initialized but not the task.
    u32 uid;
    u32 ppid, pid;
    char comm[32];  // task name
    // End of fixed field

    u64 state;  // 30+ states totally
    int fd;     // mayor fd, can be used as source or target file
    // src or the only one in non-net and socket in net
    // events capture.
    int aux_fd; // minor fd, dst file in non-net or maybe-existent
    // file in net events capture. (NET controls it)
    char name[32];
    union aux_data_t {
        char name[32];
        u64 net_info;    // port << 32 | addr
    } aux;
};  // 132B;

/*
* initialize the fixed fields (time, uid, pid, ppid, comm).
*/
static void init(struct omni_data_t *data, int pid, int ppid);
static void set_op(struct omni_data_t *data, u32 op);
static void set_state(struct omni_data_t *data, u32 state);
static void set_flag(struct omni_data_t *data, u32 flag);

static void init(struct omni_data_t *data, int pid, int ppid) {
    data->time = bpf_ktime_get_ns();
    data->uid = (u32) bpf_get_current_uid_gid();
    data->pid = pid;
    data->ppid = ppid;
    data->state = 0;
    bpf_get_current_comm(&(data->comm), 32);
}

static void set_op(struct omni_data_t *data, u32 op) {
    data->state = (data->state & 0xff00ffff) | ((op & 0xff) << 16);
}

static void set_state(struct omni_data_t *data, u32 state) {
    data->state = (data->state & 0xffff0000) | (state & 0xffff);
}

static void set_flag(struct omni_data_t *data, u32 flag) {
    data->state = (data->state & 0x00ffffff) | (flag << 24);
}

#endif //ADVANCED_LOGGER_AL_H
