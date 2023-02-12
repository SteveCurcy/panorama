#!/usr/bin/python
import ctypes as ct

from bcc import BPF
from bcc.utils import printb
import threading
import time
# import psutil
import socket
import struct

# definition of flags
AL_FLAG_PSH = 0x00000001  # push, urgent, debug, submit to userspace immediately.
AL_FLAG_CHK = 0x00000002  # check, if the return value need to be checked, and delete data if invalid.
AL_FLAG_MAYOR_NAME = 0x00000004  # get mayor name from args.
AL_FLAG_MINOR_NAME = 0x00000008  # get minor name from args.
AL_FLAG_ARG_MAYOR_FD = 0x00000010  # get mayor fd from args.
AL_FLAG_ARG_MINOR_FD = 0x00000020  # get minor fd from args.
AL_FLAG_RET_MAYOR_FD = 0x00000040  # get mayor fd from return value.
AL_FLAG_RET_MINOR_FD = 0x00000080  # get minor fd from return value.
AL_FLAG_DELAY = 0x00000100  # the name will be assigned when return.
AL_FLAG_ADDR = 0x00000200  # get the address and port.
AL_FLAG_PARENT = 0x00000400  # copy the address and port to parent data.
AL_FLAG_FINAL_MEMO = 0x00000800  # if this event be memoized in `exit()`

AL_FLAG_COMPARE_MAYOR_FD = 0x00000001  # compare with mayor fd in args.
AL_FLAG_COMPARE_MINOR_FD = 0x00000002  # compare with minor fd in args.
# end of definition of flags

# definition of operations
AL_OP_CREATE = 0x01
AL_OP_REMOVE = 0x02
AL_OP_READ = 0x03
AL_OP_WRITE = 0x04
AL_OP_COVER = 0x05
AL_OP_SAVE = 0x06
AL_OP_COMPR = 0x07
AL_OP_UNZIP = 0x08
AL_OP_SPLIT = 0x09
AL_OP_LOGIN = 0x0a
AL_OP_UPLOAD = 0x0b
# the operations defined below will be more powerful and higher priority
AL_OP_CREATE_PRI = 0x81
AL_OP_REMOVE_PRI = 0x82
AL_OP_READ_PRI = 0x83
AL_OP_WRITE_PRI = 0x84
AL_OP_COVER_PRI = 0x85
AL_OP_SAVE_PRI = 0x86
AL_OP_COMPR_PRI = 0x87  # archive, like zip, unzip, gzip, etc.
AL_OP_UNZIP_PRI = 0x88
AL_OP_SPLIT_PRI = 0x89  # split the file
AL_OP_LOGIN_PRI = 0x8a
AL_OP_UPLOAD_PRI = 0x8b
# end of definition of operations

# definition of states
AL_STATE_START = 0x0000
AL_STATE_TOUCH = 0x8000
AL_STATE_RM = 0x8001
AL_STATE_MKDIR = 0x8002
AL_STATE_RMDIR = 0x8003
AL_STATE_CAT = 0x8004
AL_STATE_MV = 0x8005
AL_STATE_CP = 0x8006
AL_STATE_GZIP = 0x8007
AL_STATE_ZIP = 0x8008
AL_STATE_UNZIP = 0x8009
AL_STATE_SPLIT = 0x800a
AL_STATE_VI = 0x800b
AL_STATE_SSH = 0x800c
AL_STATE_SCP = 0x800d
# end of definition of states

# definition of id of sys_call
AL_SYS_CALL_OPEN = 0x00
AL_SYS_CALL_OPENAT = 0x01
AL_SYS_CALL_DUP2 = 0x02
AL_SYS_CALL_RENAME = 0x03
AL_SYS_CALL_RENAMEAT2 = 0x04
AL_SYS_CALL_READ = 0x05
AL_SYS_CALL_WRITE = 0x06
AL_SYS_CALL_CLOSE = 0x07
AL_SYS_CALL_UNLINK = 0x08
AL_SYS_CALL_UNLINKAT = 0x09
AL_SYS_CALL_MKDIR = 0x0a
AL_SYS_CALL_RMDIR = 0x0b
AL_SYS_CALL_EXIT = 0x0c
AL_SYS_CALL_SOCKET = 0x0d
AL_SYS_CALL_CONNECT = 0x0e
# end of definition of sys_call's id

AL_ARGS_EQL_SRC = 0x0000000001
AL_ARGS_EQL_DST = 0x0000000002
AF_UNIX = 1
AF_INET = 2
SOCK_STREAM = 0o0000001
SOCK_NONBLOCK = 0o0004000
SOCK_CLOEXEC = 0o2000000
O_RDONLY = 0o00000000
O_WRONLY = 0o00000001
O_RDWR = 0o00000002
O_CREAT = 0o00000100
O_EXCL = 0o00000200
O_NOCTTY = 0o00000400
O_NONBLOCK = 0o00004000
O_TRUNC = 0o00001000
O_NOFOLLOW = 0o00400000


def stt_net(protocol: int, sock_type: int) -> int:
    return (protocol << 32) | sock_type


def stt_key(state: int, sys_call: int, args: int) -> int:
    return (state << 48) | (sys_call << 40) | args


def stt_val(flag: int, op: int, state: int) -> int:
    return (flag << 24) | (op << 16) | state


stt = {
    # open and open returning
    stt_key(AL_STATE_START, AL_SYS_CALL_OPEN, O_RDONLY): stt_val(
        AL_FLAG_CHK | AL_FLAG_MAYOR_NAME | AL_FLAG_RET_MAYOR_FD, 0, 1),
    stt_key(AL_STATE_START, AL_SYS_CALL_OPEN, O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK): stt_val(
        AL_FLAG_CHK | AL_FLAG_MAYOR_NAME | AL_FLAG_DELAY | AL_FLAG_RET_MAYOR_FD, 0, 10),
    stt_key(AL_STATE_START, AL_SYS_CALL_OPEN, O_RDWR | O_CREAT | O_EXCL): stt_val(AL_FLAG_RET_MINOR_FD, AL_OP_CREATE,
                                                                                  12),
    stt_key(1, AL_SYS_CALL_OPEN, O_WRONLY | O_CREAT | O_EXCL): stt_val(
        AL_FLAG_RET_MINOR_FD | AL_FLAG_MINOR_NAME | AL_FLAG_DELAY, AL_OP_CREATE, 2),
    stt_key(1, AL_SYS_CALL_OPEN, O_WRONLY | O_TRUNC): stt_val(AL_FLAG_RET_MINOR_FD | AL_FLAG_MINOR_NAME | AL_FLAG_DELAY,
                                                              AL_OP_COVER, 2),
    stt_key(6, AL_SYS_CALL_OPEN, O_WRONLY | O_CREAT | O_EXCL): stt_val(
        AL_FLAG_RET_MINOR_FD | AL_FLAG_MINOR_NAME | AL_FLAG_DELAY, AL_OP_COVER, 9),
    stt_key(6, AL_SYS_CALL_OPEN, O_WRONLY | O_TRUNC): stt_val(AL_FLAG_RET_MINOR_FD | AL_FLAG_MINOR_NAME | AL_FLAG_DELAY,
                                                              AL_OP_COVER, 9),
    stt_key(29, AL_SYS_CALL_OPEN, O_RDWR | O_CREAT | O_EXCL): stt_val(AL_FLAG_RET_MINOR_FD, AL_OP_COVER, 12),
    stt_key(6, AL_SYS_CALL_OPEN, O_RDWR | O_CREAT | O_EXCL): stt_val(AL_FLAG_RET_MINOR_FD, AL_OP_COVER, 12),
    stt_key(6, AL_SYS_CALL_OPEN, O_RDWR | O_CREAT | O_TRUNC): stt_val(
        AL_FLAG_MINOR_NAME | AL_FLAG_RET_MINOR_FD | AL_FLAG_DELAY, 0, 17),
    stt_key(12, AL_SYS_CALL_OPEN, O_RDONLY): stt_val(
        AL_FLAG_CHK | AL_FLAG_MAYOR_NAME | AL_FLAG_RET_MAYOR_FD | AL_FLAG_DELAY, 0, 13),
    stt_key(12, AL_SYS_CALL_OPEN, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW): stt_val(
        AL_FLAG_RET_MINOR_FD, 0, 16),
    stt_key(14, AL_SYS_CALL_OPEN, O_RDONLY): stt_val(
        AL_FLAG_CHK | AL_FLAG_DELAY | AL_FLAG_RET_MAYOR_FD | AL_FLAG_MAYOR_NAME, 0, 13),
    stt_key(16, AL_SYS_CALL_OPEN, O_RDONLY): stt_val(
        AL_FLAG_DELAY | AL_FLAG_MAYOR_NAME, 0, 23),
    stt_key(20, AL_SYS_CALL_OPEN, O_WRONLY | O_CREAT): stt_val(
        AL_FLAG_RET_MINOR_FD | AL_FLAG_MINOR_NAME | AL_FLAG_DELAY, 0, 21),
    stt_key(23, AL_SYS_CALL_OPEN, O_WRONLY | O_CREAT): stt_val(
        AL_FLAG_RET_MAYOR_FD | AL_FLAG_MAYOR_NAME | AL_FLAG_DELAY, 0, 25),
    stt_key(23, AL_SYS_CALL_OPEN, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW): stt_val(
        AL_FLAG_FINAL_MEMO, AL_OP_READ_PRI, AL_STATE_VI),
    stt_key(AL_STATE_VI, AL_SYS_CALL_OPEN, O_WRONLY | O_CREAT): stt_val(
        AL_FLAG_FINAL_MEMO | AL_FLAG_MAYOR_NAME | AL_FLAG_DELAY, AL_OP_SAVE_PRI, AL_STATE_VI),
    stt_key(AL_STATE_SSH, AL_SYS_CALL_OPEN, O_NONBLOCK): stt_val(
        AL_FLAG_FINAL_MEMO | AL_FLAG_DELAY | AL_FLAG_MAYOR_NAME | AL_FLAG_RET_MAYOR_FD, AL_OP_UPLOAD_PRI, AL_STATE_SCP),
    # openat and openat returning
    stt_key(AL_STATE_START, AL_SYS_CALL_OPENAT, O_RDONLY | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW): stt_val(
        AL_FLAG_MAYOR_NAME | AL_FLAG_RET_MAYOR_FD | AL_FLAG_DELAY, 0, 1),
    stt_key(1, AL_SYS_CALL_OPENAT, O_WRONLY | O_CREAT | O_EXCL): stt_val(
        AL_FLAG_RET_MINOR_FD | AL_FLAG_MINOR_NAME | AL_FLAG_DELAY, 0, 2),
    stt_key(6, AL_SYS_CALL_OPENAT, O_WRONLY | O_CREAT | O_EXCL): stt_val(
        AL_FLAG_RET_MINOR_FD | AL_FLAG_MINOR_NAME | AL_FLAG_DELAY, 0, 9),
    # dup2
    stt_key(1, AL_SYS_CALL_DUP2, 0): stt_val(AL_FLAG_ARG_MAYOR_FD, 0, 19),
    stt_key(10, AL_SYS_CALL_DUP2, 0): stt_val(0, 0, 11),
    # rename
    stt_key(AL_STATE_START, AL_SYS_CALL_RENAME, 0): stt_val(
        AL_FLAG_FINAL_MEMO | AL_FLAG_MAYOR_NAME | AL_FLAG_MINOR_NAME, AL_OP_COVER_PRI, AL_STATE_MV),
    stt_key(15, AL_SYS_CALL_RENAME, 0): stt_val(AL_FLAG_FINAL_MEMO | AL_FLAG_MINOR_NAME, AL_OP_COMPR, AL_STATE_ZIP),
    # renameat2 and returning
    stt_key(AL_STATE_START, AL_SYS_CALL_RENAMEAT2, 0): stt_val(
        AL_FLAG_FINAL_MEMO | AL_FLAG_CHK | AL_FLAG_DELAY | AL_FLAG_MAYOR_NAME | AL_FLAG_MINOR_NAME, AL_OP_CREATE,
        AL_STATE_MV),
    # read
    stt_key(1, AL_SYS_CALL_READ, AL_ARGS_EQL_SRC): stt_val(0, 0, 6),
    stt_key(2, AL_SYS_CALL_READ, AL_ARGS_EQL_SRC): stt_val(0, 0, 3),
    stt_key(13, AL_SYS_CALL_READ, AL_ARGS_EQL_SRC): stt_val(0, 0, 14),
    stt_key(19, AL_SYS_CALL_READ, AL_ARGS_EQL_SRC): stt_val(0, 0, 20),
    # write
    stt_key(3, AL_SYS_CALL_WRITE, AL_ARGS_EQL_DST): stt_val(0, 0, 4),
    # stt_key(12, AL_SYS_CALL_WRITE, AL_ARGS_EQL_DST): stt_val(0, 0, 23),
    stt_key(14, AL_SYS_CALL_WRITE, AL_ARGS_EQL_DST): stt_val(0, 0, 15),
    stt_key(17, AL_SYS_CALL_WRITE, AL_ARGS_EQL_DST): stt_val(0, 0, 18),
    stt_key(21, AL_SYS_CALL_WRITE, AL_ARGS_EQL_DST): stt_val(0, 0, 22),
    stt_key(25, AL_SYS_CALL_WRITE, AL_ARGS_EQL_SRC): stt_val(AL_FLAG_FINAL_MEMO, AL_OP_WRITE_PRI, AL_STATE_VI),
    # stt_key(24, AL_SYS_CALL_WRITE, AL_ARGS_EQL_SRC): stt_val(AL_FLAG_FINAL_MEMO, AL_OP_EDIT_PRI, AL_STATE_VI),
    # close
    stt_key(1, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_SRC): stt_val(0, 0, 0),
    stt_key(3, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_DST): stt_val(0, 0, 5),
    stt_key(4, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_DST): stt_val(0, 0, 5),
    stt_key(4, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_SRC): stt_val(0, 0, 7),
    stt_key(5, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_SRC): stt_val(AL_FLAG_FINAL_MEMO, AL_OP_CREATE, AL_STATE_CP),
    stt_key(25, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_SRC): stt_val(AL_FLAG_FINAL_MEMO, AL_OP_CREATE_PRI, AL_STATE_VI),
    stt_key(24, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_SRC): stt_val(AL_FLAG_FINAL_MEMO, AL_OP_READ_PRI, AL_STATE_VI),
    # stt_key(6, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_SRC): stt_val(0, 0, 6),
    stt_key(7, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_DST): stt_val(0, 0, 8),
    stt_key(9, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_SRC): stt_val(0, AL_OP_UNZIP, 7),
    stt_key(11, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_SRC): stt_val(AL_FLAG_FINAL_MEMO, AL_OP_CREATE, AL_STATE_TOUCH),
    stt_key(18, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_SRC): stt_val(AL_FLAG_FINAL_MEMO, AL_OP_UNZIP, AL_STATE_UNZIP),
    stt_key(22, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_DST): stt_val(AL_FLAG_PSH, AL_OP_SPLIT, 20),
    stt_key(22, AL_SYS_CALL_CLOSE, AL_ARGS_EQL_SRC): stt_val(AL_FLAG_FINAL_MEMO, AL_OP_SPLIT, AL_STATE_SPLIT),
    # unlinkat
    stt_key(AL_STATE_START, AL_SYS_CALL_UNLINKAT, 0): stt_val(AL_FLAG_MAYOR_NAME | AL_FLAG_PSH, AL_OP_REMOVE,
                                                              AL_STATE_RM),
    stt_key(AL_STATE_RM, AL_SYS_CALL_UNLINKAT, 0): stt_val(AL_FLAG_MAYOR_NAME | AL_FLAG_PSH,
                                                           AL_OP_REMOVE, AL_STATE_RM),
    stt_key(8, AL_SYS_CALL_UNLINKAT, 0): stt_val(AL_FLAG_FINAL_MEMO, AL_OP_COMPR, AL_STATE_GZIP),
    # mkdir
    stt_key(AL_STATE_START, AL_SYS_CALL_MKDIR, 0): stt_val(AL_FLAG_FINAL_MEMO | AL_FLAG_MAYOR_NAME, AL_OP_CREATE,
                                                           AL_STATE_MKDIR),
    # rmdir
    stt_key(AL_STATE_START, AL_SYS_CALL_RMDIR, 0): stt_val(AL_FLAG_FINAL_MEMO | AL_FLAG_MAYOR_NAME, AL_OP_REMOVE,
                                                           AL_STATE_RMDIR),
    # exit to end cat
    stt_key(6, AL_SYS_CALL_EXIT, 0): stt_val(AL_FLAG_FINAL_MEMO, AL_OP_READ, AL_STATE_CAT),
    # socket
    stt_key(6, AL_SYS_CALL_SOCKET, stt_net(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK)): stt_val(
        AL_FLAG_RET_MAYOR_FD | AL_FLAG_MAYOR_NAME, 0, 28),
    stt_key(29, AL_SYS_CALL_SOCKET, stt_net(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK)): stt_val(
        AL_FLAG_RET_MAYOR_FD, 0, 28),
    stt_key(29, AL_SYS_CALL_SOCKET, stt_net(AF_INET, SOCK_STREAM)): stt_val(
        AL_FLAG_RET_MAYOR_FD, 0, 30),
    # connect
    stt_key(28, AL_SYS_CALL_CONNECT, AL_ARGS_EQL_SRC): stt_val(
        0, 0, 29),
    stt_key(30, AL_SYS_CALL_CONNECT, AL_ARGS_EQL_SRC): stt_val(
        AL_FLAG_ADDR | AL_FLAG_PARENT | AL_FLAG_FINAL_MEMO, AL_OP_LOGIN, AL_STATE_SSH)
}

# boot_time = psutil.boot_time() * 1e9


# class DaemonForMap(threading.Thread):
#     def __init__(self, threadId: int, name: str, delay: float = 1):
#         super(DaemonForMap, self).__init__()
#         self.threadId = threadId
#         self.name = name
#         self.map = b["state_fir"]
#         self.timeout = 1e9  # 1s
#         self.delay = delay
#         self.threshfactor = 0.75
#         self.size = 4096
#         self.threshhold = self.size * self.threshfactor
#
#     def run(self):
#         while True:
#             time.sleep(self.delay)
#             # 查看是否需要进行清理
#             if len(self.map) < self.threshhold:
#                 continue
#             now = time.time_ns() - boot_time
#             for i in self.map:
#                 if now - self.map[i].time >= self.timeout:
#                     del self.map[i]


class AuxData(ct.Union):
    _fields_ = [("name", ct.c_char * 32),
                ("net_info", ct.c_ulonglong)]


class OmniData(ct.Structure):
    _fields_ = [("time", ct.c_uint64),
                ("uid", ct.c_uint32),
                ("ppid", ct.c_uint32),
                ("pid", ct.c_uint32),
                ("comm", ct.c_char * 32),
                ("state", ct.c_uint64),
                ("fd", ct.c_int),
                ("aux_fd", ct.c_int),
                ("name", ct.c_char * 32),
                ("aux", AuxData)]


prog = None
with open("behav.c") as f:
    prog = f.read()
# with open("net.c") as f:
#     prog += f.read()
if prog is None or prog == "":
    print("file open error")
    exit(-1)

b = BPF(text=prog)
b.attach_uprobe(name="c", sym="open", fn_name="do_open_entry")
b.attach_uprobe(name="c", sym="openat", fn_name="do_openat_entry")
b.attach_uprobe(name="c", sym="dup2", fn_name="do_dup2_entry")
b.attach_uprobe(name="c", sym="rename", fn_name="do_rename_entry")
b.attach_uprobe(name="c", sym="renameat2", fn_name="do_renameat2_entry")
b.attach_uprobe(name="c", sym="read", fn_name="do_read_entry")
b.attach_uprobe(name="c", sym="write", fn_name="do_write_entry")
b.attach_uprobe(name="c", sym="close", fn_name="do_close_entry")
b.attach_uprobe(name="c", sym="socket", fn_name="do_socket_entry")
b.attach_uprobe(name="c", sym="connect", fn_name="do_connect_entry")
# b.attach_uprobe(name="c", sym="unlink", fn_name="do_unlink_entry")
b.attach_uprobe(name="c", sym="unlinkat", fn_name="do_unlinkat_entry")
b.attach_uprobe(name="c", sym="mkdir", fn_name="do_mkdir_entry")
b.attach_uprobe(name="c", sym="rmdir", fn_name="do_rmdir_entry")
b.attach_uprobe(name="c", sym="exit", fn_name="do_exit_entry")
b.attach_uretprobe(name="c", sym="open", fn_name="do_open_return")
b.attach_uretprobe(name="c", sym="openat", fn_name="do_openat_return")
b.attach_uretprobe(name="c", sym="renameat2", fn_name="do_renameat2_return")
b.attach_uretprobe(name="c", sym="socket", fn_name="do_socket_return")

mp = b["STT_fir"]
for key, val in stt.items():
    current_key = mp.Key(key)
    current_val = mp.Leaf(val)
    mp[current_key] = current_val


def get_behavior(state: int) -> str:
    OP = (state & 0x0000000000ff0000) >> 16
    ret = ""
    if OP == AL_OP_READ or OP == AL_OP_READ_PRI:
        ret = "read"
    elif OP == AL_OP_WRITE or OP == AL_OP_WRITE_PRI:
        ret = "write"
    elif OP == AL_OP_COVER or OP == AL_OP_COVER_PRI:
        ret = "cover"
    elif OP == AL_OP_CREATE or OP == AL_OP_CREATE_PRI:
        ret = "create"
    elif OP == AL_OP_REMOVE or OP == AL_OP_REMOVE_PRI:
        ret = "remove"
    elif OP == AL_OP_SAVE or OP == AL_OP_SAVE_PRI:
        ret = "save"
    elif OP == AL_OP_COMPR or OP == AL_OP_COMPR_PRI:
        ret = "zip"
    elif OP == AL_OP_UNZIP or OP == AL_OP_UNZIP_PRI:
        ret = "unzip"
    elif OP == AL_OP_SPLIT or OP == AL_OP_SPLIT_PRI:
        ret = "split"
    elif OP == AL_OP_LOGIN or OP == AL_OP_LOGIN_PRI:
        ret = "login"
    elif OP == AL_OP_UPLOAD or OP == AL_OP_UPLOAD_PRI:
        ret = "upload"
    else:
        ret = "other"
    return ret


file_info = """{}\t{}\t{}\t\033[0;33;40m{}\033[0m\t{}\t{}\t{}\t{:X}"""
net_info = """{}\t{}\t{}\t\033[0;32;40m{}\033[0m\t{}\t{}:{}\t{}\t{:X}"""


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(OmniData)).contents
    # print("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:X}\t{:X}".format(event.ppid, event.pid, event.uid, event.comm.decode(),
    #                                                       get_behavior(event.state), event.name.decode(),
    #                                                       event.aux.name.decode(), event.state, event.time))
    state = event.state & 0x0000ffff
    if state < AL_STATE_SSH:
        print(file_info.format(event.ppid, event.pid, event.uid, event.comm.decode(),
                               get_behavior(event.state), event.name.decode(), event.aux.name.decode(), event.state))
    else:
        addr = event.aux.net_info & 0x00000000ffffffff
        port = (event.aux.net_info & 0x0000ffff00000000) >> 32
        print(net_info.format(event.ppid, event.pid, event.uid, event.comm.decode(),
                              get_behavior(event.state), socket.inet_ntoa(struct.pack('I', addr)),
                              socket.htons(port), event.name.decode(), event.state))


# daemon = DaemonForMap(1, "daemon")
# daemon.daemon = True
# daemon.start()
print("Bpf program loaded. Ctrl + C to stop...")
print("PPID\tPID\tUSER\tTASK\tTYPE")

b["perf_fir"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        exit(0)
