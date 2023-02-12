#!/bin/env python

from bcc import BPF
import ctypes as ct
import socket
import struct

FLAG_SUBMIT = 0x00000001  # push, urgent, debug, submit to userspace immediately.
FLAG_DELAY = 0x00000002  # the name will be assigned when return.
FLAG_MAYOR = 0x00000004  # get mayor name from args.
FLAG_MINOR = 0x00000008  # get minor name from args.
FLAG_MAY_FD = 0x00000010  # get mayor fd.
FLAG_MIN_FD = 0x00000020  # get minor fd.
FLAG_NET_FD = 0x00000040  # get socket fd.
FLAG_NET = 0x00000080  # get the address and port.
FLAG_PARENT = 0x00000100  # copy the address and port to parent data.
FLAG_FINAL = 0x00000200  # if this event be memoized in `exit()`
FLAGS_NEXT = 0x00000400
FLAGS_COM_IO = 0x00000800
FLAGS_CLR_MAY = 0x00001000
FLAGS_CLR_MIN = 0x00002000
FLAGS_DLY_SMT = 0x00004000
FLAGS_LST_SMT = 0x00008000

OP_CREATE = 0x01
OP_REMOVE = 0x02
OP_READ = 0x03
OP_WRITE = 0x04
OP_COVER = 0x05
OP_SAVE = 0x06
OP_COMPR = 0x07
OP_UNZIP = 0x08
OP_SPLIT = 0x09
OP_MKDIR = 0x0a
OP_RMDIR = 0x0b
OP_LOGIN = 0x0c
OP_UPLOAD = 0x0d
OP_CREATE_PRI = 0x81
OP_REMOVE_PRI = 0x82
OP_READ_PRI = 0x83
OP_WRITE_PRI = 0x84
OP_COVER_PRI = 0x85
OP_SAVE_PRI = 0x86
OP_COMPR_PRI = 0x87
OP_UNZIP_PRI = 0x88
OP_SPLIT_PRI = 0x89
OP_MKDIR_PRI = 0x8a
OP_RMDIR_PRI = 0x8b
OP_LOGIN_PRI = 0x8c
OP_UPLOAD_PRI = 0x8d

STATE_START = 0x0000
STATE_TOUCH = 0x8000
STATE_RM = 0x8001
STATE_MKDIR = 0x8002
STATE_RMDIR = 0x8003
STATE_CAT = 0x8004
STATE_MV = 0x8005
STATE_CP = 0x8006
STATE_GZIP = 0x8007
STATE_ZIP = 0x8008
STATE_UNZIP = 0x8009
STATE_SPLIT = 0x800a
STATE_VI = 0x800b
STATE_SSH = 0x800c
STATE_SCP = 0x800d

SYS_CALL_OPEN = 0x00
SYS_CALL_OPENAT = 0x01
SYS_CALL_DUP2 = 0x02
SYS_CALL_RENAME = 0x03
SYS_CALL_RENAMEAT2 = 0x04
SYS_CALL_READ = 0x05
SYS_CALL_WRITE = 0x06
SYS_CALL_CLOSE = 0x07
SYS_CALL_UNLINK = 0x08
SYS_CALL_UNLINKAT = 0x09
SYS_CALL_MKDIR = 0x0a
SYS_CALL_RMDIR = 0x0b
SYS_CALL_EXIT = 0x0c
SYS_CALL_SOCKET = 0x0d
SYS_CALL_CONNECT = 0x0e

ARGS_EQL_SRC = 0x0000000001
ARGS_EQL_DST = 0x0000000002
ARGS_EQL_NET = 0x0000000003
ARGS_EQL_IO = 0x0000000004
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
    return (flag << 32) | (op << 16) | state


stt = {
    # cat
    stt_key(STATE_START, SYS_CALL_OPEN, O_RDONLY): stt_val(FLAG_DELAY | FLAG_MAYOR | FLAG_MAY_FD, 0, 1),
    stt_key(1, SYS_CALL_READ, ARGS_EQL_SRC): stt_val(FLAGS_NEXT | FLAGS_COM_IO, 0, 2),
    stt_key(2, SYS_CALL_WRITE, ARGS_EQL_IO): stt_val(0, 0, 3),
    stt_key(3, SYS_CALL_CLOSE, ARGS_EQL_SRC): stt_val(FLAG_FINAL, OP_READ, STATE_CAT),
    # gzip for multiple files
    stt_key(STATE_START, SYS_CALL_OPENAT, O_NOCTTY | O_NONBLOCK | O_NOFOLLOW):  # this for intel
        stt_val(FLAGS_NEXT | FLAG_DELAY | FLAG_MAYOR | FLAG_MAY_FD, 0, 4),
    stt_key(STATE_START, SYS_CALL_OPENAT, 0o104400):  # this item is for arm (M2 chip)
        stt_val(FLAGS_NEXT | FLAG_DELAY | FLAG_MAYOR | FLAG_MAY_FD, 0, 4),
    stt_key(STATE_GZIP, SYS_CALL_OPENAT, O_NOCTTY | O_NONBLOCK | O_NOFOLLOW):  # this for intel
        stt_val(FLAG_DELAY | FLAG_MAYOR | FLAG_MAY_FD | FLAG_SUBMIT, 0, 4),
    stt_key(STATE_GZIP, SYS_CALL_OPENAT, 0o104400):  # this item is for arm
        stt_val(FLAG_DELAY | FLAG_MAYOR | FLAG_MAY_FD | FLAG_SUBMIT, 0, 4),
    stt_key(4, SYS_CALL_READ, ARGS_EQL_SRC): stt_val(0, OP_UNZIP, 6),
    stt_key(4, SYS_CALL_OPENAT, O_WRONLY | O_CREAT | O_EXCL): stt_val(FLAG_MINOR | FLAG_DELAY, OP_COMPR, 5),
    stt_key(6, SYS_CALL_OPENAT, O_WRONLY | O_CREAT | O_EXCL): stt_val(FLAG_MINOR | FLAG_DELAY, 0, 7),
    stt_key(5, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_FINAL, 0, STATE_GZIP),
    stt_key(7, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_FINAL, 0, STATE_GZIP),
    # mkdir and rmdir some directories
    stt_key(STATE_START, SYS_CALL_MKDIR, 0): stt_val(FLAG_MINOR | FLAGS_DLY_SMT, OP_MKDIR, STATE_MKDIR),
    stt_key(STATE_MKDIR, SYS_CALL_MKDIR, 0): stt_val(FLAG_MINOR | FLAGS_DLY_SMT, OP_MKDIR, STATE_MKDIR),
    stt_key(STATE_START, SYS_CALL_RMDIR, 0): stt_val(FLAG_MAYOR | FLAGS_DLY_SMT, OP_RMDIR, STATE_RMDIR),
    stt_key(STATE_RMDIR, SYS_CALL_RMDIR, 0): stt_val(FLAG_MAYOR | FLAGS_DLY_SMT, OP_RMDIR, STATE_RMDIR),
    # rm files
    stt_key(STATE_START, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_MAYOR | FLAGS_DLY_SMT, OP_REMOVE, STATE_RM),
    stt_key(STATE_RM, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_MAYOR | FLAGS_DLY_SMT, OP_REMOVE, STATE_RM),
    # split
    stt_key(1, SYS_CALL_DUP2, ARGS_EQL_SRC): stt_val(FLAG_MAY_FD, 0, 8),
    stt_key(8, SYS_CALL_OPEN, O_CREAT | O_WRONLY): stt_val(FLAG_MIN_FD | FLAG_MINOR | FLAG_DELAY, 0, 9),
    stt_key(9, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAG_FINAL, OP_SPLIT, STATE_SPLIT),
    stt_key(STATE_SPLIT, SYS_CALL_OPEN, O_CREAT | O_WRONLY):
        stt_val(FLAG_SUBMIT | FLAG_MIN_FD | FLAG_MINOR | FLAG_DELAY, 0, 9),
    # touch
    stt_key(STATE_START, SYS_CALL_OPEN, O_NONBLOCK | O_NOCTTY | O_CREAT | O_WRONLY):
        stt_val(FLAG_MINOR | FLAG_MIN_FD | FLAG_DELAY, 0, 10),
    stt_key(STATE_TOUCH, SYS_CALL_OPEN, O_NONBLOCK | O_NOCTTY | O_CREAT | O_WRONLY):
        stt_val(FLAGS_LST_SMT | FLAG_MINOR | FLAG_MIN_FD | FLAG_DELAY, 0, 10),
    stt_key(10, SYS_CALL_DUP2, ARGS_EQL_DST): stt_val(FLAG_MIN_FD, 0, 11),
    stt_key(10, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAG_FINAL, OP_CREATE, STATE_TOUCH),
    stt_key(11, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAG_FINAL, OP_CREATE, STATE_TOUCH),
    # ssh and scp
    stt_key(STATE_START, SYS_CALL_SOCKET, stt_net(AF_UNIX, SOCK_CLOEXEC | SOCK_NONBLOCK | SOCK_STREAM)):
        stt_val(FLAGS_CLR_MAY, 0, 12),
    stt_key(12, SYS_CALL_SOCKET, stt_net(AF_INET, SOCK_STREAM)): stt_val(FLAG_NET_FD, 0, 13),
    stt_key(13, SYS_CALL_CONNECT, ARGS_EQL_NET): stt_val(FLAG_NET | FLAG_PARENT, 0, 14),
    stt_key(14, SYS_CALL_CLOSE, ARGS_EQL_NET): stt_val(FLAG_FINAL, OP_LOGIN, STATE_SSH),
    stt_key(14, SYS_CALL_OPEN, O_NONBLOCK): stt_val(FLAG_MAY_FD | FLAG_MAYOR | FLAG_DELAY, 0, 15),
    stt_key(STATE_SCP, SYS_CALL_OPEN, O_NONBLOCK): stt_val(FLAG_SUBMIT | FLAG_MAY_FD | FLAG_MAYOR | FLAG_DELAY, 0, 15),
    stt_key(15, SYS_CALL_CLOSE, ARGS_EQL_SRC): stt_val(FLAG_FINAL, OP_UPLOAD, STATE_SCP),
    # mv
    stt_key(STATE_START, SYS_CALL_RENAMEAT2, 0): stt_val(FLAG_DELAY | FLAG_MAYOR | FLAG_MINOR | FLAG_FINAL, OP_CREATE,
                                                         STATE_MV),
    stt_key(STATE_MV, SYS_CALL_RENAMEAT2, 0): stt_val(FLAGS_LST_SMT | FLAG_DELAY | FLAG_MAYOR | FLAG_MINOR | FLAG_FINAL,
                                                      OP_CREATE_PRI, STATE_MV),
    stt_key(STATE_MV, SYS_CALL_RENAME, 0): stt_val(FLAG_DELAY | FLAG_MAYOR | FLAG_MINOR | FLAG_FINAL, OP_COVER_PRI,
                                                   STATE_MV),
    # zip
    stt_key(1, SYS_CALL_OPEN, O_TRUNC | O_CREAT | O_WRONLY): stt_val(0, OP_CREATE, 16),
    stt_key(1, SYS_CALL_OPEN, O_RDONLY): stt_val(0, 0, 20),
    stt_key(20, SYS_CALL_OPEN, O_RDWR): stt_val(0, OP_COVER, 16),
    stt_key(16, SYS_CALL_OPEN, O_RDWR | O_CREAT | O_EXCL): stt_val(0, 0, 17),
    stt_key(17, SYS_CALL_OPEN, O_RDONLY): stt_val(FLAG_MAYOR | FLAG_DELAY | FLAG_MAY_FD, 0, 18),
    stt_key(18, SYS_CALL_CLOSE, ARGS_EQL_SRC): stt_val(0, 0, 19),
    stt_key(18, SYS_CALL_OPEN, O_RDONLY): stt_val(FLAG_MAYOR | FLAG_DELAY | FLAG_MAY_FD, 0, 18),
    stt_key(19, SYS_CALL_OPEN, O_RDONLY): stt_val(FLAG_SUBMIT | FLAG_MAYOR | FLAG_DELAY | FLAG_MAY_FD, 0, 18),
    stt_key(19, SYS_CALL_RENAME, 0): stt_val(FLAG_MINOR | FLAG_FINAL, 0, STATE_ZIP),
    # unzip
    # stt_key(2, SYS_CALL_READ, ARGS_EQL_SRC): stt_val(0, 0, 21),
    stt_key(STATE_START, SYS_CALL_OPEN, O_RDWR | O_CREAT | O_TRUNC): stt_val(
        FLAG_MINOR | FLAG_MIN_FD | FLAG_DELAY | FLAG_FINAL, OP_UNZIP, STATE_UNZIP),
    stt_key(STATE_UNZIP, SYS_CALL_OPEN, O_RDWR | O_CREAT | O_TRUNC): stt_val(
        FLAG_MINOR | FLAG_MIN_FD | FLAG_DELAY | FLAGS_LST_SMT | FLAG_FINAL, 0, STATE_UNZIP),
    # cp
    stt_key(1, SYS_CALL_OPEN, O_WRONLY | O_CREAT | O_EXCL): stt_val(FLAG_MINOR | FLAG_MIN_FD | FLAG_DELAY, OP_CREATE,
                                                                    21),
    stt_key(1, SYS_CALL_OPEN, O_WRONLY | O_TRUNC): stt_val(FLAG_MINOR | FLAG_MIN_FD | FLAG_DELAY, OP_COVER, 22),
    stt_key(21, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(0, 0, 23),
    stt_key(22, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(0, 0, 23),
    stt_key(23, SYS_CALL_CLOSE, ARGS_EQL_SRC): stt_val(FLAG_FINAL, 0, STATE_CP),
    stt_key(STATE_CP, SYS_CALL_OPEN, O_RDONLY): stt_val(FLAGS_LST_SMT | FLAG_DELAY | FLAG_MAYOR | FLAG_MAY_FD, 0, 1),
    # vim vi
    stt_key(12, SYS_CALL_OPEN, O_RDWR | O_CREAT | O_EXCL): stt_val(0, 0, 24),
    stt_key(20, SYS_CALL_SOCKET, stt_net(AF_UNIX, SOCK_CLOEXEC | SOCK_NONBLOCK | SOCK_STREAM)): stt_val(0, 0, 24),
    stt_key(24, SYS_CALL_OPEN, O_NOFOLLOW | O_RDWR | O_CREAT | O_EXCL): stt_val(0, 0, 25),
    stt_key(24, SYS_CALL_OPEN, 0o100302): stt_val(0, 0, 25),  # for arm chip
    stt_key(25, SYS_CALL_OPEN, O_RDONLY): stt_val(FLAG_MAYOR | FLAG_DELAY, 0, 26),
    stt_key(26, SYS_CALL_OPEN, O_WRONLY | O_CREAT): stt_val(FLAGS_CLR_MAY | FLAG_MINOR | FLAG_MIN_FD | FLAG_DELAY, 0, 27),
    stt_key(27, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAG_FINAL, OP_CREATE, STATE_VI),
    stt_key(27, SYS_CALL_WRITE, ARGS_EQL_DST): stt_val(FLAG_FINAL, OP_WRITE, STATE_VI),
    stt_key(26, SYS_CALL_OPEN, O_NOFOLLOW | O_WRONLY | O_CREAT | O_EXCL): stt_val(FLAG_FINAL, OP_READ, STATE_VI),
    stt_key(26, SYS_CALL_OPEN, 0o100301): stt_val(FLAG_FINAL, OP_READ, STATE_VI),  # for arm chip
    stt_key(STATE_VI, SYS_CALL_OPEN, O_WRONLY | O_CREAT):
        stt_val(FLAG_DELAY | FLAG_MINOR | FLAG_FINAL | FLAGS_CLR_MAY, OP_SAVE_PRI, STATE_VI),
}


class FileT(ct.Structure):
    _fields_ = [
        ("fd", ct.c_int),
        ("i_ino", ct.c_uint32),
        ("name", ct.c_char * 32)
    ]


class ForReadT(ct.LittleEndianStructure):
    _fields_ = [
        ("state", ct.c_uint64, 16),
        ("operate", ct.c_uint64, 8),
        ("reserve", ct.c_uint64, 8),
        ("flags", ct.c_uint64, 32)
    ]


class StateT(ct.Union):
    _fields_ = [
        ("fr", ForReadT),
        ("for_assign", ct.c_uint64)
    ]


class NetT(ct.Structure):
    _fields_ = [
        ("fd", ct.c_int),
        ("addr", ct.c_uint32),
        ("port", ct.c_uint32)
    ]


class BehavT(ct.Structure):
    _fields_ = [
        ("time", ct.c_uint64),
        ("ppid", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 32),
        ("s", StateT),
        ("f0", FileT),
        ("f1", FileT),
        ("net", NetT)
    ]


prog = None
with open("panorama.c") as f:
    prog = f.read()
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
b.attach_uprobe(name="c", sym="unlinkat", fn_name="do_unlinkat_entry")
b.attach_uprobe(name="c", sym="mkdir", fn_name="do_mkdir_entry")
b.attach_uprobe(name="c", sym="rmdir", fn_name="do_rmdir_entry")
b.attach_uprobe(name="c", sym="exit", fn_name="do_exit_entry")
b.attach_uretprobe(name="c", sym="open", fn_name="do_open_return")
b.attach_uretprobe(name="c", sym="openat", fn_name="do_openat_return")
b.attach_uretprobe(name="c", sym="mkdir", fn_name="do_mkdir_return")
b.attach_uretprobe(name="c", sym="rmdir", fn_name="do_rmdir_return")
b.attach_uretprobe(name="c", sym="unlinkat", fn_name="do_unlinkat_return")
b.attach_uretprobe(name="c", sym="rename", fn_name="do_rename_return")
b.attach_uretprobe(name="c", sym="renameat2", fn_name="do_renameat2_return")
b.attach_uretprobe(name="c", sym="socket", fn_name="do_socket_return")

b.attach_kprobe(event="vfs_open", fn_name="do_vfs_open")
b.attach_kprobe(event="vfs_unlink", fn_name="do_vfs_unlink")
b.attach_kprobe(event="vfs_rename", fn_name="do_vfs_rename")
b.attach_kprobe(event="vfs_mkdir", fn_name="do_vfs_mkdir")
b.attach_kprobe(event="vfs_rmdir", fn_name="do_vfs_rmdir")
b.attach_kretprobe(event="vfs_mkdir", fn_name="do_vfs_mkdir_return")

mp = b["stt_behav"]
for key, val in stt.items():
    current_key = mp.Key(key)
    current_val = mp.Leaf(val)
    mp[current_key] = current_val

op_map = {
    OP_CREATE: "create",
    OP_CREATE_PRI: "create",
    OP_REMOVE: "remove",
    OP_REMOVE_PRI: "remove",
    OP_READ: "read",
    OP_READ_PRI: "read",
    OP_WRITE: "write",
    OP_WRITE_PRI: "write",
    OP_COVER: "cover",
    OP_COVER_PRI: "cover",
    OP_SAVE: "save",
    OP_SAVE_PRI: "save",
    OP_COMPR: "zip",
    OP_COMPR_PRI: "zip",
    OP_UNZIP: "unzip",
    OP_UNZIP_PRI: "unzip",
    OP_SPLIT: "split",
    OP_SPLIT_PRI: "split",
    OP_LOGIN: "net",
    OP_LOGIN_PRI: "net",
    OP_UPLOAD: "upload",
    OP_UPLOAD_PRI: "upload",
    OP_MKDIR: "mkdir",
    OP_MKDIR_PRI: "mkdir",
    OP_RMDIR: "rmdir",
    OP_RMDIR_PRI: "rmdir",
}


def get_behavior(OP: int) -> str:
    if OP in op_map:
        return op_map[OP]
    else:
        return "other"


__DEBUG__ = False

# debug version which prints the log on the screen.
file_info = """{:<6} {:<6} {:<5} \033[0;33;40m{:<6}\033[0m {:<6} {:<16} {:<16} {:<8} {:<8} {:<8} {} {:X}"""
net_info = """{:<6} {:<6} {:<5} \033[0;32;40m{:<6}\033[0m {:<6} {:<21} {:<16} {:<8} {} {:X}"""


class LogItem:
    def __init__(self):
        self.src = list()
        self.task = None
        self.dest = None


tmp_log = dict()  # pid -> LogItem
logs = list()  # list of logs
log_file = open("panorama.log", "a")


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(BehavT)).contents
    if __DEBUG__:
        if (event.s.fr.operate & 0x7f) < OP_LOGIN:
            print(file_info.format(event.ppid, event.pid, event.uid, event.comm.decode(),
                                   get_behavior(event.s.fr.operate), event.f0.name.decode(), event.f1.name.decode(),
                                   event.f0.i_ino, event.f1.i_ino, event.f0.fd, event.f1.fd, event.s.for_assign))
        else:
            print(net_info.format(event.ppid, event.pid, event.uid, event.comm.decode(),
                                  get_behavior(event.s.fr.operate), socket.inet_ntoa(struct.pack('I', event.net.addr)) +
                                  ":%u" % (socket.ntohs(event.net.port)), event.f0.name.decode(),
                                  event.f0.i_ino, event.f1.i_ino, event.s.for_assign))
    else:
        pid = int(event.pid)
        log = tmp_log.get(pid)
        if not log:
            log = LogItem()
            tmp_log.update({pid: log})
            log.task = "{}({},{},{},{})".format(event.comm.decode(), event.ppid, event.pid, event.uid,
                                                get_behavior(event.s.fr.operate))
        if event.f0.i_ino:
            log.src.append("{}({})".format(event.f0.i_ino, event.f0.name.decode()))
        else:
            log.src.append("None")
        if (event.s.fr.operate & 0x7f) < OP_LOGIN:
            if event.f1.i_ino != 0:
                log.dest = "{}({})".format(event.f1.i_ino, event.f1.name.decode())
        else:
            log.dest = "{}:{}".format(socket.inet_ntoa(struct.pack('I', event.net.addr)), socket.ntohs(event.net.port))
        if event.s.fr.state & 0x8000 or log.dest:
            for src in log.src:
                logs.append("{} {} {}\n".format(src, log.task, log.dest))
            del tmp_log[pid]
            del log
            if len(logs) >= 166666:
                log_file.writelines(logs)
                log_file.flush()  # write into the disk
                logs.clear()


print("Bpf program loaded. Ctrl + C to stop...")
if __DEBUG__:
    print("%-6s %-6s %-5s %-6s TYPE" % ("PPID", "PID", "USER", "TASK"))

b["behavior"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        if len(logs):
            log_file.writelines(logs)
        log_file.close()
        exit(0)
