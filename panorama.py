#!/bin/env python

from bcc import BPF
import ctypes as ct
import socket
import struct
import psutil
from datetime import datetime, timedelta
from threading import Timer, Lock

FLAG_MAYOR = 0x00000001  # get mayor name from args.
FLAG_MINOR = 0x00000002  # get minor name from args.
FLAG_NET = 0x00000004  # get the address and port.
FLAG_MAY_FD = 0x00000008  # get mayor fd.
FLAG_MIN_FD = 0x00000010  # get minor fd.
FLAG_NET_FD = 0x00000020  # get socket fd.
FLAG_PARENT = 0x00000040  # copy the address and port to parent data.
FLAGS_CLR_MAY = 0x00000080
FLAGS_CLR_MIN = 0x00000100
FLAGS_SMT_CUR = 0x00000200
FLAGS_SMT_LST = 0x00000400
FLAGS_SMT_EXT = 0x00000800
FLAGS_NEXT = 0x00001000

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
STATE_TOUCH = 0x8000    # dest output
STATE_RM = 0x8001       # src output
STATE_MKDIR = 0x8002    # dest output
STATE_RMDIR = 0x8003    # src output
STATE_CAT = 0x8004      # src output
STATE_MV = 0x8005       # dest output
STATE_CP = 0x8006       # dest output
STATE_GZIP = 0x8007     # dest output   unlink src
STATE_ZIP = 0x8008      # multi src dest output
STATE_UNZIP = 0x8009    # dest output
STATE_SPLIT = 0x800a    # dest output
STATE_VI = 0x800b       # dest output
STATE_SSH = 0x800c      # dest output
STATE_SCP = 0x800d      # dest output

SYS_CALL_OPENAT = 0x00
SYS_CALL_DUP3 = 0x01
SYS_CALL_RENAMEAT = 0x02
SYS_CALL_RENAMEAT2 = 0x03
SYS_CALL_READ = 0x04
SYS_CALL_WRITE = 0x05
SYS_CALL_CLOSE = 0x06
SYS_CALL_UNLINKAT = 0x07
SYS_CALL_MKDIRAT = 0x08
SYS_CALL_EXIT_GROUP = 0x09
SYS_CALL_SOCKET = 0x0a
SYS_CALL_CONNECT = 0x0b

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
    stt_key(STATE_START, SYS_CALL_OPENAT, 0): stt_val(FLAG_MAYOR | FLAG_MAY_FD, 0, 1),
    stt_key(1, SYS_CALL_CLOSE, ARGS_EQL_SRC): stt_val(FLAGS_CLR_MAY, 0, STATE_START),
    stt_key(1, SYS_CALL_READ, ARGS_EQL_SRC): stt_val(0, 0, 2),
    stt_key(2, SYS_CALL_WRITE, ARGS_EQL_IO): stt_val(0, 0, 3),
    stt_key(3, SYS_CALL_CLOSE, ARGS_EQL_SRC): stt_val(FLAGS_SMT_EXT, OP_READ, STATE_CAT),
    stt_key(STATE_CAT, SYS_CALL_OPENAT, 0): stt_val(FLAG_MAYOR | FLAG_MAY_FD | FLAGS_SMT_LST, 0, 1),
    # mkdir
    stt_key(STATE_START, SYS_CALL_MKDIRAT, 0): stt_val(FLAG_MINOR | FLAGS_SMT_EXT, OP_MKDIR, STATE_MKDIR),
    stt_key(STATE_MKDIR, SYS_CALL_MKDIRAT, 0): stt_val(FLAG_MINOR | FLAGS_SMT_EXT | FLAGS_SMT_LST, OP_MKDIR, STATE_MKDIR),
    # rmdir
    stt_key(STATE_START, SYS_CALL_UNLINKAT, 0o1000): stt_val(FLAG_MAYOR | FLAGS_SMT_EXT, OP_RMDIR, STATE_RMDIR),
    stt_key(STATE_RMDIR, SYS_CALL_UNLINKAT, 0o1000): stt_val(FLAG_MAYOR | FLAGS_SMT_EXT | FLAGS_SMT_LST, OP_RMDIR, STATE_RMDIR),
    # rm
    stt_key(STATE_START, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_MAYOR | FLAGS_SMT_EXT, OP_REMOVE, STATE_RM),
    stt_key(STATE_RM, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_MAYOR | FLAGS_SMT_EXT | FLAGS_SMT_LST, OP_REMOVE, STATE_RM),
    # touch
    stt_key(STATE_START, SYS_CALL_OPENAT, 0o4501): stt_val(FLAG_MINOR | FLAG_MIN_FD, 0, 17),
    stt_key(17, SYS_CALL_DUP3, ARGS_EQL_DST): stt_val(FLAG_MIN_FD, 0, 13),
    stt_key(13, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAGS_SMT_EXT, OP_CREATE, STATE_TOUCH),
    stt_key(STATE_TOUCH, SYS_CALL_OPENAT, 0o4501): stt_val(FLAG_MINOR | FLAG_MIN_FD | FLAGS_SMT_LST, 0, 13),
    # gzip
    stt_key(STATE_START, SYS_CALL_OPENAT, 0o40000): stt_val(0, 0, 5),
    stt_key(5, SYS_CALL_OPENAT, 0o104400): stt_val(FLAG_MAYOR | FLAG_MAY_FD, 0, 6),    # for arm
    # stt_key(5, SYS_CALL_OPENAT, 0o404400): stt_val(FLAG_MAYOR | FLAG_MAY_FD, 0, 6),    # for intel
    stt_key(6, SYS_CALL_OPENAT, 0o301): stt_val(FLAG_MINOR | FLAG_MIN_FD, OP_COMPR_PRI, 7),
    stt_key(7, SYS_CALL_READ, ARGS_EQL_SRC): stt_val(0, 0, 8),
    stt_key(8, SYS_CALL_WRITE, ARGS_EQL_DST): stt_val(0, 0, 9),
    stt_key(9, SYS_CALL_CLOSE, ARGS_EQL_SRC): stt_val(0, 0, 10),
    stt_key(10, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(0, 0, 11),
    stt_key(11, SYS_CALL_UNLINKAT, 0): stt_val(FLAGS_SMT_EXT, 0, STATE_GZIP),
    stt_key(STATE_GZIP, SYS_CALL_OPENAT, 0o104400): stt_val(FLAG_MAYOR | FLAG_MAY_FD | FLAGS_SMT_LST, 0, 6),
    # stt_key(STATE_GZIP, SYS_CALL_OPENAT, 0o404400): stt_val(FLAG_MAYOR | FLAG_MAY_FD | FLAGS_SMT_LST, 0, 6),
    stt_key(6, SYS_CALL_READ, ARGS_EQL_SRC): stt_val(0, OP_UNZIP_PRI, 12),
    stt_key(12, SYS_CALL_OPENAT, 0o301): stt_val(FLAG_MINOR | FLAG_MIN_FD, 0, 9),
    # zip create
    stt_key(STATE_START, SYS_CALL_OPENAT, 0o1101): stt_val(FLAG_MIN_FD, 0, 22),
    stt_key(22, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAGS_CLR_MIN, 0, 23),
    stt_key(23, SYS_CALL_OPENAT, 0o302): stt_val(FLAG_MIN_FD, 0, 24),
    stt_key(24, SYS_CALL_OPENAT, 0): stt_val(FLAG_MAYOR | FLAG_MAY_FD, 0, 26),
    stt_key(26, SYS_CALL_READ, ARGS_EQL_SRC): stt_val(0, OP_CREATE, 27),
    stt_key(27, SYS_CALL_CLOSE, ARGS_EQL_SRC): stt_val(0, 0, 28),
    stt_key(28, SYS_CALL_OPENAT, 0): stt_val(FLAG_MAYOR | FLAG_MAY_FD | FLAGS_SMT_LST, 0, 26),
    stt_key(28, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(0, 0, 29),
    stt_key(29, SYS_CALL_RENAMEAT, 0): stt_val(FLAG_MINOR | FLAGS_SMT_EXT, OP_CREATE, STATE_ZIP),
    # zip cover
    stt_key(2, SYS_CALL_CLOSE, ARGS_EQL_SRC): stt_val(FLAGS_CLR_MAY, 0, 30),
    stt_key(30, SYS_CALL_OPENAT, 0o2): stt_val(FLAG_MIN_FD, OP_COVER, 31),
    stt_key(31, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAGS_CLR_MIN, 0, 32),
    stt_key(32, SYS_CALL_OPENAT, 0o302): stt_val(FLAG_MIN_FD, 0, 33),
    stt_key(33, SYS_CALL_OPENAT, 0): stt_val(FLAG_MAYOR | FLAG_MAY_FD, 0, 34),
    stt_key(34, SYS_CALL_READ, ARGS_EQL_SRC): stt_val(0, 0, 35),
    stt_key(35, SYS_CALL_OPENAT, 0): stt_val(FLAG_MAYOR | FLAG_MAY_FD | FLAGS_SMT_LST, 0, 34),
    stt_key(35, SYS_CALL_RENAMEAT, 0): stt_val(FLAG_MINOR | FLAGS_SMT_EXT, OP_COVER, STATE_ZIP),
    # unzip
    stt_key(2, SYS_CALL_UNLINKAT, 0): stt_val(0, OP_COVER, 36),
    stt_key(36, SYS_CALL_OPENAT, 0o1102): stt_val(FLAG_MINOR | FLAG_MIN_FD, 0, 37),
    stt_key(2, SYS_CALL_OPENAT, 0o1102): stt_val(FLAG_MINOR | FLAG_MIN_FD, OP_CREATE, 37),
    stt_key(37, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAGS_SMT_EXT, 0, STATE_UNZIP),
    stt_key(STATE_UNZIP, SYS_CALL_UNLINKAT, 0): stt_val(FLAGS_SMT_LST, OP_COVER_PRI, 36),
    stt_key(STATE_UNZIP, SYS_CALL_OPENAT, 0o1102): stt_val(FLAG_MINOR | FLAG_MIN_FD | FLAGS_SMT_LST, OP_CREATE_PRI, 37),
    # split
    stt_key(1, SYS_CALL_DUP3, ARGS_EQL_SRC): stt_val(FLAG_MAY_FD, 0, 18),
    stt_key(18, SYS_CALL_READ, ARGS_EQL_SRC): stt_val(0, 0, 19),
    stt_key(19, SYS_CALL_OPENAT, 0o101): stt_val(FLAG_MINOR | FLAG_MIN_FD, 0, 20),
    stt_key(20, SYS_CALL_WRITE, ARGS_EQL_DST): stt_val(0, 0, 21),
    stt_key(21, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAGS_SMT_EXT, OP_SPLIT, STATE_SPLIT),
    stt_key(STATE_SPLIT, SYS_CALL_OPENAT, 0o101): stt_val(FLAGS_SMT_LST | FLAG_MINOR | FLAG_MIN_FD, OP_SPLIT, 20),
    # mv
    stt_key(STATE_START, SYS_CALL_RENAMEAT, 0): stt_val(FLAG_MAYOR | FLAG_MINOR | FLAGS_SMT_EXT, OP_COVER, STATE_MV),
    stt_key(STATE_START, SYS_CALL_RENAMEAT2, 0): stt_val(FLAG_MAYOR | FLAG_MINOR | FLAGS_SMT_EXT, OP_CREATE, STATE_MV),
    stt_key(STATE_MV, SYS_CALL_RENAMEAT, 0): stt_val(FLAG_MAYOR | FLAG_MINOR | FLAGS_SMT_LST | FLAGS_SMT_EXT, OP_COVER_PRI, STATE_MV),
    stt_key(STATE_MV, SYS_CALL_RENAMEAT2, 0): stt_val(FLAG_MAYOR | FLAG_MINOR | FLAGS_SMT_LST | FLAGS_SMT_EXT, OP_CREATE_PRI, STATE_MV),
    # cp
    stt_key(1, SYS_CALL_OPENAT, 0o301): stt_val(FLAG_MINOR | FLAG_MIN_FD, OP_CREATE_PRI, 38),
    stt_key(1, SYS_CALL_OPENAT, 0o1001): stt_val(FLAG_MINOR | FLAG_MIN_FD, OP_COVER_PRI, 39),
    stt_key(38, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAGS_SMT_EXT, 0, STATE_CP),
    stt_key(39, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAGS_SMT_EXT, 0, STATE_CP),
    stt_key(STATE_CP, SYS_CALL_OPENAT, 0): stt_val(FLAGS_SMT_LST | FLAG_MAY_FD | FLAG_MAYOR, 0, 1),
    # vim
    stt_key(1, SYS_CALL_OPENAT, 0): stt_val(0, 0, 14),
    stt_key(30, SYS_CALL_OPENAT, 0): stt_val(0, 0, 14),
    stt_key(14, SYS_CALL_OPENAT, 0o4000): stt_val(0, 0, 15),
    stt_key(15, SYS_CALL_OPENAT, 0o2044000): stt_val(0, 0, 16),
    stt_key(16, SYS_CALL_SOCKET, stt_net(AF_UNIX, 0o2004001)): stt_val(0, 0, 25),
    stt_key(25, SYS_CALL_OPENAT, 0o100302): stt_val(0, 0, 40),  # for intel
    stt_key(25, SYS_CALL_OPENAT, 0o400302): stt_val(0, 0, 40),  # for arm
    stt_key(40, SYS_CALL_OPENAT, 0): stt_val(FLAG_MAYOR, 0, 41),
    stt_key(41, SYS_CALL_OPENAT, 0o100301): stt_val(FLAGS_SMT_EXT, OP_READ, STATE_VI),  # for intel
    stt_key(41, SYS_CALL_OPENAT, 0o400301): stt_val(FLAGS_SMT_EXT, OP_READ, STATE_VI),  # for arm
    stt_key(STATE_VI, SYS_CALL_OPENAT, 0o101): stt_val(FLAG_MINOR | FLAGS_SMT_EXT, OP_SAVE_PRI, STATE_VI),
    stt_key(41, SYS_CALL_OPENAT, 0o101): stt_val(FLAG_MINOR | FLAG_MIN_FD | FLAGS_CLR_MAY, 0, 42),
    stt_key(42, SYS_CALL_WRITE, ARGS_EQL_DST): stt_val(FLAGS_SMT_EXT, OP_WRITE, STATE_VI),
    stt_key(42, SYS_CALL_CLOSE, ARGS_EQL_DST): stt_val(FLAGS_SMT_EXT, OP_CREATE, STATE_VI),
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
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat")
b.attach_kprobe(event=b.get_syscall_fnname("read"), fn_name="syscall__read")
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__write")
b.attach_kprobe(event=b.get_syscall_fnname("close"), fn_name="syscall__close")
b.attach_kprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat")
b.attach_kprobe(event=b.get_syscall_fnname("mkdirat"), fn_name="syscall__mkdirat")
b.attach_kprobe(event=b.get_syscall_fnname("renameat"), fn_name="syscall__renameat")
b.attach_kprobe(event=b.get_syscall_fnname("renameat2"), fn_name="syscall__renameat2")
b.attach_kprobe(event=b.get_syscall_fnname("dup3"), fn_name="syscall__dup3")
b.attach_kprobe(event=b.get_syscall_fnname("socket"), fn_name="syscall__socket")
b.attach_kprobe(event=b.get_syscall_fnname("connect"), fn_name="syscall__connect")
b.attach_kprobe(event=b.get_syscall_fnname("exit_group"), fn_name="syscall_exit_group")
b.attach_kretprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("read"), fn_name="syscall__read_return")
b.attach_kretprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__write_return")
b.attach_kretprobe(event=b.get_syscall_fnname("close"), fn_name="syscall__close_return")
b.attach_kretprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("mkdirat"), fn_name="syscall__mkdirat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("renameat"), fn_name="syscall__renameat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("renameat2"), fn_name="syscall__renameat2_return")
b.attach_kretprobe(event=b.get_syscall_fnname("dup3"), fn_name="syscall__dup3_return")
b.attach_kretprobe(event=b.get_syscall_fnname("socket"), fn_name="syscall__socket_return")
b.attach_kretprobe(event=b.get_syscall_fnname("connect"), fn_name="syscall__connect_return")

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


usr = dict()
with open("/etc/passwd") as f:
    for line in f:
        args = line.split(":")
        usr.update({int(args[2]): args[0]})

__DEBUG__ = True
boot_time = psutil.boot_time()

# debug version which prints the log on the screen.
file_info = """{:<6} {:<6} {:<5} \033[0;33;40m{:<6}\033[0m {:<6} {:<16} {:<16} {:<8} {:<8} {:<8} {} {:X}"""
net_info = """{:<6} {:<6} {:<5} \033[0;32;40m{:<6}\033[0m {:<6} {:<21} {:<16} {:<8} {} {:X}"""


class LogItem:
    def __init__(self):
        self.time = None
        self.src = list()
        self.fm = None
        self.task = None
        self.to = None
        self.dest = None


tmp_log = dict()  # pid -> LogItem
logs = list()  # list of logs
lock = Lock()
dt = datetime.now().date()
log_file = open("{}-{}-{}.log".format(dt.year, dt.month, dt.day), "w")


def log_switch():
    global log_file, timer
    date = datetime.now().date()
    with lock:
        log_file.close()
        log_file = open("{}-{}-{}.log".format(date.year, date.month, date.day), "w")
    timer = Timer(86400, log_switch)
    timer.start()


# get the next day's datetime
next_time = dt + timedelta(days=+1)
next_time = datetime(next_time.year, next_time.month, next_time.day, 3, 0, 0)
timer = Timer((next_time - datetime.now()).total_seconds(), log_switch)
timer.start()


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
            task = event.comm.decode()
            log = LogItem()
            tmp_log.update({pid: log})
            log.time = str(datetime.fromtimestamp(boot_time + int(event.time) / 1e9).time())
            log.task = "{}({})".format(task, usr[event.uid])
            if task == "gzip":
                log.fm = "remove"
        if (event.s.fr.operate & 0x7f) < OP_LOGIN:
            if event.f1.i_ino != 0:
                # strip in case "./name1"
                log.dest = "{}({})".format(event.f1.name.decode().replace(r"./", ""), event.f1.i_ino)
                log.to = get_behavior(event.s.fr.operate)
        else:
            log.dest = "{}:{}".format(socket.inet_ntoa(struct.pack('I', event.net.addr)), socket.ntohs(event.net.port))
            log.to = get_behavior(event.s.fr.operate)
        if event.f0.i_ino:
            log.src.append("{}({})".format(event.f0.name.decode().replace(r"./", ""), event.f0.i_ino))
            if not log.fm:
                log.fm = "read"
        else:
            log.src.append(None)
        if event.s.fr.state & 0x8000 or log.dest:
            if not log.dest:
                log.fm = get_behavior(event.s.fr.operate)
            for src in log.src:
                tmp = " {} {} {} {} {}\n".format(src, log.fm, log.task, log.to, log.dest)
                if len(logs) and logs[-1] == tmp:
                    continue
                logs.append(log.time)
                logs.append(tmp)
            del tmp_log[pid]
            del log
            if len(logs) >= 13618:
                with lock:
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
        timer.cancel()
        if len(logs):
            log_file.writelines(logs)
        log_file.close()
        exit(0)
