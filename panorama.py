#!/bin/env python
import sys

from bcc import BPF
import ctypes as ct
import socket
import struct
import psutil
import argparse
from datetime import datetime, timedelta
from threading import Timer, Lock, Thread

FLAG_FILE_NAME = 0x00000001
FLAG_SOCKET = 0x00000002
FLAG_FD = 0x00000004
FLAG_PARENT = 0x00000008
FLAG_SMT_CUR = 0x00000010
FLAG_SMT_LST = 0x00000020
FLAG_SMT_SOCK = 0x00000040
FLAG_RNM_SRC = 0x00000080
FLAG_ACCEPT = 0x00000100
FLAG_CHILD = 0x00000200

OP_CREATE = 0x01
OP_REMOVE = 0x02
OP_READ = 0x03
OP_WRITE = 0x04
OP_COVER = 0x05
OP_SAVE = 0x06
OP_MKDIR = 0x07
OP_RMDIR = 0x08
OP_CONNECT = 0x09
OP_ACCEPT = 0x0a

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

ARGS_EQL_FD = 0x0000000001
ARGS_EQL_IO = 0x0000000002
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


def CHECK_FLAG(s: int, f: int) -> bool:
    return not ((f & (s >> 32)) ^ f)


stt = {
    # cat
    stt_key(STATE_START, SYS_CALL_OPENAT, 0): stt_val(FLAG_FILE_NAME | FLAG_FD, OP_READ, 1),
    stt_key(1, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(0, 0, STATE_START),
    stt_key(1, SYS_CALL_READ, ARGS_EQL_FD): stt_val(0, 0, 2),
    stt_key(2, SYS_CALL_WRITE, ARGS_EQL_IO): stt_val(0, 0, 3),
    stt_key(3, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(FLAG_SMT_CUR, OP_READ, STATE_CAT),
    stt_key(STATE_CAT, SYS_CALL_OPENAT, 0): stt_val(FLAG_FILE_NAME | FLAG_FD, 0, 1),
    # mkdir
    stt_key(STATE_START, SYS_CALL_MKDIRAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_MKDIR, STATE_MKDIR),
    stt_key(STATE_MKDIR, SYS_CALL_MKDIRAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_MKDIR, STATE_MKDIR),
    # rmdir
    stt_key(STATE_START, SYS_CALL_UNLINKAT, 0o1000): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_RMDIR, STATE_RMDIR),
    stt_key(STATE_RMDIR, SYS_CALL_UNLINKAT, 0o1000): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_RMDIR, STATE_RMDIR),
    # rm
    stt_key(STATE_START, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_REMOVE, STATE_RM),
    stt_key(STATE_RM, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_REMOVE, STATE_RM),
    # touch
    stt_key(STATE_START, SYS_CALL_OPENAT, 0o4501): stt_val(FLAG_FILE_NAME | FLAG_FD, 0, 17),
    stt_key(17, SYS_CALL_DUP3, ARGS_EQL_FD): stt_val(FLAG_FD, 0, 13),
    stt_key(13, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(FLAG_SMT_CUR, OP_CREATE, STATE_TOUCH),
    stt_key(STATE_TOUCH, SYS_CALL_OPENAT, 0o4501): stt_val(FLAG_FILE_NAME, 0, 13),
    # gzip
    stt_key(STATE_START, SYS_CALL_OPENAT, 0o40000): stt_val(0, 0, 5),
    stt_key(5, SYS_CALL_OPENAT, 0o104400): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_CUR, OP_READ, 6),  # for arm
    # stt_key(5, SYS_CALL_OPENAT, 0o404400): stt_val(FLAG_MAYOR | FLAG_MAY_FD, 0, 6),    # for intel
    stt_key(6, SYS_CALL_OPENAT, 0o301): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_CUR, OP_CREATE, 7),
    stt_key(7, SYS_CALL_WRITE, ARGS_EQL_FD): stt_val(0, 0, 8),
    stt_key(8, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(0, 0, 10),
    stt_key(10, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_REMOVE, STATE_GZIP),
    stt_key(STATE_GZIP, SYS_CALL_OPENAT, 0o104400): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_CUR, OP_READ, 6),
    # stt_key(STATE_GZIP, SYS_CALL_OPENAT, 0o404400): stt_val(FLAG_MAYOR | FLAG_MAY_FD | FLAGS_SMT_LST, 0, 6),
    stt_key(6, SYS_CALL_READ, ARGS_EQL_FD): stt_val(0, 0, 12),
    stt_key(12, SYS_CALL_OPENAT, 0o301): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_CUR, OP_CREATE, 8),
    # zip create
    stt_key(STATE_START, SYS_CALL_OPENAT, 0o1101): stt_val(FLAG_FD, 0, 22),
    stt_key(22, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(0, 0, 23),
    stt_key(23, SYS_CALL_OPENAT, 0o302): stt_val(0, 0, 24),
    stt_key(24, SYS_CALL_OPENAT, 0): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_CUR, OP_READ, 26),
    # stt_key(26, SYS_CALL_READ, ARGS_EQL_FD): stt_val(0, 0, 27),
    stt_key(26, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(0, 0, 28),
    stt_key(28, SYS_CALL_OPENAT, 0): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_CUR, OP_READ, 26),
    # stt_key(28, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(0, 0, 29),
    stt_key(28, SYS_CALL_RENAMEAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_CREATE, STATE_ZIP),
    # zip cover
    stt_key(2, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(0, 0, 30),
    stt_key(30, SYS_CALL_OPENAT, 0o2): stt_val(FLAG_FD, 0, 31),
    stt_key(14, SYS_CALL_OPENAT, 0o2): stt_val(FLAG_FD, 0, 31),
    stt_key(31, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(0, 0, 32),
    stt_key(32, SYS_CALL_OPENAT, 0o302): stt_val(0, 0, 33),
    stt_key(33, SYS_CALL_OPENAT, 0): stt_val(FLAG_FILE_NAME | FLAG_FD, 0, 34),
    stt_key(34, SYS_CALL_READ, ARGS_EQL_FD): stt_val(FLAG_SMT_CUR, OP_READ, 35),
    stt_key(35, SYS_CALL_OPENAT, 0): stt_val(FLAG_FILE_NAME | FLAG_FD, 0, 34),
    stt_key(35, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_REMOVE, 9),
    stt_key(9, SYS_CALL_RENAMEAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_COVER, STATE_ZIP),
    # unzip
    stt_key(2, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_REMOVE, 36),
    stt_key(36, SYS_CALL_OPENAT, 0o1102): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_CUR, OP_COVER, 37),
    stt_key(2, SYS_CALL_OPENAT, 0o1102): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_CUR, OP_CREATE, 37),
    stt_key(37, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(0, 0, STATE_UNZIP),
    stt_key(STATE_UNZIP, SYS_CALL_UNLINKAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_REMOVE, 36),
    stt_key(STATE_UNZIP, SYS_CALL_OPENAT, 0o1102): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_CUR, OP_CREATE, 37),
    # split
    stt_key(1, SYS_CALL_DUP3, ARGS_EQL_FD): stt_val(FLAG_FD, 0, 18),
    stt_key(18, SYS_CALL_READ, ARGS_EQL_FD): stt_val(0, 0, 19),
    stt_key(19, SYS_CALL_OPENAT, 0o101): stt_val(FLAG_FILE_NAME | FLAG_FD, 0, 20),
    stt_key(20, SYS_CALL_WRITE, ARGS_EQL_FD): stt_val(FLAG_SMT_CUR, OP_WRITE, 21),
    stt_key(21, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(0, 0, STATE_SPLIT),
    stt_key(STATE_SPLIT, SYS_CALL_OPENAT, 0o101): stt_val(FLAG_FILE_NAME | FLAG_FD, 0, 20),
    # mv
    stt_key(STATE_START, SYS_CALL_RENAMEAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR | FLAG_RNM_SRC, OP_COVER,
                                                        STATE_MV),
    stt_key(STATE_START, SYS_CALL_RENAMEAT2, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR | FLAG_RNM_SRC, OP_CREATE,
                                                         STATE_MV),
    stt_key(STATE_MV, SYS_CALL_RENAMEAT, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR | FLAG_RNM_SRC, OP_COVER, STATE_MV),
    stt_key(STATE_MV, SYS_CALL_RENAMEAT2, 0): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR | FLAG_RNM_SRC, OP_CREATE,
                                                      STATE_MV),
    # cp
    stt_key(1, SYS_CALL_OPENAT, 0o301): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_LST, 0, 38),
    stt_key(1, SYS_CALL_OPENAT, 0o1001): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_LST, 0, 39),
    stt_key(38, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(FLAG_SMT_CUR, OP_CREATE, STATE_CP),
    stt_key(39, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(FLAG_SMT_CUR, OP_COVER, STATE_CP),
    stt_key(STATE_CP, SYS_CALL_OPENAT, 0): stt_val(FLAG_FILE_NAME | FLAG_FD, OP_READ, 1),
    # vim
    stt_key(1, SYS_CALL_OPENAT, 0): stt_val(0, 0, 14),
    stt_key(30, SYS_CALL_OPENAT, 0): stt_val(0, 0, 14),
    stt_key(14, SYS_CALL_OPENAT, 0o4000): stt_val(0, 0, 15),
    stt_key(15, SYS_CALL_OPENAT, 0o2044000): stt_val(0, 0, 16),
    stt_key(16, SYS_CALL_SOCKET, stt_net(AF_UNIX, 0o2004001)): stt_val(0, 0, 25),
    stt_key(25, SYS_CALL_OPENAT, 0o100302): stt_val(0, 0, 40),  # for intel
    stt_key(25, SYS_CALL_OPENAT, 0o400302): stt_val(0, 0, 40),  # for arm
    stt_key(40, SYS_CALL_OPENAT, 0): stt_val(FLAG_FILE_NAME, 0, 41),
    stt_key(41, SYS_CALL_OPENAT, 0o100301): stt_val(FLAG_SMT_CUR, OP_READ, STATE_VI),  # for intel
    stt_key(41, SYS_CALL_OPENAT, 0o400301): stt_val(FLAG_SMT_CUR, OP_READ, STATE_VI),  # for arm
    stt_key(STATE_VI, SYS_CALL_OPENAT, 0o101): stt_val(FLAG_FILE_NAME | FLAG_SMT_CUR, OP_SAVE, STATE_VI),
    stt_key(41, SYS_CALL_OPENAT, 0o101): stt_val(FLAG_FILE_NAME | FLAG_FD, 0, 42),
    stt_key(42, SYS_CALL_WRITE, ARGS_EQL_FD): stt_val(FLAG_SMT_CUR, OP_WRITE, STATE_VI),
    stt_key(42, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(FLAG_SMT_CUR, OP_CREATE, STATE_VI),
    # ssh and scp
    stt_key(STATE_START, SYS_CALL_OPENAT, 0o2): stt_val(0, 0, 43),
    stt_key(43, SYS_CALL_SOCKET, stt_net(AF_UNIX, 0o2004001)): stt_val(0, 0, 44),
    stt_key(44, SYS_CALL_SOCKET, stt_net(AF_INET, 0o1)): stt_val(FLAG_FD, 0, 45),
    stt_key(45, SYS_CALL_CONNECT, ARGS_EQL_FD): stt_val(FLAG_SOCKET | FLAG_PARENT | FLAG_SMT_CUR | FLAG_SMT_SOCK,
                                                        OP_CONNECT, 46),
    stt_key(46, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(0, 0, STATE_SSH),
    stt_key(46, SYS_CALL_OPENAT, 0o4000): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_LST, 0, 47),
    stt_key(STATE_SCP, SYS_CALL_OPENAT, 0o4000): stt_val(FLAG_FILE_NAME | FLAG_FD, 0, 47),
    stt_key(47, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(FLAG_SMT_CUR, OP_READ, STATE_SCP),
    # scp accept
    stt_key(32, SYS_CALL_SOCKET, stt_net(AF_UNIX, 0o2004001)):
        stt_val(FLAG_SMT_SOCK | FLAG_CHILD, OP_ACCEPT, 27),
    stt_key(27, SYS_CALL_OPENAT, 0o101): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_LST, 0, 29),  # for scp
    stt_key(27, SYS_CALL_OPENAT, 0o1101): stt_val(FLAG_FILE_NAME | FLAG_FD | FLAG_SMT_LST, 0, 29),  # for sftp-server
    stt_key(29, SYS_CALL_CLOSE, ARGS_EQL_FD): stt_val(FLAG_SMT_CUR, OP_WRITE, STATE_SCP),
    stt_key(STATE_SCP, SYS_CALL_OPENAT, 0o101): stt_val(FLAG_FILE_NAME | FLAG_FD, 0, 29),  # for scp
    stt_key(STATE_SCP, SYS_CALL_OPENAT, 0o1101): stt_val(FLAG_FILE_NAME | FLAG_FD, 0, 29),  # for sftp-server
    stt_key(23, SYS_CALL_OPENAT, 0o2): stt_val(FLAG_ACCEPT, 0, 48)
}


class FileT(ct.Structure):
    _fields_ = [
        ("i_ino", ct.c_uint32),
        ("name", ct.c_char * 32)
    ]


class NetT(ct.Structure):
    _fields_ = [
        ("addr", ct.c_uint32),
        ("port", ct.c_uint16),
        ("dummy", ct.c_char * 30)
    ]


class DetailT(ct.Union):
    _fields_ = [
        ("file", FileT),
        ("remote", NetT)
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


class BehavT(ct.Structure):
    _fields_ = [
        ("time", ct.c_uint64),
        ("ppid", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("fd", ct.c_int),
        ("comm", ct.c_char * 32),
        ("s", StateT),
        ("detail", DetailT),
        ("local", NetT)
    ]


# ======= end of data definition ======


with open("panorama.c") as f:
    prog = f.read()
if prog is None or prog == "":
    print("file open error")
    exit(-1)

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", help="print more infos like states for debugging", action="store_true")
args = parser.parse_args()

op_map = {
    OP_CREATE: "create",
    OP_REMOVE: "remove",
    OP_READ: "read",
    OP_WRITE: "write",
    OP_COVER: "cover",
    OP_SAVE: "save",
    OP_MKDIR: "mkdir",
    OP_RMDIR: "rmdir",
    OP_CONNECT: "connect",
    OP_ACCEPT: "accept"
}


def get_behavior(op: int) -> str:
    if op in op_map:
        return op_map[op]
    else:
        return "other"


def output_log(logs: list) -> None:
    out.writelines(logs)
    out.flush()


usr = dict()
with open("/etc/passwd") as f:
    for line in f:
        items = line.split(":")
        usr.update({int(items[2]): items[0]})

boot_time = psutil.boot_time()
# determine which output target is used
log_file_name = "/var/log/syslog.log"
if args.debug:
    out = sys.stdout
    group_size = 4
else:
    out = open(log_file_name, "w")
    group_size = 20971  # output when logs size reach 20M
log_size = 0
ready_to_write = list()

# operations of eBPF
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
b.attach_kprobe(event=b.get_syscall_fnname("accept"), fn_name="syscall__accept")
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
b.attach_kretprobe(event=b.get_syscall_fnname("accept"), fn_name="syscall__accept_return")

b.attach_kprobe(event="vfs_open", fn_name="do_vfs_open")
b.attach_kprobe(event="vfs_unlink", fn_name="do_vfs_unlink")
b.attach_kprobe(event="vfs_rename", fn_name="do_vfs_rename")
b.attach_kprobe(event="vfs_mkdir", fn_name="do_vfs_mkdir")
b.attach_kprobe(event="vfs_rmdir", fn_name="do_vfs_rmdir")
b.attach_kprobe(event="tcp_v4_connect", fn_name="do_tcp_v4_connect")
b.attach_kretprobe(event="vfs_mkdir", fn_name="do_vfs_mkdir_return")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="do_tcp_v4_connect_return")

mp = b["stt_behav"]
for key, val in stt.items():
    current_key = mp.Key(key)
    current_val = mp.Leaf(val)
    mp[current_key] = current_val


def print_event(cpu, data, size):
    global log_size, out, group_size, ready_to_write

    event = ct.cast(data, ct.POINTER(BehavT)).contents
    # items for logs
    time = str(datetime.fromtimestamp(boot_time + int(event.time) / 1e9))
    task = "{} {}".format(event.ppid, event.pid)
    if not CHECK_FLAG(event.s.for_assign, FLAG_SMT_SOCK):
        ready_to_write += [time, " ", task, " ", usr[event.uid], " ", event.comm.decode(),
                           " ", get_behavior(event.s.fr.operate), " ", event.detail.file.name.decode(),
                           ":", str(event.detail.file.i_ino)]
        if args.debug:
            ready_to_write += [" ", str(event.fd), " %x" % event.s.for_assign]
    else:
        # laddr, daddr, lport, dport = 0, 0, 0, 0
        if event.s.fr.operate == OP_CONNECT:
            laddr = event.local.addr
            lport = event.local.port
            daddr = event.detail.remote.addr
            dport = event.detail.remote.port
        else:
            laddr = event.detail.remote.addr
            lport = event.detail.remote.port
            daddr = event.local.addr
            dport = event.local.port
        ready_to_write += [time, " ", task, " ", usr[event.uid], " ", event.comm.decode(),
                           " ", get_behavior(event.s.fr.operate),
                           "-by ", "{}:{}".format(socket.inet_ntoa(struct.pack('I', laddr)), lport)]
        if args.debug:
            ready_to_write += [" %x" % event.s.for_assign]
        ready_to_write.append("\n")
        log_size += 1
        ready_to_write += [time, " ", task, " ", usr[event.uid], " ", event.comm.decode(),
                           " ", get_behavior(event.s.fr.operate),
                           " ", "{}:{}".format(socket.inet_ntoa(struct.pack('I', daddr)), dport)]
        if args.debug:
            ready_to_write += [" %x" % event.s.for_assign]
    ready_to_write.append("\n")

    log_size += 1
    if log_size >= group_size:
        log_size = 0
        Thread(target=output_log, args=(ready_to_write,)).start()
        ready_to_write = list()


print("Bpf program loaded. Ctrl + C to stop...")
if args.debug:
    print("%-26s %-6s %-6s %-10s %-6s TYPE" % ("TIME", "PPID", "PID", "USER", "TASK"))

b["behavior"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        if log_size:
            out.writelines(ready_to_write)
            out.flush()
        if not args.debug:
            out.close()
        exit(0)
