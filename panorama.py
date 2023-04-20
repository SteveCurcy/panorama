#!/bin/env python
# @author Xu.Cao
# @date   2023-04-13
# @detail 本程序使用 BCC 工具将 panorama.c 编译并注入内核，并高效的保存或显示日志；
#         用户空间程序从定义文件中读取宏定义，从状态转移文件中获取状态转移表，下发到内核程序
#
# @history
#       <author>    <time>      <version>               <description>
#       Xu.Cao      2023-04-13  6.0.5                   注释完善
#       Xu.Cao      2023-04-17  6.0.6                   修改了现有数据结构，修复了数据定义 bug，CType 空间分配问题
import re
import sys

from bcc import BPF
import ctypes as ct
import socket
import struct
import json
import psutil
import argparse
from datetime import datetime, timedelta
from threading import Timer, Lock, Thread

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", help="print more infos like states for debugging", action="store_true")
args = parser.parse_args()


class FileT(ct.Structure):
    _fields_ = [
        ("i_ino", ct.c_uint32),
        ("name", ct.c_char * 32)
    ]


class NetT(ct.Structure):
    _fields_ = [
        ("addr", ct.c_uint32),
        ("port", ct.c_uint16),
    ]


class PeerNetT(ct.Structure):
    _fields_ = [
        ("local", NetT),
        ("remote", NetT),
        ("dummy", ct.c_char * 24)
    ]


class DetailT(ct.Union):
    _fields_ = [
        ("file", FileT),
        ("net", PeerNetT)
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
        ("detail", DetailT)
    ]


def stt_key(state: int, sys_call: int, arg: int) -> int:
    return (state << 48) | (sys_call << 40) | arg


def stt_val(flag: int, op: int, state: int) -> int:
    return (flag << 32) | (op << 16) | state


def CHECK_FLAG(s: int, f: int) -> bool:
    return not ((f & (s >> 32)) ^ f)


# 根据宏定义，解析状态转移表并将其转为字典类型返回
def get_state_table(definitions_) -> dict:
    with open("state_transition_table.stt", 'r') as csv:
        lines = csv.readlines()
    state_table = dict()

    for one_line in lines:
        if one_line.strip() == '' or one_line[0] == '#':
            continue
        item_lst = one_line.strip().split()
        src = definitions_["states"][item_lst[0]] if item_lst[0] in definitions_["states"] else eval(item_lst[0])
        syscall = definitions_["sys_calls"][item_lst[1]]
        arg = definitions_["args"][item_lst[2]] if item_lst[2] in definitions_["args"] else eval(item_lst[2])
        flags_lst = item_lst[3].split('|')
        flags = 0
        for flag in flags_lst:
            if flag in definitions_['flags']:
                flags |= definitions_["flags"][flag]
            else:
                flags |= eval(flag)
        operate = definitions_["operations"][item_lst[4]] if item_lst[4] in definitions_["operations"] else eval(
            item_lst[4])
        dst = definitions_["states"][item_lst[5]] if item_lst[5] in definitions_["states"] else eval(item_lst[5])
        state_table.update({stt_key(src, syscall, arg): stt_val(flags, operate, dst)})

    return state_table


def get_behavior(op: int) -> str:
    if op in op_map:
        return op_map[op]
    else:
        return "other"


def output_log(logs: list) -> None:
    out.writelines(logs)
    out.flush()


# 调用 BCC 提供的 API 将内核程序注入到对应位置
def load_ebpf():
    with open("definitions.json") as defs:
        definitions_ = json.load(defs)
        for k in definitions_:
            for kk in definitions_[k]:
                definitions_[k][kk] = eval(definitions_[k][kk])

    micro_list = []
    for k, v in dict(definitions_).items():
        for kk, vv in v.items():
            micro_list.append("#define {} {}".format(kk, vv))

    with open("panorama.c") as fp:
        prog = fp.read()
    if prog is None or prog == "":
        print("file open error")
        exit(-1)
    prog = re.sub(r'\[MICRO_DEFINITIONS]', '\n'.join(micro_list), prog, count=1)
    # operations of eBPF
    b_ = BPF(text=prog)
    b_.attach_kprobe(event=b_.get_syscall_fnname("openat"), fn_name="syscall__openat")
    b_.attach_kprobe(event=b_.get_syscall_fnname("read"), fn_name="syscall__read")
    b_.attach_kprobe(event=b_.get_syscall_fnname("write"), fn_name="syscall__write")
    b_.attach_kprobe(event=b_.get_syscall_fnname("close"), fn_name="syscall__close")
    b_.attach_kprobe(event=b_.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat")
    b_.attach_kprobe(event=b_.get_syscall_fnname("mkdirat"), fn_name="syscall__mkdirat")
    b_.attach_kprobe(event=b_.get_syscall_fnname("renameat"), fn_name="syscall__renameat")
    b_.attach_kprobe(event=b_.get_syscall_fnname("renameat2"), fn_name="syscall__renameat2")
    b_.attach_kprobe(event=b_.get_syscall_fnname("dup3"), fn_name="syscall__dup3")
    b_.attach_kprobe(event=b_.get_syscall_fnname("socket"), fn_name="syscall__socket")
    b_.attach_kprobe(event=b_.get_syscall_fnname("connect"), fn_name="syscall__connect")
    b_.attach_kprobe(event=b_.get_syscall_fnname("accept"), fn_name="syscall__accept")
    b_.attach_kprobe(event=b_.get_syscall_fnname("exit_group"), fn_name="syscall_exit_group")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("openat"), fn_name="syscall__openat_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("read"), fn_name="syscall__read_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("write"), fn_name="syscall__write_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("close"), fn_name="syscall__close_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("mkdirat"), fn_name="syscall__mkdirat_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("renameat"), fn_name="syscall__renameat_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("renameat2"), fn_name="syscall__renameat2_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("dup3"), fn_name="syscall__dup3_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("socket"), fn_name="syscall__socket_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("connect"), fn_name="syscall__connect_return")
    b_.attach_kretprobe(event=b_.get_syscall_fnname("accept"), fn_name="syscall__accept_return")

    b_.attach_kprobe(event="vfs_open", fn_name="do_vfs_open")
    b_.attach_kprobe(event="vfs_unlink", fn_name="do_vfs_unlink")
    b_.attach_kprobe(event="vfs_rename", fn_name="do_vfs_rename")
    b_.attach_kprobe(event="vfs_mkdir", fn_name="do_vfs_mkdir")
    b_.attach_kprobe(event="vfs_rmdir", fn_name="do_vfs_rmdir")
    b_.attach_kprobe(event="tcp_v4_connect", fn_name="do_tcp_v4_connect")
    b_.attach_kretprobe(event="vfs_mkdir", fn_name="do_vfs_mkdir_return")
    b_.attach_kretprobe(event="tcp_v4_connect", fn_name="do_tcp_v4_connect_return")

    return b_, definitions_


# 程序的初始化，获取宏定义和状态转移表并将其下发到内核 eBPF 程序中
# 获取当前 Linux 系统上由哪些用户，获得 uid => username 的映射
# 根据用户选项确定程序的日志输出目标位置，是终端还是文件
def init(bpf, definitions_) -> tuple:
    global args

    mp = bpf["stt_behav"]
    stt = get_state_table(definitions_)
    for key, val in stt.items():
        current_key = mp.Key(key)
        current_val = mp.Leaf(val)
        mp[current_key] = current_val

    users_ = dict()
    with open("/etc/passwd") as f:
        for line in f:
            items = line.split(":")
            users_.update({int(items[2]): items[0]})

    # determine which output target is used
    log_file_name = "/var/log/syslog.log"
    if args.debug:
        out_ = sys.stdout
        group_size_ = 4
    else:
        out_ = open(log_file_name, "w")
        group_size_ = 20971  # output when logs size reach 20M

    return users_, out_, group_size_


boot_time, log_size, logs_cache = psutil.boot_time(), 0, list()

b, definitions = load_ebpf()
users, out, group_size = init(b, definitions)

op_map = {
    definitions['operations']["OP_CREATE"]: "create",
    definitions['operations']["OP_REMOVE"]: "remove",
    definitions['operations']["OP_READ"]: "read",
    definitions['operations']["OP_WRITE"]: "write",
    definitions['operations']["OP_COVER"]: "cover",
    definitions['operations']["OP_SAVE"]: "save",
    definitions['operations']["OP_MKDIR"]: "mkdir",
    definitions['operations']["OP_RMDIR"]: "rmdir",
    definitions['operations']["OP_CONNECT"]: "connect",
    definitions['operations']["OP_ACCEPT"]: "accept"
}


# 处理从内核空间返回的数据。将日志保存在一个全局列表中，当日志的数量超过
# 阈值时，才将其写入目标文件中。此外，存储字符串数组而不是将字符串拼接，
# 以此减少由于字符串操作导致的耗时，批量写入文件也将更高效
def print_event(cpu, data, size):
    global log_size, out, group_size, logs_cache

    event = ct.cast(data, ct.POINTER(BehavT)).contents
    # items for logs
    time = str(datetime.fromtimestamp(boot_time + int(event.time) / 1e9))
    task = "{} {}".format(event.ppid, event.pid)
    if not CHECK_FLAG(event.s.for_assign, definitions['flags']["FLAG_SMT_SOCK"]):
        logs_cache += [time, " ", task, " ", users[event.uid], " ", event.comm.decode(),
                       " ", get_behavior(event.s.fr.operate), " ", event.detail.file.name.decode(),
                       ":", str(event.detail.file.i_ino)]
        if args.debug:
            logs_cache += [" ", str(event.fd), " %x" % event.s.for_assign]
    else:
        # laddr, daddr, lport, dport = 0, 0, 0, 0
        if event.s.fr.operate == definitions['operations']["OP_CONNECT"]:
            laddr = event.detail.net.local.addr
            lport = event.detail.net.local.port
            daddr = event.detail.net.remote.addr
            dport = event.detail.net.remote.port
        else:
            laddr = event.detail.net.remote.addr
            lport = event.detail.net.remote.port
            daddr = event.detail.net.local.addr
            dport = event.detail.net.local.port
        logs_cache += [time, " ", task, " ", users[event.uid], " ", event.comm.decode(),
                       " ", get_behavior(event.s.fr.operate),
                       "-by ", "{}:{}".format(socket.inet_ntoa(struct.pack('I', laddr)), lport)]
        if args.debug:
            logs_cache += [" %x" % event.s.for_assign]
        logs_cache.append("\n")
        log_size += 1
        logs_cache += [time, " ", task, " ", users[event.uid], " ", event.comm.decode(),
                       " ", get_behavior(event.s.fr.operate),
                       " ", "{}:{}".format(socket.inet_ntoa(struct.pack('I', daddr)), dport)]
        if args.debug:
            logs_cache += [" %x" % event.s.for_assign]
    logs_cache.append("\n")

    log_size += 1
    if log_size >= group_size:
        log_size = 0
        Thread(target=output_log, args=(logs_cache,)).start()
        logs_cache = list()


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
            out.writelines(logs_cache)
            out.flush()
        if not args.debug:
            out.close()
        exit(0)
