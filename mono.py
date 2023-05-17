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
#       Xu.Cao      2023-04-26  6.1.0                   1. 实现数据定义和状态转移表与程序的剥离
#                                                       2. 不再由用户输入参数控制，而是由配置文件控制（包括调试、输出文件、定义等）
import re
import sys
from bcc import BPF
import ctypes as ct
import socket
import struct
import json
import psutil
from datetime import datetime
from threading import Thread

sys_map = {
    0: "openat",
    1: "read",
    2: "write",
    3: "close",
    4: "unlinkat",
    5: "mkdirat",
    6: "renameat",
    7: "renameat2",
    8: "dup3",
    9: "socket",
    10: "connect",
    11: "accept",
    12: "dup2",
    13: "rename",
    14: "rmdir"
}


def sys_name(sys_id: int) -> str:
    if sys_id in sys_map:
        return sys_map[sys_id]
    else:
        return "other"


# 调用 BCC 提供的 API 将内核程序注入到对应位置
with open("mono.c") as fp:
    prog = fp.read()
prog = prog.replace('COMMAND', '\"vim\"', 1)
if prog is None or prog == "":
    print("file open error")
    exit(-1)
# operations of eBPF
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat")
b.attach_kprobe(event=b.get_syscall_fnname("read"), fn_name="syscall__read")
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__write")
b.attach_kprobe(event=b.get_syscall_fnname("close"), fn_name="syscall__close")
b.attach_kprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat")
b.attach_kprobe(event=b.get_syscall_fnname("mkdirat"), fn_name="syscall__mkdirat")
b.attach_kprobe(event=b.get_syscall_fnname("mkdir"), fn_name="syscall__mkdir")
b.attach_kprobe(event=b.get_syscall_fnname("rmdir"), fn_name="syscall__rmdir")
b.attach_kprobe(event=b.get_syscall_fnname("rename"), fn_name="syscall__rename")
b.attach_kprobe(event=b.get_syscall_fnname("renameat"), fn_name="syscall__renameat")
b.attach_kprobe(event=b.get_syscall_fnname("renameat2"), fn_name="syscall__renameat2")
b.attach_kprobe(event=b.get_syscall_fnname("dup2"), fn_name="syscall__dup2")
b.attach_kprobe(event=b.get_syscall_fnname("dup3"), fn_name="syscall__dup3")
b.attach_kprobe(event=b.get_syscall_fnname("socket"), fn_name="syscall__socket")
b.attach_kprobe(event=b.get_syscall_fnname("connect"), fn_name="syscall__connect")
b.attach_kprobe(event=b.get_syscall_fnname("accept"), fn_name="syscall__accept")
b.attach_kretprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("read"), fn_name="syscall__read_return")
b.attach_kretprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__write_return")
b.attach_kretprobe(event=b.get_syscall_fnname("close"), fn_name="syscall__close_return")
b.attach_kretprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("mkdirat"), fn_name="syscall__mkdirat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("mkdir"), fn_name="syscall__mkdir_return")
b.attach_kretprobe(event=b.get_syscall_fnname("rmdir"), fn_name="syscall__rmdir_return")
b.attach_kretprobe(event=b.get_syscall_fnname("rename"), fn_name="syscall__rename_return")
b.attach_kretprobe(event=b.get_syscall_fnname("renameat"), fn_name="syscall__renameat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("renameat2"), fn_name="syscall__renameat2_return")
b.attach_kretprobe(event=b.get_syscall_fnname("dup2"), fn_name="syscall__dup2_return")
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


# 处理从内核空间返回的数据。将日志保存在一个全局列表中，当日志的数量超过
# 阈值时，才将其写入目标文件中。此外，存储字符串数组而不是将字符串拼接，
# 以此减少由于字符串操作导致的耗时，批量写入文件也将更高效
def print_event(cpu, data, size):
    event = b['events'].event(data)
    print('{} {} {} 0o{:o} {} {} {} {} {}:{} {}:{}'.format(
        event.ppid, event.pid, sys_name(event.sys_id),
        event.args, event.aux_fd, event.fd,
        event.name, event.aux_name, event.local_ip, event.local_port,
        event.remote_ip, event.remote_port))


print("Bpf program loaded. Ctrl + C to stop...")
print('PPID PID TASK ARGS AUXFD FD NAME AUXNAME LOCAL REMOTE')

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        exit(0)
