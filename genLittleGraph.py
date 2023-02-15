#!/usr/bin/env python
import sys

nodes = set()
edges = []

if len(sys.argv) <= 1:
    print("[Error] No file pointed.")
    exit(0)

with open(sys.argv[1], "r") as f:
    line = f.readline()[:-1]
    while line:
        time, src, fm, task, to, dst = line.split()
        if src != "None":
            nodes.add(src + "\n")
            edges.append("{} {} {}.{}\n".format(src, task, time, fm))
        if dst != "None":
            nodes.add(dst + "\n")
            edges.append("{} {} {}.{}\n".format(task, dst, time, to))
        nodes.add(task + "\n")
        line = f.readline()[:-1]


with open("graph_status.txt", "w") as f:
    f.writelines(nodes)
    f.writelines(edges)
