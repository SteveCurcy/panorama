#!/usr/bin/env python

nodes = []
edges = []

with open("panorama.log", "r") as f:
    line = f.readline()[:-1]
    while line:
        _, src, task, dst = line.split()
        if src != "None":
            nodes.append(src)
            edges.append("{} {}".format(src, task))
        if dst != "None":
            nodes.append(dst)
            edges.append("{} {}".format(task, dst))
        nodes.append(task)
        line = f.readline()[:-1]

for node in nodes:
    print(node)
for edge in edges:
    print(edge)
