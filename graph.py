#!/usr/bin/env python

## Categorical color scale 连续颜色
# libraries
import pandas as pd
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
 
# Build a dataframe with your connections
df = pd.DataFrame(None, columns=['from', 'to'])
# And a data frame with characteristics for your nodes
carac = pd.DataFrame(None, columns=['ID', 'myvalue'])

with open("panorama.log", "r") as f:
    line = f.readline()[:-1]
    while line:
        _, src, task, dst = line.split()
        if src != "None":
            df = df.append([{'from': src, 'to': task}], ignore_index=True)
            carac = carac.append([{'ID': src, 'myvalue': 'file'}], ignore_index=True)
        if dst != "None":
            df = df.append([{'from': task, 'to': dst}], ignore_index=True)
            carac = carac.append([{'ID': dst, 'myvalue': 'file'}], ignore_index=True)
        carac = carac.append([{'ID': task, 'myvalue': 'task'}])
        line = f.readline()[:-1]

# Build your graph
# 建立图
G=nx.from_pandas_edgelist(df, 'from', 'to', create_using=nx.MultiDiGraph())
 
# The order of the node for networkX is the following order:
# 打印节点顺序
G.nodes()
# Thus, we cannot give directly the 'myvalue' column to netowrkX, we need to arrange the order!
 
# Here is the tricky part: I need to reorder carac to assign the good color to each node
carac= carac.set_index('ID')
# 根据节点顺序设定值
carac = carac[~carac.index.duplicated()]
carac=carac.reindex(G.nodes())
 
# And I need to transform my categorical column in a numerical value: group1->1, group2->2...
# 设定类别
carac['myvalue']=pd.Categorical(carac['myvalue'])
carac['myvalue'].cat.codes
    
# Custom the nodes:
nx.draw(G, with_labels=True, node_color=carac['myvalue'].cat.codes, cmap=plt.cm.Set1, node_size=1500, pos=nx.random_layout(G))
plt.show()
