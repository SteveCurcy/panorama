# Panorama

[![](https://img.shields.io/badge/Author-Xu.Cao-lightgreen)](https://github.com/SteveCurcy) [![](https://img.shields.io/badge/Dependencies-BCC-blue)](https://github.com/iovisor/bcc) ![](https://img.shields.io/badge/Version-6.1.1-yellow)

Panorama 是一个用于产生高级行为日志的日志采集系统。它将采集用户的行为而非海量系统或应用日志，并将采集的日志存储在 `/var/log/syslog.log`。

## 内容列表

- [背景 :cheese:](#背景-cheese)
- [使用说明 :strawberry:](#使用说明-strawberry)
- [示例 :cake:](#示例-cake)
- [支持行为 :muscle:](#支持行为-muscle)
- [使用许可 :page_facing_up:](#使用许可-page_facing_up)

## 背景 :cheese:

终端检测与响应（Endpoint Detection and Response，EDR）是一种主动式终端安全解决方案。它通过记录终端与网络事件，并通常将其传输到集中数据库，结合已有攻击指示器和行为分析来监测任何可能的安全威胁，并对这些安全威胁做出快速响应。

但我们不可能将海量的系统和应用日志都传输到集中数据库，因为这不仅影响到本地主机和中心服务器的性能，还将极大地影响网络的可用性。如果我们进行本地的分析，然后将分析数据传输到中心节点，这有可能导致威胁的遗漏（因为本地的分析不像中心服务器那样全面，而是包含了部分分析工作）。

因此，我们考虑在终端节点直接采集用户的行为日志，从而极大减少日志的产量并提升了日志的质量。我们的日志采集使用 eBPF 将程序动态注入到内核中，不会影响其他程序的正常运行（除非你的计算机上运行了除本项目以外的 eBPF 程序）。此外，由于产生的日志包含行为语义并且日志量非常少，因此可以简化行为分析过程并降低日志处理难度。

## 使用说明 :strawberry:

本项目依赖于 IO Visor 的开源项目 BCC。因此要运行本项目，请首先安装 BCC 工具，具体请参照 [BCC 安装](https://github.com/iovisor/bcc/blob/master/INSTALL.md)，推荐使用源码安装。

BCC 项目提供了所需的所有依赖库，并提供实时编译，因此你无需手动编译安装即可使用。

```bash
sudo ./panorama.py
```

运行该命令默认将捕获日志并将日志保存到 `/var/log/syslog.log`。`-d` 选项将用于 DEBUG 模式，并将日志和状态信息直接输出到终端。但我们并不建议使用该选项，除非你要进行调试。据我们不严谨的实验测试，在资源密集型工作中，开启 DEBUG 模式将增加近 10 倍的开销。

## 示例 :cake:

你可以尝试在任意路径下创建 f2.txt 文件，然后可以启动一个 docker 容器并在上面开启 ssh 服务以便于 scp 文件传输。然后运行以下命令（本人直接使用容器的 root 连接）：

```bash
scp f2.txt root@172.17.0.2:/root
```

然后你将得到以下输出：

```bash
2023-04-02 16:52:27.271656 3760 3761 parallels ssh read known_hosts:2639560
2023-04-02 16:52:27.271964 3760 3761 parallels ssh remove known_hosts.XXXXXj6xj9Z:2641846
2023-04-02 16:52:25.468648 2682 3760 parallels scp connect-by 172.17.0.1:43716
2023-04-02 16:52:25.468648 2682 3760 parallels scp connect 172.17.0.2:22
2023-04-02 16:52:27.275448 3762 3777 root scp accept-by 172.17.0.1:43716
2023-04-02 16:52:27.275448 3762 3777 root scp accept 172.17.0.2:22
2023-04-02 16:52:27.276747 2682 3760 parallels scp read f2.txt:3015807
2023-04-02 16:52:27.276845 3762 3777 root scp write f2.txt:1049529
```

由于容器是轻量级的，并且也会在宿主系统上产生类似的行为，因此也会被监测到。因此这里输出了两个终端的行为日志。

**注意**：如果你使用的是虚拟机或真实主机之间的文件传输，那么你还将看到大量用于网络控制的系统事件，这些是无法避免的。 

## 支持行为 :muscle:

目前项目所支持的行为有限，包含：

- 查看文件：`cat, vi/vim`
- 创建文件：`touch, vi/vim`
- 删除文件：`rm`
- 拆分文件：`split`
- 压缩与解压：`zip, gzip, unzip`
- 移动拷贝：`cp, mv`
- 文件夹创建与删除：`mkdir, rmdir`
- 文件传输：`scp`

## 使用许可 :page_facing_up:

[GPL 2.0](./LICENSE) :copyright: Xu.Cao (Steve Curcy)
