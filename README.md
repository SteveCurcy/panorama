# Panorama
Panorama 是一个用于监控系统事件并还原高级行为的日志采集系统。它主要通过使用 eBPF 技术对系统调用和内核函数进行监控，并使用状态机来获取当前系统所处的行为状态以发掘一系列系统调用背后隐藏的用户行为。

[![](https://img.shields.io/badge/Author-Xu.Cao-lightgreen)](https://github.com/SteveCurcy) [![](https://img.shields.io/badge/Dependencies-BCC-blue)](https://github.com/iovisor/bcc) ![](https://img.shields.io/badge/Version-6.1.0-yellow)


## 使用
本项目依赖于 IO Visor 的开源项目 BCC。因此要运行本项目，请首先安装 BCC 工具，具体请参照 [BCC 安装](https://github.com/iovisor/bcc/blob/master/INSTALL.md)，推荐使用源码安装。

BCC 项目提供了所需的所有依赖库，并提供实时编译，因此你无需手动编译安装即可使用。

```bash
sudo ./panorama.py
```

运行该命令默认将捕获日志并将日志保存到 `/var/log/syslog.log`。`-d` 选项将用于 DEBUG 模式，并将日志和状态信息直接输出到终端。但我们并不建议使用该选项，除非你要进行调试。据我们不严谨的实验测试，在资源密集型工作中，开启 DEBUG 模式将增加近 10 倍的开销。

## 支持行为
目前项目所支持的行为有限，包含：
- 查看文件：`cat, vi/vim`
- 创建文件：`touch, vi/vim`
- 删除文件：`rm`
- 拆分文件：`split`
- 压缩与解压：`zip, gzip, unzip`
- 移动拷贝：`cp, mv`
- 文件夹创建与删除：`mkdir, rmdir`
- 文件传输：`scp`
