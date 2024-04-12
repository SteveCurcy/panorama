# Panorama

[![](https://img.shields.io/badge/Author-Xu.Cao-lightgreen)](https://github.com/SteveCurcy) [![](https://img.shields.io/badge/Dependencies-libbpf-blue)](https://github.com/libbpf/libbpf-bootstrap) ![](https://img.shields.io/badge/Version-1.5.6-yellow)

Panorama 是一个用于产生高级行为日志的监控系统。它将采集进程的行为而非海量系统或应用日志。

本程序基于 libbpf-bootstrap 进行二次开发。

## 内容列表

- [使用说明](#使用说明)
- [示例](#示例)
- [现有问题](#现有问题)
- [使用许可](#使用许可)

## 使用说明

### 安装依赖

由于本程序使用 libbpf 和 libbpf-bootstrap 框架进行开发，因此你需要 `clang`（v11 及以上版本），libelf 和 zlib 来构建。

在 Debian/Ubuntu 上，请执行：

```shell
apt install clang libelf1 libelf-dev zlib1g-dev cmake
```

在 CentOS/Fedora 上，请执行：

```shell
dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel cmake
```

### 项目构建

我们推荐在部署编译的时候创建一个单独的路径，如 build。然后执行对应的编译构建命令。本项目的所有源代码都放置在 src 目录下，主要包括 genor 行为模式采集、sttGenor 自动机规则生成工具和 panorama 系统监控工具。

```shell
git clone https://github.com/SteveCurcy/panorama.git
cd panorama
git submodule update --init --recursive # 初始化依赖库
mkdir build && cd build
cmake ../src
make
clang++ -O3 ../src/sttGenor.cpp -o sttGenor
```

## 示例

在使用前，需要编写关注的行为脚本。例如：希望监控 cat、touch 命令的行为，则可以编写以下脚本：

```bash
cat c1
cat c1 c2
touch t1
rm t1
touch t1 t2
rm t1 t2
```

其中需要注意编写使用命令进行多文件操作，这样可以使 genor 和 sttGenor 获取更准确的进程行为。为了实现系统监控并识别进程的行为，首先需要获取自动机的识别规则。通过 genor 命令获取上述脚本中的命令的行为模式，并使用 sttGenor 将行为模式转换为自动机执行规则即可。最后，执行 panorama 工具开启系统监控即可。

```shell
# terminal 1 首先执行 build 路径下 genor
sudo ./genor
# terminal 2 再执行 test 路径下 test.sh
# 测试中包含 scp 命令，因此，需要安装 docker，并在容器中开启 ssh
./test.sh
# 这样，在 /var/log/genor.log 中就得到了脚本中包含的命令的行为模式。
# 然后执行 sttGenor，它会生成对应的状态转移表并保存在二进制和文本文件中
# panorama 将加载状态转移表的二进制文件，并更新到内核 map 中 
./sttGenor
# 终端 1 中执行日志捕获程序
sudo ./panorama
# 终端 2 中执行 test.sh 测试文件，查看日志输出
./test.sh
# 最终的日志将产生并输出在 /var/log/panorama.log 中
cat /var/log/panorama.log
<...>
```

## 现有问题

暂无。但是随着加入的行为增多，可能出现某些行为的输入事件序列完全相同的情况，进而出现误报或漏报。

## 使用许可

[BSD-3](./LICENSE) (c) Xu.Cao (Steve Curcy)
