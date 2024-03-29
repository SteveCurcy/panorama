# Panorama

[![](https://img.shields.io/badge/Author-Xu.Cao-lightgreen)](https://github.com/SteveCurcy) [![](https://img.shields.io/badge/Dependencies-libbpf-blue)](https://github.com/libbpf/libbpf-bootstrap) ![](https://img.shields.io/badge/Version-1.5.6-yellow)

Panorama 是一个用于产生高级行为日志的日志采集系统。它将采集用户的行为而非海量系统或应用日志。

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

我们推荐在部署编译的时候创建一个单独的路径，如 build。然后执行对应的编译构建命令。

```shell
# 当前路径为 panorama 项目根目录
git submodule update --init --recursive # 初始化依赖库
mkdir build && cd build
cmake ../src
make
clang++ -O3 ../src/sttGenor.cpp -o sttGenor
```

## 示例

新增了测试样例，您可以直接使用测试样例进行测试。

```shell
# terminal 1 首先执行 build 路径下 genor
sudo ./genor
# terminal 2 再执行 test 路径下 test.sh
# 测试中包含 scp 命令，因此，需要安装 docker，并在容器中开启 ssh
./test.sh
# 这样，在 /var/log/genor.log 中就形成了中间文件，或者简化后的模式
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

## 说明

本项目主要分为了 genor 和 panorama 两个部分。其中 genor 是用来生成指定命令的行为模式，然后通过 sttGenor 根据行为模式生成状态机；panorama 则根据状态机识别进程行为并输出日志。

首先调用 genor 将行为模式存储在 /var/log/genor.log 文件中，sttGenor 将读取该文件并输出生成的状态机。现在 genor 和 panorama 都可以根据 ini 配置文件完成配置，而不需重新编译。

## 现有问题

部分进程，如 split 命令执行到末尾会回到之前的状态，导致无法增加结束状态，从而无法判断该行为。

存在部分进程行为的误报，这是由于不同进程可能存在某一段行为相同，会导致中间状态出现误报。

## 使用许可

[BSD-3](./LICENSE) (c) Xu.Cao (Steve Curcy)
