# Panorama

[![](https://img.shields.io/badge/Author-Xu.Cao-lightgreen)](https://github.com/SteveCurcy) [![](https://img.shields.io/badge/Dependencies-libbpf-blue)](https://github.com/libbpf/libbpf-bootstrap) ![](https://img.shields.io/badge/Version-7.4.1-yellow)

Panorama 是一个用于产生高级行为日志的日志采集系统。它将采集用户的行为而非海量系统或应用日志。

本程序基于 libbpf-bootstrap 进行二次开发。

## 内容列表

- [使用说明](#使用说明)
- [示例](#示例)
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
# 然后执行 stt，它会生成对应的状态转移表并输出在终端，拷贝粘贴到 panorama.c 
# 的状态转移表中，然后重新 make 编译
./stt
# 终端 1 中执行日志捕获程序
sudo ./panorama
# 终端 2 中执行 test.sh 测试文件，查看日志输出
./test.sh
# 最终的日志将产生并输出在 /var/log/panorama.log 中
cat /var/log/panorama.log
<...>
```

## 说明

本项目主要分为了 genor 和 panorama 两个部分。其中 genor 是用来生成指定命令的行为模式，然后通过 stt 根据行为模式生成状态机；panorama 则根据状态机识别进程行为并输出日志。

首先调用 genor 将行为模式存储在 /var/log/genor.log 文件中，stt 将读取该文件并输出生成的状态机。在单进程命令操作单个文件的条件下，生成的状态机可以直接复制粘贴到 panorama.c 文件中使用；如果单进程命令想识别操作多个文件的命令，则需要进行人工矫正。

## 使用许可

[BSD-3](./LICENSE) (c) Xu.Cao (Steve Curcy)
