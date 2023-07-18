# Panorama

[![](https://img.shields.io/badge/Author-Xu.Cao-lightgreen)](https://github.com/SteveCurcy) [![](https://img.shields.io/badge/Dependencies-libbpf-blue)](https://github.com/libbpf/libbpf-bootstrap) ![](https://img.shields.io/badge/Version-7.0.1-yellow)

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
```

## 示例

构建完后直接执行该程序即可。

```shell
sudo ./panorama
<...>
```

## 使用许可

[BSD-3](./LICENSE) :copyright: Xu.Cao (Steve Curcy)
