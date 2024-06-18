# rats-rs
[![Testing](/../../actions/workflows/build-and-test.yaml/badge.svg)](/../../actions/workflows/build-and-test.yaml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


rats-rs是一个纯Rust实现的TEE远程证明库，它的最终目标是让开发者能够方便地将远程证明能力集成到应用程序的各个方面。它还包含了一个基于SPDM协议的安全会话层实现，能够为与TEE环境的通信提供类似于TLS的安全加密层。

## 关键特性
<!-- Key features -->

- 纯Rust实现
- 提供易于使用的生成器模式(Builder Pattern)API
- 对不同TEE类型的可扩展性
- 为上层应用提供三种层次的API
- 支持指定证书使用的加密算法
- 自动检测当前运环境TEE类型
- 支持基于features的功能剪裁
- 提供C API调用和CMake构建

## 支持的TEE类型
<!-- Supported TEE types -->

本项目在支持的TEE类型方面采用了模块化设计，目前对不同TEE类型的支持情况如下：

| SGX DCAP(Occlum) | TDX | SEV-SNP | CSV | CCA |
|------------------|-----|---------|-----|-----|
| ✔️               | ✔️  | 🚧      | 🚧  | 🚧  |


## 快速开始
<!-- Quick start -->

接下来的流程将指引你在SGX实例上运行rats-rs的样例程序spdm-echosvr，其源码可以在[这里](/examples/spdm/)找到。

1. 首先准备rats-rs的构建环境，建议直接使用我们预构建的Docker容器

    ```sh
    docker run -it --privileged --device=/dev/sgx_enclave --device=/dev/sgx_provision ghcr.io/inclavare-containers/rats-rs:builder bash
    ```

2. Clone代码并编译样例程序
    
    ```sh
    git clone git@github.com:inclavare-containers/rats-rs.git
    cd rats-rs
    
    just prepare-repo

    cargo build --bin spdm
    ```

3. 运行Server端程序

    ```sh
    just run-in-occlum echo-server --attest-self --listen-on-tcp 127.0.0.1:8080
    ```

4. 运行Client端程序（在新的终端中）

    ```sh
    just run-in-host echo-client --verify-peer --connect-to-tcp 127.0.0.1:8080
    ```

    你将从程序日志中观测到Client和Server之间的交互，并且可以使用环境变量`RATS_RS_LOG_LEVEL`来控制日志级别。

    关于示例程序的更多详细信息，请查看[这份](/examples/spdm/README.md)文档

## 作为依赖使用

将以下内容添加到你的`Cargo.toml`文件

```toml
[dependencies]
rats-rs = {git = "https://github.com/inclavare-containers/rats-rs", branch = "master"}
```

要开始使用rats-rs的API，建议参考[示例程序](/examples/spdm/)。

此外值得一提的是，rats-rs的编译和运行依赖于一些系统库，你可以在[这里](/docs/how-to-build.md)找到完整的构建环境搭建流程。

## 对于开发人员

本项目采用[just](https://github.com/casey/just/)工具来封装一些自动化流程，诸如测试、运行、代码覆盖率计算等。它与Makefile非常相似，当你需要引入新的流程时，请尽量将其添加到[justfile](/justfile)中。

在开始编码之前，你可以先阅读[docs](/docs/)下的文档。

## 项目文档

大部分文档都归类在[docs](/docs/)目录下，这里列举出一些相对重要的文档，方便开始接触本项目。

- [环境搭建与项目构建指引](/docs/how-to-build.md)
- [C API的构建与使用](/c-api/README.md)
- [测试指引与代码覆盖率](/docs/how-to-run-test.md)
- [项目整体架构与模块功能描述](/docs/architecture-of-the-project.md)
- [CPU-SPDM协议核心设计思路](/docs/core-design-of-cpu-spdm.md)
- [示例程序构建与运行说明](/examples/spdm/README.md)
- [CPU-TEE SPDM协议标准化文档：CPU TEE Secured Messages using SPDM Binding Specification](/docs/CPU%20TEE%20Secured%20Messages%20using%20SPDM%20Binding%20Specification.pdf)


## License

该项目使用Apache License 2.0 许可证授权
