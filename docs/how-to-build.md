
# 编译

## 环境准备

### Docker

本项目提供提供了以Docker容器形式的构建开发环境，可以使用如下命令拉取构建开发环境的镜像。

```sh
docker pull ghcr.io/inclavare-containers/rats-rs:builder
```

或者也可以直接以Dockerfile的形式构建

```sh
git clone git@github.com:inclavare-containers/rats-rs.git
cd rats-rs

docker build --tag rats-rs:builder --target builder .
```

接着根据不同的TEE类型，使用相应命令启动环境

- SGX实例：

    ```sh
    docker run -it --privileged --device=/dev/sgx_enclave --device=/dev/sgx_provision rats-rs:builder bash
    ```

- TDX实例：

    ```sh
    docker run -it --privileged --device=/dev/tdx_guest rats-rs:builder bash
    ```

### 手动安装依赖

下面提供Ubuntu 20.04发行版上的依赖安装流程，在其它发行版上的流程比较类似，可以参考[Intel_SGX_SW_Installation_Guide_for_Linux.pdf](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)。

1. 安装基础依赖库

    ```sh
    # If you need mirror
    echo "deb http://cn.archive.ubuntu.com/ubuntu focal main" >> /etc/apt/sources.list

    apt-get update
    apt-get update && apt-get install -y make git vim clang-format gcc \
        pkg-config protobuf-compiler debhelper cmake \
        wget net-tools curl file gnupg tree libcurl4-openssl-dev \
        libbinutils libseccomp-dev libssl-dev binutils-dev libprotoc-dev libprotobuf-dev \
        clang jq
    ```

2. 安装Rust工具链

    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    ```
    将下面语句添加到`~/.bashrc`末尾
    ```sh
    export PATH=/root/.cargo/bin:$PATH
    ```

    （Optional）安装用于计算代码覆盖率的工具`llvm-tools-preview`
    ```
    rustup component add llvm-tools-preview
    ```

3. 本项目使用[just](https://github.com/casey/just/)工具来封装本项目的构建、测试、运行流程，因此首先需要安装just。

    ```sh
    cargo install just
    ```
4. 安装Intel SGX LVI mitigated toolchain

    ```sh
    wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/as.ld.objdump.r4.tar.gz && \
        tar -zxvf as.ld.objdump.r4.tar.gz && cp -rf external/toolset/ubuntu20.04/* /usr/local/bin/ && \
        rm -rf external && rm -rf as.ld.objdump.r4.tar.gz
    ```

5. 安装Intel SGX SDK

    > 依赖于Intel SGX SDK version >= 2.23

    ```sh
    SGX_SDK_VERSION=2.23
    SGX_SDK_RELEASE_NUMBER=2.23.100.2
    wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/distro/ubuntu20.04-server/sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && \
        chmod +x sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && \
        echo -e 'no\n/opt/intel\n' | ./sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin
    ```

6. 安装SGX DCAP软件包

    引入Intel官方提供的在线apt repo

    ```sh
    echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | tee /etc/apt/sources.list.d/intel-sgx.list && \
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
    apt-get update -y
    ```

    安装SGX DCAP软件包

    ```sh
    SGX_SDK_VERSION=2.23
    SGX_DCAP_VERSION=1.20
    apt-get update -y && apt-get install -y libsgx-headers="$SGX_SDK_VERSION*" \
        libsgx-uae-service="$SGX_SDK_VERSION*" \
        libsgx-dcap-quote-verify-dev="$SGX_DCAP_VERSION*" \
        libsgx-dcap-ql-dev="$SGX_DCAP_VERSION*" \
        libsgx-dcap-default-qpl-dev="$SGX_DCAP_VERSION*"
    ```


7. 安装occlum，用于在occlum环境中运行rats-rs样例程序

    ```sh
    echo 'deb [arch=amd64] https://occlum.io/occlum-package-repos/debian focal main' | tee /etc/apt/sources.list.d/occlum.list
    wget -qO - https://occlum.io/occlum-package-repos/debian/public.key | apt-key add -
    apt-get update
    apt-get install -y libfuse2 occlum occlum-toolchains-glibc
    ```

    将下面语句添加到`~/.bashrc`末尾

    ```sh
    export PATH="/opt/occlum/build/bin:${PATH}"
    ```

8. （针对TDX实例）安装TDX Attestation library
    ```sh
    SGX_DCAP_VERSION=1.20
    apt-get install -y libtdx-attest-dev="$SGX_DCAP_VERSION*"
    ```


## 编译

如果你准备单独构建该项目，或者简单尝试该项目中提供的样例程序，可以使用如下方法来构建代码

1. 拉取源码
    
    ```sh
    git clone git@github.com:inclavare-containers/rats-rs.git
    cd rats-rs
    ```

2. 准备

    ```sh
    just prepare-repo-spdm
    ```

3. 构建项目（这将同时构建rats-cert和rats-transport）

    ```sh
    just build
    ```

4. （可选）构建样例程序

    ```sh
    just build-example-spdm
    ```

    对于如何运行样例程序，请参考examples目录下的[例子](/examples/spdm)。