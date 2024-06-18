FROM ubuntu:20.04 as builder

ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
ENV DEBIAN_FRONTEND noninteractive

ENV SGX_SDK_VERSION 2.23
ENV SGX_SDK_RELEASE_NUMBER 2.23.100.2
ENV SGX_DCAP_VERSION 1.20

# install some necessary packages
RUN echo "deb http://cn.archive.ubuntu.com/ubuntu bionic main" >> /etc/apt/sources.list && apt-get update && apt-get install -y libprotobuf10

RUN apt-get update && apt-get install -y make git vim clang-format-9 gcc \
        pkg-config protobuf-compiler debhelper cmake \
        wget net-tools curl file gnupg tree libcurl4-openssl-dev \
        libbinutils libseccomp-dev libssl-dev binutils-dev libprotoc-dev \
        clang jq

# install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
ENV PATH         /root/.cargo/bin:$PATH

# install tools for code-coverage
RUN rustup component add llvm-tools-preview

# install "just"
RUN cargo install just

# install LVI binutils for rats-tls build
RUN wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/as.ld.objdump.r4.tar.gz && \
    tar -zxvf as.ld.objdump.r4.tar.gz && cp -rf external/toolset/ubuntu20.04/* /usr/local/bin/ && \
    rm -rf external && rm -rf as.ld.objdump.r4.tar.gz

# install SGX SDK
RUN [ ! -f sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin ] && \
    wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/distro/ubuntu20.04-server/sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && \
    chmod +x sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && echo -e 'no\n/opt/intel\n' | ./sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && \
    rm -f sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin

# add repository to package manager
RUN echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | tee /etc/apt/sources.list.d/intel-sgx.list && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -

# install SGX DCAP
RUN apt-get update -y && apt-get install -y libsgx-headers="$SGX_SDK_VERSION*" \
        libsgx-uae-service="$SGX_SDK_VERSION*" \
        libsgx-dcap-quote-verify-dev="$SGX_DCAP_VERSION*" \
        libsgx-dcap-quote-verify="$SGX_DCAP_VERSION*" \
        libsgx-dcap-ql-dev="$SGX_DCAP_VERSION*" \
        libsgx-dcap-ql="$SGX_DCAP_VERSION*" \
        libsgx-dcap-default-qpl-dev="$SGX_DCAP_VERSION*" \
        libsgx-dcap-default-qpl="$SGX_DCAP_VERSION*"

# install tdx
RUN apt-get install -y \
        libtdx-attest-dev="$SGX_DCAP_VERSION*" \
        libtdx-attest="$SGX_DCAP_VERSION*"

# install occlum
RUN echo 'deb [arch=amd64] https://occlum.io/occlum-package-repos/debian focal main' | tee /etc/apt/sources.list.d/occlum.list && \
    wget -qO - https://occlum.io/occlum-package-repos/debian/public.key | apt-key add - && \
    apt-get update && \
    apt-get install -y libfuse2 occlum occlum-toolchains-glibc
ENV PATH="/opt/occlum/build/bin:${PATH}"


FROM builder as builder-c-api

# build source code
WORKDIR /root/rats-rs
COPY . .

RUN just prepare-repo && \
    cmake -Hc-api -Bbuild && make -Cbuild install
