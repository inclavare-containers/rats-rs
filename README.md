# rats-rs
[![Testing](https://github.com/imlk0/rats-rs/actions/workflows/build-and-test.yaml/badge.svg)](https://github.com/imlk0/rats-rs/actions/workflows/build-and-test.yaml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


rats-rs是一个纯Rust的CPU-TEE SPDM远程证明和安全传输实现，它建立在[spdm-rs](https://github.com/ccc-spdm-tools/spdm-rs)之上。

**注意，这个项目目前还未达到生产可用状态，其安全性也未得到正式评估。**

在设计上，该项目尽量模块化，并通过cargo的features来进行条件编译，（现在或者未来）包含如下模块：
- `attester` / `verifier`：不同CPU TEE的证明和验证逻辑的实现
    - 现在包含了SGX-DCAP（ECDSA）的支持，由`attester-sgx-dcap-occlum`和`verifier-sgx-dcap`控制
- `crypto`：提供密码学原语的抽象接口，例如hash、非对称加密（签名）
    - 目前的提供了一个基于[RustCrypto](https://github.com/RustCrypto)的实现（通过`crypto-rustcrypto`控制），未来可以考虑提供基于[ring](https://github.com/briansmith/ring)或者[rust-openssl](https://github.com/sfackler/rust-openssl)的实现
- `cert`：提供证书的生成和签名验证实现。
    - 现在我们拥有一个符合[Interoperable RA-TLS](https://github.com/CCC-Attestation/interoperable-ra-tls)的实现（我们将其简称为dice证书），需要注意的是dice证书与[DSP0274](https://www.dmtf.org/dsp/DSP0274)中对SPDM证书的规定描述存在一定距离，例如：
        - dice证书是单一的自签名证书，而SPDM证书包含了多级证书，且包含Device/Alias/Generic三种证书模型
        - 对于代表设备的证书，SPDM对其中的一些字段有强制要求
        
        尽管如此，由于dice证书和SPDM证书的用途和目的是一致的，在目前阶段本项目中仍然使用dice证书作为SPDM协商过程中的证书格式，未来将考虑设计一种更符合SPDM证书要求的证书格式。
- `transport`：提供建立在远程证明之上的任意安全传输层（例如SPDM和TLS、DTLS）的实现。
    - 目前包含了一个基于SPDM协议的实现，能够完成握手和数据传输。    
        SPDM协议的部分基于[spdm-rs](https://github.com/ccc-spdm-tools/spdm-rs)项目，我们提供了对Requester和Responder的简易封装

        此外，spdm-rs中提供了SPDM传输层（`trait SpdmTransportEncap`）的PCIDOE和MCTP两种不同的实现。对此，我们提供了一个类似的`struct SimpleTransportEncap`实现，使用一个`u8`的tag来区分SPDM消息、受保护的SPDM消息和APP消息这三种消息。
        
        为了让SPDM协议在现有通信链路如TCP等基于上运行，我们提供了一个`struct FramedStream`实现。

        由于spdm-rs的原始实现与本项目的设计目标之间存在一些差距，我们对spdm-rs项目进行了fork和修改，主要有：
        - 调整spdm-rs的`ResponderContext::process_message()`在处理app_message时的逻辑，剔除`SpdmAppMessageHandler`。
        - 调整`max_cert_chain_data_size`，以容纳我们的dice证书（该变更不改变SPDM协议）
        - 剔除将一些全局的、类似于c的函数指针的callback实现，抽象成trait接口，例如：
            - `SecretAsymSigner`：SPDM通信方的私钥和签名逻辑，在SPDM协商阶段会使用该接口完成对给定数据的签名
            - `CertValidationStrategy`：对SPDM通信对方的证书验证的逻辑
            - `MeasurementProvider`：提供SPDM通信方的measurements

## 测试

### 单元测试

> [!NOTE]  
> 由于时间原因，本项目目前只对部分组件提供了单元测试。

本项目目前支持在非TEE环境和Occlum环境运行。由于部分逻辑依赖于TEE环境的支持，一些测试在非TEE环境中会被跳过，因此建议在Host和Occlum环境中分别运行一次单元测试。

- 在Host环境运行单元测试

```sh
just run-test-in-host
```

- 在Occlum环境运行单元测试

```sh
just run-test-in-occlum
```

### 集成测试

TODO: CI/CD

## example

### spdm

本项目提供了一个样例程序`examples/spdm.rs`，演示了如何创建一个运行于TCP流之上的SPDM安全通信外壳，并在其中进行数据传输。

该程序支持在非TEE的host环境，和基于SGX的Occlum环境运行。以下提供一个简单的运行方法，详细的参数可以通过在执行时指定`--help`选项了解。

1. 在Occlum中运行server端

    ```sh
    just run-in-occlum server --attest-self --listen-on-tcp 127.0.0.1:8080
    ```
> [!IMPORTANT]  
> `--attest-self`选项指定服务端需要作为attester向对端证明自己的身份，指定该选项时必须在某种TEE环境中运行。

2. 运行client端

    在该例子中，client端不需要向peer证明自己身份，因此，既可以运行在非TEE环境也可以运行在TEE环境。

    例如，运行在非TEE环境：
    ```sh
    just run-in-host client --verify-peer --connect-to-tcp 127.0.0.1:8080
    ```

    或者，运行在非TEE环境：
    ```sh
    just run-in-occlum client --verify-peer --connect-to-tcp 127.0.0.1:8080
    ```

> [!NOTE]
> 可使用环境变量`RATS_RS_LOG_LEVEL`来控制该程序启用的日志级别，环境变量的取值为`error`, `warn`, `info`, `debug`和`trace`，默认值为`trace`


## License

该项目使用Apache License 2.0 许可证授权
