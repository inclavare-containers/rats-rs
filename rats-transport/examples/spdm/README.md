# spdm

该目录下是一个用于演示上层应用使用rats-rs进行开发的样例程序`spdm`，主要涵盖了使用rats-rs提供的基于远程证明和SPDM协议进行安全通信的实例。

该样例程序`spdm`目前主要涵盖两个例子`spdm-echosvr`和`spdm-tunnel`。为减少重复代码，这两个例子被集成在同一个示例程序的不同子命令里，接下来将分别介绍这两个例子的使用。


## 构建

首先，参考[构建文档](/docs/how-to-build.md)完成构建环境的搭建，我们推荐直接使用Docker容器来快速建立构建环境。

接下来，使用如下命令构建本样例程序
```sh
just build-example-spdm
```

可以使用`target/debug/spdm --help`命令查看该样例程序的命令行参数
```txt
Usage: spdm <COMMAND>

Commands:
  echo-server    
  echo-client    
  tunnel-server  
  tunnel-client  
  help           Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## spdm-echosvr

该例子演示了如何创建一个运行于TCP流之上的SPDM安全通信外壳并在其中进行通信。对应的是示例程序`spdm`中的`echo-server`和`echo-client`这两个子命令，分别对应了server端和client端。

在与server端建立SPDM会话后，client端会持续随机生成数据并将其发送到server端，随后server端将数据发回到client端。旨在展示使用rats-rs实现由远程证明保证的双向安全数据传输的能力。

该程序支持在非TEE环境、基于SGX的Occlum环境、TDX虚拟机环境运行。以下提供一个在Occlum环境中的简单运行方法，更详细的参数可以通过指定`--help`选项了解。

1. 在Occlum中运行server端

    ```sh
    just run-in-occlum echo-server --attest-self --listen-on-tcp 127.0.0.1:8080
    ```
> [!IMPORTANT]  
> `--attest-self`选项指定服务端需要作为attester向对端证明自己的身份，当该选项被指定时，必须在某种TEE环境中运行。

2. 运行client端

    在该例子中使用的是单向远程证明，client端不需要向peer证明自己身份，因此，既可以运行在非TEE环境，也可以运行在TEE环境。

    例如，运行在非TEE环境：
    ```sh
    just run-in-host echo-client --verify-peer --connect-to-tcp 127.0.0.1:8080
    ```

    或者，运行在Occlum环境：
    ```sh
    just run-in-occlum echo-client --verify-peer --connect-to-tcp 127.0.0.1:8080
    ```

> [!NOTE]
> 可使用环境变量`RATS_RS_LOG_LEVEL`来控制该程序启用的日志级别，环境变量的取值为`error`, `warn`, `info`, `debug`和`trace`，默认值为`trace`

## spdm-tunnel

针对一些不期望对业务代码进行任何修改，或者并不拥有业务程序源码，但是仍然期望引入安全通信能力的场景，可以通过建立一个隧道来解决这种需求。该例子演示了在TEE实例和非TEE实例之间建立TCP转发的能力。

该示例同样包含server端和client端，分别对应示例程序`spdm`中的`tunnel-server`和`tunnel-client`这两个子命令。

![tunnel](src/tunnel/tunnel.svg)

1. 在TDX实例中运行一个nginx服务，以模拟业务场景中，在TDX实例中运行的业务服务端程序。

    ```sh
    nginx -c `realpath ./examples/spdm/src/tunnel/nginx.conf`
    ```

    该nginx将监听在`9091`端口，并暴露一个nginx默认页。

2. 在TDX实例中运行server端

    ```sh
    just run-in-host tunnel-server --attest-self --listen-on-tcp 127.0.0.1:8080 --upstream 127.0.0.1:9091
    ```
    该程序将在`127.0.0.1:8080`监听来自client端的请求，并将SPDM安全会话中的数据转发到上游`127.0.0.1:9091`的nginx服务

3. 在非TEE环境中运行client端

    ```sh
    just run-in-host tunnel-client --verify-peer --connect-to-tcp 127.0.0.1:8080 --ingress 127.0.0.1:9090
    ```

    该程序将在`127.0.0.1:9090`监听来自业务client端（如浏览器）的发来的TCP连接请求，并将其中数据经过SPDM安全会话转发到上游的`127.0.0.1:8080`spdm-tunnel server端。

4. 在非TEE环境中启动浏览器访问`http://127.0.0.1:9090/`，或者使用`curl http://127.0.0.1:9090/`测试。将观测到浏览器中正确回显了nginx的默认页内容。
