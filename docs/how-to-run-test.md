# 测试

为了提高代码健壮性，发现潜在的程序缺陷或逻辑漏洞，在项目开发过程中还应注重测试程序的编写，为此，本项目中按照rust程序惯例编写了单元测试。

## 单元测试

本项目目前支持在多种不同的TEE环境中运行。由于部分逻辑依赖于特定TEE环境的支持，一些测试在非TEE环境中会被跳过，因此建议在非TEE环境和TEE环境中分别运行一次单元测试。

- 在非TEE环境、或TDX环境中运行单元测试

    ```sh
    just run-test-in-host
    ```

- 在Occlum环境运行单元测试

    ```sh
    just run-test-in-occlum
    ```

本项目还以Github Action的形式添加了[自动化测试](/.github/workflows/build-and-test.yaml)（CI/CD），针对每一个新的Commit/Pull Request运行单元测试，以确保新的提交不会破坏已有功能。尽管如此，还是应该在新功能添加时尽可能的创建对应的单元测试。

## 代码覆盖率

计算代码覆盖率，对程序测试的覆盖范围认知，和单元测试的编写具有指引作用。本项目提供了[基于插桩的代码覆盖率](https://doc.rust-lang.org/rustc/instrument-coverage.html#instrumentation-based-code-coverage)（Instrumentation-based Code Coverage）计算，能够在运行单元测试的同时计算代码覆盖率结果。

项目将相关流程进行了封装，可以直接使用如下语句运行覆盖率计算

```sh
just code-coverage
```
> [!IMPORTANT]  
> 由于部分单元测试依赖于特定TEE环境的支持，这意味着完整的代码覆盖率的计算需要在不同的TEE环境中分别运行，再进行合并才能得出准确的覆盖率情况。在目前的实现中，上述语句需要在SGX平台上运行，且只会计算非TEE环境和Occlum环境（SGX）的代码覆盖率。
>
> 出现这种限制是因为用于开发的TDX环境和SGX环境不在同一个实例上，因此未来还需要改进代码以实现多TEE实例上代码覆盖率数据的自动化合并。

程序实例输出如下：
```txt

```

相关产物将存放在`target-sbcc/coverage/`目录下。除了命令行中输出的代码覆盖率，还可以通过浏览器查看每个文件中的代码执行覆盖情况：

```sh
python3 -m http.server --directory target-sbcc/coverage/www/
```

