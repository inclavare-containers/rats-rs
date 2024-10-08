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
Filename                                     Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
transport/spdm/transport.rs                       56                14    75.00%          11                 3    72.73%         131                20    84.73%          12                 4    66.67%
transport/spdm/io/framed_stream.rs                66                23    65.15%          11                 5    54.55%         103                18    82.52%          16                 5    68.75%
transport/spdm/secret/asym_crypto.rs              86                41    52.33%           7                 1    85.71%         181                80    55.80%           8                 5    37.50%
transport/spdm/secret/measurement.rs              84                34    59.52%          10                 3    70.00%         189                37    80.42%          20                 9    55.00%
transport/spdm/secret/cert_validation.rs          20                 4    80.00%           6                 0   100.00%          48                 5    89.58%           2                 1    50.00%
transport/spdm/secret/cert_provider.rs            22                 6    72.73%           5                 0   100.00%          64                12    81.25%           4                 2    50.00%
transport/spdm/requester.rs                      104                48    53.85%           9                 4    55.56%         303                84    72.28%           6                 1    83.33%
transport/spdm/half.rs                            35                10    71.43%           3                 0   100.00%          89                12    86.52%           6                 3    50.00%
transport/spdm/responder.rs                      112                46    58.93%          12                 5    58.33%         365                86    76.44%           4                 1    75.00%
crypto/mod.rs                                     58                20    65.52%           7                 1    85.71%          80                20    75.00%           0                 0         -
errors.rs                                         31                22    29.03%          17                12    29.41%          85                55    35.29%           0                 0         -
cert/verify.rs                                   155                44    71.61%          13                 1    92.31%         192                25    86.98%          14                 2    85.71%
cert/dice/extensions.rs                           18                 6    66.67%           8                 4    50.00%          50                12    76.00%           0                 0         -
cert/dice/mod.rs                                  42                 7    83.33%           3                 1    66.67%          56                 1    98.21%           0                 0         -
cert/dice/cbor.rs                                108                24    77.78%          15                 0   100.00%         172                18    89.53%           2                 1    50.00%
cert/create.rs                                    76                17    77.63%          11                 1    90.91%         116                 4    96.55%           2                 0   100.00%
tee/sgx_dcap/evidence.rs                          32                13    59.38%           9                 0   100.00%          88                40    54.55%          22                16    27.27%
tee/sgx_dcap/claims.rs                             1                 0   100.00%           1                 0   100.00%          78                 0   100.00%           0                 0         -
tee/sgx_dcap/verifier.rs                          55                22    60.00%           4                 1    75.00%          89                32    64.04%           6                 4    33.33%
tee/sgx_dcap/attester.rs                          22                 6    72.73%           3                 0   100.00%          37                 5    86.49%           4                 1    75.00%
tee/sgx_dcap/mod.rs                               17                 2    88.24%           1                 0   100.00%          20                 0   100.00%           2                 0   100.00%
tee/mod.rs                                        54                 5    90.74%          14                 0   100.00%         101                 9    91.09%           6                 0   100.00%
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                           1254               414    66.99%         180                42    76.67%        2637               575    78.19%         136                55    59.56%
```

输出显示行覆盖率已达到78.19%

相关产物将存放在`target-sbcc/coverage/`目录下。除了命令行中输出的代码覆盖率，还可以通过浏览器查看每个文件中的代码执行覆盖情况，首先需要启动一个静态文件服务：

```sh
python3 -m http.server --directory target-sbcc/coverage/www/
```

然后在浏览器中打开 http://localhost:8000/ 即可查看。
