
# rats-rs C API

为了方便在其他非Rust语言编写的程序中调用rats-rs，我们提供了一组C API。目前支持动态库（.so）和静态库（.a）两种形式链接到rats-rs。

# Build and Install

rats-rs C API 使用cmake作为项目构建工具，并提供了两种不同的依赖方式。

## Include in existing cmake project

这种方式适合于同样使用cmake（或者其他与cmake兼容的构建工具）的项目中引入rats-rs。

TODO...

## Install to system and link

这种方式需要先构建rats-rs并安装到系统中，然后在项目中链接到rats-rs。虽然更加繁琐，但更加灵活，且适用场景更广泛。

1. 在rats-rs项目的根目录下执行cmake：

    ```sh
    cmake -Hc-api -Bbuild
    # 如果要构建只需和CoCo AS/AA对接的rats-rs，避免链接过多TEE的依赖库，则使用
    # cmake -Hc-api -Bbuild -DCOCO_ONLY=ON
    ```
    这将创建一个build目录用于存放cmake的构建产物

2. 编译并安装到系统路径中

    ```sh
    make -Cbuild install
    ```

    安装产物内容及路径：
    - 头文件：`/usr/local/include/rats-rs`
    - 库文件（.so和.a）：`/usr/local/lib/rats-rs/`
    - cmake搜索配置文件：`/usr/local/lib/cmake/RatsRs/`

3. 在项目的CMakeLists.txt中引入

    ```cmake
    # Find rats-rs in system
    find_package(RatsRs REQUIRED)
    # link target-app with rats-rs (shared library or static library) 
    target_link_libraries(target-app RatsRs::shared)
    # target_link_libraries(target-app RatsRs::static)
    ```

# Usage

要了解C API的详细用法，请参照头文件[include/rats-rs.h](include/rats-rs.h)。以下为在C语言程序使用rats-rs的一个简单的例子。

```c
#include <stdio.h>
#include <rats-rs/rats-rs.h>

int main() {
    /* Set log level */
    rats_rs_set_log_level(RATS_RS_LOG_LEVEL_DEBUG);

    /* Create cert */
    uint8_t *privkey = NULL;
    size_t privkey_len = 0;
    uint8_t *certificate = NULL;
    size_t certificate_len = 0;
    rats_rs_attester_type_t attester_type = {
        .tag = RATS_RS_ATTESTER_TYPE_LOCAL,
        .LOCAL = {.type = RATS_RS_LOCAL_ATTESTER_TYPE_AUTO}};
    rats_rs_error_obj_t *error_obj = rats_rs_create_cert(
        "CN=Demo App,O=Inclavare Containers", RATS_RS_HASH_ALGO_SHA256,
        RATS_RS_ASYMMETRIC_ALGO_P256, attester_type, NULL, 0, &privkey,
        &privkey_len, &certificate, &certificate_len);

    if (error_obj == NULL) {
        printf("Create cert successfully\n");
        printf("Generated privkey: %p len: %zu\n", privkey, privkey_len);
        printf("Generated pem certificate: %p len: %zu\n", certificate,
               certificate_len);
    } else {
        printf("Create cert failed\n");
        rats_rs_error_msg_t error_msg = rats_rs_err_get_msg_ref(error_obj);
        printf("Error kind: %#x msg: %*s\n", rats_rs_err_get_kind(error_obj),
               (int)error_msg.msg_len, error_msg.msg);
        rats_rs_err_free(error_obj);
        exit(1);
    }

    /* Verify cert */
    rats_rs_claim_t expected_claims[] = {
        /* Replace with your expected claims here */
    };
    rats_rs_verify_policy_t verify_policy = {
        .tag = RATS_RS_VERIFY_POLICY_LOCAL,
        .LOCAL = {.claims_check = {
                      .tag = RATS_RS_CLAIMS_CHECK_CONTAINS,
                      .CONTAINS = {.claims = expected_claims,
                                   .claims_len = sizeof(expected_claims) /
                                                 sizeof(expected_claims[0])},
                  }}};
    rats_rs_verify_policy_output_t verify_policy_output =
        RATS_RS_VERIFY_POLICY_OUTPUT_FAILED;
    error_obj = rats_rs_verify_cert(certificate, certificate_len,
                                    verify_policy, &verify_policy_output);

    if (error_obj == NULL) {
        printf("Verify cert result: %d\n", verify_policy_output);
    } else {
        printf("Failed to verify cert\n");
        rats_rs_error_msg_t error_msg = rats_rs_err_get_msg_ref(error_obj);
        printf("Error kind: %#x msg: %*s\n", rats_rs_err_get_kind(error_obj),
               (int)error_msg.msg_len, error_msg.msg);
        rats_rs_err_free(error_obj);
        exit(1);
    }

    /* Clean up */
    rats_rs_rust_free(privkey, privkey_len);
    rats_rs_rust_free(certificate, certificate_len);

    return 0;
}
```

# For developers

## Modification and Debug

C API整体由Rust侧的FFI代码和头文件生成两部分组成。项目使用cbindgen工具从FFI代码中生成头文件，这一过程被编码在在`build.rs`中。在编译过程中可以自动化完成头文件的生成，后续的功能添加过程只需要添加对应的FFI函数定义，即可自动生成头文件。但请注意编写合适的注释文档，以说明新增的C API的用途。

由于cbindgen工具目前存在一些功能问题，新增加的C API可能无法生成预期的头文件。此时，可使用cbindgen的命令行工具进行测试。

首先安装cbindgen命令行工具：
```sh
cargo install cbindgen
```

运行以下语句查看详细的调试信息：
```sh
cd c-api
cbindgen -l c -c cbindgen.toml .
```

为了方便开发和追踪变更，我们也使用git追踪生成的头文件。因此在对C API进行的变更提交前，请务必触发一次头文件生成，并将变更使用`git add`添加到仓库中。

如果你使用`rust-analyzer`，这应该是自动完成的。或者，你可以使用如下语句触发一次头文件生成。
```sh
cargo build --package c-api
```
