# CPU-TEE 的SPDM消息内容设计

本文档介绍rats-rs项目SPDM安全会话层部分的核心设计思路，即SPDM和TEE Attestation的融合内容

## CPU-TEE的X.509证书的生成

本项目中的X.509证书整体采用一级自签名证书的设计。并在证书的扩展字段中嵌入TEE实例的Evidence以及Endorsements。

证书生成的具体流程为：

1. TEE实例内生成一对非对称密钥（称之为pubkey、privkey），私钥部分保留在TEE内。

2. 构造Custom claims清单，其中包含一个名为"pubkey-hash"的字段，它的值为pubkey的hash值。其余的字段为上层应用程序可任意填入的键值对数据。

3. 将Custom claims清单数据按照CBOR格式编码为二进制数据，计算其Hash值。

4. 将步骤3的Hash值作为User-Data，调用远程证明原语层的逻辑，生成Evidence（如SGX中的Quote）。

5. 调用远程证明原语层的逻辑，获取Evidence对应的Endorsements（如SGX中的Collateral）。

6. 打包Tagged Evidence和Endorsements Manifest，并分别序列化为CBOR二进制数据，分别放入对应的证书的扩展字段中。

7. 根据pubkey生成证书的SubjectPublickeyInfo字段。

8. 用pubkey为该证书签名。


![完整流程的示意图](./rats-rs-x509-cert.svg)

文件[demo-sgx-cert.pem](demo-sgx-cert.pem)是在SGX实例上使用rats-rs建立SPDM安全会话过程中生成的一个证书的示例。

## CPU-TEE的Measurements消息内容定制


所谓Measurements，本质上是对当前TEE环境状态的描述。在SPDM协议中，Requester方可以通过发送GET_MEASUREMENTS消息检查对端TEE环境的状态。

SPDM消息中定义的Measurement由Block的形式表示，每个Block由Measurement Index来标识，Index的取值范围为0x00-0xFE。而其中有一个特殊的编号为0xFD的Block，对应的Block存储的数据的含义为Measurement manifest。一般来说，Measurement manifest记录了该设备上的所有Measuremtns的Index以及对应的度量内容的含义；或者直接以清单形式描述了该设备上的所有Measurements的值。

本项目中为CPU-TEE定义了一个Measurement Block，其相关属性信息如下

```txt
Index = 0xFD
DMTFSpecMeasurementValueType[6:0] = 0x04 (Freeform measurement manifest)
```

而该Measurement Block中存储的数据即为以CBOR形式格式化的从Evidence中解析出的Claims。

下图是以SGX类型的TEE为例的Measurement Block构造过程：

![MEASUREMENTS消息](./rats-rs-measurements.svg)

检查Measurements的过程如下：

1. 在检查时，Requester首先发送GET_MEASUREMENTS消息，并携带目标查询的Index为0xFD。

2. 在收到该请求后，Responder检查查询目标Index，并调用远程证明原语层获取当前实例的Evidence数据，然后将其解析为Claims，构造Measurement Data随后构造MEASUREMENTS消息返回给Requester。

3. Requester将Measurement Data反序列化为Claims，并与上层用户提供的参考值进行比较，从而决定是否要进行会话建立。
