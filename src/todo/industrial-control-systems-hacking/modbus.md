# Modbus 协议

{{#include ../../banners/hacktricks-training.md}}

## Modbus 简介

Modbus 是一种开放的应用层协议，广泛用于 PLC、传感器、执行器及其他工业设备。其请求/响应模型通过功能码暴露线圈和寄存器。因此，安全测试应重点关注未授权读取/写入、流量观察、replay 以及不安全的设备行为，而不应仅仅停留在发现 TCP 端口 502。<sup>[[1]](#references)</sup>

许多部署仍保留传统串行设备，因为升级需要停机、重新认证或更换现场设备。传统 Modbus 不提供机密性或对端身份验证；Modbus Security 是一种独立的、基于 TLS 的配置文件，使用 X.509 证书和 TCP 端口 802。由于该规范是公开的，且可以由不同厂商独立实现，因此各厂商的行为和可选功能支持情况存在差异，应进行指纹识别，而不是想当然地假设其行为。<sup>[[1]](#references)[[2]](#references)</sup>

## 客户端-服务器架构

在当前术语中，**客户端**发起事务，**服务器**返回响应。较早的文档使用 **master/slave**。不要将这种应用层关系与 SPI 或 I2C 混淆：它们是不同的总线协议。<sup>[[1]](#references)</sup>

## 串行与以太网传输

相同的 Modbus 应用数据可以通过串行变体（RTU 或 ASCII 帧格式）以及 Modbus TCP 传输。Modbus TCP 增加了 MBAP header，通常使用 TCP 端口 502；串行 RTU 使用紧凑的二进制帧格式和 CRC，而串行 ASCII 将字节表示为十六进制字符，并使用 LRC。<sup>[[1]](#references)[[3]](#references)</sup>

## 数据表示

数据模型由单比特线圈/离散输入以及 16 位输入/保持寄存器组成。多寄存器值、字节序、缩放方式和语义含义均由设备决定，必须根据厂商的寄存器映射进行确认。<sup>[[1]](#references)</sup>

## 功能码

功能码用于选择操作，例如读取线圈（`0x01`）、读取保持寄存器（`0x03`）、写入单个线圈/寄存器（`0x05`/`0x06`），以及写入多个线圈/寄存器（`0x0F`/`0x10`）。当部署没有补偿性身份验证或过程状态检查时，捕获到的写入请求可能可以 replay。在获得授权的情况下，如果能够识别电气接口、终端电阻和安全连接方法，评估人员还可以在较长的串行线路上直接捕获或注入帧。上述任一操作都可能影响物理过程，因此应在实验室环境中进行，或取得明确的运行授权。<sup>[[1]](#references)[[3]](#references)</sup>

## 寻址

串行设备使用单元地址。Modbus TCP 使用 IP 地址以及 MBAP header 中的 Unit Identifier；当 TCP-to-serial gateway 将请求路由到下游单元时，这一点尤其重要。产品文档中显示的寄存器引用可能采用从 1 开始的编号（`40001`），而协议地址则从 0 开始，这是产生 off-by-one 错误的常见原因。<sup>[[1]](#references)[[3]](#references)</sup>

串行帧格式包含传输错误检查（RTU 使用 CRC，ASCII 使用 LRC），而 TCP 提供其常规的传输校验和。这些机制可以检测意外损坏，但不提供加密完整性或源身份验证。<sup>[[3]](#references)</sup>

在获得授权的评估期间，应测试暴露情况、允许使用的功能码、可写地址范围、异常处理、速率限制，以及网络分段或支持 Modbus 的 firewall 是否限制客户端。相关威胁包括被动泄露、未授权命令注入、replay、数据伪造和 denial of service。应与流程负责人协调所有主动测试，因为看似微小的寄存器更改也可能改变物理过程。

## References

- [1] [Modbus Organization — Modbus 应用协议规范 V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Modbus Security 协议和实施指南](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Modbus 串行线路规范和实施指南 V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
