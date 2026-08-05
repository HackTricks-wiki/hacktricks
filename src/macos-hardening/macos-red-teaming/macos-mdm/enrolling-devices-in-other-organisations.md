# 在其他组织中注册设备

{{#include ../../../banners/hacktricks-training.md}}

## Intro

正如[**之前所述**](#what-is-mdm-mobile-device-management)**，**为了尝试将设备注册到某个组织中，**只需要一个属于该组织的 Serial Number**。设备注册后，许多组织会在新设备上安装敏感数据：证书、应用程序、WiFi 密码、VPN 配置[等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
因此，如果注册流程没有得到正确保护，这可能会成为攻击者的危险入口点。

**以下是研究 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe) 的摘要。请查阅该研究以获取更多技术细节！**<sup>[[1]](#references)</sup>

## DEP 和 MDM Binary Analysis 概述

该研究深入分析了 macOS 上与 Device Enrollment Program (DEP) 和 Mobile Device Management (MDM) 相关的 binaries。主要组件包括：

- **`mdmclient`**：与 MDM servers 通信，并在 10.13.4 之前的 macOS 版本上触发 DEP check-ins。
- **`profiles`**：管理 Configuration Profiles，并在 macOS 10.13.4 及更高版本上触发 DEP check-ins。
- **`cloudconfigurationd`**：管理 DEP API 通信并获取 Device Enrollment profiles。

DEP check-ins 使用 private Configuration Profiles framework 中的 `CPFetchActivationRecord` 和 `CPGetActivationRecord` functions 来获取 Activation Record，其中 `CPFetchActivationRecord` 通过 XPC 与 `cloudconfigurationd` 协调。<sup>[[1]](#references)</sup>

## Tesla Protocol 和 Absinthe Scheme Reverse Engineering

DEP check-in 涉及 `cloudconfigurationd` 向 _iprofiles.apple.com/macProfile_ 发送加密且经过签名的 JSON payload。该 payload 包含设备的 serial number 以及操作 `"RequestProfileConfiguration"`。所使用的 encryption scheme 在内部被称为 "Absinthe"。破解该 scheme 非常复杂，需要执行大量步骤，因此研究人员开始探索在 Activation Record request 中插入任意 serial numbers 的替代方法。<sup>[[1]](#references)</sup>

## Proxying DEP Requests

使用 Charles Proxy 等工具拦截和修改发送到 _iprofiles.apple.com_ 的 DEP requests 时，会受到 payload encryption 和 SSL/TLS security measures 的阻碍。不过，启用 `MCCloudConfigAcceptAnyHTTPSCertificate` configuration 可以绕过 server certificate validation，但由于 payload 处于加密状态，在没有 decryption key 的情况下仍然无法修改 serial number。<sup>[[1]](#references)</sup>

## Instrumenting System Binaries Interacting with DEP

对 `cloudconfigurationd` 等 system binaries 进行 instrumentation 需要在 macOS 上禁用 System Integrity Protection (SIP)。禁用 SIP 后，可以使用 LLDB 等工具附加到 system processes，并可能修改 DEP API interactions 中使用的 serial number。由于可以避开 entitlements 和 code signing 的复杂性，这种方法更为理想。

**Exploiting Binary Instrumentation：**
在 `cloudconfigurationd` 中 JSON serialization 之前修改 DEP request payload 已被证明有效。该过程包括：

1. 将 LLDB 附加到 `cloudconfigurationd`。
2. 定位系统获取 system serial number 的位置。
3. 在 payload 被加密并发送之前，将任意 serial number 注入 memory。

该方法可以获取任意 serial numbers 对应的完整 DEP profiles，证明了一个潜在的 vulnerability。<sup>[[1]](#references)</sup>

### 使用 Python 自动化 Instrumentation

该 exploitation process 使用 Python 和 LLDB API 实现自动化，从而可以通过编程方式注入任意 serial numbers，并获取相应的 DEP profiles。<sup>[[1]](#references)</sup>

### DEP 和 MDM Vulnerabilities 的潜在影响

该研究强调了重大的 security concerns：

1. **Information Disclosure**：通过提供一个已在 DEP 中注册的 serial number，可以获取 DEP profile 中包含的敏感组织信息。<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
