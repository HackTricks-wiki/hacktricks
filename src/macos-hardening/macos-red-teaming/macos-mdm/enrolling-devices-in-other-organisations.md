# 在其他组织中注册设备

{{#include ../../../banners/hacktricks-training.md}}

## 简介

Apple Automated Device Enrollment（原称 DEP）首先会识别分配给某个组织的设备。此处总结的 2018 年研究表明，只要知道已分配设备的序列号，就足以获取某些组织的 enrollment profiles，因为这些组织未要求足够的额外身份验证。这是一项历史性发现，并不意味着当前所有 MDM 都可以仅凭序列号加入。Profiles 可能包含证书、应用程序、Wi-Fi secrets、VPN 设置及其他敏感配置。<sup>[[1]](#references)[[2]](#references)</sup>

**以下内容是研究 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe) 的总结。请参阅该研究以获取更多技术细节！**<sup>[[1]](#references)</sup>

## DEP 和 MDM Binary Analysis 概述

该研究分析了当时 macOS 版本中与 DEP 和 MDM 相关的 binaries。组件名称及其职责可能会随版本变化：

- **`mdmclient`**：与 MDM servers 通信，并在 10.13.4 之前的 macOS 版本上触发 DEP check-ins。
- **`profiles`**：管理 Configuration Profiles，并在 macOS 10.13.4 及更高版本上触发 DEP check-ins。
- **`cloudconfigurationd`**：管理 DEP API 通信并获取 Device Enrollment profiles。

DEP check-ins 使用 private Configuration Profiles framework 中的 `CPFetchActivationRecord` 和 `CPGetActivationRecord` functions 来获取 Activation Record，其中 `CPFetchActivationRecord` 通过 XPC 与 `cloudconfigurationd` 协调。<sup>[[1]](#references)</sup>

## Tesla Protocol 和 Absinthe Scheme Reverse Engineering

DEP check-in 包括 `cloudconfigurationd` 向 _iprofiles.apple.com/macProfile_ 发送加密且签名的 JSON payload。该 payload 包含设备的序列号以及操作 `"RequestProfileConfiguration"`。所使用的 encryption scheme 在内部称为“Absinthe”。破解该 scheme 十分复杂，需要经过许多步骤，因此研究人员转而探索在 Activation Record request 中插入任意序列号的替代方法。<sup>[[1]](#references)</sup>

## Proxying DEP Requests

尝试使用 Charles Proxy 等 tools 拦截和修改发送到 _iprofiles.apple.com_ 的 DEP requests 时，会受到 payload encryption 及 SSL/TLS security measures 的阻碍。不过，启用 `MCCloudConfigAcceptAnyHTTPSCertificate` configuration 可以绕过 server certificate validation，但 payload 的 encrypted nature 仍然使得在没有 decryption key 的情况下无法修改序列号。<sup>[[1]](#references)</sup>

## Instrumenting 与 DEP 交互的 System Binaries

对 `cloudconfigurationd` 等 system binaries 进行 instrumentation 需要在 macOS 上禁用 System Integrity Protection（SIP）。禁用 SIP 后，可以使用 LLDB 等 tools attach 到 system processes，并可能修改 DEP API interactions 中使用的序列号。由于避免了 entitlements 和 code signing 的复杂性，这种方法更为合适。<sup>[[1]](#references)</sup>

**利用 Binary Instrumentation：**
在 `cloudconfigurationd` 中 JSON serialization 之前修改 DEP request payload 已被证明有效。该过程包括：

1. 将 LLDB attach 到 `cloudconfigurationd`。
2. 定位系统获取序列号的位置。
3. 在 payload 加密并发送之前，将任意序列号注入 memory。

该方法使研究人员能够获取所提供且已分配序列号对应的 DEP profiles。它并不能使未分配的任意序列号变得有效。<sup>[[1]](#references)</sup>

### 使用 Python 自动化 Instrumentation

研究人员使用 Python 和 LLDB API 自动化了 exploitation process，从而可以通过程序注入任意序列号并获取相应的 DEP profiles。<sup>[[1]](#references)</sup>

### DEP 和 MDM Vulnerabilities 的潜在影响

该研究指出了严重的 security concerns：

1. **Information Disclosure**：通过提供已在 DEP 中注册的序列号，可以获取 DEP profile 中包含的敏感组织信息。<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe：Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
