# 在其他组织中注册设备

{{#include ../../../banners/hacktricks-training.md}}

## 介绍

正如[**之前提到的**](#what-is-mdm-mobile-device-management)**，**为了尝试将设备注册到一个组织中**只需要该组织的序列号**。一旦设备注册，多个组织将会在新设备上安装敏感数据：证书、应用程序、WiFi 密码、VPN 配置[等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
因此，如果注册过程没有得到正确保护，这可能成为攻击者的危险入口。

**以下是研究的摘要[https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)。请查看以获取更多技术细节！**

## DEP 和 MDM 二进制分析概述

本研究深入探讨了与 macOS 上的设备注册程序（DEP）和移动设备管理（MDM）相关的二进制文件。关键组件包括：

- **`mdmclient`**：与 MDM 服务器通信，并在 macOS 10.13.4 之前的版本上触发 DEP 检查。
- **`profiles`**：管理配置文件，并在 macOS 10.13.4 及更高版本上触发 DEP 检查。
- **`cloudconfigurationd`**：管理 DEP API 通信并检索设备注册配置文件。

DEP 检查利用私有配置文件框架中的 `CPFetchActivationRecord` 和 `CPGetActivationRecord` 函数来获取激活记录，`CPFetchActivationRecord` 通过 XPC 与 `cloudconfigurationd` 协调。

## 特斯拉协议和 Absinthe 方案逆向工程

DEP 检查涉及 `cloudconfigurationd` 向 _iprofiles.apple.com/macProfile_ 发送加密的签名 JSON 负载。负载包括设备的序列号和操作 "RequestProfileConfiguration"。所使用的加密方案在内部称为 "Absinthe"。解开这个方案是复杂的，涉及多个步骤，这导致探索插入任意序列号到激活记录请求的替代方法。

## 代理 DEP 请求

使用 Charles Proxy 等工具拦截和修改对 _iprofiles.apple.com_ 的 DEP 请求的尝试受到负载加密和 SSL/TLS 安全措施的阻碍。然而，启用 `MCCloudConfigAcceptAnyHTTPSCertificate` 配置可以绕过服务器证书验证，尽管负载的加密特性仍然阻止在没有解密密钥的情况下修改序列号。

## 对与 DEP 交互的系统二进制文件进行插桩

对系统二进制文件如 `cloudconfigurationd` 进行插桩需要在 macOS 上禁用系统完整性保护（SIP）。禁用 SIP 后，可以使用 LLDB 等工具附加到系统进程，并可能修改在 DEP API 交互中使用的序列号。这种方法更可取，因为它避免了权限和代码签名的复杂性。

**利用二进制插桩：**
在 `cloudconfigurationd` 中 JSON 序列化之前修改 DEP 请求负载被证明是有效的。该过程涉及：

1. 将 LLDB 附加到 `cloudconfigurationd`。
2. 找到获取系统序列号的点。
3. 在负载被加密并发送之前，将任意序列号注入内存中。

这种方法允许检索任意序列号的完整 DEP 配置文件，展示了潜在的漏洞。

### 使用 Python 自动化插桩

利用 LLDB API，使用 Python 自动化了利用过程，使得可以以编程方式注入任意序列号并检索相应的 DEP 配置文件。

### DEP 和 MDM 漏洞的潜在影响

研究突出了重大的安全隐患：

1. **信息泄露**：通过提供一个 DEP 注册的序列号，可以检索 DEP 配置文件中包含的敏感组织信息。

{{#include ../../../banners/hacktricks-training.md}}
