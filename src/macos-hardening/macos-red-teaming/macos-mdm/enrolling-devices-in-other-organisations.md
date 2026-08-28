# 在其他组织中注册设备

{{#include ../../../banners/hacktricks-training.md}}

## 简介

Apple Automated Device Enrollment（原名 DEP）首先会识别分配给某个组织的设备。此处总结的 2018 年研究表明，只要知道已分配的序列号，就足以获取某些组织的 enrollment profiles，因为这些组织没有要求足够的额外身份验证。这是一项历史性发现，并不意味着所有当前的 MDM 都能仅凭序列号加入。Profiles 可能包含证书、应用程序、Wi-Fi 密钥、VPN 设置以及其他敏感配置。<sup>[[1]](#references)[[2]](#references)</sup>

**以下是该研究的摘要：[https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)。如需进一步的技术细节，请查阅原文！**<sup>[[1]](#references)</sup>

## DEP 和 MDM Binary Analysis 概述

该研究分析了当时 macOS 版本中与 DEP 和 MDM 相关的 binaries。组件名称和职责可能会随版本更新而变化：

- **`mdmclient`**：与 MDM servers 通信，并在 10.13.4 之前的 macOS 版本中触发 DEP check-ins。
- **`profiles`**：管理 Configuration Profiles，并在 macOS 10.13.4 及更高版本中触发 DEP check-ins。
- **`cloudconfigurationd`**：管理 DEP API 通信并获取 Device Enrollment profiles。

DEP check-ins 使用 private Configuration Profiles framework 中的 `CPFetchActivationRecord` 和 `CPGetActivationRecord` functions 来获取 Activation Record，其中 `CPFetchActivationRecord` 通过 XPC 与 `cloudconfigurationd` 协调。<sup>[[1]](#references)</sup>

## Tesla Protocol 和 Absinthe Scheme Reverse Engineering

DEP check-in 包括 `cloudconfigurationd` 向 _iprofiles.apple.com/macProfile_ 发送加密且签名的 JSON payload。该 payload 包含设备的序列号以及操作 "RequestProfileConfiguration"。所使用的 encryption scheme 在内部称为 "Absinthe"。破解该 scheme 十分复杂，需要经过大量步骤，因此研究人员转而探索在 Activation Record request 中插入任意序列号的替代方法。<sup>[[1]](#references)</sup>

## Proxying DEP Requests

使用 Charles Proxy 等工具拦截并修改发送到 _iprofiles.apple.com_ 的 DEP requests 时，会受到 payload encryption 和 SSL/TLS security measures 的阻碍。不过，启用 `MCCloudConfigAcceptAnyHTTPSCertificate` configuration 可以绕过 server certificate validation，但由于 payload 处于加密状态，在没有 decryption key 的情况下仍然无法修改序列号。<sup>[[1]](#references)</sup>

## Instrumenting 与 DEP 交互的 System Binaries

对 `cloudconfigurationd` 等 system binaries 进行 instrumentation 需要在 macOS 上禁用 System Integrity Protection（SIP）。禁用 SIP 后，可以使用 LLDB 等工具附加到 system processes，并可能修改 DEP API interactions 中使用的序列号。由于可以避免 entitlements 和 code signing 的复杂性，因此这种方法更为理想。<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation：**
在 `cloudconfigurationd` 中 JSON serialization 之前修改 DEP request payload 已被证明有效。具体过程包括：

1. 将 LLDB 附加到 `cloudconfigurationd`。
2. 定位系统获取序列号的位置。
3. 在 payload 被加密并发送之前，将任意序列号注入内存。

这种方法使研究人员能够获取所提供且已分配序列号对应的 DEP profiles。但它并不能使未分配的任意序列号变得有效。<sup>[[1]](#references)</sup>

### 使用 Python 自动化 Instrumentation

研究人员使用 Python 和 LLDB API 将 exploitation process 自动化，从而能够以编程方式注入任意序列号并获取相应的 DEP profiles。<sup>[[1]](#references)</sup>

## 2025 年回顾：从 VM 进行 Rogue Enrollment

Black Hat Asia 2025 的研究表明，原有的 trust-boundary problem 在 **MDM layer** 仍可能存在：研究人员没有使用 LLDB patch `cloudconfigurationd`，而是通过 OpenCore 在 QEMU/KVM 中运行 macOS，并通过 VM 的 SMBIOS 提供候选 identity。未经修改的 macOS enrollment stack 随后执行了加密的 Apple exchange。因此，无需拥有对应的实体 Mac，也可以测试公开泄露的 serials 和看似有效的 candidates；但要成功，仍然需要该序列号已分配给某个组织，并且该组织的 enrollment path authentication 不充分。<sup>[[3]](#references)</sup>

对于经过授权的 lab device，相关的 OpenCore `PlatformInfo` values 包括 product model 和 serial（实际部署还会在内部保持 ROM 与 UUID 的一致性）：<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
同一项研究在私有文件 `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck` 中发现了 `CheckProfilesFetchRateLimit` 状态。由于该 check 在客户端维护，修改存储的时间值即可使其失效。这些路径未公开且依赖版本，但在评估当前 macOS build 时，它们可作为有用的逆向切入点：<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
第二个 artifact 可以披露缓存的 activation record，包括该流程使用的是直接的 `ConfigurationURL`，还是需要认证的 `ConfigurationWebURL`。测试官方公布的流程，以及任何 MDM 专用的 legacy enrollment endpoint：仅在主 web 流程上启用 SSO，并不能保护并行的 direct endpoint。完整的协议序列请参阅 [macOS MDM overview](README.md)。<sup>[[3]](#references)</sup>

### Enrollment 后的 Secret Hunting

Rogue enrollment 只是入口。完成 enrollment 后，检查所有下发的 profile、bootstrap policy、package-repository configuration、agent installation script 和 self-service item。2025 年的研究发现了 Wi-Fi credentials、共享的 local-administrator passwords、已签名的 cloud-storage URLs、webhook URLs、security-agent activation data 以及 MDM/API credentials 等实例。下发脚本中的 tenant API credential 可以将一个 rogue endpoint 转变为对其他受管设备的控制入口，因此应同时搜索 live filesystem 以及已下载或缓存的 policy 内容。<sup>[[3]](#references)</sup>

有用的检查目标包括：<sup>[[3]](#references)</sup>

- 已安装的 `.mobileconfig` payload 以及 Configuration Profiles database。
- 创建 accounts 或安装 EDR/VPN agents 的 PreStage/bootstrap scripts 和 packages。
- Munki 或其他 package repository URLs，尤其是包含 bearer/SAS-style signatures 的 query strings。
- Self-service catalogs 及其后端 policy APIs，包括可能未强制执行 enrollment SSO policy 的 legacy routes。
- Shell history 和缓存的 policy output，搜索 `password`、`token`、`secret`、`Authorization`、webhook hostnames 以及 vendor API endpoints。

### 强化 Trust Boundary

应将 serial number 视为 inventory/routing attribute，**而不是** possession proof。Enrollment 和 self service 必须要求 user authentication；为每台设备生成唯一的 local administrator passwords；绝不要在 profiles 或 scripts 中嵌入 tenant API credentials 或可重复使用的 infrastructure secrets。任何无法避免的 bootstrap token 都应具有较短的有效期，并限制为仅执行正在配置的单个 action 且仅适用于目标设备。<sup>[[3]](#references)</sup>

在运行 macOS 14 或更高版本的 Apple-silicon Macs 上，Managed Device Attestation 可以将 identity 以 cryptographic 方式绑定到 Secure Enclave。其以 Apple 为根的 attestation 可以携带新鲜的 nonce，以及 serial number、UDID、OS version、SIP state 和 secure-boot state；随后 ACME 可以签发 hardware-bound client identity。使用该 identity 保护 MDM channel，并控制高价值 certificates、VPN access 和其他 resources；同时保留独立的 user authentication，因为 device attestation 证明的是 device，而不是 operator。<sup>[[4]](#references)</sup>

## DEP 和 MDM Vulnerabilities 的潜在影响

该研究指出了重大的 security concerns：

1. **Information Disclosure**：提供 DEP-registered serial number 后，可以检索 DEP profile 中包含的敏感组织信息。<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM Me Maybe：Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome：使用 Rogue Device Enrolments 攻击 Apple MDMs](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
