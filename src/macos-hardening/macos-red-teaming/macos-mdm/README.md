# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**了解 macOS MDM，请参考：**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## 基础知识

### **MDM（Mobile Device Management）概述**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management)（MDM）用于管理各种终端用户设备，例如智能手机、笔记本电脑和平板电脑。对于 Apple 平台（iOS、macOS、tvOS），它包含一组专用功能、API 和实践。MDM 的运行依赖于兼容的 MDM server，该 server 可以是商业产品或开源软件，并且必须支持 [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。主要要点包括：

- 对设备进行集中控制。
- 依赖遵循 MDM 协议的 MDM server。
- MDM server 能够向设备发送各种命令，例如远程擦除数据或安装配置。

### **DEP（Device Enrollment Program）基础知识**

Apple 提供的 [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf)（DEP）通过为 iOS、macOS 和 tvOS 设备提供零接触配置，简化了 Mobile Device Management（MDM）的集成。DEP 会自动完成 enrollment 流程，使设备开箱即用，并将用户或管理员的干预降至最低。主要方面包括：

- 设备首次激活时，能够自动向预定义的 MDM server 注册。
- 主要适用于全新设备，但也适用于正在重新配置的设备。
- 提供简单直接的设置流程，使设备能够快速投入组织使用。

### **安全注意事项**

需要注意的是，DEP 提供的便捷 enrollment 虽然很有用，但也可能带来安全风险。如果没有对 MDM enrollment 充分实施保护措施，攻击者可能利用这一简化流程，将自己的设备注册到组织的 MDM server，并伪装成企业设备。<sup>[[2]](#references)</sup>

> [!CAUTION]
> **安全警告**：如果没有适当的保护措施，简化的 DEP enrollment 可能允许未授权设备注册到组织的 MDM server。

### SCEP（Simple Certificate Enrolment Protocol）基础知识

- 一种相对较旧的协议，创建于 TLS 和 HTTPS 尚未普及之前。
- 为客户端提供一种标准化方式，用于发送 **Certificate Signing Request**（CSR），以申请证书。客户端会请求 server 为其提供已签名的证书。

### Configuration Profiles（也称为 mobileconfigs）是什么？

- Apple 官方用于**设置/强制实施系统配置**的方式。
- 一种可以包含多个 payload 的文件格式。
- 基于 property lists（XML 格式）。
- “可以进行签名和加密，以验证其来源、确保其完整性并保护其内容。”《iOS Security Guide》，2018 年 1 月，第 70 页。

## 协议

### MDM

- APNs（**Apple server**）+ RESTful API（**MDM** **vendor** server）的组合
- **通信**发生在**设备**与关联于设备**管理**产品的 server 之间
- 命令以 **plist-encoded dictionaries** 的形式从 MDM **发送**到设备
- 全部通过 **HTTPS** 传输。MDM server 可以（通常也会）进行 pinning。
- Apple 向 MDM vendor 授予用于身份验证的 **APNs certificate**

### DEP

- **3 个 API**：1 个用于 resellers，1 个用于 MDM vendors，1 个用于设备身份（未公开）：
- 所谓的 [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。MDM server 使用它将 DEP profiles 与特定设备关联。
- [Apple Authorized Resellers 使用的 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)，用于 enrollment 设备、检查 enrollment 状态以及检查 transaction 状态。
- 未公开的 private DEP API。Apple Devices 使用它请求自身的 DEP profile。在 macOS 上，`cloudconfigurationd` binary 负责通过此 API 进行通信。
- 更现代且基于 **JSON**（相对于 plist）
- Apple 向 MDM vendor 授予一个 **OAuth token**

**DEP "cloud service" API**

- RESTful
- 将 device records 从 Apple 同步到 MDM server
- 将“DEP profiles”从 MDM server 同步到 Apple（之后由 Apple 发送给设备）
- DEP “profile”包含：
- MDM vendor server URL
- 用于 server URL 的其他受信任 certificates（可选 pinning）
- 额外设置（例如在 Setup Assistant 中跳过哪些屏幕）

## 序列号

2010 年之后生产的 Apple 设备通常具有 **12 位字母数字组合**序列号，其中**前 3 位表示生产地点**，接下来的**2 位表示生产年份和周数**，再接下来的 **3 位**提供一个**唯一**的**标识符**，最后 **4 位**表示**型号编号**。


{{#ref}}
macos-serial-number.md
{{#endref}}

## Enrollment 和管理步骤

1. Device record creation（Reseller、Apple）：创建新设备的 record
2. Device record assignment（Customer）：将设备分配给 MDM server
3. Device record sync（MDM vendor）：MDM 同步 device records，并将 DEP profiles 推送给 Apple
4. DEP check-in（Device）：设备获取其 DEP profile
5. Profile retrieval（Device）
6. Profile installation（Device），包括 MDM、SCEP 和 root CA payloads
7. MDM command issuance（Device）

![Serial Number - Enrollment 和管理步骤：7. MDM command issuance（Device）](<../../../images/image (694).png>)

文件 `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` 导出了可视为 enrollment 流程中**高层“步骤”**的 functions。

### 步骤 4：DEP check-in - 获取 Activation Record

当**用户首次启动 Mac**（或执行完全擦除后）时，流程的这一部分会发生。

![Enrollment 和管理步骤 - 步骤 4：DEP check-in - 获取 Activation Record：当用户首次启动 Mac（或执行完全...后）时，流程的这一部分会发生](<../../../images/image (1044).png>)

或者执行 `sudo profiles show -type enrollment` 时发生。

- 确定**设备是否启用了 DEP**
- Activation Record 是 DEP “profile”的内部名称
- 设备连接到 Internet 后立即开始
- 由 **`CPFetchActivationRecord`** 驱动
- 由 **`cloudconfigurationd`** 通过 XPC 实现。**"Setup Assistant**"（设备首次启动时）或 **`profiles`** command 会**联系此 daemon**来获取 activation record。
- LaunchDaemon（始终以 root 身份运行）

获取 Activation Record 的过程由 **`MCTeslaConfigurationFetcher`** 执行，使用名为 **Absinthe** 的加密方式。<sup>[[1]](#references)</sup>

1. 获取 **certificate**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 从 certificate 初始化 **state**（**`NACInit`**）
1. 使用各种设备特定数据（即通过 **`IOKit`** 获取的 **Serial Number**）
3. 获取 **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 建立 session（**`NACKeyEstablishment`**）
5. 发出 request
1. POST 到 [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)，发送数据 `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON payload 使用 Absinthe 加密（**`NACSign`**）
3. 所有 requests 通过 HTTPs 发送，使用内置 root certificates

![Enrollment 和管理步骤 - 步骤 4：DEP check-in - 获取 Activation Record：3. 所有 requests 通过 HTTPs 发送，使用内置 root certificates](<../../../images/image (566) (1).png>)

响应是一个 JSON dictionary，其中包含一些重要数据，例如：

- **url**：用于 activation profile 的 MDM vendor host URL
- **anchor-certs**：用作 trusted anchors 的 DER certificates 数组

### **步骤 5：Profile Retrieval**

![步骤 4：DEP check-in - 获取 Activation Record - 步骤 5：Profile Retrieval：步骤 5：Profile Retrieval](<../../../images/image (444).png>)

- Request 发送到 **DEP profile 中提供的 url**。
- 如果提供了 **Anchor certificates**，则使用它们来**评估 trust**。
- 提醒：DEP profile 的 **anchor_certs** property
- **Request 是一个简单的 .plist**，包含设备标识信息
- 示例：**UDID、OS version**。
- CMS-signed、DER-encoded
- 使用**设备 identity certificate（来自 APNS）**签名
- **Certificate chain** 包含已过期的 **Apple iPhone Device CA**

![步骤 4：DEP check-in - 获取 Activation Record - 步骤 5：Profile Retrieval：使用设备 identity certificate（来自 APNS）签名](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### 步骤 6：Profile Installation

- 获取后，**profile 会存储在系统中**
- 此步骤会自动开始（如果处于 **setup assistant** 中）
- 由 **`CPInstallActivationProfile`** 驱动
- 由 mdmclient 通过 XPC 实现
- LaunchDaemon（以 root 身份运行）或 LaunchAgent（以 user 身份运行），具体取决于上下文
- Configuration profiles 包含多个待安装的 payloads
- Framework 采用基于 plugin 的架构来安装 profiles
- 每种 payload type 都与一个 plugin 关联
- 可以是 XPC（位于 framework 中）或 classic Cocoa（位于 ManagedClient.app 中）
- 示例：
- Certificate Payloads 使用 CertificateService.xpc

通常，MDM vendor 提供的 **activation profile** 会包含以下 payloads：

- `com.apple.mdm`：用于在 MDM 中 **enroll** 设备
- `com.apple.security.scep`：用于安全地向设备提供 **client certificate**。
- `com.apple.security.pem`：用于将 trusted CA certificates **安装**到设备的 System Keychain。
- 安装等同于文档中 **MDM check-in** 的 MDM payload
- Payload **包含关键 properties**：
- - MDM Check-In URL（**`CheckInURL`**）
- MDM Command Polling URL（**`ServerURL`**）+ 用于触发它的 APNs topic
- 要安装 MDM payload，request 会发送到 **`CheckInURL`**
- 由 **`mdmclient`** 实现
- MDM payload 可以依赖其他 payloads
- 允许将 **requests pinning 到指定 certificates**：
- Property：**`CheckInURLPinningCertificateUUIDs`**
- Property：**`ServerURLPinningCertificateUUIDs`**
- 通过 PEM payload 传送
- 允许为设备分配 identity certificate：
- Property：IdentityCertificateUUID
- 通过 SCEP payload 传送

### **步骤 7：监听 MDM commands**

- MDM check-in 完成后，vendor 可以使用 APNs **发送 push notifications**
- 收到后由 **`mdmclient`** 处理
- 要 poll MDM commands，request 会发送到 ServerURL
- 使用之前安装的 MDM payload：
- 用于 request pinning 的 **`ServerURLPinningCertificateUUIDs`**
- 用于 TLS client certificate 的 **`IdentityCertificateUUID`**

## 攻击

### 将设备 Enrollment 到其他组织

如前文所述，要尝试将设备 enrollment 到某个组织，**只需要一个属于该组织的 Serial Number**。设备 enrollment 后，许多组织会在新设备上安装敏感数据：certificates、applications、WiFi passwords、VPN configurations [等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
因此，如果 enrollment 流程没有得到正确保护，这可能成为攻击者的危险入口：<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [深入分析 macOS MDM（以及如何被 Compromised）](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?"（DEP/MDM enrollment security research）](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
