# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**了解 macOS MDM，请查看：**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 基础知识

### **MDM（Mobile Device Management）概述**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management)（MDM）用于管理各种终端用户设备，例如智能手机、笔记本电脑和平板电脑。对于 Apple 平台（iOS、macOS、tvOS），它涉及一组专用功能、API 和实践。MDM 的运行依赖于兼容的 MDM 服务器，该服务器可以是商业产品或开源项目，并且必须支持 [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。要点包括：

- 对设备进行集中控制。
- 依赖遵循 MDM 协议的 MDM 服务器。
- MDM 服务器能够向设备发送各种命令，例如远程擦除数据或安装配置。

### **DEP（Device Enrollment Program）基础知识**

Apple 提供的 [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf)（DEP）通过为 iOS、macOS 和 tvOS 设备提供零接触配置，简化了 Mobile Device Management（MDM）的集成。DEP 能够自动完成注册过程，使设备开箱后即可运行，并最大限度减少用户或管理员的干预。主要内容包括：

- 设备首次激活时，能够自动向预先定义的 MDM 服务器注册。
- 主要适用于全新设备，也适用于正在重新配置的设备。
- 提供简单直接的设置流程，使设备能够快速投入组织使用。

### **安全注意事项**

需要注意的是，DEP 提供的简便注册功能虽然有益，但也可能带来安全风险。如果没有充分实施 MDM 注册保护措施，攻击者可能利用这一简化流程，将自己的设备注册到组织的 MDM 服务器上，并伪装成企业设备。<sup>[[2]](#references)</sup>

> [!CAUTION]
> **安全警告**：如果没有适当的保护措施，简化的 DEP 注册可能允许未授权设备注册到组织的 MDM 服务器上。

### SCEP（Simple Certificate Enrolment Protocol）基础知识

- 一种相对老旧的协议，创建于 TLS 和 HTTPS 尚未普及之前。
- 为客户端提供一种标准化方式，用于发送 **Certificate Signing Request**（CSR），以申请证书。客户端会请求服务器为其提供签名证书。

### 什么是 Configuration Profiles（也称为 mobileconfigs）？

- Apple 官方用于**设置/强制系统配置**的方式。
- 一种可以包含多个 payload 的文件格式。
- 基于 property lists（XML 格式）。
- “可以进行签名和加密，以验证其来源、确保其完整性并保护其内容。”《iOS Security Guide》，2018 年 1 月，第 70 页。

## 协议

### MDM

- 由 APNs（**Apple 服务器**）+ RESTful API（**MDM** **vendor** 服务器）组成
- **通信**发生在**设备**与关联于设备**管理**产品的服务器之间
- 命令以 **plist 编码的字典**形式从 MDM 发送到设备
- 全部通过 **HTTPS** 传输。MDM 服务器可以（通常也会）进行 pinning。
- Apple 为 MDM vendor 授予用于身份验证的 **APNs 证书**

### DEP

- **3 个 API**：1 个供 reseller 使用，1 个供 MDM vendor 使用，1 个供设备身份使用（未公开）：
- 所谓的 [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。MDM 服务器使用它将 DEP profile 与特定设备关联。
- [Apple Authorized Resellers 使用的 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)，用于注册设备、检查注册状态以及检查事务状态。
- 未公开的私有 DEP API。Apple 设备使用它请求自身的 DEP profile。在 macOS 上，`cloudconfigurationd` 二进制文件负责通过此 API 进行通信。
- 更现代，并且基于 **JSON**（相对于 plist）
- Apple 为 MDM vendor 授予一个 **OAuth token**

**DEP "cloud service" API**

- RESTful
- 将设备记录从 Apple 同步到 MDM 服务器
- 将“DEP profiles”从 MDM 服务器同步到 Apple（之后由 Apple 发送到设备）
- DEP “profile”包含：
- MDM vendor 服务器 URL
- 服务器 URL 的其他受信任证书（可选 pinning）
- 额外设置（例如在 Setup Assistant 中跳过哪些屏幕）

## Serial Number

2010 年之后生产的 Apple 设备通常具有 **12 位字母数字**序列号，其中**前三位数字代表制造地点**，接下来的**两位表示制造年份和周数**，之后的**三位数字提供唯一** **标识符**，最后的**四位数字表示型号**。


{{#ref}}
macos-serial-number.md
{{#endref}}

## 注册和管理步骤

1. 设备记录创建（Reseller、Apple）：创建新设备的记录
2. 设备记录分配（Customer）：将设备分配给 MDM 服务器
3. 设备记录同步（MDM vendor）：MDM 同步设备记录，并将 DEP profiles 推送到 Apple
4. DEP check-in（Device）：设备获取其 DEP profile
5. Profile retrieval（Device）
6. Profile installation（Device）a. 包括 MDM、SCEP 和 root CA payloads
7. MDM command issuance（Device）

![Serial Number - 注册和管理步骤：7. MDM command issuance（Device）](<../../../images/image (694).png>)

文件 `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` 导出了可视为注册过程**高级“步骤”**的函数。

### 步骤 4：DEP check-in - 获取 Activation Record

此过程发生在**用户首次启动 Mac 时**（或执行完全擦除后）

![注册和管理步骤 - 步骤 4：DEP check-in - 获取 Activation Record：此过程发生在用户首次启动 Mac 时（或执行完全擦除后）](<../../../images/image (1044).png>)

或执行 `sudo profiles show -type enrollment` 时

- 确定**设备是否启用了 DEP**
- Activation Record 是 **DEP “profile”** 的内部名称
- 设备连接到 Internet 后立即开始
- 由 **`CPFetchActivationRecord`** 驱动
- 由 **`cloudconfigurationd`** 通过 XPC 实现。**"Setup Assistant**"（设备首次启动时）或 **`profiles`** 命令会**联系此 daemon**以获取 activation record。
- LaunchDaemon（始终以 root 身份运行）

获取 Activation Record 的过程由 **`MCTeslaConfigurationFetcher`** 执行。此过程使用名为 **Absinthe** 的加密方式<sup>[[1]](#references)</sup>

1. 获取**证书**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 从证书初始化状态（**`NACInit`**）
1. 使用各种设备专属数据（即通过 **`IOKit`** 获取的 **Serial Number**）
3. 获取**会话密钥**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 建立会话（**`NACKeyEstablishment`**）
5. 发出请求
1. POST 到 [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)，发送数据 `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON payload 使用 Absinthe 加密（**`NACSign`**）
3. 所有请求均通过 HTTPs 传输，使用内置 root certificates

![注册和管理步骤 - 步骤 4：DEP check-in - 获取 Activation Record：3. 所有请求均通过 HTTPs 传输，使用内置 root certificates](<../../../images/image (566) (1).png>)

响应是一个 JSON 字典，其中包含一些重要数据，例如：

- **url**：activation profile 的 MDM vendor 主机 URL
- **anchor-certs**：用作可信锚点的 DER 证书数组

### **步骤 5：Profile Retrieval**

![步骤 4：DEP check-in - 获取 Activation Record - 步骤 5：Profile Retrieval：步骤 5：Profile Retrieval](<../../../images/image (444).png>)

- 请求发送到 **DEP profile 中提供的 url**。
- 如果提供了 **Anchor certificates**，则使用它们来**评估信任**。
- 提醒：DEP profile 的 **anchor_certs** 属性
- **请求是一个简单的 .plist**，包含设备标识信息
- 示例：**UDID、OS 版本**。
- CMS 签名、DER 编码
- 使用 **device identity certificate（来自 APNS）** 签名
- **证书链**包含已过期的 **Apple iPhone Device CA**

![步骤 4：DEP check-in - 获取 Activation Record - 步骤 5：Profile Retrieval：使用 device identity certificate（来自 APNS）签名](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### 步骤 6：Profile Installation

- 获取后，**profile 会存储在系统中**
- 如果处于 **setup assistant** 中，此步骤会自动开始
- 由 **`CPInstallActivationProfile`** 驱动
- 由 mdmclient 通过 XPC 实现
- 根据上下文，以 root 身份运行的 LaunchDaemon 或以用户身份运行的 LaunchAgent
- Configuration profiles 包含多个待安装的 payload
- Framework 采用基于 plugin 的架构来安装 profiles
- 每种 payload 类型都与一个 plugin 关联
- 可以是 XPC（位于 framework 中）或经典 Cocoa（位于 ManagedClient.app 中）
- 示例：
- Certificate Payloads 使用 CertificateService.xpc

通常，MDM vendor 提供的 **activation profile** 会**包含以下 payloads**：

- `com.apple.mdm`：用于在 MDM 中**注册**设备
- `com.apple.security.scep`：用于向设备安全地提供**客户端证书**
- `com.apple.security.pem`：用于将受信任的 CA 证书**安装到**设备的 System Keychain 中
- 安装等同于文档中 **MDM check-in** 的 MDM payload
- Payload **包含关键属性**：
- - MDM Check-In URL（**`CheckInURL`**）
- MDM Command Polling URL（**`ServerURL`**）+ 用于触发它的 APNs topic
- 要安装 MDM payload，请向 **`CheckInURL`** 发送请求
- 由 **`mdmclient`** 实现
- MDM payload 可以依赖其他 payloads
- 允许**将请求 pinning 到特定证书**：
- 属性：**`CheckInURLPinningCertificateUUIDs`**
- 属性：**`ServerURLPinningCertificateUUIDs`**
- 通过 PEM payload 交付
- 允许为设备分配 identity certificate：
- 属性：IdentityCertificateUUID
- 通过 SCEP payload 交付

### **步骤 7：监听 MDM 命令**

- MDM check-in 完成后，vendor 可以**使用 APNs 发出 push notifications**
- 收到通知后，由 **`mdmclient`** 处理
- 要轮询 MDM 命令，请向 ServerURL 发送请求
- 使用之前安装的 MDM payload：
- 用于请求 pinning 的 **`ServerURLPinningCertificateUUIDs`**
- 用于 TLS 客户端证书的 **`IdentityCertificateUUID`**

## 攻击

### 将设备注册到其他组织

如前文所述，要尝试将设备注册到某个组织，**只需要一个属于该组织的 Serial Number**。设备注册后，许多组织会在新设备上安装敏感数据：证书、应用程序、WiFi 密码、VPN 配置[等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
因此，如果注册流程没有得到正确保护，这可能成为攻击者的危险入口：<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## 参考资料

- [1] [深入了解 macOS MDM（以及如何被攻破）](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — “MDM Me Maybe?”（DEP/MDM 注册安全研究）](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
