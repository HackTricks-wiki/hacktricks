# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**要了解 macOS MDM，请查看：**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 基础知识

### **MDM（移动设备管理）概述**

[移动设备管理](https://en.wikipedia.org/wiki/Mobile_device_management)（MDM）用于管理各种终端用户设备，如智能手机、笔记本电脑和平板电脑。特别是对于苹果的平台（iOS、macOS、tvOS），它涉及一套专门的功能、API 和实践。MDM 的操作依赖于一个兼容的 MDM 服务器，该服务器可以是商业可用的或开源的，并且必须支持 [MDM 协议](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。关键点包括：

- 对设备的集中控制。
- 依赖于遵循 MDM 协议的 MDM 服务器。
- MDM 服务器能够向设备发送各种命令，例如远程数据擦除或配置安装。

### **DEP（设备注册计划）基础知识**

苹果提供的 [设备注册计划](https://www.apple.com/business/site/docs/DEP_Guide.pdf)（DEP）通过为 iOS、macOS 和 tvOS 设备提供零接触配置，简化了移动设备管理（MDM）的集成。DEP 自动化注册过程，使设备在开箱即用时即可操作，最小化用户或管理干预。基本方面包括：

- 使设备在首次激活时能够自动注册到预定义的 MDM 服务器。
- 主要对全新设备有利，但也适用于正在重新配置的设备。
- 促进简单的设置，使设备迅速准备好用于组织。

### **安全考虑**

需要注意的是，DEP 提供的注册便利性虽然有利，但也可能带来安全风险。如果没有充分执行保护措施，攻击者可能利用这一简化过程在组织的 MDM 服务器上注册他们的设备，伪装成企业设备。

> [!CAUTION]
> **安全警报**：如果没有适当的保护措施，简化的 DEP 注册可能允许未经授权的设备在组织的 MDM 服务器上注册。

### 基础知识 什么是 SCEP（简单证书注册协议）？

- 一种相对较旧的协议，创建于 TLS 和 HTTPS 广泛使用之前。
- 为客户端提供了一种标准化的方式来发送 **证书签名请求**（CSR），以获得证书。客户端将请求服务器为其提供签名证书。

### 什么是配置文件（即 mobileconfigs）？

- 苹果官方的 **设置/强制系统配置** 的方式。
- 可以包含多个有效负载的文件格式。
- 基于属性列表（XML 类型）。
- “可以被签名和加密以验证其来源，确保其完整性，并保护其内容。” 基础知识 — 第 70 页，iOS 安全指南，2018 年 1 月。

## 协议

### MDM

- APNs（**苹果服务器**）+ RESTful API（**MDM** **供应商**服务器）的组合
- **通信**发生在 **设备** 和与 **设备管理** **产品** 相关的服务器之间
- **命令**以 **plist 编码字典** 的形式从 MDM 发送到设备
- 所有通信通过 **HTTPS**。MDM 服务器可以（并且通常会）进行固定。
- 苹果向 MDM 供应商授予 **APNs 证书** 以进行身份验证

### DEP

- **3 个 API**：1 个用于经销商，1 个用于 MDM 供应商，1 个用于设备身份（未记录）：
- 所谓的 [DEP "云服务" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。MDM 服务器使用此 API 将 DEP 配置文件与特定设备关联。
- [苹果授权经销商使用的 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)，用于注册设备、检查注册状态和检查交易状态。
- 未记录的私有 DEP API。苹果设备使用此 API 请求其 DEP 配置文件。在 macOS 上，`cloudconfigurationd` 二进制文件负责通过此 API 进行通信。
- 更现代且基于 **JSON**（与 plist 相比）
- 苹果向 MDM 供应商授予 **OAuth 令牌**

**DEP "云服务" API**

- RESTful
- 从苹果同步设备记录到 MDM 服务器
- 从 MDM 服务器同步“DEP 配置文件”到苹果（稍后由苹果传递给设备）
- 一个 DEP “配置文件”包含：
- MDM 供应商服务器 URL
- 服务器 URL 的附加受信任证书（可选固定）
- 额外设置（例如，跳过设置助手中的哪些屏幕）

## 序列号

2010 年后制造的苹果设备通常具有 **12 个字符的字母数字** 序列号，**前三个数字表示制造地点**，接下来的 **两个** 表示 **制造的年份** 和 **周数**，接下来的 **三个** 数字提供一个 **唯一的** **标识符**，最后 **四个** 数字表示 **型号**。

{{#ref}}
macos-serial-number.md
{{#endref}}

## 注册和管理步骤

1. 设备记录创建（经销商，苹果）：为新设备创建记录
2. 设备记录分配（客户）：将设备分配给 MDM 服务器
3. 设备记录同步（MDM 供应商）：MDM 同步设备记录并将 DEP 配置文件推送到苹果
4. DEP 签到（设备）：设备获取其 DEP 配置文件
5. 配置文件检索（设备）
6. 配置文件安装（设备） a. 包括 MDM、SCEP 和根 CA 有效负载
7. MDM 命令发布（设备）

![](<../../../images/image (694).png>)

文件 `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` 导出可以被视为 **高层次的“步骤”** 的注册过程的函数。

### 第 4 步：DEP 签到 - 获取激活记录

该过程发生在 **用户首次启动 Mac 时**（或在完全擦除后）

![](<../../../images/image (1044).png>)

或在执行 `sudo profiles show -type enrollment` 时

- 确定 **设备是否启用 DEP**
- 激活记录是 **DEP “配置文件”** 的内部名称
- 一旦设备连接到互联网就开始
- 由 **`CPFetchActivationRecord`** 驱动
- 通过 XPC 由 **`cloudconfigurationd`** 实现。**“设置助手”**（当设备首次启动时）或 **`profiles`** 命令将 **联系此守护进程** 以检索激活记录。
- LaunchDaemon（始终以 root 身份运行）

它遵循几个步骤来获取激活记录，由 **`MCTeslaConfigurationFetcher`** 执行。此过程使用一种称为 **Absinthe** 的加密

1. 检索 **证书**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **初始化** 状态来自证书（**`NACInit`**）
1. 使用各种设备特定数据（即 **通过 `IOKit` 的序列号**）
3. 检索 **会话密钥**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 建立会话（**`NACKeyEstablishment`**）
5. 发出请求
1. POST 到 [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)，发送数据 `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON 有效负载使用 Absinthe 加密（**`NACSign`**）
3. 所有请求通过 HTTPs，使用内置根证书

![](<../../../images/image (566) (1).png>)

响应是一个 JSON 字典，包含一些重要数据，如：

- **url**：激活配置文件的 MDM 供应商主机的 URL
- **anchor-certs**：用作受信任锚的 DER 证书数组

### **第 5 步：配置文件检索**

![](<../../../images/image (444).png>)

- 请求发送到 **DEP 配置文件中提供的 URL**。
- **锚证书** 用于 **评估信任**（如果提供）。
- 提醒：**DEP 配置文件的 anchor_certs 属性**
- **请求是一个简单的 .plist**，包含设备识别信息
- 示例：**UDID、操作系统版本**。
- CMS 签名，DER 编码
- 使用 **设备身份证书（来自 APNS）** 签名
- **证书链** 包括过期的 **Apple iPhone Device CA**

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### 第 6 步：配置文件安装

- 一旦检索到，**配置文件将存储在系统上**
- 此步骤自动开始（如果在 **设置助手** 中）
- 由 **`CPInstallActivationProfile`** 驱动
- 通过 mdmclient 通过 XPC 实现
- LaunchDaemon（以 root 身份）或 LaunchAgent（以用户身份），具体取决于上下文
- 配置文件有多个有效负载需要安装
- 框架具有基于插件的架构来安装配置文件
- 每种有效负载类型与一个插件相关联
- 可以是 XPC（在框架中）或经典 Cocoa（在 ManagedClient.app 中）
- 示例：
- 证书有效负载使用 CertificateService.xpc

通常，MDM 供应商提供的 **激活配置文件** 将 **包括以下有效负载**：

- `com.apple.mdm`：用于 **注册** 设备到 MDM
- `com.apple.security.scep`：安全地向设备提供 **客户端证书**。
- `com.apple.security.pem`：向设备的系统钥匙串 **安装受信任的 CA 证书**。
- 安装 MDM 有效负载相当于文档中的 **MDM 签到**
- 有效负载 **包含关键属性**：
- - MDM 签到 URL（**`CheckInURL`**）
- MDM 命令轮询 URL（**`ServerURL`**） + 触发它的 APNs 主题
- 要安装 MDM 有效负载，请向 **`CheckInURL`** 发送请求
- 在 **`mdmclient`** 中实现
- MDM 有效负载可以依赖于其他有效负载
- 允许 **请求固定到特定证书**：
- 属性：**`CheckInURLPinningCertificateUUIDs`**
- 属性：**`ServerURLPinningCertificateUUIDs`**
- 通过 PEM 有效负载传递
- 允许设备被赋予身份证书：
- 属性：IdentityCertificateUUID
- 通过 SCEP 有效负载传递

### **第 7 步：监听 MDM 命令**

- 在 MDM 签到完成后，供应商可以 **使用 APNs 发布推送通知**
- 收到后，由 **`mdmclient`** 处理
- 要轮询 MDM 命令，请向 ServerURL 发送请求
- 利用先前安装的 MDM 有效负载：
- **`ServerURLPinningCertificateUUIDs`** 用于固定请求
- **`IdentityCertificateUUID`** 用于 TLS 客户端证书

## 攻击

### 在其他组织中注册设备

如前所述，为了尝试将设备注册到一个组织 **只需要该组织的序列号**。一旦设备注册，多个组织将会在新设备上安装敏感数据：证书、应用程序、WiFi 密码、VPN 配置 [等等](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
因此，如果注册过程没有得到正确保护，这可能成为攻击者的一个危险入口点：

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
