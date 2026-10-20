# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**了解 macOS MDM，请查看：**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## 基础知识

### **MDM（移动设备管理）概述**

[移动设备管理](https://en.wikipedia.org/wiki/Mobile_device_management)（MDM）用于管理智能手机、笔记本电脑和平板电脑等各种终端用户设备。对于 Apple 平台（iOS、macOS、tvOS），MDM 涉及一系列专用功能、API 和实践。MDM 的运行依赖兼容的 MDM 服务器，该服务器可以是商用或开源的，并且必须支持 [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。要点包括：

- 对设备进行集中控制。
- 依赖遵循 MDM protocol 的 MDM 服务器。
- MDM 服务器能够向设备发送各种命令，例如远程擦除数据或安装配置。

### **DEP（设备注册计划）基础知识**

Apple 提供的 [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf)（DEP）通过为 iOS、macOS 和 tvOS 设备提供零接触配置，简化了 Mobile Device Management（MDM）的集成。DEP 可自动完成注册流程，使设备开箱后即可投入使用，几乎不需要用户或管理员介入。主要特点包括：

- 设备首次激活时，可自动向预先指定的 MDM 服务器注册。
- 主要适用于全新设备，也适用于需要重新配置的设备。
- 简化设置流程，使设备能够快速投入组织使用。

### **安全注意事项**

需要注意的是，DEP 提供的便捷注册方式虽然有益，也可能带来安全风险。如果没有充分落实 MDM 注册保护措施，攻击者可能利用这一简化流程，将自己的设备注册到组织的 MDM 服务器上，并伪装成企业设备。<sup>[[2]](#references)</sup>

> [!CAUTION]
> **安全警报**：如果没有适当的保护措施，简化的 DEP 注册流程可能允许未经授权的设备注册到组织的 MDM 服务器。

### 基础知识：什么是 SCEP（简单证书注册协议）？

- 一种相对古老的协议，诞生于 TLS 和 HTTPS 尚未普及的时期。
- 为客户端提供标准化方式，以发送 **Certificate Signing Request**（CSR）并申请证书。客户端会请求服务器签发证书。

### 什么是 Configuration Profiles（又称 mobileconfigs）？

- Apple 官方提供的**设置/强制系统配置**方式。
- 一种可包含多个 payload 的文件格式。
- 基于 property lists（XML 格式）。
- “可进行签名和加密，以验证其来源、确保其完整性并保护其内容。”《iOS Security Guide》，2018 年 1 月，基础知识 — 第 70 页。

## 协议

### MDM

- 由 APNs（**Apple 服务器**）和 RESTful API（**MDM** **供应商**服务器）组合而成
- **通信**发生在**设备**与关联于**设备** **管理** **产品**的服务器之间
- MDM 发送给设备的**命令**采用 **plist 编码字典**
- 全部通过 **HTTPS** 进行。MDM 服务器可以（通常也会）进行证书固定。
- Apple 向 MDM 供应商颁发 **APNs 证书**用于身份验证

### DEP

- **3 个 API**：1 个供经销商使用，1 个供 MDM 供应商使用，1 个用于设备身份验证（未公开）：
  - 所谓的 [DEP“云服务”API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。MDM 服务器使用此 API 将 DEP profiles 与特定设备关联。
  - [Apple 授权经销商使用的 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)，用于注册设备、检查注册状态以及检查交易状态。
  - 未公开的私有 DEP API。Apple 设备使用此 API 请求其 DEP profile。在 macOS 上，`cloudconfigurationd` 二进制文件负责通过此 API 进行通信。
- 更现代，基于 **JSON**（而非 plist）
- Apple 向 MDM 供应商授予 **OAuth token**

**DEP“云服务”API**

- RESTful
- 将设备记录从 Apple 同步到 MDM 服务器
- 将“DEP profiles”从 MDM 服务器同步到 Apple（之后由 Apple 下发到设备）
- DEP“profile”包含：
  - MDM 供应商服务器 URL
  - 服务器 URL 的其他受信任证书（可选的证书固定）
  - 额外设置（例如在 Setup Assistant 中跳过哪些界面）

## 序列号

2010 年后生产的 Apple 设备通常使用 **12 位字母数字**序列号：**前三位表示制造地点**，接下来的**两位**表示制造的**年份**和**周数**，随后**三位**提供**唯一**标识符，**最后** **四位**表示**型号**。


{{#ref}}
macos-serial-number.md
{{#endref}}

## 注册和管理步骤

1. 创建设备记录（经销商、Apple）：创建新设备的记录
2. 分配设备记录（客户）：将设备分配给 MDM 服务器
3. 同步设备记录（MDM 供应商）：MDM 同步设备记录，并将 DEP profiles 推送到 Apple
4. DEP check-in（设备）：设备获取其 DEP profile
5. 获取 profile（设备）
6. 安装 profile（设备），包括 MDM、SCEP 和根 CA payload
7. 下发 MDM 命令（设备）

![序列号 - 注册和管理步骤：7. 下发 MDM 命令（设备）](<../../../images/image (694).png>)

文件 `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` 导出了可视为注册流程高级“步骤”的函数。

### 步骤 4：DEP check-in - 获取 Activation Record

此流程发生在**用户首次启动 Mac 时**（或完全抹除设备后）

![注册和管理步骤 - 步骤 4：DEP check-in - 获取 Activation Record：此流程发生在用户首次启动 Mac 时（或完全...](<../../../images/image (1044).png>)

或执行 `sudo profiles show -type enrollment` 时

- 确定设备是否已启用 **DEP**
- Activation Record 是 **DEP“profile”**的内部名称
- 设备连接到互联网后立即开始
- 由 **`CPFetchActivationRecord`** 驱动
- 通过 XPC 由 **`cloudconfigurationd`** 实现。**“Setup Assistant”**（设备首次启动时）或 **`profiles`** 命令会**联系此守护进程**以获取 activation record。
  - LaunchDaemon（始终以 root 身份运行）

获取 Activation Record 时会由 **`MCTeslaConfigurationFetcher`** 执行几个步骤。此流程使用一种名为 **Absinthe** 的加密方式<sup>[[1]](#references)</sup>

1. 获取**证书**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 根据证书**初始化**状态（**`NACInit`**）
   1. 使用各种设备专属数据（即通过 `IOKit` 获取的**序列号**）
3. 获取**会话密钥**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. 建立会话（**`NACKeyEstablishment`**）
5. 发送请求
   1. POST 到 [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)，发送数据 `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. JSON payload 使用 Absinthe 加密（**`NACSign`**）
   3. 所有请求均通过 HTTPS 发送，使用内置根证书

![注册和管理步骤 - 步骤 4：DEP check-in - 获取 Activation Record：3. 所有请求均通过 HTTPS 发送，使用内置根证书](<../../../images/image (566) (1).png>)

响应是一个 JSON 字典，其中包含一些重要数据，例如：

- **url**：用于 activation profile 的 MDM 供应商主机 URL
- **anchor-certs**：用作信任锚的 DER 证书数组

### **步骤 5：获取 Profile**

![步骤 4：DEP check-in - 获取 Activation Record - 步骤 5：获取 Profile：步骤 5：获取 Profile](<../../../images/image (444).png>)

- 请求发送到 **DEP profile 中提供的 url**。
- 如果提供了**锚证书**，则用于**评估信任**。
  - 提醒：DEP profile 的 **anchor_certs** 属性
- **请求是一个简单的 .plist**，包含设备标识信息
  - 示例：**UDID、OS 版本**。
- 由 CMS 签名，使用 DER 编码
- 使用**设备身份验证证书（来自 APNS）**签名
- **证书链**包含已过期的 **Apple iPhone Device CA**

![步骤 4：DEP check-in - 获取 Activation Record - 步骤 5：获取 Profile：使用设备身份验证证书（来自 APNS）签名](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### 步骤 6：安装 Profile

- 获取后，**profile 会存储在系统中**
- 此步骤会自动开始（如果处于 **Setup Assistant** 中）
- 由 **`CPInstallActivationProfile`** 驱动
- 通过 XPC 由 mdmclient 实现
  - LaunchDaemon（以 root 身份运行）或 LaunchAgent（以用户身份运行），取决于上下文
- Configuration profiles 包含多个待安装的 payload
- Framework 使用基于插件的架构来安装 profiles
- 每种 payload 类型都关联一个插件
  - 可以是 XPC（在 framework 中）或经典 Cocoa（在 ManagedClient.app 中）
- 示例：
  - Certificate payload 使用 CertificateService.xpc

通常，MDM 供应商提供的 **activation profile** 会包含以下 payload：

- `com.apple.mdm`：用于将设备**注册**到 MDM
- `com.apple.security.scep`：用于向设备安全地提供**客户端证书**。
- `com.apple.security.pem`：用于将**受信任的 CA 证书安装**到设备的 System Keychain。
- 安装 MDM payload，相当于文档中所说的 **MDM check-in**
- Payload **包含关键属性**：
- - MDM Check-In URL（**`CheckInURL`**）
  - MDM 命令轮询 URL（**`ServerURL`**）以及用于触发轮询的 APNs topic
- 要安装 MDM payload，请求会发送到 **`CheckInURL`**
- 由 **`mdmclient`** 实现
- MDM payload 可以依赖其他 payload
- 允许将**请求固定到特定证书**：
  - 属性：**`CheckInURLPinningCertificateUUIDs`**
  - 属性：**`ServerURLPinningCertificateUUIDs`**
  - 通过 PEM payload 下发
- 允许为设备配置身份验证证书：
  - 属性：IdentityCertificateUUID
  - 通过 SCEP payload 下发

### **步骤 7：监听 MDM 命令**

- MDM check-in 完成后，供应商可以使用 APNs **发送推送通知**
- 收到通知后，由 **`mdmclient`** 处理
- 要轮询 MDM 命令，请求会发送到 ServerURL
- 使用之前安装的 MDM payload：
  - 使用 **`ServerURLPinningCertificateUUIDs`** 固定请求
  - 使用 **`IdentityCertificateUUID`** 作为 TLS 客户端证书

## 攻击

### 将设备注册到其他组织

分配的序列号可以表明组织的注册路径，但**不能**保证设备一定会注册到 MDM。服务器可以要求用户通过 `configuration_web_url` 进行身份验证，然后才返回注册 profile。应检查是否存在省略此验证的备用注册路径，而不要假设每个已分配的序列号都能加入设备群组。<sup>[[3]](#references)</sup>

如需了解 rogue-enrollment 工作流，请查看下方链接页面。如需了解入侵后的 MDM 控制和软件包下发，请参阅 [macOS Red Teaming](../)。


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [深入了解 macOS MDM（以及它如何被攻破）](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — “MDM Me Maybe?”（DEP/MDM 注册安全研究）](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — 通过网页视图进行身份验证](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
