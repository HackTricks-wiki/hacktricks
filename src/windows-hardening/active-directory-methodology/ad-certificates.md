# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- 证书的**主题**表示其所有者。
- **公钥**与私有密钥配对，将证书与其合法所有者关联。
- **有效期**由**NotBefore**和**NotAfter**日期定义，标记证书的有效持续时间。
- 由证书颁发机构（CA）提供的唯一**序列号**标识每个证书。
- **颁发者**指的是颁发证书的CA。
- **SubjectAlternativeName**允许为主题提供额外名称，增强识别灵活性。
- **基本约束**识别证书是用于CA还是终端实体，并定义使用限制。
- **扩展密钥使用（EKUs）**通过对象标识符（OIDs）划定证书的特定用途，如代码签名或电子邮件加密。
- **签名算法**指定签署证书的方法。
- 使用颁发者的私钥创建的**签名**保证证书的真实性。

### Special Considerations

- **主题备用名称（SANs）**扩展证书对多个身份的适用性，对于具有多个域的服务器至关重要。安全的颁发流程对于避免攻击者操纵SAN规范进行冒充风险至关重要。

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS通过指定的容器在AD森林中承认CA证书，每个容器承担独特角色：

- **Certification Authorities**容器保存受信任的根CA证书。
- **Enrolment Services**容器详细说明企业CA及其证书模板。
- **NTAuthCertificates**对象包括被授权用于AD身份验证的CA证书。
- **AIA (Authority Information Access)**容器通过中间和交叉CA证书促进证书链验证。

### Certificate Acquisition: Client Certificate Request Flow

1. 请求过程从客户端寻找企业CA开始。
2. 在生成公私钥对后，创建包含公钥和其他详细信息的CSR。
3. CA根据可用证书模板评估CSR，并根据模板的权限颁发证书。
4. 经批准后，CA使用其私钥签署证书并将其返回给客户端。

### Certificate Templates

在AD中定义，这些模板概述了颁发证书的设置和权限，包括允许的EKUs和注册或修改权利，对于管理证书服务的访问至关重要。

## Certificate Enrollment

证书的注册过程由管理员**创建证书模板**，然后由企业证书颁发机构（CA）**发布**。这使得模板可用于客户端注册，通过将模板名称添加到Active Directory对象的`certificatetemplates`字段来实现。

为了让客户端请求证书，必须授予**注册权限**。这些权限由证书模板和企业CA本身的安全描述符定义。必须在两个位置授予权限，才能成功请求。

### Template Enrollment Rights

这些权限通过访问控制条目（ACEs）指定，详细说明权限，如：

- **证书注册**和**证书自动注册**权限，每个权限与特定的GUID相关联。
- **ExtendedRights**，允许所有扩展权限。
- **FullControl/GenericAll**，提供对模板的完全控制。

### Enterprise CA Enrollment Rights

CA的权限在其安全描述符中列出，可以通过证书颁发机构管理控制台访问。有些设置甚至允许低权限用户远程访问，这可能是一个安全隐患。

### Additional Issuance Controls

某些控制可能适用，例如：

- **经理批准**：将请求置于待处理状态，直到由证书经理批准。
- **注册代理和授权签名**：指定CSR上所需的签名数量和必要的应用程序策略OIDs。

### Methods to Request Certificates

可以通过以下方式请求证书：

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)，使用DCOM接口。
2. **ICertPassage Remote Protocol** (MS-ICPR)，通过命名管道或TCP/IP。
3. **证书注册Web界面**，安装了证书颁发机构Web注册角色。
4. **证书注册服务** (CES)，与证书注册策略（CEP）服务结合使用。
5. **网络设备注册服务** (NDES)用于网络设备，使用简单证书注册协议（SCEP）。

Windows用户还可以通过GUI（`certmgr.msc`或`certlm.msc`）或命令行工具（`certreq.exe`或PowerShell的`Get-Certificate`命令）请求证书。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 证书认证

Active Directory (AD) 支持证书认证，主要利用 **Kerberos** 和 **安全通道 (Schannel)** 协议。

### Kerberos 认证过程

在 Kerberos 认证过程中，用户请求的票证授予票证 (TGT) 使用用户证书的 **私钥** 进行签名。该请求经过域控制器的多个验证，包括证书的 **有效性**、**路径** 和 **撤销状态**。验证还包括确认证书来自受信任的来源，并确认发行者在 **NTAUTH 证书存储** 中的存在。成功的验证将导致 TGT 的发放。AD 中的 **`NTAuthCertificates`** 对象位于：
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
在证书认证中建立信任是至关重要的。

### 安全通道 (Schannel) 认证

Schannel 促进安全的 TLS/SSL 连接，在握手过程中，客户端提供一个证书，如果成功验证，则授权访问。将证书映射到 AD 账户可能涉及 Kerberos 的 **S4U2Self** 函数或证书的 **主题备用名称 (SAN)**，以及其他方法。

### AD 证书服务枚举

AD 的证书服务可以通过 LDAP 查询进行枚举，揭示有关 **企业证书颁发机构 (CAs)** 及其配置的信息。这对任何经过域认证的用户都是可访问的，无需特殊权限。工具如 **[Certify](https://github.com/GhostPack/Certify)** 和 **[Certipy](https://github.com/ly4k/Certipy)** 被用于在 AD CS 环境中的枚举和漏洞评估。

使用这些工具的命令包括：
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
---

## 最近的漏洞与安全更新 (2022-2025)

| 年份 | ID / 名称 | 影响 | 关键要点 |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *特权提升*，通过在 PKINIT 期间伪造机器账户证书。 | 补丁包含在 **2022年5月10日** 的安全更新中。通过 **KB5014754** 引入了审计和强映射控制；环境现在应处于 *完全强制* 模式。 |
| 2023 | **CVE-2023-35350 / 35351** | *远程代码执行* 在 AD CS Web Enrollment (certsrv) 和 CES 角色中。 | 公开的 PoC 限制较少，但易受攻击的 IIS 组件通常在内部暴露。补丁自 **2023年7月** 的补丁星期二起生效。 |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | 具有注册权限的低权限用户可以在 CSR 生成期间覆盖 **任何** EKU 或 SAN，发放可用于客户端身份验证或代码签名的证书，导致 *域被攻陷*。 | 在 **2024年4月** 的更新中解决。移除模板中的“请求中提供”并限制注册权限。 |

### 微软强化时间表 (KB5014754)

微软引入了三阶段的推出（兼容性 → 审计 → 强制），以将 Kerberos 证书认证从弱隐式映射中转移出去。自 **2025年2月11日** 起，如果未设置 `StrongCertificateBindingEnforcement` 注册表值，域控制器将自动切换到 **完全强制**。管理员应：

1. 修补所有 DC 和 AD CS 服务器（2022年5月或更晚）。
2. 在 *审计* 阶段监控事件 ID 39/41 以查找弱映射。
3. 在 2025年2月之前重新发放带有新 **SID 扩展** 的客户端认证证书或配置强手动映射。

---

## 检测与强化增强

* **Defender for Identity AD CS 传感器 (2023-2024)** 现在提供 ESC1-ESC8/ESC11 的姿态评估，并生成实时警报，如 *“非 DC 的域控制器证书发放”* (ESC8) 和 *“防止使用任意应用程序策略的证书注册”* (ESC15)。确保传感器部署到所有 AD CS 服务器以受益于这些检测。
* 禁用或严格限制所有模板上的 **“请求中提供”** 选项；优先使用明确定义的 SAN/EKU 值。
* 除非绝对必要，否则从模板中移除 **任何目的** 或 **无 EKU**（解决 ESC2 场景）。
* 对于敏感模板（例如，WebServer / CodeSigning），要求 **经理批准** 或专用注册代理工作流。
* 将 Web 注册 (`certsrv`) 和 CES/NDES 端点限制在受信网络或客户端证书认证后面。
* 强制 RPC 注册加密 (`certutil –setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQ`) 以减轻 ESC11。

---

## 参考文献

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
