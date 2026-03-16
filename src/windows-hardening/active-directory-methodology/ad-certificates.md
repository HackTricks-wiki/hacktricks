# AD 证书

{{#include ../../banners/hacktricks-training.md}}

## 介绍

### 证书的组成部分

- 证书的 **Subject** 表示其所有者。
- **Public Key** 与对应的私钥配对，用于将证书绑定到其合法所有者。
- **Validity Period**（由 **NotBefore** 和 **NotAfter** 日期定义）标示证书的有效期限。
- 唯一的 **Serial Number**，由 Certificate Authority (CA) 提供，用于标识每个证书。
- **Issuer** 指签发该证书的 CA。
- **SubjectAlternativeName** 允许为主体添加额外名称，增强标识的灵活性。
- **Basic Constraints** 用于标识证书是用于 CA 还是终端实体，并定义使用限制。
- **Extended Key Usages (EKUs)** 通过对象标识符 (OIDs) 指定证书的具体用途，例如代码签名或邮件加密。
- **Signature Algorithm** 指定签署证书所用的方法。
- 使用签发者私钥创建的 **Signature** 用以保证证书的真实性。

### 特殊注意事项

- **Subject Alternative Names (SANs)** 扩展证书适用的身份范围，使其可用于多个身份，这对拥有多个域名的服务器至关重要。必须确保签发流程安全，以防攻击者通过操纵 SAN 规范进行冒充。

### Active Directory (AD) 中的 Certificate Authorities (CAs)

AD CS 通过指定的容器在 AD 林中识别 CA 证书，每个容器有不同的作用：

- **Certification Authorities** 容器保存受信任的根 CA 证书。
- **Enrolment Services** 容器记录 Enterprise CAs 及其证书模板。
- **NTAuthCertificates** 对象包含被授权用于 AD 身份验证的 CA 证书。
- **AIA (Authority Information Access)** 容器通过包含中间 CA 和跨认证 CA 证书来促进证书链验证。

### 证书获取：客户端证书请求流程

1. 客户端首先查找可用的 Enterprise CA。
2. 生成公私钥对后，创建 CSR，包含公钥及其他信息。
3. CA 根据可用的证书模板评估 CSR，并根据模板的权限来颁发证书。
4. 经批准后，CA 使用其私钥对证书签名并返回给客户端。

### 证书模板

在 AD 中定义的这些模板规定了颁发证书的设置和权限，包括允许的 EKUs 以及注册或修改权限，对于管理对证书服务的访问至关重要。

**模板架构版本很重要。** 传统的 **v1** 模板（例如内置的 **WebServer** 模板）缺少若干现代的强制控制选项。研究 **ESC15/EKUwu** 显示，在 **v1 模板** 上，请求者可以在 CSR 中嵌入 **Application Policies/EKUs**，这些会被优先于模板已配置的 EKUs，从而在只有注册权限的情况下获得 client-auth、enrollment agent 或 code-signing 证书。应优先使用 **v2/v3 模板**，删除或覆盖 v1 的默认设置，并将 EKUs 严格限定到预期用途。

## 证书注册

证书的注册流程由管理员发起，管理员 **创建证书模板**，然后由 Enterprise Certificate Authority (CA) **发布**。发布后，模板即可供客户端注册，通常通过将模板名称添加到 Active Directory 对象的 certificatetemplates 字段来实现。

客户端请求证书时，必须被授予 **enrollment rights**。这些权限由证书模板和 Enterprise CA 本身上的安全描述符定义。要成功发起请求，必须在两处都授予相应权限。

### 模板注册权限

这些权限通过 Access Control Entries (ACEs) 指定，包含如下权限：

- **Certificate-Enrollment** 和 **Certificate-AutoEnrollment** 权限，每个权限对应特定的 GUID。
- **ExtendedRights**，允许所有扩展权限。
- **FullControl/GenericAll**，对模板提供完全控制权限。

### Enterprise CA 注册权限

CA 的权限在其安全描述符中列出，可以通过 Certificate Authority 管理控制台查看。有些设置甚至允许低权限用户进行远程访问，这可能构成安全隐患。

### 额外的签发控制

可能适用的控制包括：

- **Manager Approval**：将请求置于挂起状态，直到被证书管理员批准。
- **Enrolment Agents and Authorized Signatures**：指定 CSR 上所需签名的数量以及必要的 Application Policy OIDs。

### 请求证书的方法

证书可以通过以下方式请求：

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)，使用 DCOM 接口。
2. **ICertPassage Remote Protocol** (MS-ICPR)，通过命名管道或 TCP/IP。
3. 使用安装了 Certificate Authority Web Enrollment 角色的 **certificate enrollment web interface**。
4. **Certificate Enrollment Service** (CES)，与 Certificate Enrollment Policy (CEP) 服务配合使用。
5. 针对网络设备使用 **Network Device Enrollment Service** (NDES)，通过 Simple Certificate Enrollment Protocol (SCEP)。

Windows 用户也可以通过 GUI（certmgr.msc 或 certlm.msc）或命令行工具（certreq.exe 或 PowerShell 的 Get-Certificate 命令）请求证书。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 证书认证

Active Directory (AD) 支持证书认证，主要使用 **Kerberos** 和 **Secure Channel (Schannel)** 协议。

### Kerberos 身份验证过程

在 Kerberos 身份验证过程中，用户请求 Ticket Granting Ticket (TGT) 时，该请求使用用户证书的 **私钥** 签名。该请求由域控制器进行多项验证，包括证书的 **有效性**、**路径** 和 **吊销状态**。验证还包括确认证书来自受信任来源并确认颁发者存在于 **NTAUTH certificate store**。验证成功后会签发 TGT。AD 中的 **`NTAuthCertificates`** 对象位于：
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
对于建立证书认证的信任至关重要。

### Secure Channel (Schannel) Authentication

Schannel 促成安全的 TLS/SSL 连接，在握手期间，客户端出示证书；如果验证成功，则授权访问。将证书映射到 AD 帐户可能涉及 Kerberos 的 **S4U2Self** 功能或证书的 **Subject Alternative Name (SAN)**，以及其他方法。

### AD Certificate Services Enumeration

可以通过 LDAP 查询枚举 AD 的证书服务，从而揭示 **Enterprise Certificate Authorities (CAs)** 及其配置的相关信息。任何域认证用户无需特殊权限即可访问这些信息。在 AD CS 环境中，工具如 **[Certify](https://github.com/GhostPack/Certify)** 和 **[Certipy](https://github.com/ly4k/Certipy)** 常用于枚举和漏洞评估。

Commands for using these tools include:
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
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## 最近的漏洞与安全更新 (2022-2025)

| 年份 | ID / 名称 | 影响 | 关键要点 |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *特权提升*：通过在 PKINIT 期间伪造计算机帐户证书实现。 | 补丁包含在 **2022 年 5 月 10 日** 的安全更新中。通过 **KB5014754** 引入了审计和强绑定控制；环境现在应处于 *Full Enforcement* 模式。  |
| 2023 | **CVE-2023-35350 / 35351** | *远程代码执行*：影响 AD CS Web Enrollment (certsrv) 和 CES 角色。 | 公开 PoC 限制较多，但易受攻击的 IIS 组件在内部网络中经常暴露。补丁已于 **2023 年 7 月** Patch Tuesday 发布。  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | 在 **v1 templates** 上，有注册权限的申请者可以在 CSR 中嵌入 **Application Policies/EKUs**，这些会优先于模板 EKU，从而生成 client-auth、enrollment agent 或 code-signing 证书。 | 补丁已于 **2024 年 11 月 12 日** 发布。替换或取代 v1 templates（例如默认 WebServer），将 EKU 限定为预期用途，并限制注册权限。 |

### Microsoft 加固时间线 (KB5014754)

Microsoft 引入了三阶段部署（Compatibility → Audit → Enforcement），以将 Kerberos 证书身份验证从弱的隐式映射中移出。截至 **2025 年 2 月 11 日**，如果未设置 `StrongCertificateBindingEnforcement` 注册表值，域控制器会自动切换到 **Full Enforcement**。管理员应当：

1. 修补所有 DC 和 AD CS 服务器（2022 年 5 月或更晚的更新）。
2. 在 *Audit* 阶段监控 Event ID 39/41 以检测弱映射。
3. 在 2025 年 2 月之前，使用新的 **SID extension** 重新签发 client-auth 证书，或配置强制手动映射。

---

## 检测与加固增强

* **Defender for Identity AD CS sensor (2023-2024)** 现在会显示 ESC1-ESC8/ESC11 的态势评估，并生成实时警报，例如 *“Domain-controller certificate issuance for a non-DC”* (ESC8) 和 *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15)。确保在所有 AD CS 服务器上部署这些传感器以利用这些检测。
* 禁用或严格限定所有模板上的 **“Supply in the request”** 选项；优先使用明确定义的 SAN/EKU 值。
* 除非绝对必要（可解决 ESC2 场景），否则从模板中移除 **Any Purpose** 或 **No EKU**。
* 对敏感模板（例如 WebServer / CodeSigning）要求 **manager approval** 或专用的 Enrollment Agent 工作流。
* 将 web enrollment (`certsrv`) 和 CES/NDES 端点限制在受信任网络内，或置于客户端证书认证之后。
* 强制 RPC 注册加密（`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`）以缓解 ESC11（RPC 中继）。该标志默认启用，但常为兼容旧客户端而被禁用，这会重新开启中继风险。
* 保护 **基于 IIS 的注册端点**（CES/Certsrv）：在可能的情况下禁用 NTLM，或要求 HTTPS + Extended Protection 来阻止 ESC8 中继。

---



## 参考资料

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
