# AD 证书

{{#include ../../banners/hacktricks-training.md}}

## 简介

### 证书的组件

- 证书的 **Subject** 表示其所有者。
- **Public Key** 与私有持有的密钥配对，用于将证书关联到其合法所有者。
- 由 **NotBefore** 和 **NotAfter** 日期定义的 **Validity Period** 标示证书的有效期限。
- 由 Certificate Authority (CA) 提供的唯一 **Serial Number** 用于标识每张证书。
- **Issuer** 指代签发该证书的 CA。
- **SubjectAlternativeName** 允许为主体添加其他名称，从而提高标识的灵活性。
- **Basic Constraints** 用于标识证书是属于 CA 还是终端实体，并定义使用限制。
- **Extended Key Usages (EKUs)** 通过 Object Identifiers (OIDs) 划分证书的具体用途，例如代码签名或电子邮件加密。
- **Signature Algorithm** 指定用于签署证书的方法。
- 使用签发者私钥创建的 **Signature** 可保证证书的真实性。<sup>[[4]](#references)</sup>

### 特别注意事项

- **Subject Alternative Names (SANs)** 将证书的适用范围扩展到多个身份，这对于具有多个域名的服务器至关重要。必须采用安全的签发流程，以避免攻击者操纵 SAN 规范而实施冒充攻击。<sup>[[4]](#references)</sup>

### Active Directory (AD) 中的 Certificate Authorities (CAs)

AD CS 通过指定的容器识别 AD forest 中的 CA 证书，每个容器承担不同的作用：<sup>[[4]](#references)</sup>

- **Certification Authorities** 容器保存受信任的根 CA 证书。
- **Enrolment Services** 容器详细记录 Enterprise CAs 及其 certificate templates。
- **NTAuthCertificates** 对象包含获准用于 AD 身份验证的 CA 证书。
- **AIA (Authority Information Access)** 容器通过中间 CA 证书和交叉 CA 证书促进证书链验证。

### 证书获取：Client Certificate Request Flow

1. 请求流程始于客户端查找 Enterprise CA。
2. 在生成公钥-私钥对后，创建包含公钥及其他详细信息的 CSR。
3. CA 根据可用的 certificate templates 评估 CSR，并依据模板权限签发证书。
4. 审批通过后，CA 使用其私钥签署证书并将其返回给客户端。<sup>[[4]](#references)</sup>

### Certificate Templates

这些模板在 AD 中定义，用于说明证书签发的设置和权限，包括允许的 EKUs 以及 enrollment 或修改权限，对于管理对证书服务的访问至关重要。<sup>[[4]](#references)</sup>

**模板 schema 版本非常重要。** Legacy **v1** templates（例如内置的 **WebServer** template）缺少多个现代 enforcement 控制项。**ESC15/EKUwu** 研究表明，在 **v1 templates** 中，请求者可以在 CSR 中嵌入 **Application Policies/EKUs**；这些设置会**优先于**模板中配置的 EKUs，从而仅凭 enrollment 权限即可获取 client-auth、enrollment agent 或 code-signing certificates。应优先使用 **v2/v3 templates**，移除或替代 v1 默认模板，并严格限制 EKUs 的用途。<sup>[[1]](#references)</sup>

## Certificate Enrollment

证书的 enrollment 流程由管理员启动，管理员首先**创建 certificate template**，然后由 Enterprise Certificate Authority (CA) 将其**发布**。这样一来，客户端便可进行 enrollment；具体操作是将模板名称添加到 Active Directory 对象的 `certificatetemplates` 字段中。<sup>[[4]](#references)</sup>

客户端要请求证书，必须被授予 **enrollment rights**。这些权限由 certificate template 和 Enterprise CA 上的 security descriptors 定义。请求要成功，必须在这两个位置都授予相应权限。

### Template Enrollment Rights

这些权限通过 Access Control Entries (ACEs) 指定，用于详细说明以下权限：

- **Certificate-Enrollment** 和 **Certificate-AutoEnrollment** 权限，每项权限都与特定 GUID 相关联。
- **ExtendedRights**，允许所有扩展权限。
- **FullControl/GenericAll**，提供对模板的完全控制权。

### Enterprise CA Enrollment Rights

CA 的权限在其 security descriptor 中定义，可通过 Certificate Authority 管理控制台访问。某些设置甚至允许低权限用户进行远程访问，这可能带来安全风险。

### Additional Issuance Controls

可能会应用某些控制措施，例如：

- **Manager Approval**：在证书管理员批准之前，将请求置于 pending 状态。
- **Enrolment Agents and Authorized Signatures**：指定 CSR 所需的签名数量以及必要的 Application Policy OIDs。

### Methods to Request Certificates

可以通过以下方式请求证书：

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)，使用 DCOM interfaces。
2. **ICertPassage Remote Protocol** (MS-ICPR)，通过 named pipes 或 TCP/IP。
3. **certificate enrollment web interface**，前提是已安装 Certificate Authority Web Enrollment role。
4. **Certificate Enrollment Service** (CES)，与 Certificate Enrollment Policy (CEP) service 配合使用。
5. 面向 network devices 的 **Network Device Enrollment Service** (NDES)，使用 Simple Certificate Enrollment Protocol (SCEP)。

Windows 用户还可以通过 GUI（`certmgr.msc` 或 `certlm.msc`）或命令行工具（`certreq.exe` 或 PowerShell 的 `Get-Certificate` command）请求证书。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) 支持 certificate authentication，主要使用 **Kerberos** 和 **Secure Channel (Schannel)** 协议。

### Kerberos Authentication Process

在 Kerberos authentication process 中，用户请求 Ticket Granting Ticket (TGT) 时，会使用用户 certificate 的 **private key** 对请求进行签名。该请求会由 domain controller 执行多项验证，包括 certificate 的 **validity**、**path** 和 **revocation status**。验证还包括确认 certificate 来自可信来源，以及确认 issuer 存在于 **NTAUTH certificate store** 中。验证成功后，将签发 TGT。AD 中的 **`NTAuthCertificates`** 对象位于：
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
是建立 certificate authentication 信任的核心。<sup>[[4]](#references)</sup>

自 **KB5014754** 推出以来，现代 Kerberos certificate auth 主要关注 **mapping strength**，而不仅仅是 EKU。<sup>[[2]](#references)</sup> 在已强化的 forest 中：

- 仅携带 **UPN/DNS SAN** 的 certificate 可能不再足以用于登录。
- KDC 更倾向于使用 **strong binding**，通常是 **SID security extension**（`1.3.6.1.4.1.311.25.2`），或 `altSecurityIdentities` 中的强显式 mapping。
- 如果 cert 缺少 strong mapping，DC 会在 compatibility mode 下记录 **Kdcsvc Event ID 39/41**，并在 enforcement mode 下拒绝 authentication。
- 在混合攻击路径中，**ESC9/ESC16** 很重要，因为它们会从已签发的 cert 中移除 SID extension；随后，operators 会依赖显式 mappings，或在攻击路径支持时使用 SAN URL SID 格式。

### Secure Channel (Schannel) Authentication

Schannel 用于建立安全的 TLS/SSL 连接。在 handshake 期间，client 会提交一个 certificate；如果该 certificate 成功通过验证，则会授权访问。将 certificate 映射到 AD account 可能涉及 Kerberos 的 **S4U2Self** function、certificate 的 **Subject Alternative Name (SAN)** 以及其他方法。<sup>[[4]](#references)</sup>

当 **PKINIT** 不可用时，Schannel 也是实际可用的 fallback。例如，如果 domain controller 没有合适的 **Smart Card Logon** certificate，`certipy auth`/PKINIT tooling 可能无法获取 TGT，但同一个 certificate 仍可用于通过 **LDAPS** 或 **LDAP StartTLS** 进行 authentication 和 LDAP operations。

### AD Certificate Services Enumeration

可以通过 LDAP queries 枚举 AD 的 certificate services，从而获取有关 **Enterprise Certificate Authorities (CAs)** 及其 configurations 的信息。任何经过 domain authentication 的 user 都可以访问这些信息，无需特殊 privileges。在 AD CS environments 中，常用 **[Certify](https://github.com/GhostPack/Certify)** 和 **[Certipy](https://github.com/ly4k/Certipy)** 进行 enumeration 和 vulnerability assessment。

使用这些 tools 的 commands 包括：
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## 近期漏洞与安全更新（2022-2025）

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | 在 PKINIT 期间通过 spoofing machine account certificates 实现*权限提升*。 | 补丁已包含在 **2022 年 5 月 10 日**的安全更新中。通过 **KB5014754** 引入了 auditing 和 strong-mapping 控制；环境现在应处于 *Full Enforcement* 模式。  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment（certsrv）和 CES roles 中的*远程代码执行*。 | 公开 PoC 有限，但存在漏洞的 IIS 组件经常暴露在内部网络中。已在 **2023 年 7 月** Patch Tuesday 中修复。  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | 在 **v1 templates** 上，具有 enrollment rights 的 requester 可以在 CSR 中嵌入 **Application Policies/EKUs**，这些内容的优先级高于 template EKUs，从而生成 client-auth、enrollment agent 或 code-signing certificates。 | 已于 **2024 年 11 月 12 日**修复。替换或 supersede v1 templates（例如默认的 WebServer），将 EKUs 限制为预期用途，并限制 enrollment rights。 |

### Microsoft 加固时间线（KB5014754）

Microsoft 引入了分三个阶段的 rollout（Compatibility → Audit → Enforcement），以使 Kerberos certificate authentication 脱离 weak implicit mappings。截至 **2025 年 2 月 11 日**，如果未设置 `StrongCertificateBindingEnforcement` registry value，domain controllers 会自动切换到 **Full Enforcement**。Microsoft 后来更新了时间线，使 fallback 到 compatibility mode 的可能性持续到 **2025 年 9 月 9 日**的安全更新。<sup>[[2]](#references)</sup> Administrators 应：

1. 为所有 DCs 和 AD CS servers 安装补丁（2022 年 5 月或更高版本）。
2. 在 *Audit* 阶段监控 Event ID 39/41，以发现 weak mappings。
3. 使用新的 **SID extension** 重新签发 client-auth certificates，或在 enforcement 阻止 weak mappings 之前配置 strong manual mappings。

### 针对已加固 forests 的 operator notes

- 在 2025+ 环境中，**ESC1/ESC6 alone is no longer the whole story**。如果你为另一个 principal request a cert，通常还需要一个 strong mapping artifact，例如 SID extension 或 explicit mapping。
- **ESC15 (EKUwu)** 主要在未打补丁的环境中有价值，因为它可以通过注入 **Application Policies**，将 **WebServer** 等无害的 **v1** templates 转变为具备 authentication 或 enrollment-agent 能力的 certs。Kerberos PKINIT 仍会评估 EKUs，但 **LDAP Schannel** 也会遵循 Application Policies，因此基于 LDAP 的 abuse 仍然相关。<sup>[[1]](#references)</sup>
- **ESC16** 是 CA-wide knob：如果 CA 在全局禁用 SID security extension，则除非 attack chain 通过其他受支持的格式注入 SID，否则每个 issued certificate 都会回退到更弱的 mapping behavior。

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** 现在会显示针对 ESC1-ESC8/ESC11 的 posture assessments，并生成实时 alerts，例如 *“Domain-controller certificate issuance for a non-DC”*（ESC8）和 *“Prevent Certificate Enrollment with arbitrary Application Policies”*（ESC15）。确保所有 AD CS servers 都部署 sensors，以利用这些 detections。<sup>[[3]](#references)</sup>
* 禁用所有 templates 上的 **“Supply in the request”** 选项，或严格限制其范围；优先使用明确定义的 SAN/EKU values。
* 除非绝对必要，否则从 templates 中移除 **Any Purpose** 或 **No EKU**（用于处理 ESC2 scenarios）。
* 对敏感 templates（例如 WebServer / CodeSigning）要求 **manager approval**，或使用专用的 Enrollment Agent workflows。
* 将 web enrollment（`certsrv`）和 CES/NDES endpoints 限制在 trusted networks 中，或置于 client-certificate authentication 之后。
* 强制使用 RPC enrollment encryption（`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`）以缓解 ESC11（RPC relay）。该 flag **默认开启**，但经常因 legacy clients 而被禁用，从而重新引入 relay risk。
* 保护 **基于 IIS 的 enrollment endpoints**（CES/Certsrv）：在可能的情况下禁用 NTLM，或要求 HTTPS + Extended Protection，以阻止 ESC8 relays。

---

## References

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
