# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- 证书的 **Subject** 表示其所有者。
- **Public Key** 与私有持有的密钥配对，用于将证书关联到其合法所有者。
- **Validity Period** 由 **NotBefore** 和 **NotAfter** 日期定义，标示证书的有效期限。
- 由证书颁发机构 (CA) 提供的唯一 **Serial Number** 用于标识每张证书。
- **Issuer** 指颁发证书的 CA。
- **SubjectAlternativeName** 允许为 subject 添加其他名称，提高身份识别的灵活性。
- **Basic Constraints** 用于确定证书是 CA 证书还是终端实体证书，并定义使用限制。
- **Extended Key Usages (EKUs)** 通过对象标识符 (OIDs) 指明证书的特定用途，例如代码签名或电子邮件加密。
- **Signature Algorithm** 指定用于签署证书的方法。
- 使用颁发者的私钥创建的 **Signature** 可保证证书的真实性。<sup>[[4]](#references)</sup>

### Special Considerations

- **Subject Alternative Names (SANs)** 扩展了证书适用的身份范围，使其能够涵盖多个身份，这对于拥有多个域名的服务器至关重要。安全的签发流程十分重要，可避免攻击者操纵 SAN 配置进行冒充的风险。<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS 通过指定的容器识别 AD forest 中的 CA 证书，每个容器都承担独特的作用：<sup>[[4]](#references)</sup>

- **Certification Authorities** 容器保存受信任的根 CA 证书。
- **Enrolment Services** 容器列出 Enterprise CA 及其证书模板。
- **NTAuthCertificates** 对象包含获准用于 AD authentication 的 CA 证书。
- **AIA (Authority Information Access)** 容器通过中间 CA 证书和交叉 CA 证书，帮助验证证书链。

### Certificate Acquisition: Client Certificate Request Flow

1. 请求流程始于客户端查找 Enterprise CA。
2. 生成公私钥对后，创建包含公钥和其他信息的 CSR。
3. CA 根据可用的证书模板审核 CSR，并依据模板权限签发证书。
4. 请求获批后，CA 使用其私钥签署证书并将其返回给客户端。<sup>[[4]](#references)</sup>

### Certificate Templates

这些模板在 AD 中定义，规定签发证书的设置和权限，包括允许的 EKUs 以及 enrollment 或修改权限，对于管理证书服务的访问至关重要。<sup>[[4]](#references)</sup>

**模板架构版本很重要。** 旧版 **v1** 模板（例如内置的 **WebServer** 模板）缺少若干现代强制执行选项。**ESC15/EKUwu** 研究显示，在 **v1 模板**上，请求者可以在 CSR 中嵌入 **Application Policies/EKUs**，且这些设置的优先级**高于**模板中配置的 EKUs，因此仅凭 enrollment 权限即可获得 client-auth、enrollment agent 或代码签名证书。建议优先使用 **v2/v3 模板**，移除或替换 v1 默认模板，并严格限制 EKUs，使其仅适用于预期用途。<sup>[[1]](#references)</sup>

## Certificate Enrollment

证书 enrollment 流程由管理员发起，管理员先**创建证书模板**，再由 Enterprise Certificate Authority (CA) **发布**该模板。发布后，客户端即可使用该模板申请证书；具体做法是将模板名称添加到 Active Directory 对象的 `certificatetemplates` 字段中。<sup>[[4]](#references)</sup>

客户端要申请证书，必须获得 **enrollment rights**。这些权限由证书模板本身和 Enterprise CA 的安全描述符定义。必须在这两个位置都授予权限，请求才能成功。

### Template Enrollment Rights

这些权限通过 Access Control Entries (ACEs) 指定，用于详细说明以下权限：

- **Certificate-Enrollment** 和 **Certificate-AutoEnrollment** 权限，各自对应特定的 GUID。
- **ExtendedRights**，允许使用所有扩展权限。
- **FullControl/GenericAll**，提供对模板的完全控制权。

### Enterprise CA Enrollment Rights

CA 的权限由其安全描述符规定，可通过 Certificate Authority 管理控制台访问。某些设置甚至允许低权限用户进行远程访问，这可能构成安全隐患。

### Additional Issuance Controls

还可能应用一些控制措施，例如：

- **Manager Approval**：将请求置于待处理状态，直到证书管理者批准。
- **Enrolment Agents and Authorized Signatures**：指定 CSR 所需的签名数量以及必要的 Application Policy OIDs。

### Methods to Request Certificates

可以通过以下方式申请证书：

1. 使用 DCOM 接口的 **Windows Client Certificate Enrollment Protocol** (MS-WCCE)。
2. 通过命名管道或 TCP/IP 使用 **ICertPassage Remote Protocol** (MS-ICPR)。
3. 使用已安装 Certificate Authority Web Enrollment 角色的 **certificate enrollment web interface**。
4. 配合 Certificate Enrollment Policy (CEP) 服务使用 **Certificate Enrollment Service** (CES)。
5. 网络设备可通过 **Network Device Enrollment Service** (NDES) 使用 Simple Certificate Enrollment Protocol (SCEP)。

Windows 用户也可以通过 GUI（`certmgr.msc` 或 `certlm.msc`）或命令行工具（`certreq.exe` 或 PowerShell 的 `Get-Certificate` 命令）申请证书。

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## 证书身份验证

Active Directory (AD) 支持证书身份验证，主要使用 **Kerberos** 和 **Secure Channel (Schannel)** 协议。

### Kerberos 身份验证流程

在 Kerberos 身份验证流程中，用户请求 Ticket Granting Ticket (TGT) 时，会使用用户证书的 **private key** 对请求进行签名。域控制器会对该请求进行多项验证，包括证书的 **有效性**、**路径**和**吊销状态**。验证还包括确认证书来自可信来源，并确认颁发者存在于 **NTAUTH 证书存储**中。验证成功后，将颁发 TGT。AD 中的 **`NTAuthCertificates`** 对象位于：

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

是建立证书身份验证信任的关键。<sup>[[4]](#references)</sup>

自 **KB5014754** 推出以来，现代 Kerberos 证书身份验证主要关注**映射强度**，而不仅仅是 EKU。<sup>[[2]](#references)</sup> 在经过强化的林中：

- 仅包含 **UPN/DNS SAN** 的证书可能不再足以用于登录。
- KDC 更倾向于使用**强绑定**，通常是 **SID security extension** (`1.3.6.1.4.1.311.25.2`)，或在 `altSecurityIdentities` 中配置的强显式映射。
- 如果证书缺少强映射，DC 会在兼容模式下记录 **Kdcsvc Event ID 39/41**，并在强制模式下拒绝身份验证。
- 在混合攻击路径中，**ESC9/ESC16** 很重要，因为它们会从签发的证书中移除 SID extension；随后，攻击者会依赖显式映射，或在攻击路径支持时使用 SAN URL SID 格式。

### Secure Channel (Schannel) 身份验证

Schannel 用于建立安全的 TLS/SSL 连接。在握手期间，客户端会提供一个证书；如果验证成功，该证书便可授权访问。将证书映射到 AD 帐户时，可能会用到 Kerberos 的 **S4U2Self** 功能或证书的 **Subject Alternative Name (SAN)** 等方法。<sup>[[4]](#references)</sup>

当 **PKINIT** 不可用时，Schannel 也是实际可行的备用方案。例如，如果域控制器没有合适的 **Smart Card Logon** 证书，`certipy auth`/PKINIT 工具可能无法获取 TGT，但同一证书仍可用于通过 **LDAPS** 或 **LDAP StartTLS** 进行身份验证和 LDAP 操作。

### AD Certificate Services 枚举

可以通过 LDAP 查询枚举 AD 的证书服务，从而获取有关 **Enterprise Certificate Authorities (CAs)** 及其配置的信息。任何经过域身份验证的用户都可以访问这些信息，无需特殊权限。**[Certify](https://github.com/GhostPack/Certify)** 和 **[Certipy](https://github.com/ly4k/Certipy)** 等工具可用于 AD CS 环境中的枚举和漏洞评估。

使用这些工具的命令包括：

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

| 年份 | ID / 名称 | 影响 | 关键要点 |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | 在 PKINIT 期间伪造机器帐户证书以实现*权限提升*。 | 修复已包含在 **2022 年 5 月 10 日**的安全更新中。审核和强映射控制通过 **KB5014754** 引入；环境现在应处于 *Full Enforcement* 模式。  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) 和 CES 角色中的*远程代码执行*。 | 公开 PoC 有限，但存在漏洞的 IIS 组件通常在内部网络中暴露。请安装 **2023 年 7 月** Patch Tuesday 更新。  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | 在 **v1 模板**上，具有注册权限的请求者可以在 CSR 中嵌入优先于模板 EKU 的 **Application Policies/EKUs**，从而生成客户端身份验证、注册代理或代码签名证书。 | 已于 **2024 年 11 月 12 日**修复。替换或取代 v1 模板（例如默认的 WebServer），将 EKU 限制为预期用途，并限制注册权限。 |

### Microsoft 加固时间线（KB5014754）

Microsoft 引入了分三个阶段的推出流程（Compatibility → Audit → Enforcement），以使 Kerberos 证书身份验证不再使用较弱的隐式映射。截至 **2025 年 2 月 11 日**，如果未设置 `StrongCertificateBindingEnforcement` 注册表值，域控制器会自动切换到 **Full Enforcement**。Microsoft 后来更新了时间线，允许在 **2025 年 9 月 9 日**安全更新之前回退到兼容模式。<sup>[[2]](#references)</sup> 管理员应：

1. 为所有 DC 和 AD CS 服务器安装补丁（2022 年 5 月或更新版本）。
2. 在 *Audit* 阶段监控 Event ID 39/41，查找较弱的映射。
3. 使用新的 **SID extension** 重新签发客户端身份验证证书，或在强制执行阶段阻止较弱映射之前配置强手动映射。

### 加固林环境中的操作人员须知

- 在 2025 年及之后的环境中，**仅有 ESC1/ESC6 已不足以说明全部情况**。如果请求另一个主体的证书，通常还需要强映射凭据，例如 SID extension 或显式映射。
- **ESC15 (EKUwu)** 在未修补的环境中最有价值，因为它可以通过注入 **Application Policies**，将无害的 **v1** 模板（如 **WebServer**）转换为可用于身份验证或注册代理的证书。Kerberos PKINIT 仍会评估 EKU，但 **LDAP Schannel** 也会遵循 Application Policies，因此基于 LDAP 的滥用仍然有效。<sup>[[1]](#references)</sup>
- **ESC16** 是适用于整个 CA 的设置：如果 CA 全局禁用 SID 安全扩展，除非攻击链通过其他受支持的格式注入 SID，否则所有签发的证书都会回退到较弱的映射行为。
- **ESC7 权限各不相同：** CA 上的 `ManageCA` 授权可以允许更改 `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) 等设置，而 `ManageCertificates` 控制请求审批。即使同时存在 Allow，对证书管理器权限的显式 Deny 也能阻止该审批路径；在组合使用设置和模板之前，应评估实际生效的 CA ACL。请参阅 [Microsoft 的 CA ACL 评估](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting)。

---

## 检测与加固改进

* **Defender for Identity AD CS sensor（2023-2024）** 现在会显示 ESC1-ESC8/ESC11 的安全态势评估，并生成实时警报，例如 *“向非 DC 签发域控制器证书”* (ESC8) 和 *“阻止使用任意 Application Policies 进行证书注册”* (ESC15)。请确保所有 AD CS 服务器都部署了 sensor，以利用这些检测功能。<sup>[[3]](#references)</sup>
* 在所有模板上禁用或严格限制 **“Supply in the request”** 选项；优先使用明确定义的 SAN/EKU 值。
* 除非绝对必要，否则从模板中移除 **Any Purpose** 或 **No EKU**（应对 ESC2 场景）。
* 对敏感模板（例如 WebServer / CodeSigning）要求**经理审批**或使用专用的 Enrollment Agent 工作流。
* 将 Web Enrollment (`certsrv`) 和 CES/NDES 端点限制在受信任网络内，或要求使用客户端证书进行身份验证。
* 强制执行 RPC 注册加密（`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`）以缓解 ESC11（RPC relay）。该标志**默认启用**，但常因旧版客户端而被禁用，从而再次带来 relay 风险。
* 保护**基于 IIS 的注册端点**（CES/Certsrv）：尽可能禁用 NTLM，或要求 HTTPS + Extended Protection，以阻止 ESC8 relay。

在运行 CA 的主机上评估 ESC11；该主机可能是域成员服务器，而不是域控制器。读取活动 CA 在 `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` 下的 `InterfaceFlags`；如果无法读取该值或该值缺失，结果应视为未知，不能据此证明 RPC 加密已禁用。`IF_ENFORCEENCRYPTICERTREQUEST` 位未设置是一个配置线索，但仍需确认存在可访问的注册 RPC 端点、可被强制认证的凭据，以及可用的证书模板。对于 ESC8，仅有 HTTP NTLM challenge 并不足够：请确认存在可正常工作的注册端点。

---

## References

- [1] [EKUwu：不只是另一个 AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754：Windows 域控制器上的基于证书的身份验证变更](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [证书安全态势评估 - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned：滥用 Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
