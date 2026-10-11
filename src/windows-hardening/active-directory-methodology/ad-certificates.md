# AD 证书

{{#include ../../banners/hacktricks-training.md}}

## 简介

### 证书组件

- 证书的 **Subject** 表示其所有者。
- **Public Key** 与由所有者私下持有的密钥配对，用于将证书关联到其合法所有者。
- 由 **NotBefore** 和 **NotAfter** 日期定义的 **Validity Period**，标示证书的有效期限。
- 由证书颁发机构 (CA) 提供的唯一 **Serial Number**，用于识别每张证书。
- **Issuer** 指颁发证书的 CA。
- **SubjectAlternativeName** 允许为 Subject 添加其他名称，提高身份识别的灵活性。
- **Basic Constraints** 用于标明证书属于 CA 还是终端实体，并定义使用限制。
- **Extended Key Usages (EKUs)** 通过对象标识符 (OIDs) 指定证书的用途，例如代码签名或电子邮件加密。
- **Signature Algorithm** 指定证书的签名方法。
- 使用颁发者的私钥创建的 **Signature** 可保证证书的真实性。<sup>[[4]](#references)</sup>

### 特别注意事项

- **Subject Alternative Names (SANs)** 扩展了证书可适用的身份范围，对于拥有多个域名的服务器至关重要。安全的颁发流程十分重要，可避免攻击者操纵 SAN 规范来冒充他人。<sup>[[4]](#references)</sup>

### Active Directory (AD) 中的证书颁发机构 (CAs)

AD CS 通过指定的容器识别 AD 林中的 CA 证书，每个容器都有其独特用途：<sup>[[4]](#references)</sup>

- **Certification Authorities** 容器存放受信任的根 CA 证书。
- **Enrolment Services** 容器列出 Enterprise CAs 及其证书模板。
- **NTAuthCertificates** 对象包含获准用于 AD 身份验证的 CA 证书。
- **AIA (Authority Information Access)** 容器提供中间 CA 和交叉 CA 证书，用于验证证书链。

### 证书获取：客户端证书请求流程

1. 请求流程从客户端查找 Enterprise CA 开始。
2. 生成公私钥对后，创建包含公钥及其他信息的 CSR。
3. CA 根据可用证书模板审核 CSR，并依据模板权限颁发证书。
4. 请求获批后，CA 使用其私钥为证书签名，再将证书返回给客户端。<sup>[[4]](#references)</sup>

### 证书模板

这些模板在 AD 中定义，列明颁发证书的设置和权限，包括允许的 EKUs，以及注册或修改权限；它们对于管理证书服务的访问至关重要。<sup>[[4]](#references)</sup>

**模板架构版本很重要。** 旧版 **v1** 模板（例如内置的 **WebServer** 模板）缺少一些现代强制实施选项。**ESC15/EKUwu** 研究表明，对于 **v1 模板**，请求者可以在 CSR 中嵌入 **Application Policies/EKUs**，且这些内容的优先级**高于**模板配置的 EKUs，因此仅凭注册权限就能获取客户端身份验证、注册代理或代码签名证书。建议使用 **v2/v3 模板**，移除或替换默认的 v1 模板，并严格限定 EKUs 的用途。<sup>[[1]](#references)</sup>

## 证书注册

证书注册流程由管理员启动：管理员先**创建证书模板**，再由 Enterprise Certificate Authority (CA) **发布该模板**。这样客户端便可使用该模板申请证书；具体做法是将模板名称添加到 Active Directory 对象的 `certificatetemplates` 字段中。<sup>[[4]](#references)</sup>

客户端要申请证书，必须拥有**注册权限**。这些权限由证书模板本身及 Enterprise CA 上的安全描述符定义。请求要成功，必须在这两个位置都授予相应权限。

### 模板注册权限

这些权限通过访问控制项 (ACEs) 指定，包括：

- **Certificate-Enrollment** 和 **Certificate-AutoEnrollment** 权限，各自关联特定 GUID。
- **ExtendedRights**，允许使用所有扩展权限。
- **FullControl/GenericAll**，提供对模板的完全控制权。

### Enterprise CA 注册权限

CA 的权限在其安全描述符中列出，可通过 Certificate Authority 管理控制台查看。某些设置甚至允许低权限用户远程访问，这可能构成安全隐患。

### 其他颁发控制

可能适用的控制包括：

- **Manager Approval**：将请求置于待处理状态，直至证书管理员批准。
- **Enrolment Agents and Authorized Signatures**：指定 CSR 所需的签名数量，以及必需的 Application Policy OIDs。

### 证书申请方式

可以通过以下方式申请证书：

1. 使用 DCOM 接口的 **Windows Client Certificate Enrollment Protocol** (MS-WCCE)。
2. 通过命名管道或 TCP/IP 使用 **ICertPassage Remote Protocol** (MS-ICPR)。
3. 安装 Certificate Authority Web Enrollment 角色后，通过**证书注册 Web 界面**申请。
4. 配合 Certificate Enrollment Policy (CEP) 服务使用 **Certificate Enrollment Service** (CES)。
5. 网络设备可通过 **Network Device Enrollment Service** (NDES) 使用 Simple Certificate Enrollment Protocol (SCEP) 申请。

Windows 用户也可以通过 GUI（`certmgr.msc` 或 `certlm.msc`）或命令行工具（`certreq.exe` 或 PowerShell 的 `Get-Certificate` 命令）申请证书。

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Certificate Authentication

Active Directory (AD) 支持证书身份验证，主要使用 **Kerberos** 和 **Secure Channel (Schannel)** 协议。

### Kerberos Authentication Process

在 Kerberos 身份验证过程中，用户请求 Ticket Granting Ticket (TGT) 时，会使用用户证书的 **私钥** 对请求进行签名。域控制器会对该请求进行多项验证，包括证书的**有效性**、**证书链**和**吊销状态**。验证还包括确认该证书来自受信任的来源，并确认颁发者存在于 **NTAUTH certificate store** 中。验证成功后，系统会颁发 TGT。AD 中的 **`NTAuthCertificates`** 对象位于：

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

是建立证书身份验证信任的核心。<sup>[[4]](#references)</sup>

自 **KB5014754** 部署以来，现代 Kerberos 证书身份验证主要取决于**映射强度**，而不仅仅是 EKU。<sup>[[2]](#references)</sup> 在强化后的 forest 中：

- 仅包含 **UPN/DNS SAN** 的证书可能不再足以用于登录。
- KDC 更倾向于使用**强绑定**，通常是 **SID security extension** (`1.3.6.1.4.1.311.25.2`)，或 `altSecurityIdentities` 中的强显式映射。
- 如果证书缺少强映射，DC 会在兼容模式下记录 **Kdcsvc Event ID 39/41**，并在强制模式下拒绝身份验证。
- 在混合攻击路径中，**ESC9/ESC16** 很重要，因为它们会从签发的证书中移除 SID extension；之后，操作人员会依赖显式映射，或在攻击路径支持的情况下使用 SAN URL SID 格式。

### Secure Channel (Schannel) 身份验证

Schannel 用于建立安全的 TLS/SSL 连接。在握手期间，客户端会出示证书；如果证书验证成功，即可获得访问权限。将证书映射到 AD 账户可能会用到 Kerberos 的 **S4U2Self** 功能或证书的 **Subject Alternative Name (SAN)** 等方法。<sup>[[4]](#references)</sup>

当 **PKINIT** 不可用时，Schannel 也是实际可行的备用方式。例如，如果域控制器没有合适的 **Smart Card Logon** 证书，`certipy auth`/PKINIT 工具可能无法获取 TGT，但同一证书仍可用于 **LDAPS** 或 **LDAP StartTLS** 身份验证和 LDAP 操作。

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
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | 在 PKINIT 期间伪造机器账户证书，实现*权限提升*。 | 已在 **2022 年 5 月 10 日**安全更新中修复。通过 **KB5014754** 引入了审计和强映射控制；目前环境应处于 *Full Enforcement* 模式。  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment（certsrv）和 CES 角色中的*远程代码执行*漏洞。 | 公开 PoC 有限，但存在漏洞的 IIS 组件经常暴露在内部网络中。请安装 **2023 年 7 月** Patch Tuesday 更新进行修复。  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | 对于 **v1 模板**，具有注册权限的请求者可以在 CSR 中嵌入优先于模板 EKU 的 **Application Policies/EKU**，从而生成客户端身份验证、注册代理或代码签名证书。 | 已于 **2024 年 11 月 12 日**修复。替换或取代 v1 模板（例如默认的 WebServer），将 EKU 限定为预期用途，并限制注册权限。 |

### Microsoft 加固时间线（KB5014754）

Microsoft 引入了分三个阶段的部署流程（Compatibility → Audit → Enforcement），以使 Kerberos 证书身份验证不再依赖较弱的隐式映射。截至 **2025 年 2 月 11 日**，如果未设置 `StrongCertificateBindingEnforcement` 注册表值，域控制器会自动切换到 **Full Enforcement**。Microsoft 后来更新了时间线，允许在 **2025 年 9 月 9 日**安全更新之前回退到兼容模式。<sup>[[2]](#references)</sup> 管理员应：

1. 为所有 DC 和 AD CS 服务器安装补丁（2022 年 5 月或之后发布的补丁）。
2. 在 *Audit* 阶段监控 Event ID 39/41，以发现较弱的映射。
3. 使用新的 **SID 扩展**重新颁发客户端身份验证证书，或在强制执行阶段阻止弱映射之前配置强手动映射。

### 加固环境中的 Operator 注意事项

- 在 2025 年及之后的环境中，**仅有 ESC1/ESC6 已不足以涵盖所有情况**。如果为其他主体申请证书，通常还需要强映射凭据，例如 SID 扩展或显式映射。
- **ESC15（EKUwu）**在未修补的环境中最有价值，因为它可以通过注入 **Application Policies**，将无害的 **v1** 模板（例如 **WebServer**）变为可用于身份验证或注册代理的证书。Kerberos PKINIT 仍会检查 EKU，但 **LDAP Schannel** 也会认可 Application Policies，因此基于 LDAP 的滥用仍然可行。<sup>[[1]](#references)</sup>
- **ESC16** 是 CA 级别的设置：如果 CA 全局禁用 SID 安全扩展，除非攻击链通过其他受支持的格式注入 SID，否则所有颁发的证书都会退化为较弱的映射行为。
- **ESC7 权限各不相同：**CA 上的 `ManageCA` 授权可以允许更改 `EDITF_ATTRIBUTESUBJECTALTNAME2`（ESC6）等设置，而 `ManageCertificates` 控制请求审批。即使存在 Allow，针对证书管理器权限的显式 Deny 也能阻止该审批途径；在串联设置和模板之前，应评估 CA ACL 的有效权限。请参阅 [Microsoft 的 CA ACL 评估指南](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting)。

---

## 检测与加固改进

* **Defender for Identity AD CS sensor（2023-2024）**现在会显示针对 ESC1-ESC8/ESC11 的安全态势评估，并生成实时警报，例如*“向非 DC 颁发域控制器证书”*（ESC8）和*“阻止使用任意 Application Policies 注册证书”*（ESC15）。请确保在所有 AD CS 服务器上部署传感器，以利用这些检测功能。<sup>[[3]](#references)</sup>
* 在所有模板上禁用或严格限制 **“Supply in the request”** 选项；优先使用明确指定的 SAN/EKU 值。
* 除非确有必要，否则从模板中移除 **Any Purpose** 或 **No EKU**（应对 ESC2 场景）。
* 对敏感模板（例如 WebServer / CodeSigning）要求 **经理审批**，或使用专用的 Enrollment Agent 工作流。
* 将 Web Enrollment（`certsrv`）和 CES/NDES 端点限制在可信网络内，或要求通过客户端证书进行身份验证。
* 强制执行 RPC 注册加密（`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`），以缓解 ESC11（RPC relay）。该标志**默认启用**，但常因旧版客户端而被禁用，从而重新引入 relay 风险。
* 保护 **基于 IIS 的注册端点**（CES/Certsrv）：在可能的情况下禁用 NTLM，或要求使用 HTTPS + Extended Protection，以阻止 ESC8 relay。

在运行 CA 的主机上评估 ESC11；该主机可能是域成员服务器，而非域控制器。读取活动 CA 在 `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` 下的 `InterfaceFlags`；值不可读或缺失表示结果未知，并不能证明 RPC 加密已禁用。若 `IF_ENFORCEENCRYPTICERTREQUEST` 位未设置，这只是一个配置线索，仍需确认存在可访问的注册 RPC 端点、可被强制认证的凭据，以及可用的证书模板。对于 ESC8，仅有 HTTP NTLM challenge 并不足够：请确认存在可用的注册端点。

---

## References

- [1] [EKUwu：不只是另一个 AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754：Windows 域控制器上的基于证书的身份验证变更](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [证书安全态势评估 - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned：滥用 Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
