# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Certificate 的组件

- certificate 的 **Subject** 表示其所有者。
- **Public Key** 会与一个私钥配对，用于将 certificate 绑定到其合法所有者。
- **Validity Period**，由 **NotBefore** 和 **NotAfter** 日期定义，表示 certificate 的生效期限。
- 由 Certificate Authority (CA) 提供的唯一 **Serial Number** 用于标识每个 certificate。
- **Issuer** 指的是签发该 certificate 的 CA。
- **SubjectAlternativeName** 允许为 subject 添加额外名称，提升识别灵活性。
- **Basic Constraints** 指示 certificate 是用于 CA 还是用于终端实体，并定义使用限制。
- **Extended Key Usages (EKUs)** 通过 Object Identifiers (OIDs) 说明 certificate 的具体用途，例如 code signing 或 email encryption。
- **Signature Algorithm** 指定签署 certificate 的方法。
- 由 issuer 的私钥创建的 **Signature** 保证 certificate 的真实性。

### Special Considerations

- **Subject Alternative Names (SANs)** 扩展了 certificate 对多个身份的适用性，这对拥有多个域的服务器至关重要。安全的签发流程非常关键，以避免 attacker 通过操纵 SAN 规范进行冒充风险。

### Active Directory (AD) 中的 Certificate Authorities (CAs)

AD CS 会通过指定的容器在 AD forest 中识别 CA certificates，每个容器承担不同角色：

- **Certification Authorities** 容器保存受信任的根 CA certificates。
- **Enrolment Services** 容器包含 Enterprise CAs 及其 certificate templates 的详细信息。
- **NTAuthCertificates** 对象包含被授权用于 AD authentication 的 CA certificates。
- **AIA (Authority Information Access)** 容器通过中间 CA 和 cross CA certificates 促进 certificate chain validation。

### Certificate Acquisition: Client Certificate Request Flow

1. 请求流程从 clients 找到一个 Enterprise CA 开始。
2. 在生成 public-private key pair 后，会创建一个 CSR，其中包含 public key 和其他细节。
3. CA 根据可用的 certificate templates 评估 CSR，并依据 template 的 permissions 签发 certificate。
4. 在批准后，CA 使用其私钥对 certificate 签名并将其返回给 client。

### Certificate Templates

这些 templates 定义在 AD 中，概述了 certificate 签发的设置和权限，包括允许的 EKUs 以及 enrollment 或修改权限，这对管理对 certificate services 的访问至关重要。

**Template schema version 很重要。** 旧版 **v1** templates（例如内置的 **WebServer** template）缺少若干现代 enforcement knobs。**ESC15/EKUwu** 研究表明，在 **v1 templates** 上，请求者可以在 CSR 中嵌入 **Application Policies/EKUs**，并且这些内容会**优先于** template 中配置的 EKUs，从而仅凭 enrollment rights 就能获得 client-auth、enrollment agent 或 code-signing certificates。应优先使用 **v2/v3 templates**，移除或替换 v1 默认项，并将 EKUs 严格限定为预期用途。

## Certificate Enrollment

certificate 的 enrollment 流程由管理员发起，管理员会**创建一个 certificate template**，随后由 Enterprise Certificate Authority (CA) 将其**发布**。这样该 template 就可供 client enrollment 使用，这一步是通过将 template 的名称添加到 Active Directory 对象的 `certificatetemplates` 字段来实现的。

要让 client 请求 certificate，必须授予**enrollment rights**。这些权限由 certificate template 和 Enterprise CA 本身上的 security descriptor 定义。只有在两个位置都授予权限，请求才能成功。

### Template Enrollment Rights

这些权限通过 Access Control Entries (ACEs) 指定，描述诸如以下权限：

- **Certificate-Enrollment** 和 **Certificate-AutoEnrollment** 权限，各自关联特定的 GUIDs。
- **ExtendedRights**，允许所有扩展权限。
- **FullControl/GenericAll**，对 template 提供完全控制。

### Enterprise CA Enrollment Rights

CA 的权限由其 security descriptor 规定，可通过 Certificate Authority 管理控制台访问。某些设置甚至允许低权限用户远程访问，这可能带来安全隐患。

### Additional Issuance Controls

某些控制可能会适用，例如：

- **Manager Approval**：将请求置于 pending 状态，直到 certificate manager 批准。
- **Enrolment Agents and Authorized Signatures**：指定 CSR 所需签名数量以及必要的 Application Policy OIDs。

### Methods to Request Certificates

可以通过以下方式请求 certificates：

1. 使用 **Windows Client Certificate Enrollment Protocol** (MS-WCCE)，通过 DCOM interfaces。
2. 使用 **ICertPassage Remote Protocol** (MS-ICPR)，通过 named pipes 或 TCP/IP。
3. 使用 **certificate enrollment web interface**，前提是安装了 Certificate Authority Web Enrollment 角色。
4. 使用 **Certificate Enrollment Service** (CES)，配合 Certificate Enrollment Policy (CEP) service。
5. 使用 **Network Device Enrollment Service** (NDES) 为 network devices 请求，使用 Simple Certificate Enrollment Protocol (SCEP)。

Windows users 也可以通过 GUI（`certmgr.msc` 或 `certlm.msc`）或命令行工具（`certreq.exe` 或 PowerShell 的 `Get-Certificate` 命令）请求 certificates。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 证书认证

Active Directory (AD) 支持证书认证，主要使用 **Kerberos** 和 **Secure Channel (Schannel)** 协议。

### Kerberos 认证流程

在 Kerberos 认证流程中，用户请求 Ticket Granting Ticket (TGT) 时，会使用用户证书的 **private key** 对请求进行签名。该请求会经过域控制器的多项验证，包括证书的 **validity**、**path** 和 **revocation status**。验证还包括确认证书来自受信任的来源，并确认签发者存在于 **NTAUTH certificate store** 中。验证成功后会签发 TGT。AD 中的 **`NTAuthCertificates`** 对象，位于：
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
是建立 certificate authentication 信任的核心。

自 **KB5014754** rollout 之后，现代 Kerberos certificate auth 主要关注的是 **mapping strength**，而不只是 EKUs。在 hardened forests 中：

- 只带有 **UPN/DNS SAN** 的 certificate 可能已不足以用于 logon。
- KDC 更倾向于 **strong binding**，通常是 **SID security extension** (`1.3.6.1.4.1.311.25.2`) 或 `altSecurityIdentities` 中的强显式映射。
- 如果 cert 缺少 strong mapping，DC 会在 compatibility mode 下记录 **Kdcsvc Event ID 39/41**，并在 enforcement mode 下拒绝 auth。
- 在混合 attack paths 中，**ESC9/ESC16** 很重要，因为它们会从已签发的 cert 中去除 SID extension；之后 operator 只能依赖显式映射，或在 attack path 支持时使用 SAN URL SID 格式。

### Secure Channel (Schannel) Authentication

Schannel 负责安全的 TLS/SSL connections；在 handshake 期间，client 会提交一个 certificate，若验证成功，即被授权访问。certificate 到 AD account 的 mapping 可能涉及 Kerberos 的 **S4U2Self** 功能，或 certificate 的 **Subject Alternative Name (SAN)**，以及其他方法。

当 **PKINIT** 不可用时，Schannel 也是实际可用的 fallback。比如，如果 domain controller 没有合适的 **Smart Card Logon** certificate，`certipy auth`/PKINIT tooling 可能无法获取 TGT，但同一个 certificate 仍可用于 **LDAPS** 或 **LDAP StartTLS** 的 authentication 和 LDAP operations。

### AD Certificate Services Enumeration

可以通过 LDAP queries 枚举 AD 的 certificate services，从而获取 **Enterprise Certificate Authorities (CAs)** 及其配置的信息。任何通过 domain authentication 的用户都可以访问这些信息，不需要特殊权限。像 **[Certify](https://github.com/GhostPack/Certify)** 和 **[Certipy](https://github.com/ly4k/Certipy)** 这类 tools 常用于 AD CS 环境中的枚举与 vulnerability assessment。

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

## 最近的漏洞与安全更新 (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | 通过在 PKINIT 期间伪造 machine account certificates 实现 *Privilege escalation*。 | 补丁包含在 **2022年5月10日** 的安全更新中。通过 **KB5014754** 引入了审计与 strong-mapping 控制；环境现在应处于 *Full Enforcement* 模式。 |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) 和 CES roles 中的 *Remote code-execution*。 | 公开 PoC 有限，但易受攻击的 IIS 组件通常在内部暴露。补丁截至 **2023年7月** Patch Tuesday。 |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | 在 **v1 templates** 上，具有 enrollment rights 的请求者可以在 CSR 中嵌入 **Application Policies/EKUs**，其优先于 template EKUs，从而生成 client-auth、enrollment agent 或 code-signing certificates。 | 截至 **2024年11月12日** 已修补。替换或淘汰 v1 templates（例如默认的 WebServer），将 EKUs 限制为预期用途，并限制 enrollment rights。 |

### Microsoft hardening timeline (KB5014754)

Microsoft 引入了三阶段 rollout（Compatibility → Audit → Enforcement），以将 Kerberos certificate authentication 迁移 away from weak implicit mappings。截止 **2025年2月11日**，如果未设置 `StrongCertificateBindingEnforcement` registry value，domain controllers 会自动切换到 **Full Enforcement**。Microsoft 之后更新了 timeline，因此在 **2025年9月9日** 的安全更新之前，仍然可以回退到 compatibility mode。管理员应当：

1. Patch 所有 DCs 和 AD CS servers（2022年5月或之后）。
2. 在 *Audit* 阶段监控 Event ID 39/41，查找 weak mappings。
3. 在 enforcement 阻止 weak mappings 之前，重新签发带有新的 **SID extension** 的 client-auth certificates，或配置 strong manual mappings。

### 加固 forests 的操作备注

- 到 2025+ 环境中，**仅 ESC1/ESC6 已不再是全部问题**。如果你为另一个 principal 请求 cert，通常还需要一个 strong mapping artifact，例如 SID extension 或显式 mapping。
- **ESC15 (EKUwu)** 在未修补环境中最有价值，因为它会通过注入 **Application Policies**，把像 **WebServer** 这样的无害 **v1** templates 变成具备 authentication- 或 enrollment-agent 能力的 certs。Kerberos PKINIT 仍然会评估 EKUs，但 **LDAP Schannel** 也会遵循 Application Policies，因此基于 LDAP 的 abuse 仍然相关。
- **ESC16** 是一个 CA-wide knob：如果 CA 全局禁用 SID security extension，那么每个签发的 certificate 都会回退到更弱的 mapping 行为，除非 attack chain 通过其他受支持的格式注入 SID。

---

## 检测与加固增强

* **Defender for Identity AD CS sensor (2023-2024)** 现在会展示 ESC1-ESC8/ESC11 的 posture assessments，并生成实时告警，例如 *“Domain-controller certificate issuance for a non-DC”* (ESC8) 和 *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15)。请确保将 sensors 部署到所有 AD CS servers，以便获得这些检测能力。
* 在所有 templates 上禁用或严格限定 **“Supply in the request”** 选项；优先使用显式定义的 SAN/EKU 值。
* 除非绝对必要，否则从 templates 中移除 **Any Purpose** 或 **No EKU**（解决 ESC2 场景）。
* 对敏感 templates（例如 WebServer / CodeSigning）要求 **manager approval** 或专门的 Enrollment Agent workflows。
* 将 web enrollment (`certsrv`) 和 CES/NDES endpoints 限制为受信任网络，或放在 client-certificate authentication 之后。
* 强制 RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) 以缓解 ESC11 (RPC relay)。该标志默认是 **on**，但经常为了兼容 legacy clients 而被关闭，这会重新开启 relay 风险。
* 保护基于 **IIS** 的 enrollment endpoints（CES/Certsrv）：尽可能禁用 NTLM，或要求 HTTPS + Extended Protection 以阻止 ESC8 relays。

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
