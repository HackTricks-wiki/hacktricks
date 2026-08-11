# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### 证书的组成部分

- 证书的 **Subject** 表示其所有者。
- **Public Key** 与私有持有的密钥配对，用于将证书关联到其合法所有者。
- 由 **NotBefore** 和 **NotAfter** 日期定义的 **Validity Period** 标示证书的有效期限。
- 由 Certificate Authority (CA) 提供的唯一 **Serial Number** 用于标识每张证书。
- **Issuer** 指签发证书的 CA。
- **SubjectAlternativeName** 允许为主体指定其他名称，从而提高身份标识的灵活性。
- **Basic Constraints** 用于标识证书属于 CA 还是终端实体，并定义使用限制。
- **Extended Key Usages (EKUs)** 通过 Object Identifiers (OIDs) 划定证书的具体用途，例如代码签名或电子邮件加密。
- **Signature Algorithm** 指定证书的签名方法。
- 使用签发者的私钥创建的 **Signature** 可确保证书的真实性。<sup>[[1]](#references)</sup>

### 特别注意事项

- **Subject Alternative Names (SANs)** 将证书的适用范围扩展到多个身份，这对于拥有多个域名的服务器至关重要。必须采用安全的签发流程，以避免攻击者操纵 SAN 规范而造成冒充风险。<sup>[[1]](#references)</sup>

### Active Directory (AD) 中的 Certificate Authorities (CAs)

AD CS 通过指定的容器识别 AD forest 中的 CA 证书，每个容器承担独特的作用：<sup>[[1]](#references)</sup>

- **Certification Authorities** 容器保存受信任的根 CA 证书。
- **Enrolment Services** 容器记录 Enterprise CAs 及其 certificate templates。
- **NTAuthCertificates** 对象包含获授权用于 AD 身份验证的 CA 证书。
- **AIA (Authority Information Access)** 容器通过 intermediate 和 cross CA 证书促进证书链验证。

### Certificate Acquisition: Client Certificate Request Flow

1. 请求流程从客户端查找 Enterprise CA 开始。
2. 生成公钥-私钥对后，创建包含公钥及其他详细信息的 CSR。
3. CA 根据可用的 certificate templates 评估 CSR，并依据模板权限签发证书。
4. 获得批准后，CA 使用其私钥对证书进行签名，并将其返回给客户端。<sup>[[1]](#references)</sup>

### Certificate Templates

这些模板在 AD 中定义，用于规定证书签发时的设置和权限，包括允许的 EKUs 以及 enrollment 或 modification 权限，对于管理对 certificate services 的访问至关重要。<sup>[[1]](#references)</sup>

## Certificate Enrollment

证书的 enrollment 流程由管理员启动，管理员首先 **creates a certificate template**，然后由 Enterprise Certificate Authority (CA) **publishes** 该模板。这样客户端即可进行 enrollment；具体实现方式是将模板名称添加到 Active Directory 对象的 `certificatetemplates` 字段中。<sup>[[1]](#references)</sup>

客户端要请求证书，必须授予 **enrollment rights**。这些权限由 certificate template 和 Enterprise CA 本身的 security descriptors 定义。必须在这两个位置都授予权限，请求才能成功。<sup>[[1]](#references)</sup>

### Template Enrollment Rights

这些权限通过 Access Control Entries (ACEs) 指定，用于详细说明以下权限：<sup>[[1]](#references)</sup>

- **Certificate-Enrollment** 和 **Certificate-AutoEnrollment** 权限，每项权限都与特定的 GUID 关联。
- **ExtendedRights**，允许所有 extended permissions。
- **FullControl/GenericAll**，提供对模板的完全控制权。

### Enterprise CA Enrollment Rights

CA 的权限在其 security descriptor 中定义，可通过 Certificate Authority management console 访问。其中一些设置甚至允许低权限用户进行远程访问，这可能带来安全风险。<sup>[[1]](#references)</sup>

### Additional Issuance Controls

某些 controls 可能适用，例如：<sup>[[1]](#references)</sup>

- **Manager Approval**：在 certificate manager 批准请求之前，将请求置于 pending 状态。
- **Enrolment Agents and Authorized Signatures**：指定 CSR 所需的签名数量以及必要的 Application Policy OIDs。

### Methods to Request Certificates

可以通过以下方式请求证书：<sup>[[1]](#references)</sup>

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
## 证书身份验证

Active Directory (AD) 支持证书身份验证，主要使用 **Kerberos** 和 **Secure Channel (Schannel)** 协议。<sup>[[1]](#references)</sup>

### Kerberos 身份验证过程

在 Kerberos 身份验证过程中，用户请求 Ticket Granting Ticket (TGT) 时，会使用用户证书的 **private key** 进行签名。该请求会由 domain controller 执行多项验证，包括证书的 **validity**、**path** 和 **revocation status**。验证还包括确认该证书来自受信任的来源，以及确认其颁发者存在于 **NTAUTH certificate store** 中。验证成功后，将签发 TGT。AD 中的 **`NTAuthCertificates`** 对象位于：
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
是建立 certificate authentication 信任的核心。<sup>[[1]](#references)</sup>

### Secure Channel (Schannel) Authentication

Schannel 用于建立安全的 TLS/SSL 连接。在握手期间，客户端会提供一个 certificate；如果该 certificate 成功通过验证，则会授予访问权限。<sup>[[2]](#references)</sup> 将 certificate 映射到 AD account 可能会涉及 Kerberos 的 **S4U2Self** function、certificate 的 **Subject Alternative Name (SAN)** 以及其他方法。<sup>[[1]](#references)</sup>

### AD Certificate Services Enumeration

可以通过 LDAP queries 枚举 AD 的 certificate services，从而获取有关 **Enterprise Certificate Authorities (CAs)** 及其配置的信息。任何经过 domain authentication 的 user 都可以访问此功能，无需特殊权限。<sup>[[1]](#references)</sup> **[Certify](https://github.com/GhostPack/Certify)** 和 **[Certipy](https://github.com/ly4k/Certipy)** 等 tools 可用于 AD CS environments 中的 enumeration 和 vulnerability assessment。<sup>[[3]](#references)</sup>

使用这些 tools 的 commands 包括：
```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
Rubeus 还可以使用受密码保护的 PFX 证书进行 PKINIT 身份验证并请求 TGT。可选的 `/getcredentials` switch 会请求 U2U service ticket，并尝试恢复账户 NT hash：<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned：滥用 Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [什么是 SSL/TLS 客户端身份验证？它是如何工作的？](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
