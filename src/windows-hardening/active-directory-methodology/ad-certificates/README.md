# AD 证书

{{#include ../../../banners/hacktricks-training.md}}

## 介绍

### 证书的组成部分

- 证书的 **Subject** 表示其所有者。
- **Public Key** 与一个私有的密钥配对，以将证书与其合法所有者关联起来。
- **Validity Period**（由 **NotBefore** 和 **NotAfter** 日期定义）标示证书的有效期间。
- 一个唯一的 **Serial Number**，由 Certificate Authority (CA) 提供，用于标识每个证书。
- **Issuer** 指的是签发该证书的 CA。
- **SubjectAlternativeName** 允许为 Subject 指定额外的名称，以增强识别灵活性。
- **Basic Constraints** 标识证书是用于 CA 还是终端实体，并定义使用限制。
- **Extended Key Usages (EKUs)** 通过 Object Identifiers (OIDs) 划定证书的特定用途，例如代码签名或邮件加密。
- **Signature Algorithm** 指定签署证书的方法。
- **Signature** 使用颁发者的私钥创建，以保证证书的真实性。

### 特别注意事项

- **Subject Alternative Names (SANs)** 将证书的适用性扩展到多个身份，对于托管多个域名的服务器尤为重要。必须确保安全的签发流程，以避免攻击者通过操纵 SAN 规范进行冒充的风险。

### Active Directory (AD) 中的 Certificate Authorities (CAs)

AD CS 在 AD 林中通过指定的容器认可 CA 证书，每个容器承担不同的角色：

- **Certification Authorities** 容器保存受信任的根 CA 证书。
- **Enrolment Services** 容器列出 Enterprise CAs 及其证书模板。
- **NTAuthCertificates** 对象包含被授权用于 AD 身份验证的 CA 证书。
- **AIA (Authority Information Access)** 容器通过中间 CA 和跨域 CA 证书来支持证书链验证。

### 证书获取：客户端证书请求流程

1. 请求流程始于客户端查找一个 Enterprise CA。
2. 在生成公私钥对后，会创建一个 CSR（包含公钥和其他信息）。
3. CA 根据可用的证书模板评估 CSR，并基于模板的权限决定是否签发证书。
4. 经批准后，CA 使用其私钥对证书签名并将其返回给客户端。

### 证书模板

这些模板在 AD 中定义，概述了颁发证书的设置和权限，包括允许的 EKU 以及注册或修改权限，对管理对证书服务的访问至关重要。

## 证书注册

证书的注册流程由管理员启动，管理员 **creates a certificate template**，然后由 Enterprise Certificate Authority (CA) 将其 **published**。这使模板可供客户端申请，方法是将模板名称添加到 Active Directory 对象的 `certificatetemplates` 字段中。

为了使客户端能够请求证书，必须授予其 **enrollment rights**。这些权限由证书模板和 Enterprise CA 本身上的安全描述符定义。请求要成功，必须在两个位置都授予相应权限。

### 模板注册权限

这些权限通过 Access Control Entries (ACEs) 指定，描述了诸如：

- **Certificate-Enrollment** 和 **Certificate-AutoEnrollment** 权限，每个都关联特定的 GUID。
- **ExtendedRights**，允许所有扩展权限。
- **FullControl/GenericAll**，赋予对模板的完全控制。

### Enterprise CA 注册权限

CA 的权限在其安全描述符中定义，可通过 Certificate Authority 管理控制台查看。一些设置甚至允许低权限用户进行远程访问，这可能构成安全隐患。

### 额外颁发控制

可能适用的某些控制包括：

- **Manager Approval**：将请求置于挂起状态，直到证书管理员批准。
- **Enrolment Agents and Authorized Signatures**：指定 CSR 所需的签名数量及必要的 Application Policy OIDs。

### 请求证书的方法

可以通过以下方式请求证书：

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)，使用 DCOM 接口。
2. **ICertPassage Remote Protocol** (MS-ICPR)，通过命名管道或 TCP/IP。
3. 通过安装了 Certificate Authority Web Enrollment role 的 **certificate enrollment web interface**。
4. **Certificate Enrollment Service** (CES)，配合 Certificate Enrollment Policy (CEP) 服务使用。
5. 用于网络设备的 **Network Device Enrollment Service** (NDES)，使用 Simple Certificate Enrollment Protocol (SCEP)。

Windows 用户还可以通过 GUI（`certmgr.msc` 或 `certlm.msc`）或命令行工具（`certreq.exe` 或 PowerShell 的 `Get-Certificate` 命令）请求证书。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 证书认证

Active Directory (AD) 支持证书认证，主要使用 **Kerberos** 和 **Secure Channel (Schannel)** 协议。

### Kerberos 认证流程

在 Kerberos 认证流程中，用户请求 Ticket Granting Ticket (TGT) 时，该请求由用户证书的 **私钥** 签名。该请求会被域控制器进行多项校验，包括证书的 **有效性**、**路径** 和 **吊销状态**。校验还包括确认证书来源是否受信任，以及确认证书颁发者是否存在于 **NTAUTH 证书存储** 中。校验通过后会颁发 TGT。AD 中的 **`NTAuthCertificates`** 对象，位于：
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
是建立证书认证信任的核心。

### Secure Channel (Schannel) Authentication

Schannel 促进安全的 TLS/SSL 连接，在握手期间，客户端会出示一个证书；如果该证书被成功验证，则授权访问。证书与 AD 帐户的映射可能涉及 Kerberos 的 **S4U2Self** 功能，或证书的 **Subject Alternative Name (SAN)**，以及其他方法。

### AD Certificate Services Enumeration

AD 的证书服务可以通过 LDAP 查询进行枚举，揭示有关 **Enterprise Certificate Authorities (CAs)** 及其配置的信息。任何经过域身份验证的用户都可以访问这些信息，无需特殊权限。像 **[Certify](https://github.com/GhostPack/Certify)** 和 **[Certipy](https://github.com/ly4k/Certipy)** 这样的工具用于在 AD CS 环境中进行枚举和漏洞评估。

Commands for using these tools include:
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
## 参考资料

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
