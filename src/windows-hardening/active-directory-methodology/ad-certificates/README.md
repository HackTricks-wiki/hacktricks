# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- 证书的 **Subject** 表示其所有者。
- **Public Key** 与私有密钥配对，用以将证书与其合法所有者关联。
- **Validity Period**（由 **NotBefore** 和 **NotAfter** 定义）标示证书的有效时段。
- 唯一的 **Serial Number**（由 Certificate Authority (CA) 提供）用于识别每个证书。
- **Issuer** 指发出证书的 CA。
- **SubjectAlternativeName** 允许为 Subject 指定额外名称，增强识别的灵活性。
- **Basic Constraints** 用于标识证书是 CA 证书还是终端实体证书，并定义使用限制。
- **Extended Key Usages (EKUs)** 通过对象标识符 (OIDs) 指明证书的具体用途，例如 code signing 或 email encryption。
- **Signature Algorithm** 指定用于签署证书的方法。
- 使用发行者的私钥创建的 **Signature** 保证了证书的真实性。

### Special Considerations

- **Subject Alternative Names (SANs)** 将证书的适用性扩展到多个身份，这对于拥有多个域名的服务器至关重要。必须有安全的签发流程，以防止攻击者通过操纵 SAN 规范进行冒充。

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS 通过指定的容器在 AD 林中识别 CA 证书，每个容器都有其特定作用：

- **Certification Authorities** 容器保存受信任的 root CA 证书。
- **Enrolment Services** 容器列出 Enterprise CAs 及其证书模板。
- **NTAuthCertificates** 对象包含被授权用于 AD 身份验证的 CA 证书。
- **AIA (Authority Information Access)** 容器用于通过中间 CA 和 cross CA 证书来验证证书链。

### Certificate Acquisition: Client Certificate Request Flow

1. 请求过程始于客户端查找 Enterprise CA。
2. 在生成公私钥对后，创建包含公钥和其他细节的 CSR。
3. CA 根据可用的 certificate templates 评估 CSR，并基于模板权限颁发证书。
4. 经批准后，CA 使用其私钥对证书进行签名并将其返回给客户端。

### Certificate Templates

在 AD 中定义的这些模板规定了颁发证书的设置和权限，包括允许的 EKUs 以及注册或修改权限，对于管理对证书服务的访问至关重要。

## Certificate Enrollment

证书的注册过程由管理员发起，管理员 **创建证书模板**，随后 Enterprise Certificate Authority (CA) **发布** 该模板。发布后，模板可供客户端注册，方法是将模板名称添加到 Active Directory 对象的 `certificatetemplates` 字段中。

要使客户端请求证书，必须授予 **enrollment rights**。这些权限由 certificate template 和 Enterprise CA 本身的安全描述符定义。请求成功需要在这两个位置都授予相应权限。

### Template Enrollment Rights

这些权限通过 Access Control Entries (ACEs) 指定，描述的权限包括：

- **Certificate-Enrollment** 和 **Certificate-AutoEnrollment** 权限，每个都关联特定的 GUID。
- **ExtendedRights**，允许所有扩展权限。
- **FullControl/GenericAll**，对模板提供完全控制。

### Enterprise CA Enrollment Rights

CA 的权限在其安全描述符中列出，可通过 Certificate Authority 管理控制台访问。有些设置甚至允许低权限用户进行远程访问，这可能是一个安全隐患。

### Additional Issuance Controls

可能会应用某些控制，例如：

- **Manager Approval**：将请求置于挂起状态，直到证书管理员批准。
- **Enrolment Agents and Authorized Signatures**：指定 CSR 所需的签名数量以及所需的 Application Policy OIDs。

### Methods to Request Certificates

可以通过以下方式请求证书：

1. 使用 DCOM 接口的 **Windows Client Certificate Enrollment Protocol** (MS-WCCE)。
2. 通过命名管道或 TCP/IP 使用 **ICertPassage Remote Protocol** (MS-ICPR)。
3. 安装 Certificate Authority Web Enrollment 角色后使用 **certificate enrollment web interface**。
4. 与 Certificate Enrollment Policy (CEP) 服务配合使用的 **Certificate Enrollment Service** (CES)。
5. 面向网络设备的 **Network Device Enrollment Service** (NDES)，使用 Simple Certificate Enrollment Protocol (SCEP)。

Windows 用户也可以通过 GUI（`certmgr.msc` 或 `certlm.msc`）或命令行工具（`certreq.exe` 或 PowerShell 的 `Get-Certificate` 命令）请求证书。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) 支持证书认证，主要使用 **Kerberos** 和 **Secure Channel (Schannel)** 协议。

### Kerberos Authentication Process

在 Kerberos 认证流程中，用户请求 Ticket Granting Ticket (TGT) 时，该请求会使用用户证书的 **私钥** 进行签名。域控制器会对该请求执行多项验证，包括证书的 **有效性**、**路径** 和 **吊销状态**。验证还包括确认证书来自受信任的来源，并确认颁发者是否存在于 **NTAUTH 证书存储**。验证通过后会签发 TGT。AD 中的 **`NTAuthCertificates`** 对象位于：
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
对于建立证书认证的信任至关重要。

### 安全通道 (Schannel) 认证

Schannel 协助建立安全的 TLS/SSL 连接，在握手过程中，客户端会出示证书；如果证书验证成功，则授予访问权限。将证书映射到 AD 帐户可能涉及 Kerberos 的 **S4U2Self** 功能或证书的 **Subject Alternative Name (SAN)**，以及其他方法。

### AD 证书服务枚举

可以通过 LDAP 查询来枚举 AD 的证书服务，从而揭示 **Enterprise Certificate Authorities (CAs)** 及其配置的信息。任何经过域认证的用户都可以访问这些信息，无需特殊权限。像 **[Certify](https://github.com/GhostPack/Certify)** 和 **[Certipy](https://github.com/ly4k/Certipy)** 这样的工具用于在 AD CS 环境中进行枚举和漏洞评估。

用于使用这些工具的命令包括：
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
