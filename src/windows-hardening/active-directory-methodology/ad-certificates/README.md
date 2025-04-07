# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

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

- **主题备用名称（SANs）**扩展证书的适用性到多个身份，对于具有多个域的服务器至关重要。安全的颁发流程对于避免攻击者操纵SAN规范进行冒充风险至关重要。

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS通过指定的容器在AD森林中承认CA证书，每个容器承担独特角色：

- **Certification Authorities**容器保存受信任的根CA证书。
- **Enrolment Services**容器详细说明企业CA及其证书模板。
- **NTAuthCertificates**对象包括被授权用于AD身份验证的CA证书。
- **AIA (Authority Information Access)**容器通过中间和交叉CA证书促进证书链验证。

### Certificate Acquisition: Client Certificate Request Flow

1. 请求过程始于客户端寻找企业CA。
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
- **扩展权限**，允许所有扩展权限。
- **完全控制/通用所有**，提供对模板的完全控制。

### Enterprise CA Enrollment Rights

CA的权限在其安全描述符中列出，可以通过证书颁发机构管理控制台访问。一些设置甚至允许低权限用户远程访问，这可能是一个安全隐患。

### Additional Issuance Controls

某些控制可能适用，例如：

- **经理批准**：将请求置于待处理状态，直到证书经理批准。
- **注册代理和授权签名**：指定CSR上所需的签名数量和必要的应用程序策略OIDs。

### Methods to Request Certificates

可以通过以下方式请求证书：

1. **Windows客户端证书注册协议**（MS-WCCE），使用DCOM接口。
2. **ICertPassage远程协议**（MS-ICPR），通过命名管道或TCP/IP。
3. **证书注册Web界面**，安装了证书颁发机构Web注册角色。
4. **证书注册服务**（CES），与证书注册策略（CEP）服务结合使用。
5. **网络设备注册服务**（NDES）用于网络设备，使用简单证书注册协议（SCEP）。

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

Schannel 促进安全的 TLS/SSL 连接，在握手过程中，客户端会提供一个证书，如果成功验证，则授权访问。将证书映射到 AD 账户可能涉及 Kerberos 的 **S4U2Self** 函数或证书的 **主题备用名称 (SAN)**，以及其他方法。

### AD 证书服务枚举

AD 的证书服务可以通过 LDAP 查询进行枚举，揭示有关 **企业证书授权机构 (CAs)** 及其配置的信息。这对任何经过域认证的用户都是可访问的，无需特殊权限。工具如 **[Certify](https://github.com/GhostPack/Certify)** 和 **[Certipy](https://github.com/ly4k/Certipy)** 被用于 AD CS 环境中的枚举和漏洞评估。

使用这些工具的命令包括：
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## 参考

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{{#include ../../../banners/hacktricks-training.md}}
