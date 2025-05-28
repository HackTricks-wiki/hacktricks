# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Delegated Managed Service Accounts (**dMSAs**) ni aina mpya ya AD principal iliyozintroduced na **Windows Server 2025**. Zimeundwa kubadilisha akaunti za huduma za zamani kwa kuruhusu “muhamala” wa bonyeza moja ambao kiotomatiki unakopya Majina ya Wakuu wa Huduma (SPNs), uanachama wa vikundi, mipangilio ya uwakilishi, na hata funguo za cryptographic katika dMSA mpya, ikitoa matumizi ya kuhamasisha bila mshono na kuondoa hatari ya Kerberoasting.

Watafiti wa Akamai waligundua kuwa sifa moja — **`msDS‑ManagedAccountPrecededByLink`** — inamwambia KDC ni akaunti gani ya zamani ambayo dMSA “inasimama”. Ikiwa mshambuliaji anaweza kuandika sifa hiyo (na kubadilisha **`msDS‑DelegatedMSAState` → 2**), KDC itajenga PAC ambayo **inapata kila SID ya mwathirika aliyechaguliwa**, ikiruhusu dMSA kuiga mtumiaji yeyote, ikiwa ni pamoja na Wasimamizi wa Kikoa.

## What exactly is a dMSA?

* Imejengwa juu ya teknolojia ya **gMSA** lakini inahifadhiwa kama darasa jipya la AD **`msDS‑DelegatedManagedServiceAccount`**.
* Inasaidia **muhamala wa kujiunga**: kuita `Start‑ADServiceAccountMigration` kunahusisha dMSA na akaunti ya zamani, kunatoa akaunti ya zamani ruhusa ya kuandika kwenye `msDS‑GroupMSAMembership`, na kubadilisha `msDS‑DelegatedMSAState` = 1.
* Baada ya `Complete‑ADServiceAccountMigration`, akaunti iliyozuiliwa inazuiliwa na dMSA inakuwa na kazi kamili; mwenyeji yeyote ambaye hapo awali alitumia akaunti ya zamani kiotomatiki anaruhusiwa kuchukua nenosiri la dMSA.
* Wakati wa uthibitishaji, KDC inaingiza kidokezo cha **KERB‑SUPERSEDED‑BY‑USER** ili wateja wa Windows 11/24H2 wajaribu tena kwa uwazi na dMSA.


## Requirements to attack
1. **Angalau Windows Server 2025 DC** ili dMSA LDAP darasa na mantiki ya KDC iwepo.
2. **Haki zozote za kuunda vitu au kuandika sifa kwenye OU** (OU yoyote) – e.g. `Create msDS‑DelegatedManagedServiceAccount` au kwa urahisi **Create All Child Objects**. Akamai iligundua kuwa 91 % ya wapangaji wa ulimwengu halisi wanatoa ruhusa za “benign” za OU kwa wasimamizi wasio.
3. Uwezo wa kuendesha zana (PowerShell/Rubeus) kutoka kwa mwenyeji yeyote aliyeunganishwa na kikoa ili kuomba tiketi za Kerberos.
*Hakuna udhibiti juu ya mtumiaji wa mwathirika unahitajika; shambulio haligusi akaunti ya lengo moja kwa moja.*

## Step‑by‑step: BadSuccessor*privilege escalation

1. **Tafuta au unda dMSA unayodhibiti**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Kwa sababu umekuwa ukiumba kitu ndani ya OU unachoweza kuandika, moja kwa moja unamiliki sifa zake zote.

2. **Simuliza “muhamala ulio kamilika” katika maandiko mawili ya LDAP**:
- Weka `msDS‑ManagedAccountPrecededByLink = DN` ya mwathirika yeyote (e.g. `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Weka `msDS‑DelegatedMSAState = 2` (muhamala umekamilika).

Zana kama **Set‑ADComputer, ldapmodify**, au hata **ADSI Edit** zinafanya kazi; hakuna haki za msimamizi wa kikoa zinazohitajika.

3. **Omba TGT kwa dMSA** — Rubeus inasaidia bendera ya `/dmsa`:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

PAC iliyorejeshwa sasa ina SID 500 (Msimamizi) pamoja na vikundi vya Wasimamizi wa Kikoa/Wasimamizi wa Biashara.

## Gather all the users passwords

Wakati wa muhajirisho halali KDC lazima iruhusu dMSA mpya kufungua **tiketi zilizotolewa kwa akaunti ya zamani kabla ya kuhamasisha**. Ili kuepuka kuvunja vikao vya moja kwa moja inatia funguo zote za sasa na funguo za awali ndani ya blob mpya ya ASN.1 inayoitwa **`KERB‑DMSA‑KEY‑PACKAGE`**.

Kwa sababu muhajirisho wetu wa uwongo unadai dMSA inasimama kwa mwathirika, KDC kwa uaminifu inakopya funguo za RC4‑HMAC za mwathirika kwenye orodha ya **funguo za awali** – hata kama dMSA haikuwa na nenosiri “la awali”. Funguo hiyo ya RC4 haina chumvi, hivyo kwa ufanisi ni hash ya NT ya mwathirika, ikimpa mshambuliaji **uwezo wa kuvunja nje au “kupitisha hash”**.

Hivyo basi, kuunganisha maelfu ya watumiaji kunaruhusu mshambuliaji kutupa hash “kwa kiwango,” ikigeuza **BadSuccessor kuwa msingi wa kupandisha hadhi na kuathiri hati**.

## Tools

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## References

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)


{{#include ../../../banners/hacktricks-training.md}}
