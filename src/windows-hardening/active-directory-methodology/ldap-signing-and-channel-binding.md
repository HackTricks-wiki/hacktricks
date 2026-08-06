# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno

LDAP relay/MITM omogućava napadačima da proslede bind zahteve Domain Controllerima i dobiju autentifikovane kontekste. Dve kontrole na serveru ublažavaju ove napade:

- **LDAP Channel Binding (CBT)** vezuje LDAPS bind za određeni TLS tunel, čime onemogućava relays/replays preko različitih kanala.
- **LDAP Signing** zahteva poruke LDAP-a zaštićene integritetom, čime se sprečavaju izmene i većina unsigned relays napada.

**Brza offensive provera**: alati kao što je `netexec ldap <dc> -u user -p pass` prikazuju stanje servera. Ako vidite `(signing:None)` i `(channel binding:Never)`, **relays ka LDAP-u** putem Kerberos/NTLM-a su mogući (npr. korišćenjem KrbRelayUp za upis vrednosti `msDS-AllowedToActOnBehalfOfOtherIdentity` radi RBCD-a i impersonacije administratora).<sup>[[4]](#references)</sup>

**Server 2025 DC-ovi** uvode novu GPO politiku (**LDAP server signing requirements Enforcement**) koja podrazumevano postavlja **Require Signing** kada je ostavljena na **Not Configured**. Da biste izbegli enforcement, ovu politiku morate eksplicitno postaviti na **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (samo LDAPS)

- **Zahtevi**:
- CVE-2017-8563 patch (2017) dodaje podršku za Extended Protection for Authentication.<sup>[[3]](#references)</sup>
- **KB4520412** (Server 2019/2022) dodaje LDAPS CBT „what-if“ telemetriju.<sup>[[2]](#references)</sup>
- **GPO (DC-ovi)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (podrazumevano, bez CBT-a)
- `When Supported` (audit: generiše greške, ali ih ne blokira)
- `Always` (enforce: odbija LDAPS bind zahteve bez validnog CBT-a)<sup>[[1]](#references)</sup>
- **Audit**: postavite na **When Supported** da biste otkrili:
- **3074** – LDAPS bind bi pao CBT validaciju da je enforcement omogućen.
- **3075** – LDAPS bind nije sadržao CBT podatke i bio bi odbijen da je enforcement omogućen.
- (Event **3039** i dalje signalizira CBT greške na starijim buildovima.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: postavite na **Always** kada LDAPS klijenti počnu da šalju CBT-ove; ovo je efektivno samo za **LDAPS** (ne i za raw 389).<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (nasuprot podrazumevanom `Negotiate signing` na modernom Windowsu).<sup>[[1]](#references)</sup>
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (podrazumevana vrednost je `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: ostavite legacy politiku na `None` i postavite `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforcement je podrazumevano omogućen; postavite `Disabled` da biste ga izbegli).<sup>[[1]](#references)</sup>
- **Kompatibilnost**: samo Windows **XP SP3+** podržava LDAP signing; stariji sistemi će prestati da rade kada se enforcement omogući.

## Uvođenje sa fokusom na audit (preporučeno oko 30 dana)

1. Omogućite LDAP interface diagnostics na svakom DC-u da biste beležili unsigned bind zahteve (Event **2889**):<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Podesite DC GPO `LDAP server channel binding token requirements` = **When Supported** da biste pokrenuli CBT telemetry.<sup>[[1]](#references)</sup>
3. Pratite Directory Service događaje:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – unsigned/unsigned-allow bind-ovi (neusaglašeni sa signing-om).
- **3074/3075** – LDAPS bind-ovi koji bi bili neuspešni ili bi izostavili CBT (zahteva KB4520412 na verzijama 2019/2022 i prethodni korak 2).
4. Primenite kroz odvojene izmene:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DC-ovi).
- `LDAP client signing requirements` = **Require signing** (klijenti).
- `LDAP server signing requirements` = **Require signing** (DC-ovi) **ili** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Reference

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
