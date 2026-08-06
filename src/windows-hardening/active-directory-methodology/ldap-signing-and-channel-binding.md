# LDAP Signing & Channel Binding-verharding

{{#include ../../banners/hacktricks-training.md}}

## Waarom dit saak maak

LDAP relay/MITM stel aanvallers in staat om binds na Domain Controllers aan te stuur om geauthentiseerde kontekste te verkry. Twee bedienerkant-kontroles verswak hierdie paaie:

- **LDAP Channel Binding (CBT)** koppel 'n LDAPS-bind aan die spesifieke TLS-tonnel, wat relays/replays oor verskillende kanale verbreek.
- **LDAP Signing** dwing integriteitsbeskermde LDAP-boodskappe af, wat manipulering en die meeste unsigned relays voorkom.

**Vinnige offensive check**: tools soos `netexec ldap <dc> -u user -p pass` druk die bediener se postuur uit. As jy `(signing:None)` en `(channel binding:Never)` sien, is Kerberos/NTLM **relays na LDAP** moontlik (byvoorbeeld deur KrbRelayUp te gebruik om `msDS-AllowedToActOnBehalfOfOtherIdentity` vir RBCD te skryf en administrators te impersonate).<sup>[[4]](#references)</sup>

**Server 2025 DCs** stel 'n nuwe GPO (**LDAP server signing requirements Enforcement**) bekend wat standaard op **Require Signing** ingestel word wanneer dit **Not Configured** gelaat word. Om enforcement te vermy, moet jy daardie policy uitdruklik op **Disabled** stel.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (slegs LDAPS)

- **Vereistes**:
- CVE-2017-8563 patch (2017) voeg Extended Protection for Authentication-ondersteuning by.<sup>[[3]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (standaard, geen CBT)
- `When Supported` (oudit: genereer failures, maar blokkeer nie)
- `Always` (enforce: verwerp LDAPS-binds sonder geldige CBT)<sup>[[1]](#references)</sup>
- **Oudit**: stel **When Supported** in om die volgende sigbaar te maak:
- **3074** – LDAPS-bind sou CBT-validasie gefaal het indien dit enforced was.
- **3075** – LDAPS-bind het CBT-data weggelaat en sou verwerp word indien dit enforced was.
- (Event **3039** dui steeds op CBT-failures in ouer builds.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: stel **Always** in sodra LDAPS-clients CBTs stuur; dit is slegs effektief op **LDAPS** (nie raw 389 nie).<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (teenoor die `Negotiate signing`-standaard op moderne Windows).<sup>[[1]](#references)</sup>
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (standaard is `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: laat die legacy-policy op `None` en stel `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = standaard enforced; stel `Disabled` in om dit te vermy).<sup>[[1]](#references)</sup>
- **Verenigbaarheid**: slegs Windows **XP SP3+** ondersteun LDAP signing; ouer stelsels sal breek wanneer enforcement enabled word.

## Oudit-eerste ontplooiing (aanbeveel: ongeveer 30 dae)

1. Enable LDAP interface diagnostics op elke DC om unsigned binds (Event **2889**) te log:<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Stel DC GPO `LDAP server channel binding token requirements` = **When Supported** om CBT-telemetrie te begin.<sup>[[1]](#references)</sup>
3. Monitor Directory Service-gebeurtenisse:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – unsigned/unsigned-allow binds (signing-nie-voldoenend).
- **3074/3075** – LDAPS binds wat sou misluk of CBT sou weglaat (vereis KB4520412 op 2019/2022 en stap 2 hierbo).
4. Dwing dit af in afsonderlike veranderinge:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (kliënte).
- `LDAP server signing requirements` = **Require signing** (DCs) **of** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Verwysings

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
