# LDAP Signing & Channel Binding Verharding

{{#include ../../banners/hacktricks-training.md}}

## Waarom dit saak maak

LDAP relay/MITM laat aanvalvoerders toe om binds na Domain Controllers deur te stuur om geverifieerde kontekste te bekom. Twee bediener-side kontroles maak hierdie weë moeilik:

- **LDAP Channel Binding (CBT)** bind 'n LDAPS bind aan die spesifieke TLS-tunnel, en breek relays/replays oor verskillende kanale.
- **LDAP Signing** dwing integriteit-beskermde LDAP-boodskappe af, wat manipulasie en meeste ongehandtekende relays verhoed.

**Vinnige offensiewe kontrole**: gereedskap soos `netexec ldap <dc> -u user -p pass` druk die serverpostuur. As jy `(signing:None)` en `(channel binding:Never)` sien, is Kerberos/NTLM **relays to LDAP** uitvoerbaar (bv. met KrbRelayUp om `msDS-AllowedToActOnBehalfOfOtherIdentity` te skryf vir RBCD en administrateurs te imiteer).

Server 2025 DCs stel 'n nuwe GPO bekend (**LDAP server signing requirements Enforcement**) wat standaard op **Require Signing** stel wanneer dit **Not Configured** gelaat word. Om afdwinging te vermy moet jy daardie beleid eksplisiet op **Disabled** stel.

## LDAP Channel Binding (LDAPS only)

- **Vereistes**:
- CVE-2017-8563 patch (2017) voeg Extended Protection for Authentication ondersteuning by.
- **KB4520412** (Server 2019/2022) voeg LDAPS CBT “what-if” telemetrie by.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emits failures, does not block)
- `Always` (enforce: rejects LDAPS binds without valid CBT)
- **Audit**: stel **When Supported** om die volgende te openbaar:
- **3074** – LDAPS bind sou CBT-validasie misluk het as dit afgedwing is.
- **3075** – LDAPS bind het CBT-data weggelaat en sou verwerp word as dit afgedwing is.
- (Event **3039** dui steeds op CBT-foute op ouer builds.)
- **Enforcement**: stel **Always** slegs wanneer LDAPS-kliente CBTs stuur; slegs effektief op **LDAPS** (nie ruwe 389 nie).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: laat die legacy beleid op `None` en stel `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; stel `Disabled` om dit te vermy).
- **Compatibility**: slegs Windows **XP SP3+** ondersteun LDAP signing; ouer stelsels sal breek wanneer afdwinging geaktiveer word.

## Audit-first rollout (recommended ~30 days)

1. Enable LDAP interface diagnostics on each DC to log unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Stel DC GPO `LDAP server channel binding token requirements` = **When Supported** om CBT-telemetrie te begin.
3. Moniteer Directory Service-gebeurtenisse:
- **2889** – unsigned/unsigned-allow binds (ondertekening nie-kompliant).
- **3074/3075** – LDAPS binds wat sou misluk of CBT weglat (vereis KB4520412 op 2019/2022 en stap 2 hierbo).
4. Handhaaf in afsonderlike veranderinge:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (kliënte).
- `LDAP server signing requirements` = **Require signing** (DCs) **of** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Verwysings

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
