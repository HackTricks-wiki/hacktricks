# LDAP Signing & Channel Binding Verharding

{{#include ../../banners/hacktricks-training.md}}

## Waarom dit saak maak

LDAP relay/MITM laat aanvallers binds na Domain Controllers deurstuur om geauthentiseerde kontekste te bekom. Twee bediener-kant beheermaatreëls versag hierdie paaie:

- **LDAP Channel Binding (CBT)** ties an LDAPS bind to the specific TLS tunnel, breaking relays/replays across different channels.
- **LDAP Signing** dwing integriteits-beskermde LDAP-boodskappe af, wat knoeiery en die meeste ongetekende relays voorkom.

**Server 2025 DCs** stel ’n nuwe GPO bekend (**LDAP server signing requirements Enforcement**) wat standaard na **Require Signing** spring wanneer dit op **Not Configured** gelaat word. Om afdwinging te vermy moet jy daardie beleid uitdruklik op **Disabled** stel.

## LDAP Channel Binding (slegs LDAPS)

- **Requirements**:
- CVE-2017-8563 patch (2017) adds Extended Protection for Authentication support.
- **KB4520412** (Server 2019/2022) adds LDAPS CBT “what-if” telemetry.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (standaard, geen CBT)
- `When Supported` (oudit: genereer foutmeldings, blokkeer nie)
- `Always` (enforce: verwerp LDAPS binds sonder geldige CBT)
- **Audit**: stel **When Supported** om dit te rapporteer:
- **3074** – LDAPS bind sou aan CBT-validering misluk het as dit afgedwing is.
- **3075** – LDAPS bind het CBT-data weggelaat en sou verwerp gewees het as dit afgedwing is.
- (Gebeurtenis **3039** dui steeds CBT-foute op ouer boue aan.)
- **Enforcement**: stel **Always** sodra LDAPS-kliente CBTs stuur; slegs effektief op **LDAPS** (nie rou 389 nie).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: laat die legacy-beleid op `None` en stel `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = standaard afgedwing; stel op `Disabled` om dit te vermy).
- **Compatibility**: slegs Windows **XP SP3+** ondersteun LDAP signing; ouer stelsels sal breek wanneer afdwinging aangeskakel is.

## Oudit-eerst uitrol (aanbeveel ~30 dae)

1. Skakel LDAP-koppelvlakdiagnostiek op elke DC in om ongetekende binds te registreer (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Stel DC GPO `LDAP server channel binding token requirements` = **When Supported** om CBT-telemetrie te begin.
3. Moniteer Directory Service-gebeure:
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds wat sou misluk of CBT weglate (vereis KB4520412 op 2019/2022 en stap 2 hierbo).
4. Handhaaf in afsonderlike veranderinge:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Verwysings

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
