# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno

LDAP relay/MITM omogućava napadačima da proslede binds ka Domain Controllers kako bi stekli autentifikovane kontekste. Dve kontrole na strani servera sučeljavaju ove puteve:

- **LDAP Channel Binding (CBT)** vezuje LDAPS bind za određeni TLS tunel, prekidajući relays/replays koji prelaze različite kanale.
- **LDAP Signing** nameće integritetom zaštićene LDAP poruke, sprečavajući manipulacije i većinu unsigned relays.

**Server 2025 DCs** uvode novu GPO (**LDAP server signing requirements Enforcement**) koja je podrazumevano podešena na **Require Signing** kada je ostavljena na **Not Configured**. Da biste izbegli primenu (enforcement), morate eksplicitno podesiti tu politiku na **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch (2017) dodaje podršku za Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) dodaje LDAPS CBT “what-if” telemetry.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emits failures, does not block)
- `Always` (enforce: rejects LDAPS binds without valid CBT)
- **Audit**: set **When Supported** to surface:
- **3074** – LDAPS bind would have failed CBT validation if enforced.
- **3075** – LDAPS bind omitted CBT data and would be rejected if enforced.
- (Event **3039** still signals CBT failures on older builds.)
- **Enforcement**: set **Always** once LDAPS clients send CBTs; only effective on **LDAPS** (not raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: leave legacy policy at `None` and set `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; set `Disabled` to avoid it).
- **Compatibility**: only Windows **XP SP3+** supports LDAP signing; older systems will break when enforcement is enabled.

## Audit-first rollout (recommended ~30 days)

1. Enable LDAP interface diagnostics on each DC to log unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Podesite DC GPO `LDAP server channel binding token requirements` = **When Supported** da biste pokrenuli CBT telemetriju.
3. Pratite događaje Directory Service:
- **2889** – unsigned/unsigned-allow bindovi (potpisivanje nije u skladu).
- **3074/3075** – LDAPS bindovi koji bi propali ili izostavili CBT (zahteva KB4520412 za 2019/2022 i korak 2 iznad).
4. Sprovodite u odvojenim promenama:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **ili** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
