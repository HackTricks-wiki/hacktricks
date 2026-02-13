# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Neden önemli

LDAP relay/MITM, saldırganların binds'i Domain Controllers'a ileterek kimlik doğrulanmış bağlamlar elde etmelerini sağlar. Bu yolları kesen iki sunucu tarafı kontrolü vardır:

- **LDAP Channel Binding (CBT)** ties an LDAPS bind to the specific TLS tunnel, breaking relays/replays across different channels.
- **LDAP Signing** forces integrity-protected LDAP messages, preventing tampering and most unsigned relays.

**Server 2025 DCs** yeni bir GPO (**LDAP server signing requirements Enforcement**) ekler; bu GPO **Not Configured** bırakıldığında varsayılan olarak **Require Signing** olur. Zorlamadan kaçınmak için bu politikayı açıkça **Disabled** olarak ayarlamalısınız.

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch (2017) adds Extended Protection for Authentication support.
- **KB4520412** (Server 2019/2022) adds LDAPS CBT “what-if” telemetry.
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

1. Her DC'de imzasız binds'leri kaydetmek için LDAP arayüzü tanılamalarını etkinleştirin (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. DC GPO'unda `LDAP server channel binding token requirements` = **When Supported** olarak ayarlayın, CBT telemetrisi başlatmak için.
3. Directory Service olaylarını izleyin:
- **2889** – unsigned/unsigned-allow binds (imzalama gereksinimlerine uymuyor).
- **3074/3075** – LDAPS binds that would fail or omit CBT (requires KB4520412 on 2019/2022 and step 2 above).
4. Ayrı değişikliklerle zorlayın:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **veya** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Kaynaklar

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
