# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini ni muhimu

LDAP relay/MITM inaruhusu wawashambuliaji kupeleka binds kwa Domain Controllers ili kupata authenticated contexts. Kuna udhibiti wawili upande wa server unaokatiza njia hizi:

- **LDAP Channel Binding (CBT)** inafunga LDAPS bind kwenye tunnel maalum ya TLS, ikivunja relays/replays kati ya chaneli tofauti.
- **LDAP Signing** inalazimisha ujumbe za LDAP zilizo na ulinzi wa integriti, ikizuia tampering na relays nyingi zisizosisitishwa.

**Server 2025 DCs** zinaleta GPO mpya (**LDAP server signing requirements Enforcement**) ambayo kwa default iko **Require Signing** pale inapobaki **Not Configured**. Ili kuepuka enforcement lazima uweke sera hiyo wazi kuwa **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch (2017) inaongeza Extended Protection for Authentication support.
- **KB4520412** (Server 2019/2022) inaongeza telemetry ya LDAPS CBT “what-if”.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (chaguo-msingi, hakuna CBT)
- `When Supported` (audit: hutoa failures, haizuizi)
- `Always` (enforce: inakataa LDAPS binds bila CBT halali)
- **Audit**: weka **When Supported** ili kuonyesha:
- **3074** – LDAPS bind ingekuwa imefeli uthibitisho wa CBT ikiwa ingewekwa enforcement.
- **3075** – LDAPS bind iliacha data ya CBT na ingekataliwa ikiwa ingewekwa enforcement.
- (Event **3039** bado inaonyesha kushindwa kwa CBT kwenye builds za zamani.)
- **Enforcement**: weka **Always** mara LDAPS clients wanaporusha CBTs; inatumika tu kwa **LDAPS** (si raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: acha sera ya legacy kuwa `None` na weka `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; weka `Disabled` ili kuepuka).
- **Compatibility**: ni Windows **XP SP3+** pekee zinazounga mkono LDAP signing; mifumo ya zamani itaathirika wakati enforcement itakapowashwa.

## Audit-first rollout (recommended ~30 days)

1. Washa diagnostics ya interface ya LDAP kwenye kila DC ili kurekodi binds zisizosainiwa (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Weka DC GPO `LDAP server channel binding token requirements` = **When Supported** ili kuanza telemetri ya CBT.
3. Fuatilia matukio ya Directory Service:
- **2889** – unsigned/unsigned-allow binds (saini haina ulinganifu).
- **3074/3075** – LDAPS binds ambazo zingeanguka au kuacha CBT (inahitaji KB4520412 kwa 2019/2022 na hatua 2 hapo juu).
4. Lazimisha kwa mabadiliko tofauti:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Marejeo

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
