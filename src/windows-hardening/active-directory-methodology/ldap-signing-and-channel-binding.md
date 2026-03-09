# Kuimarisha LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini ni muhimu

LDAP relay/MITM huruhusu washambuliaji kupeleka binds kwa Domain Controllers ili kupata muktadha uliothibitishwa. Udhibiti mbili upande wa server hupunguza njia hizi:

- **LDAP Channel Binding (CBT)** inahusisha LDAPS bind na tuneli maalum ya TLS, ikivunja relays/replays kati ya chaneli tofauti.
- **LDAP Signing** inalazimisha ujumbe za LDAP zilizo na ulinzi wa uadilifu, kuzuia utovu wa data na relays nyingi zisizotiwa saini.

**Quick offensive check**: zana kama `netexec ldap <dc> -u user -p pass` zinaonyesha hali ya server. Ikiwa unaona `(signing:None)` na `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** zinawezekana (kwa mfano, kutumia KrbRelayUp kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity` kwa RBCD na kuiga wasimamizi).

**Server 2025 DCs** zinaleta GPO mpya (**LDAP server signing requirements Enforcement**) ambayo kimsingi inaweka **Require Signing** wakati imeachwa **Not Configured**. Ili kuepuka utekelezaji lazima uweke sera hiyo kwa wazi kuwa **Disabled**.

## LDAP Channel Binding (LDAPS pekee)

- **Mahitaji**:
- CVE-2017-8563 patch (2017) inaongeza msaada wa Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) inaongeza telemetry ya LDAPS CBT “what-if”.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emits failures, does not block)
- `Always` (enforce: rejects LDAPS binds without valid CBT)
- **Audit**: weka **When Supported** ili kuonyesha:
- **3074** – LDAPS bind ingeanguka kwenye uhalalishaji wa CBT ikiwa ingekuwa ialazimishwa.
- **3075** – LDAPS bind iliupuza data za CBT na ingekataliwa ikiwa lingekuwa linalazimishwa.
- (Tukio **3039** bado linaonyesha makosa ya CBT kwenye builds za zamani.)
- **Enforcement**: weka **Always** mara wateja wa LDAPS watakapotuma CBT; inafanya kazi tu kwa **LDAPS** (si raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: acha sera ya mirithi kuwa `None` na weka `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; weka `Disabled` ili kuepuka).
- **Compatibility**: only Windows **XP SP3+** supports LDAP signing; mifumo ya zamani itaacha kufanya kazi wakati utekelezaji utawezeshwa.

## Mzunguko wa kuanzisha kwa msingi wa uchunguzi (inapendekezwa ~siku 30)

1. Washa uchunguzi wa kiolesura cha LDAP kwenye kila DC ili kurekodi binds zisizo na saini (Tukio **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Weka DC GPO `LDAP server channel binding token requirements` = **When Supported** ili kuanza telemetry ya CBT.
3. Fuatilia matukio ya Directory Service:
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds that would fail or omit CBT (inahitaji KB4520412 kwenye 2019/2022 na hatua 2 hapo juu).
4. Lazimisha kwa mabadiliko tofauti:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **au** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Marejeleo

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
