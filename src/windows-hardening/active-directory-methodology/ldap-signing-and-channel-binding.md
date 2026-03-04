# LDAP Signing & Channel Binding Kuweka Salama

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini ni muhimu

LDAP relay/MITM huruhusu watapeli kupeleka binds kwa Domain Controllers ili kupata muktadha ulioidhinishwa. Udhibiti mbili upande wa server hupunguza njia hizi:

- **LDAP Channel Binding (CBT)** inafunga LDAPS bind kwa tunnel maalum ya TLS, ikivunja relays/replays kati ya kanali tofauti.
- **LDAP Signing** inalazimisha ujumbe za LDAP zenye ulinzi wa uadilifu, ikizuia uharibifu na relays nyingi zisizotiwa saini.

**Ukaguzi wa haraka wa kushambulia**: zana kama `netexec ldap <dc> -u user -p pass` zinaonyesha msimamo wa server. Ikiwa unaona `(signing:None)` na `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** zinawezekana (mfano, kwa kutumia KrbRelayUp kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity` kwa RBCD na kuiga wasimamizi).

**Server 2025 DCs** zinaanzisha GPO mpya (**LDAP server signing requirements Enforcement**) ambayo kwa default iko **Require Signing** wakati imeacha **Not Configured**. Ili kuepuka utekelezaji lazima uweke sera hiyo kuwa **Disabled**.

## LDAP Channel Binding (LDAPS tu)

- **Requirements**:
- CVE-2017-8563 patch (2017) inaongeza Extended Protection for Authentication support.
- **KB4520412** (Server 2019/2022) inaongeza LDAPS CBT “what-if” telemetry.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (chaguo-msingi, hakuna CBT)
- `When Supported` (audit: inatoa matukio ya kushindwa, haiizuizi)
- `Always` (enforce: inakataa LDAPS binds bila CBT halali)
- **Audit**: weka **When Supported** ili kuonyesha:
- **3074** – LDAPS bind ingekuwa imeshindwa uthibitisho wa CBT kama ingetekelezwa.
- **3075** – LDAPS bind iliacha data ya CBT na ingekataliwa kama ingetekelezwa.
- (Event **3039** bado inaashiria kushindwa kwa CBT kwenye matoleo ya zamani.)
- **Enforcement**: weka **Always** mara tu wateja wa LDAPS watakapotuma CBT; inafanya kazi tu kwa **LDAPS** (si raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (ikilinganishwa na `Negotiate signing` chaguo-msingi kwenye Windows za kisasa).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (chaguo-msingi ni `None`).
- **Server 2025**: iachie sera ya kijadi kuwa `None` na weka `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = inatekelezwa kwa default; weka `Disabled` kuepuka).
- **Compatibility**: ni Windows tu **XP SP3+** zinazoisaidia LDAP signing; mifumo ya zamani itavurugika wakati utekelezaji utakapowashwa.

## Utekelezaji wa kwanza kwa auditi (inapendekezwa ~30 siku)

1. Washa utambuzi wa kiolesura cha LDAP kwenye kila DC ili kurekodi binds zisizotiwa saini (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Weka DC GPO `LDAP server channel binding token requirements` = **When Supported** ili kuanza telemetry ya CBT.
3. Fuatilia matukio ya Directory Service:
- **2889** – unsigned/unsigned-allow binds (kusaini haikidhi mahitaji).
- **3074/3075** – LDAPS binds ambazo zingeashindwa au kuacha CBT (zinahitaji KB4520412 kwa 2019/2022 na hatua 2 hapo juu).
4. Lazimisha kwa mabadiliko tofauti:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Marejeleo

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
