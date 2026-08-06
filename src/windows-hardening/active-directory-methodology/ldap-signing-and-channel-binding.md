# Kuimarisha LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini ni muhimu

LDAP relay/MITM huwawezesha washambuliaji kupeleka binds kwa Domain Controllers ili kupata authenticated contexts. Vidhibiti viwili vya upande wa server hupunguza njia hizi:

- **LDAP Channel Binding (CBT)** huunganisha bind ya LDAPS na TLS tunnel maalum, hivyo kuvunja relays/replays kwenye channels tofauti.
- **LDAP Signing** hulazimisha LDAP messages zilindwe kwa integrity, hivyo kuzuia tampering na relays nyingi zisizo na signing.

**Ukaguzi wa haraka wa offensive**: tools kama `netexec ldap <dc> -u user -p pass` huonyesha server posture. Ukiona `(signing:None)` na `(channel binding:Never)`, **relays za Kerberos/NTLM kwa LDAP** zinawezekana (kwa mfano, kwa kutumia KrbRelayUp kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity` kwa RBCD na ku-impersonate administrators).<sup>[[4]](#references)</sup>

**Server 2025 DCs** huanzisha GPO mpya (**LDAP server signing requirements Enforcement**) ambayo kwa default huweka **Require Signing** ikiwa imeachwa **Not Configured**. Ili kuepuka enforcement, lazima uweke policy hiyo wazi kuwa **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch (2017) huongeza support ya Extended Protection for Authentication.<sup>[[3]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, bila CBT)
- `When Supported` (audit: hutoa failures, lakini haizuii)
- `Always` (enforce: hukataa LDAPS binds bila CBT halali)<sup>[[1]](#references)</sup>
- **Audit**: weka **When Supported** ili kubaini:
- **3074** – LDAPS bind ingeshindwa CBT validation ikiwa enforcement ingewekwa.
- **3075** – LDAPS bind haikujumuisha CBT data na ingekataliwa ikiwa enforcement ingewekwa.
- (Event **3039** bado huashiria CBT failures kwenye builds za zamani.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: weka **Always** baada ya LDAPS clients kutuma CBTs; hufanya kazi kwenye **LDAPS** pekee (si raw 389).<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (kinyume na `Negotiate signing`, ambayo ni default kwenye Windows za kisasa).<sup>[[1]](#references)</sup>
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default ni `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: acha legacy policy ikiwa `None` na uweke `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = inatumika kwa default; weka `Disabled` ili kuiepuka).<sup>[[1]](#references)</sup>
- **Compatibility**: Windows **XP SP3+** pekee ndiyo inayounga mkono LDAP signing; systems za zamani zitaharibika enforcement inapowezeshwa.

## Audit-first rollout (inayopendekezwa takriban siku 30)

1. Washa LDAP interface diagnostics kwenye kila DC ili kurekodi unsigned binds (Event **2889**):<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Weka DC GPO `LDAP server channel binding token requirements` = **When Supported** ili kuanza CBT telemetry.<sup>[[1]](#references)</sup>
3. Fuatilia Directory Service events:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – unsigned/unsigned-allow binds (signing isiyokidhi mahitaji).
- **3074/3075** – LDAPS binds ambazo zingeshindwa au kuacha CBT (inahitaji KB4520412 kwenye 2019/2022 na hatua ya 2 hapo juu).
4. Tekeleza katika mabadiliko tofauti:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **au** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Marejeo

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
