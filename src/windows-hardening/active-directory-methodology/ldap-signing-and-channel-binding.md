# Uimarishaji wa LDAP Signing na Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini ni muhimu

Mashambulizi ya LDAP relay/MITM husambaza authentication kwa domain controller ili kupata muktadha wa LDAP uliothibitishwa. Vidhibiti viwili vinavyohusiana hupunguza njia hizi:

- **LDAP channel binding (CBT)** hufunga authentication husika kwenye cheti/channel ya seva ya TLS inayotumiwa na LDAPS, hivyo kuzuia relay ya kuvuka channels.
- **LDAP signing** huhitaji ulinzi wa integrity kwa SASL LDAP binds. Haiongezi usiri; tumia TLS ikiwa maudhui ya LDAP yanahitaji pia usimbaji fiche.<sup>[[2]](#references)</sup>

**Ukaguzi wa haraka wa hali**: zana kama `netexec ldap <dc> -u user -p pass` huripoti sera za signing na channel-binding zinazoonekana. `(signing:None)` na `(channel binding:Never)` huonyesha kuwa vidhibiti havipo, lakini mafanikio ya relay bado hutegemea aina ya authentication iliyonaswa, tabia ya EPA, ruhusa za akaunti, protocol lengwa, na ulinzi dhidi ya relay. Principal aliyerelayiwa akiwa na ruhusa zinazohitajika, zana kama KrbRelayUp zinaweza kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity`, kusanidi resource-based constrained delegation (RBCD), na kutumia njia ya delegation inayotokana nayo kujifanya principal mwenye upendeleo.<sup>[[4]](#references)</sup>

**Server 2025 DCs** zinaanzisha GPO mpya (**LDAP server signing requirements Enforcement**) ambayo chaguomsingi lake ni **Require Signing** sera inapoachwa **Not Configured**. Ili kuepuka utekelezaji, lazima uweke sera hiyo waziwazi kuwa **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS pekee)

- **Mahitaji**:
  - Kiraka cha CVE-2017-8563 (2017) kinaongeza usaidizi wa Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) kinaongeza telemetry ya LDAPS CBT ya “what-if”.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (chaguomsingi, hakuna CBT)
  - `When Supported` (utekelezaji wa sehemu: clients zinazotumia CBT lazima zitoe token halali; clients zisizotumia CBT bado zinaweza kufanya bind, na matukio ya ukaguzi hutolewa)
  - `Always` (utekelezaji: hukataa LDAPS binds zisizo na CBT halali)<sup>[[1]](#references)</sup>
- **Ukaguzi**: weka **When Supported** ili kubaini:
  - **3074** – LDAPS bind ingeshindwa uthibitishaji wa CBT kama ungetekelezwa.
  - **3075** – LDAPS bind haikujumuisha data ya CBT na ingekataliwa kama CBT ingetekelezwa.
  - (Tukio **3039** bado huashiria hitilafu za CBT kwenye build za zamani.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Utekelezaji**: weka **Always** mara clients za LDAPS zinapotuma CBTs; hufanya kazi kwenye **LDAPS** pekee (si 389 ya kawaida).<sup>[[1]](#references)</sup>

`When Supported` si ya ukaguzi pekee: huthibitisha CBT kwa clients zinazoiunga mkono huku ikiruhusu clients zisizo na usaidizi wa CBT. [Rejeleo la sera la Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) linaeleza chaguomsingi lake linalotegemea toleo. LDAP signing hutumika kwa binds husika kwenye LDAP/389; channel binding hutumika kwa authentication ya LDAP iliyolindwa na TLS.


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (badala ya chaguomsingi la `Negotiate signing` kwenye Windows za kisasa).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Ya zamani: `Domain controller: LDAP server signing requirements` = `Require signing` (chaguomsingi ni `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: acha sera ya zamani ikiwa `None` na uweke `LDAP server signing requirements Enforcement` = `Enabled` (sera ya Not Configured hutekelezwa kwa chaguomsingi; weka `Disabled` ili kuepuka utekelezaji wake).<sup>[[1]](#references)</sup>
- **Uoanifu**: Orodhesha vifaa na programu zisizo za Windows zinazotumia simple binds au unsigned SASL binds. Microsoft inaeleza usaidizi kwenye matoleo ya Windows yanayodumishwa; madai ya uoanifu na clients za zamani yanapaswa kuthibitishwa dhidi ya stack halisi ya client badala ya kufupishwa kuwa kizingiti cha toleo la XP.<sup>[[2]](#references)</sup>

## Utoaji unaoanza kwa ukaguzi (inapendekezwa ~siku 30)

1. Washa uchunguzi wa kiolesura cha LDAP kwenye kila DC ili kurekodi unsigned binds (Tukio **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Weka DC GPO `LDAP server channel binding token requirements` = **When Supported** kwa utekelezaji wa sehemu wa CBT na telemetry; thibitisha kwanza ulinganifu na clients za zamani.<sup>[[1]](#references)</sup>
3. Fuatilia matukio ya Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – binds zisizosainiwa/zinazoruhusu binds zisizosainiwa (hazifuati masharti ya signing).
   - **3074/3075** – LDAPS binds ambazo zingeshindwa au kuacha CBT (inahitaji KB4520412 kwenye 2019/2022 na hatua ya 2 hapo juu).
4. Tekeleza kwa mabadiliko tofauti:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **au** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - LDAP Channel Binding na LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Mahitaji ya LDAP channel binding na signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Sasisho la kupunguza LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing imezimwa → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
