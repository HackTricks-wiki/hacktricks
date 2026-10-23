# Kuimarisha LDAP Signing na Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini ni muhimu

Mashambulizi ya LDAP relay/MITM husambaza uthibitishaji hadi kwa domain controller ili kupata muktadha wa LDAP uliothibitishwa. [Muhtasari wa name-resolution poisoning na relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) unaeleza mtiririko mpana zaidi. Vidhibiti viwili vinavyohusiana hupunguza njia hizi:

- **LDAP channel binding (CBT)** hufungamanisha uthibitishaji unaohusika na cheti/channel ya seva ya TLS inayotumiwa na LDAPS, hivyo kukwamisha relay kati ya channels tofauti.
- **LDAP signing** huhitaji ulinzi wa integrity kwa SASL LDAP binds. Haitaongezi confidentiality; tumia TLS ikiwa maudhui ya LDAP pia yanahitaji usimbaji fiche.<sup>[[2]](#references)</sup>

**Ukaguzi wa haraka wa hali**: zana kama `netexec ldap <dc> -u user -p pass` huripoti signing na sera ya channel binding inayozingatiwa. `(signing:None)` na `(channel binding:Never)` zinaonyesha vidhibiti havipo, lakini relay iliyofanikiwa bado hutegemea aina ya uthibitishaji uliokamatwa, tabia ya EPA, ruhusa za akaunti, protocol lengwa, na ulinzi dhidi ya relay. Principal aliyerelayiwa akiwa na haki zinazohitajika, zana kama KrbRelayUp zinaweza kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity`, kusanidi resource-based constrained delegation (RBCD), na kutumia njia ya delegation inayotokana na hilo kuiga principal mwenye mamlaka makubwa.<sup>[[4]](#references)</sup>

**Server 2025 DCs** huleta GPO mpya (**LDAP server signing requirements Enforcement**) ambayo chaguomsingi lake ni **Require Signing** sera inapoachwa **Not Configured**. Ili kuepuka utekelezaji, lazima uweke sera hiyo waziwazi kuwa **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS pekee)

- **Mahitaji**:
  - Kiraka cha CVE-2017-8563 (2017) kinaongeza usaidizi wa Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) kinaongeza telemetry ya LDAPS CBT ya “what-if”.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (chaguomsingi, hakuna CBT)
  - `When Supported` (utekelezaji wa sehemu: clients zinazoweza kutumia CBT lazima zitume tokeni halali; clients zisizotumia CBT bado zinaweza kuunganisha, na matukio ya ukaguzi huandikwa)
  - `Always` (utekelezaji: hukataa LDAPS binds zisizo na CBT halali)<sup>[[1]](#references)</sup>
- **Ukaguzi**: weka **When Supported** ili kubaini:
  - **3074** – LDAPS bind ingeshindwa uthibitishaji wa CBT kama ungetekelezwa.
  - **3075** – LDAPS bind haikutuma data ya CBT na ingekataliwa kama utekelezaji ungewezeshwa.
  - (Tukio **3039** bado huashiria hitilafu za CBT kwenye builds za zamani.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Utekelezaji**: weka **Always** baada ya LDAPS clients kuanza kutuma CBTs; hufanya kazi kwenye **LDAPS** pekee (si raw 389).<sup>[[1]](#references)</sup>

`When Supported` si ya ukaguzi pekee: hukagua CBT kwa clients zinazoiunga mkono huku ikiruhusu clients zisizoiunga mkono. [Rejea ya sera ya Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) inaeleza chaguomsingi zinazotegemea toleo. LDAP signing hutumika kwa binds husika kwenye LDAP/389; channel binding hutumika kwa uthibitishaji wa LDAP unaolindwa na TLS.


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (badala ya chaguomsingi la `Negotiate signing` kwenye Windows za kisasa).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Ya zamani: `Domain controller: LDAP server signing requirements` = `Require signing` (chaguomsingi ni `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: acha sera ya zamani ikiwa `None` na uweke `LDAP server signing requirements Enforcement` = `Enabled` (sera ya Not Configured hutekelezwa kwa chaguomsingi; weka `Disabled` ili kuepuka utekelezaji huo).<sup>[[1]](#references)</sup>
- **Ulinganifu**: Orodhesha appliances na applications zisizo za Windows zinazotumia simple binds au SASL binds zisizosainiwa. Microsoft inaeleza usaidizi kwenye matoleo ya Windows yanayodumishwa; kauli kuhusu ulinganifu na clients za zamani zinapaswa kuthibitishwa dhidi ya client stack halisi badala ya kuhitimishwa kwa kutumia kikomo cha toleo la XP.<sup>[[2]](#references)</sup>

## Utoaji wa hatua kwa hatua ukianza na ukaguzi (inapendekezwa takriban siku 30)

1. Washa LDAP interface diagnostics kwenye kila DC ili kurekodi unsigned binds (Tukio **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Weka DC GPO `LDAP server channel binding token requirements` = **When Supported** ili kutekeleza CBT kwa sehemu na kukusanya telemetry; hakiki kwanza uoanifu na clients za zamani.<sup>[[1]](#references)</sup>
3. Fuatilia matukio ya Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – binds zisizo na signing/zinazoruhusu binds zisizo na signing (hazizingatii signing).
   - **3074/3075** – LDAPS binds ambazo zingeshindwa au kuacha CBT (inahitaji KB4520412 kwenye 2019/2022 na hatua ya 2 hapo juu).
4. Tekeleza kupitia mabadiliko tofauti:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **au** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP Channel Binding na LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Mahitaji ya LDAP channel binding na signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Sasisho la kupunguza LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing imezimwa → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
