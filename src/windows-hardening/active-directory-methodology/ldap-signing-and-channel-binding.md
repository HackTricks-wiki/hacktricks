# Uimarishaji wa LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Kwa nini ni muhimu

LDAP relay/MITM attacks husambaza authentication kwa domain controller ili kupata muktadha wa LDAP ulio-authenticate. [Muhtasari wa name-resolution poisoning na relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) unaeleza workflow pana zaidi. Controls mbili zinazohusiana hupunguza njia hizi:

- **LDAP channel binding (CBT)** hufunga authentication husika kwenye cheti/channel ya TLS server inayotumiwa na LDAPS, na hivyo kuzuia relay kati ya channels.
- **LDAP signing** huhitaji ulinzi wa integrity kwa SASL LDAP binds. Haiongezi confidentiality; tumia TLS wakati maudhui ya LDAP yanahitaji pia encryption.<sup>[[2]](#references)</sup>

**Ukaguzi wa haraka wa hali**: tools kama `netexec ldap <dc> -u user -p pass` huripoti signing na channel-binding policy iliyozingatiwa. `(signing:None)` na `(channel binding:Never)` zinaonyesha controls hazipo, lakini relay iliyofanikiwa bado hutegemea aina ya authentication iliyokamatwa, tabia ya EPA, privileges za account, target protocol, na ulinzi dhidi ya relay. Principal iliyorelayiwa ikiwa na ruhusa zinazohitajika, tooling kama KrbRelayUp inaweza kuandika `msDS-AllowedToActOnBehalfOfOtherIdentity`, kusanidi resource-based constrained delegation (RBCD), na kutumia njia ya delegation inayotokana na hilo kuiga principal mwenye privilege.<sup>[[4]](#references)</sup>

**Server 2025 DCs** zinaanzisha GPO mpya (**LDAP server signing requirements Enforcement**) ambayo kwa chaguomsingi huwa **Require Signing** ikiwa itaachwa **Not Configured**. Ili kuepuka enforcement, lazima uweke policy hiyo waziwazi kuwa **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS pekee)

- **Mahitaji**:
  - Patch ya CVE-2017-8563 (2017) inaongeza uwezo wa Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) inaongeza telemetry ya LDAPS CBT ya “what-if”.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (chaguomsingi, hakuna CBT)
  - `When Supported` (enforcement ya sehemu: clients zinazotumia CBT lazima zitoe token halali; clients zisizotumia CBT bado zinaweza kufanya bind, na audit events hutolewa)
  - `Always` (tekeleza: hukataa LDAPS binds zisizo na CBT halali)<sup>[[1]](#references)</sup>
- **Audit**: weka **When Supported** ili kuona:
  - **3074** – LDAPS bind ingeshindwa uthibitishaji wa CBT kama enforcement ingetekelezwa.
  - **3075** – LDAPS bind haikujumuisha data ya CBT na ingekataliwa kama enforcement ingetekelezwa.
  - (Event **3039** bado huashiria kushindwa kwa CBT kwenye builds za zamani.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: weka **Always** baada ya clients za LDAPS kutuma CBTs; hufanya kazi kwenye **LDAPS** pekee (si raw 389).<sup>[[1]](#references)</sup>

`When Supported` si audit pekee: huthibitisha CBT kwa clients zinazoiunga mkono huku ikiruhusu clients zisizo na usaidizi wa CBT. [Marejeleo ya policy ya Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) yanaeleza defaults zinazotegemea version. LDAP signing hutumika kwa binds husika kwenye LDAP/389; channel binding hutumika kwa LDAP authentication inayolindwa na TLS.


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (badala ya `Negotiate signing`, chaguomsingi kwenye Windows za kisasa).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (chaguomsingi ni `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: acha policy ya legacy ikiwa `None` na uweke `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` humaanisha enforced kwa chaguomsingi; weka `Disabled` ili kuepuka enforcement).<sup>[[1]](#references)</sup>
- **Compatibility**: Orodhesha vifaa na applications zisizo za Windows zinazotumia simple binds au SASL binds zisizosainiwa. Microsoft inaandika kuhusu usaidizi kwenye Windows versions zinazodumishwa; kauli kuhusu compatibility ya legacy clients zinapaswa kuthibitishwa kwa kutumia client stack halisi badala ya kuzifupisha kuwa kizingiti cha version ya XP.<sup>[[2]](#references)</sup>

## Njia za relay na signed-SASL reauthentication

Ikiwa **signing pekee** ndiyo inayohitajika, relay kwenda LDAPS bado inaweza kufanya kazi wakati channel binding haijatekelezwa: TLS hutoa transport integrity. Ikiwa **channel binding pekee** ndiyo inayohitajika, plain LDAP haina TLS channel ya kufungia; relay inaweza kufanya authentication kupitia TCP 389 kisha kutumia StartTLS kwa operations zinazohitaji TLS, ikiwa identity iliyorelayiwa ina ruhusa zinazohitajika. Kutekeleza zote mbili hufunga njia hizi za kawaida, lakini hakukuzuia udhaifu ufuatao kwenye domain controllers ambazo hazijapachikwa.<sup>[[5]](#references)</sup>

### Kuongeza LDAP operation baada ya relayed Bind

Kwenye Windows Server 2016–2025 domain controllers zilizoathirika, kwanza anzisha **signed NTLM SASL LDAP connection** kwenye TCP 389 kama identity X, ukitumia credentials ambazo unajua session key yake (au anonymous NTLM SASL context pale inapokubaliwa). Shurutisha identity Y kufanya authentication **kupitia SMB** kwenda kwa relay. Sambaza NTLM NEGOTIATE ya Y na CHALLENGE ya DC kupitia GSS-SPNEGO Bind requests kwenye LDAP connection iliyopo ya X. Windows SMB client huweka `NTLMSSP_NEGOTIATE_SIGN`, kwa hivyo LDAP bind inayotokana nayo huhitaji signed SASL layer; exchange inayotoka HTTP/WebDAV kwa kawaida haina flag hiyo na haiwezi kutumika badala yake katika hali hii.<sup>[[5]](#references)</sup>

Y inapotuma NTLM AUTHENTICATE, weka **LDAP messages mbili tofauti ndani ya SASL record moja yenye length prefix**: BindRequest yenye response hiyo, ikifuatiwa na ModifyRequest. Saini record nzima kwa kutumia key inayojulikana ya X. DC iliyo hatarini huthibitisha record kwa kutumia X, hukamilisha Bind na kubadilisha authorization ya connection kuwa ya Y, kisha hutekeleza ModifyRequest iliyobaki kama Y bila kuthibitisha tena record kwa kutumia key ya Y. Hii haifichui password au session key ya Y; record ya baadaye iliyosainiwa na X itashindwa. Uandishi wa RBCD kwenye `msDS-AllowedToActOnBehalfOfOtherIdentity` au uandishi wa shadow credential kwenye `msDS-KeyCredentialLink` bado unahitaji Y kuwa na ruhusa kwenye target object. Tazama [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md), na, kwa akaunti ya mashine ya DC iliyorelayiwa, [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

Hii ni bypass ya **plain LDAP**, si bypass ya LDAPS channel binding. Kwenye LDAPS, TLS hulinda connection na Windows haiundi NTLM SASL signing layer ya X-key inayohitajika kwa njia hii ya record-stacking. TCP 389 isipopatikana, technique hii haihamishiki tu kwenda TCP 636. Security updates za Oktoba 2026 huzuia operation ya same-record kwa kutupa data iliyobaki baada ya Bind kubadilisha utambulisho wa connection.<sup>[[5]](#references)</sup> KB5126646 ni update ya Windows Server 2025; matoleo mengine ya Server yaliyoathirika yana namba tofauti za KB.<sup>[[7]](#references)</sup>

[LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) ya mtafiti hufungasha `ntlmrelayx.py` iliyorekebishwa kwa workflow hii. Inahitaji chanzo cha SMB coercion, Impacket tree maalum inayotoa LDAP signing/security-context APIs (PyPI Impacket 0.13.1 haitoshi), na account inayodhibitiwa na mshambulizi kwa initial signed bind. Kwa uandishi wa RBCD, toa DN ya victim object na SID ya computer ya delegating inayodhibitiwa; tumia `-attribute` pamoja na `-value` au `-value-hex` kwa uandishi mwingine unaoruhusiwa. Thibitisha matokeo kwa signed read-back huru ya tool, badala ya kuchukulia ujumbe wa `FAILED` wa upande wa relay kuwa uthibitisho kwamba ModifyRequest ilishindwa.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Anzisha uthibitishaji wa SMB kando; tazama [forcing privileged NTLM authentication](printers-spooler-service-abuse.md) kwa njia moja ya kulazimisha uthibitishaji na [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) kwa njia nyingine. Amri na utekelezaji wa zana hiyo vimeandikwa kwenye repository yake.<sup>[[6]](#references)</sup>

## Utekelezaji unaoanza na ukaguzi (inapendekezwa kwa takriban siku 30)

1. Washa uchunguzi wa kiolesura cha LDAP kwenye kila DC ili kurekodi unsigned binds (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Weka DC GPO `LDAP server channel binding token requirements` = **When Supported** kwa utekelezaji wa sehemu wa CBT na telemetry; thibitisha kwanza ulinganifu na clients za zamani.<sup>[[1]](#references)</sup>
3. Fuatilia matukio ya Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – bind zisizo na signing/zinazoruhusu bind zisizo na signing (hazitii masharti ya signing).
   - **3074/3075** – bind za LDAPS ambazo zingeshindwa au kuacha CBT (zinahitaji KB4520412 kwenye 2019/2022 na hatua ya 2 hapo juu).
4. Tekeleza katika mabadiliko tofauti:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **au** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP Channel Binding na LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Mahitaji ya LDAP channel binding na signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Sasisho la kupunguza LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing imezimwa → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Signed, Sealed, and Relayed, mtindo wa NTLM](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [Uthibitisho wa dhana wa LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Taarifa kuhusu matoleo ya Windows Server](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
