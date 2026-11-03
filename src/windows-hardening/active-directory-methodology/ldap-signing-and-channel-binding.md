# LDAP Signing & Channel Binding को Hardening करना

{{#include ../../banners/hacktricks-training.md}}

## यह क्यों मायने रखता है

LDAP relay/MITM attacks में authentication को domain controller तक forward किया जाता है, ताकि authenticated LDAP context प्राप्त किया जा सके। [name-resolution poisoning and relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) में इस व्यापक workflow का विवरण है। दो संबंधित controls इन रास्तों को कम करते हैं:

- **LDAP channel binding (CBT)** लागू authentication को LDAPS द्वारा उपयोग किए गए TLS server certificate/channel से bind करता है, जिससे cross-channel relay कठिन हो जाता है।
- **LDAP signing** के लिए SASL LDAP binds पर integrity protection आवश्यक है। इससे confidentiality नहीं मिलती; अगर LDAP contents को भी encrypt करना हो, तो TLS का उपयोग करें।<sup>[[2]](#references)</sup>

**त्वरित posture जाँच**: `netexec ldap <dc> -u user -p pass` जैसे tools देखी गई signing और channel-binding policy की रिपोर्ट देते हैं। `(signing:None)` और `(channel binding:Never)` का अर्थ है कि controls मौजूद नहीं हैं, लेकिन relay की सफलता फिर भी captured authentication type, EPA behavior, account privileges, target protocol और relay protections पर निर्भर करती है। जब relayed principal के पास आवश्यक rights हों, तो KrbRelayUp जैसे tools `msDS-AllowedToActOnBehalfOfOtherIdentity` लिख सकते हैं, resource-based constrained delegation (RBCD) configure कर सकते हैं, और resulting delegation path का उपयोग करके किसी privileged principal का impersonation कर सकते हैं।<sup>[[4]](#references)</sup>

**Server 2025 DCs** में एक नया GPO (**LDAP server signing requirements Enforcement**) शामिल है, जो **Not Configured** रहने पर डिफ़ॉल्ट रूप से **Require Signing** पर सेट होता है। Enforcement से बचने के लिए आपको उस policy को स्पष्ट रूप से **Disabled** पर सेट करना होगा।<sup>[[1]](#references)</sup>

## LDAP Channel Binding (केवल LDAPS)

- **आवश्यकताएँ**:
  - CVE-2017-8563 patch (2017) Extended Protection for Authentication support जोड़ता है।<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) LDAPS CBT “what-if” telemetry जोड़ता है।<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (डिफ़ॉल्ट, CBT नहीं)
  - `When Supported` (आंशिक enforcement: CBT-सक्षम clients को valid token देना होगा; CBT support न रखने वाले clients फिर भी bind कर सकते हैं, और audit events जारी होते हैं)
  - `Always` (enforce: valid CBT के बिना LDAPS binds अस्वीकार करता है)<sup>[[1]](#references)</sup>
- **Audit**: निम्नलिखित events देखने के लिए **When Supported** सेट करें:
  - **3074** – अगर enforcement लागू होता, तो CBT validation विफल होने के कारण LDAPS bind विफल हो जाता।
  - **3075** – LDAPS bind में CBT data नहीं था और enforcement लागू होने पर उसे अस्वीकार कर दिया जाता।
  - (पुराने builds पर Event **3039** अब भी CBT failures दर्शाता है।)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: LDAPS clients के CBT भेजने के बाद **Always** सेट करें; यह केवल **LDAPS** पर प्रभावी है (raw 389 पर नहीं)।<sup>[[1]](#references)</sup>

`When Supported` केवल audit के लिए नहीं है: यह CBT-सक्षम clients के CBT को validate करता है और CBT support न रखने वाले clients को अनुमति देता है। [Microsoft policy reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) में version के अनुसार बदलने वाले defaults का विवरण है। LDAP signing, LDAP/389 पर लागू binds पर असर करता है; channel binding, TLS-सुरक्षित LDAP authentication पर लागू होता है।

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (आधुनिक Windows पर डिफ़ॉल्ट `Negotiate signing` के बजाय)।<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (डिफ़ॉल्ट `None` है)।<sup>[[2]](#references)</sup>
  - **Server 2025**: legacy policy को `None` पर रहने दें और `LDAP server signing requirements Enforcement` = `Enabled` सेट करें (`Not Configured` होने पर डिफ़ॉल्ट रूप से enforcement लागू होता है; इससे बचने के लिए `Disabled` सेट करें)।<sup>[[1]](#references)</sup>
- **Compatibility**: simple binds या unsigned SASL binds का उपयोग करने वाले non-Windows appliances और applications की सूची बनाएँ। Microsoft maintained Windows versions पर support का दस्तावेज़ देता है; legacy-client compatibility से जुड़े बयानों को XP version threshold तक सीमित करने के बजाय वास्तविक client stack के आधार पर सत्यापित करना चाहिए।<sup>[[2]](#references)</sup>

## Relay paths और signed-SASL reauthentication

अगर **केवल signing** आवश्यक है, तो channel binding लागू न होने पर LDAPS पर relay अब भी काम कर सकता है: TLS transport integrity देता है। अगर **केवल channel binding** आवश्यक है, तो plain LDAP में bind करने के लिए TLS channel नहीं होता; relay TCP 389 पर authenticate कर सकता है और फिर उन operations के लिए StartTLS का उपयोग कर सकता है जिन्हें TLS चाहिए, बशर्ते relayed identity के पास आवश्यक rights हों। दोनों लागू करने से ये आम विकल्प बंद हो जाते हैं, लेकिन इससे unpatched domain controllers पर मौजूद अगली खामी नहीं रुकी।<sup>[[5]](#references)</sup>

### Relayed Bind के बाद LDAP operation जोड़ना

प्रभावित Windows Server 2016–2025 domain controllers पर, पहले TCP 389 पर identity X के रूप में **signed NTLM SASL LDAP connection** स्थापित करें। इसके लिए ऐसे credentials इस्तेमाल करें जिनकी session key आपको पता हो (या स्वीकार किए जाने पर anonymous NTLM SASL context)। Identity Y को **SMB** के ज़रिए relay तक authenticate करने के लिए coerce करें। Y का NTLM NEGOTIATE और DC का CHALLENGE, X के मौजूदा LDAP connection पर GSS-SPNEGO Bind requests के ज़रिए forward करें। Windows SMB client `NTLMSSP_NEGOTIATE_SIGN` flag सेट करता है, इसलिए resulting LDAP bind के लिए signed SASL layer आवश्यक होती है; HTTP/WebDAV से शुरू हुआ exchange आम तौर पर यह flag नहीं रखता और यहाँ उसका विकल्प नहीं है।<sup>[[5]](#references)</sup>

जब Y NTLM AUTHENTICATE भेजता है, तो **एक length-prefixed SASL record में दो अलग LDAP messages** रखें: उस response वाला BindRequest, फिर एक ModifyRequest। पूरे record को X की ज्ञात key से sign करें। vulnerable DC record को X के अंतर्गत verify करता है, Bind पूरा करके connection का authorization Y पर बदलता है, फिर बाकी ModifyRequest को Y के रूप में record को Y की key से दोबारा जाँचे बिना execute करता है। इससे Y का password या session key उजागर नहीं होता; X से sign किया गया बाद का record विफल होगा। `msDS-AllowedToActOnBehalfOfOtherIdentity` पर RBCD write या `msDS-KeyCredentialLink` पर shadow-credential write के लिए अब भी ज़रूरी है कि Y के पास target object पर permission हो। [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md), और relayed DC machine account के मामले में [DCSync](dcsync.md) देखें।<sup>[[5]](#references)</sup>

यह **plain LDAP** bypass है, LDAPS channel-binding bypass नहीं। LDAPS पर TLS connection को सुरक्षित करता है और Windows इस record-stacking path के लिए आवश्यक X-key NTLM SASL signing layer स्थापित नहीं करता। अगर TCP 389 उपलब्ध नहीं है, तो यह technique सीधे TCP 636 पर इस्तेमाल नहीं की जा सकती। October 2026 security updates, Bind द्वारा connection identity बदलने के बाद बचा हुआ data discard करके इसी record में operation होने से रोकते हैं।<sup>[[5]](#references)</sup> KB5126646, Windows Server 2025 का update है; अन्य प्रभावित Server releases के KB numbers अलग हैं।<sup>[[7]](#references)</sup>

शोधकर्ता का [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) इस workflow के लिए संशोधित `ntlmrelayx.py` को wrap करता है। इसके लिए **SMB** coercion source, LDAP signing/security-context APIs उपलब्ध कराने वाला pinned Impacket tree (PyPI Impacket 0.13.1 पर्याप्त नहीं है), और शुरुआती signed bind के लिए attacker-controlled account चाहिए। RBCD write के लिए victim object का DN और नियंत्रित delegating computer का SID दें; किसी अन्य अनुमत write के लिए `-attribute` के साथ `-value` या `-value-hex` का उपयोग करें। Tool द्वारा की गई independent signed read-back की पुष्टि करें; relay-side `FAILED` message को इस बात का प्रमाण न मानें कि ModifyRequest विफल हुआ।<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

SMB authentication को अलग से trigger करें; coercion surface के एक उदाहरण के लिए [privileged NTLM authentication को force करना](printers-spooler-service-abuse.md) देखें, और अन्य उदाहरणों के लिए [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) देखें। टूल का command और implementation उसके repository में documented हैं।<sup>[[6]](#references)</sup>

## Audit-first rollout (अनुशंसित ~30 दिन)

1. Unsigned binds लॉग करने के लिए हर DC पर LDAP interface diagnostics enable करें (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. आंशिक CBT enforcement और telemetry के लिए DC GPO `LDAP server channel binding token requirements` = **When Supported** सेट करें; पहले legacy-client compatibility की पुष्टि करें।<sup>[[1]](#references)</sup>
3. Directory Service events की निगरानी करें:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – unsigned/unsigned-allow binds (signing अनुपालन नहीं)।
   - **3074/3075** – ऐसे LDAPS binds जो विफल हो सकते हैं या CBT छोड़ सकते हैं (इसके लिए 2019/2022 पर KB4520412 और ऊपर दिया गया चरण 2 आवश्यक है)।
4. अलग-अलग बदलावों में लागू करें:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs)।
   - `LDAP client signing requirements` = **Require signing** (clients)।
   - `LDAP server signing requirements` = **Require signing** (DCs) **या** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**।



## References

- [1] [TrustedSec - LDAP Channel Binding और LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding और signing आवश्यकताएँ](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Signed, Sealed, and Relayed, NTLM-style](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [LDAP Switcheroo proof of concept](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Windows Server release information](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
