# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## यह क्यों मायने रखता है

LDAP relay/MITM attacks में authentication को domain controller तक forward किया जाता है, ताकि authenticated LDAP context प्राप्त किया जा सके। [name-resolution poisoning and relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) में इससे जुड़ी व्यापक प्रक्रिया दी गई है। दो संबंधित controls इन रास्तों को सीमित करते हैं:

- **LDAP channel binding (CBT)** लागू होने पर authentication को LDAPS द्वारा उपयोग किए गए TLS server certificate/channel से bind करता है, जिससे cross-channel relay मुश्किल हो जाता है।
- **LDAP signing**, SASL LDAP binds के लिए integrity protection अनिवार्य करता है। इससे confidentiality नहीं मिलती; LDAP contents को encrypt करने की आवश्यकता हो तो TLS का उपयोग करें।<sup>[[2]](#references)</sup>

**त्वरित posture जाँच**: `netexec ldap <dc> -u user -p pass` जैसे tools, signing और channel-binding की दिखाई गई policy बताते हैं। `(signing:None)` और `(channel binding:Never)` का अर्थ है कि controls लागू नहीं हैं, लेकिन सफल relay अब भी captured authentication type, EPA behavior, account privileges, target protocol और relay protections पर निर्भर करता है। जब relayed principal के पास आवश्यक अधिकार हों, तो KrbRelayUp जैसे tools `msDS-AllowedToActOnBehalfOfOtherIdentity` लिख सकते हैं, resource-based constrained delegation (RBCD) configure कर सकते हैं और परिणामी delegation path का उपयोग करके किसी privileged principal का impersonation कर सकते हैं।<sup>[[4]](#references)</sup>

**Server 2025 DCs** में एक नई GPO (**LDAP server signing requirements Enforcement**) शामिल है, जो **Not Configured** रहने पर डिफ़ॉल्ट रूप से **Require Signing** लागू करती है। इसे लागू होने से रोकने के लिए आपको स्पष्ट रूप से उस policy को **Disabled** पर सेट करना होगा।<sup>[[1]](#references)</sup>

## LDAP Channel Binding (केवल LDAPS)

- **आवश्यकताएँ**:
  - CVE-2017-8563 patch (2017), Extended Protection for Authentication support जोड़ता है।<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022), LDAPS CBT “what-if” telemetry जोड़ता है।<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (डिफ़ॉल्ट, CBT नहीं)
  - `When Supported` (आंशिक enforcement: CBT-सक्षम clients को valid token देना होगा; CBT support के बिना clients फिर भी bind कर सकते हैं और audit events जारी होते हैं)
  - `Always` (enforce: valid CBT के बिना LDAPS binds अस्वीकार करता है)<sup>[[1]](#references)</sup>
- **Audit**: इन घटनाओं को देखने के लिए **When Supported** सेट करें:
  - **3074** – यदि enforcement लागू होता, तो यह LDAPS bind CBT validation में विफल होता।
  - **3075** – इस LDAPS bind में CBT data नहीं था और enforcement लागू होने पर इसे अस्वीकार कर दिया जाता।
  - (पुराने builds में Event **3039** अब भी CBT failures दर्शाता है।)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: LDAPS clients द्वारा CBT भेजना शुरू करने के बाद **Always** सेट करें; यह केवल **LDAPS** पर प्रभावी है (raw 389 पर नहीं)।<sup>[[1]](#references)</sup>

`When Supported` केवल audit के लिए नहीं है: यह CBT-सक्षम clients के CBT को validate करता है और CBT support के बिना clients को अनुमति देता है। [Microsoft policy reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) में version के अनुसार बदलने वाले defaults बताए गए हैं। LDAP signing, LDAP/389 पर लागू binds पर असर डालता है; channel binding, TLS-सुरक्षित LDAP authentication पर लागू होता है।


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (आधुनिक Windows में डिफ़ॉल्ट `Negotiate signing` के बजाय)।<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (डिफ़ॉल्ट `None` है)।<sup>[[2]](#references)</sup>
  - **Server 2025**: legacy policy को `None` पर रहने दें और `LDAP server signing requirements Enforcement` = `Enabled` सेट करें (`Not Configured` होने पर डिफ़ॉल्ट रूप से enforce होता है; इसे लागू होने से रोकने के लिए `Disabled` सेट करें)।<sup>[[1]](#references)</sup>
- **Compatibility**: simple binds या unsigned SASL binds का उपयोग करने वाले non-Windows appliances और applications की सूची बनाएँ। Microsoft maintained Windows versions पर support का दस्तावेज़ देता है; legacy-client compatibility से जुड़े कथनों को XP version की सीमा तक सीमित करने के बजाय, वास्तविक client stack के विरुद्ध सत्यापित करना चाहिए।<sup>[[2]](#references)</sup>

## पहले Audit करें (लगभग 30 दिनों का rollout अनुशंसित)

1. Unsigned binds log करने के लिए प्रत्येक DC पर LDAP interface diagnostics सक्षम करें (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. आंशिक CBT enforcement और telemetry के लिए DC GPO `LDAP server channel binding token requirements` = **When Supported** सेट करें; पहले legacy-client compatibility validate करें।<sup>[[1]](#references)</sup>
3. Directory Service events monitor करें:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – unsigned/unsigned-allow binds (signing अनुपालक नहीं है)।
   - **3074/3075** – ऐसे LDAPS binds जो fail होंगे या जिनमें CBT नहीं होगा (2019/2022 पर KB4520412 और ऊपर दिया गया step 2 आवश्यक है)।
4. अलग-अलग बदलावों में enforce करें:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs)।
   - `LDAP client signing requirements` = **Require signing** (clients)।
   - `LDAP server signing requirements` = **Require signing** (DCs) **या** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**।



## References

- [1] [TrustedSec - LDAP Channel Binding और LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding और signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
