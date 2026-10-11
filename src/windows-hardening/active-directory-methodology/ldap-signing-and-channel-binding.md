# LDAP Signing & Channel Binding को Hardening करना

{{#include ../../banners/hacktricks-training.md}}

## यह क्यों महत्वपूर्ण है

LDAP relay/MITM attacks, authenticated LDAP context प्राप्त करने के लिए authentication को domain controller तक forward करते हैं। इनसे जुड़े दो controls ऐसे रास्तों को कम करते हैं:

- **LDAP channel binding (CBT)**, LDAPS द्वारा उपयोग किए गए TLS server certificate/channel से लागू authentication को bind करता है, जिससे cross-channel relay मुश्किल हो जाता है।
- **LDAP signing**, SASL LDAP binds के लिए integrity protection अनिवार्य करता है। यह confidentiality नहीं जोड़ता; LDAP contents को encrypt करने की आवश्यकता होने पर TLS का उपयोग करें।<sup>[[2]](#references)</sup>

**त्वरित posture जाँच**: `netexec ldap <dc> -u user -p pass` जैसे tools, देखी गई signing और channel-binding policy की जानकारी देते हैं। `(signing:None)` और `(channel binding:Never)` का अर्थ है कि controls मौजूद नहीं हैं, लेकिन सफल relay, captured authentication type, EPA behavior, account privileges, target protocol और relay protections पर भी निर्भर करता है। जब relayed principal के पास आवश्यक अधिकार हों, तो KrbRelayUp जैसे tooling `msDS-AllowedToActOnBehalfOfOtherIdentity` लिख सकते हैं, resource-based constrained delegation (RBCD) configure कर सकते हैं और resulting delegation path का उपयोग करके privileged principal का impersonation कर सकते हैं।<sup>[[4]](#references)</sup>

**Server 2025 DCs** में एक नई GPO (**LDAP server signing requirements Enforcement**) आती है, जो **Not Configured** रहने पर default रूप से **Require Signing** पर सेट होती है। Enforcement से बचने के लिए आपको उस policy को स्पष्ट रूप से **Disabled** पर सेट करना होगा।<sup>[[1]](#references)</sup>

## LDAP Channel Binding (केवल LDAPS)

- **आवश्यकताएँ**:
  - CVE-2017-8563 patch (2017), Extended Protection for Authentication support जोड़ता है।<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022), LDAPS CBT “what-if” telemetry जोड़ता है।<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (default, CBT नहीं)
  - `When Supported` (आंशिक enforcement: CBT-capable clients को valid token देना होगा; CBT support के बिना clients फिर भी bind कर सकते हैं और audit events जारी होते हैं)
  - `Always` (enforcement: valid CBT के बिना LDAPS binds अस्वीकार करता है)<sup>[[1]](#references)</sup>
- **Audit**: यह दिखाने के लिए **When Supported** सेट करें:
  - **3074** – यदि enforcement लागू होता, तो LDAPS bind CBT validation में विफल होता।
  - **3075** – LDAPS bind में CBT data नहीं था और enforcement लागू होने पर उसे अस्वीकार कर दिया जाता।
  - (पुराने builds पर Event **3039** अब भी CBT failures का संकेत देता है।)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: LDAPS clients द्वारा CBTs भेजना शुरू करने पर **Always** सेट करें; यह केवल **LDAPS** पर प्रभावी है (raw 389 पर नहीं)।<sup>[[1]](#references)</sup>

`When Supported` केवल audit के लिए नहीं है: यह CBT-capable clients के CBT को validate करता है, जबकि CBT support के बिना clients को अनुमति देता है। [Microsoft policy reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) में version-dependent defaults दिए गए हैं। LDAP signing, LDAP/389 पर लागू binds पर असर डालता है; channel binding, TLS-protected LDAP authentication पर लागू होता है।

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (आधुनिक Windows में default `Negotiate signing` के विपरीत)।<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default `None` है)।<sup>[[2]](#references)</sup>
  - **Server 2025**: legacy policy को `None` पर रहने दें और `LDAP server signing requirements Enforcement` = `Enabled` सेट करें (`Not Configured` होने पर default रूप से enforcement लागू होता है; इससे बचने के लिए `Disabled` सेट करें)।<sup>[[1]](#references)</sup>
- **Compatibility**: simple binds या unsigned SASL binds का उपयोग करने वाले non-Windows appliances और applications की inventory बनाएँ। Microsoft maintained Windows versions पर support का दस्तावेज़ देता है; legacy-client compatibility के दावों को XP version threshold तक सीमित करने के बजाय वास्तविक client stack के आधार पर जाँचना चाहिए।<sup>[[2]](#references)</sup>

## पहले audit के साथ rollout (लगभग 30 दिन अनुशंसित)

1. Unsigned binds log करने के लिए हर DC पर LDAP interface diagnostics सक्षम करें (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. आंशिक CBT प्रवर्तन और टेलीमेट्री के लिए DC GPO `LDAP server channel binding token requirements` = **When Supported** सेट करें; पहले legacy-client संगतता सत्यापित करें।<sup>[[1]](#references)</sup>
3. Directory Service events मॉनिटर करें:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – unsigned/unsigned-allow binds (signing गैर-अनुपालक)।
   - **3074/3075** – ऐसे LDAPS binds जो विफल होंगे या CBT छोड़ देंगे (2019/2022 पर KB4520412 और ऊपर दिए गए step 2 की आवश्यकता है)।
4. अलग-अलग बदलावों में लागू करें:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs)।
   - `LDAP client signing requirements` = **Require signing** (clients)।
   - `LDAP server signing requirements` = **Require signing** (DCs) **या** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**।

## References

- [1] [TrustedSec - LDAP Channel Binding और LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding और signing आवश्यकताएँ](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
