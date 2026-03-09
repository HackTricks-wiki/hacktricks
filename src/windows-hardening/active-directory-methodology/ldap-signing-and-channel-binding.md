# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## क्यों यह महत्वपूर्ण है

LDAP relay/MITM हमलावरों को Domain Controllers पर binds फॉरवर्ड करके authenticated contexts प्राप्त करने देता है। इन मार्गों को रोकने के लिए दो server-side नियंत्रण हैं:

- **LDAP Channel Binding (CBT)** एक LDAPS bind को विशिष्ट TLS टनल से बाँधता है, जिससे विभिन्न चैनलों में relays/replays टूट जाते हैं।
- **LDAP Signing** integrity-protected LDAP messages को अनिवार्य करता है, tampering और अधिकांश unsigned relays को रोकता है।

**Quick offensive check**: `netexec ldap <dc> -u user -p pass` जैसे टूल सर्वर की स्थिति दिखाते हैं। यदि आप `(signing:None)` और `(channel binding:Never)` देखते हैं, तो Kerberos/NTLM **relays to LDAP** व्यावहारिक हैं (उदा., KrbRelayUp का उपयोग करके `msDS-AllowedToActOnBehalfOfOtherIdentity` लिखने के लिए RBCD और प्रशासकों का प्रतिरूपण करने हेतु)।

**Server 2025 DCs** एक नया GPO (**LDAP server signing requirements Enforcement**) पेश करते हैं जो जब **Not Configured** पर छोड़ा जाता है तो डिफ़ॉल्ट रूप से **Require Signing** होता है। लागूकरण से बचने के लिए आपको उस नीति को स्पष्ट रूप से **Disabled** पर सेट करना होगा।

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch (2017) Extended Protection for Authentication समर्थन जोड़ता है।
- **KB4520412** (Server 2019/2022) LDAPS CBT “what-if” telemetry जोड़ता है।
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emits failures, does not block)
- `Always` (enforce: rejects LDAPS binds without valid CBT)
- **Audit**: surface करने के लिए **When Supported** सेट करें:
- **3074** – LDAPS bind CBT validation विफल हो जाता यदि लागू किया गया होता।
- **3075** – LDAPS bind ने CBT डेटा छोड़ दिया और यदि लागू किया गया होता तो अस्वीकृत हो जाता।
- (Event **3039** अभी भी पुराने बिल्ड्स पर CBT विफलताओं का संकेत देता है।)
- **Enforcement**: LDAPS क्लाइंट CBT भेजना शुरू करने पर **Always** सेट करें; यह केवल **LDAPS** पर प्रभावी है (raw 389 पर नहीं)।

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: legacy policy को `None` पर छोड़ें और `LDAP server signing requirements Enforcement` = `Enabled` सेट करें (Not Configured = डिफ़ॉल्ट रूप से लागू; इससे बचने के लिए `Disabled` सेट करें)।
- **Compatibility**: केवल Windows **XP SP3+** LDAP signing का समर्थन करते हैं; पुराने सिस्टम enforcement सक्षम होने पर टूट सकते हैं।

## Audit-first rollout (recommended ~30 days)

1. प्रत्येक DC पर LDAP interface diagnostics सक्षम करें ताकि unsigned binds (Event **2889**) लॉग हो सकें:
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. CBT telemetry शुरू करने के लिए DC GPO `LDAP server channel binding token requirements` = **When Supported** सेट करें।
3. Directory Service घटनाओं की निगरानी करें:
- **2889** – unsigned/unsigned-allow binds (signing अनुपालन नहीं)।
- **3074/3075** – ऐसे LDAPS binds जो CBT को विफल या छोड़ देंगे (इसके लिए 2019/2022 पर KB4520412 और ऊपर कदम 2 आवश्यक है)।
4. अलग परिवर्तनों में लागू करें:
- `LDAP server channel binding token requirements` = **Always** (DCs)।
- `LDAP client signing requirements` = **Require signing** (clients)।
- `LDAP server signing requirements` = **Require signing** (DCs) **या** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**।

## संदर्भ

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
