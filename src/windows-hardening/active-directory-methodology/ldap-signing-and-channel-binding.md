# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## क्यों यह महत्वपूर्ण है

LDAP relay/MITM से आक्रमणकारी Domain Controllers पर binds अग्रेषित करके authenticated contexts प्राप्त कर सकते हैं। ये दोनों सर्वर-साइड नियंत्रण इन मार्गों को रोकते हैं:

- **LDAP Channel Binding (CBT)** LDAPS bind को विशिष्ट TLS टनल से जोड़ता है, जिससे विभिन्न चैनलों में relays/replays टूट जाते हैं।
- **LDAP Signing** LDAP संदेशों की integrity-सुरक्षा को अनिवार्य करता है, जिससे tampering और अधिकांश unsigned relays रोके जाते हैं।

**Quick offensive check**: `netexec ldap <dc> -u user -p pass` जैसे उपकरण सर्वर की स्थिति प्रदर्शित करते हैं। यदि आप `(signing:None)` और `(channel binding:Never)` देखते हैं, तो Kerberos/NTLM **relays to LDAP** संभव हैं (उदा., KrbRelayUp का उपयोग करके `msDS-AllowedToActOnBehalfOfOtherIdentity` लिखने के लिए RBCD और administrators का impersonate करने के लिए)।

**Server 2025 DCs** एक नया GPO (**LDAP server signing requirements Enforcement**) पेश करते हैं जो जब **Not Configured** छोड़ा जाता है तो डिफ़ॉल्ट रूप से **Require Signing** होता है। प्रवर्तन से बचने के लिये आपको स्पष्ट रूप से उस नीति को **Disabled** पर सेट करना होगा।

## LDAP Channel Binding (LDAPS only)

- **आवश्यकताएँ**:
- CVE-2017-8563 patch (2017) Extended Protection for Authentication समर्थन जोड़ता है।
- **KB4520412** (Server 2019/2022) LDAPS CBT “what-if” telemetry जोड़ता है।
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, कोई CBT नहीं)
- `When Supported` (audit: failures को emitir करता है, block नहीं करता)
- `Always` (enforce: वैध CBT के बिना LDAPS binds को reject करता है)
- **ऑडिट**: surface करने के लिए **When Supported** सेट करें:
- **3074** – यदि लागू किया गया होता तो LDAPS bind CBT validation में असफल होता।
- **3075** – LDAPS bind ने CBT डेटा छोड़ा और यदि लागू किया गया होता तो reject हो जाता।
- (Event **3039** अभी भी पुराने बिल्डों पर CBT असफलताओं का संकेत देता है।)
- **प्रवर्तन**: एक बार LDAPS clients CBTs भेजने लगे तो **Always** सेट करें; केवल **LDAPS** पर प्रभावी (raw 389 पर नहीं)।

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (विरुद्ध `Negotiate signing` जो आधुनिक Windows पर डिफ़ॉल्ट है)।
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (डिफ़ॉल्ट `None` है)।
- **Server 2025**: legacy नीति को `None` पर छोड़ें और `LDAP server signing requirements Enforcement` = `Enabled` सेट करें (Not Configured = डिफ़ॉल्ट रूप से लागू; इससे बचने के लिए `Disabled` सेट करें)।
- **अनुकूलता**: केवल Windows **XP SP3+** LDAP signing को सपोर्ट करता है; पुराने सिस्टम प्रवर्तन सक्षम होने पर टूट सकते हैं।

## Audit-first rollout (recommended ~30 days)

1. प्रत्येक DC पर LDAP interface diagnostics सक्षम करें ताकि unsigned binds लॉग हों (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. CBT telemetry शुरू करने के लिए DC GPO `LDAP server channel binding token requirements` = **When Supported** सेट करें.
3. Directory Service घटनाओं की निगरानी करें:
- **2889** – unsigned/unsigned-allow binds (signing गैर-अनुपालन).
- **3074/3075** – LDAPS binds जो CBT को फेल या छोड़ सकते हैं (इसके लिए 2019/2022 पर KB4520412 और ऊपर दिए गए step 2 की आवश्यकता होती है).
4. अलग-अलग परिवर्तनों में लागू करें:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **या** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
