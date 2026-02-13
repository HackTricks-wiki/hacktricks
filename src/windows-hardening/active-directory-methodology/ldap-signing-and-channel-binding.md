# LDAP Signing & Channel Binding हार्डनिंग

{{#include ../../banners/hacktricks-training.md}}

## यह क्यों महत्वपूर्ण है

LDAP relay/MITM attackers को Domain Controllers पर binds अग्रेषित करने देता है ताकि प्रमाणीकृत संदर्भ (authenticated contexts) प्राप्त किए जा सकें। इन रास्तों को रोकने के लिए दो server-side नियंत्रण हैं:

- **LDAP Channel Binding (CBT)** एक LDAPS bind को विशिष्ट TLS टनल से जोड़ता है, जिससे विभिन्न चैनलों पर relays/replays टूट जाते हैं।
- **LDAP Signing** इन्टीग्रिटी-प्रोटेक्टेड LDAP संदेशों को आवश्यक बनाता है, जिससे छेड़छाड़ और अधिकांश unsigned relays रोके जाते हैं।

**Server 2025 DCs** एक नया GPO (**LDAP server signing requirements Enforcement**) पेश करते हैं जो जब **Not Configured** छोड़ा जाता है तो डिफ़ॉल्ट रूप से **Require Signing** बन जाता है। लागू होने से बचने के लिए आपको उस नीति को स्पष्ट रूप से **Disabled** पर सेट करना होगा।

## LDAP Channel Binding (केवल LDAPS)

- **आवश्यकताएँ**:
- CVE-2017-8563 patch (2017) Extended Protection for Authentication समर्थन जोड़ता है।
- **KB4520412** (Server 2019/2022) LDAPS CBT “what-if” telemetry जोड़ता है।
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (डिफ़ॉल्ट, कोई CBT नहीं)
- `When Supported` (audit: विफलताओं को रिपोर्ट करता है, ब्लॉक नहीं करता)
- `Always` (enforce: वैध CBT के बिना LDAPS binds को अस्वीकार करता है)
- **Audit**: **When Supported** सेट करें ताकि निम्न दिखाई दें:
- **3074** – LDAPS bind लागू होने पर CBT सत्यापन में विफल हो जाता।
- **3075** – LDAPS bind ने CBT डेटा छोड़ दिया और लागू होने पर अस्वीकार किया जाएगा।
- (Event **3039** पुरानी बिल्ड्स पर अभी भी CBT विफलताओं का संकेत देता है.)
- **Enforcement**: एक बार जब LDAPS clients CBTs भेजते हैं तो **Always** सेट करें; केवल **LDAPS** पर प्रभावी है (not raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: legacy policy को `None` पर छोड़ें और `LDAP server signing requirements Enforcement` = `Enabled` सेट करें (Not Configured = डिफ़ॉल्ट रूप से लागू; इससे बचने के लिए `Disabled` सेट करें).
- **Compatibility**: केवल Windows **XP SP3+** LDAP signing का समर्थन करता है; जब enforcement सक्षम होगा तो पुराने सिस्टम टूट सकते हैं।

## Audit-first rollout (recommended ~30 days)

1. प्रत्येक DC पर unsigned binds को लॉग करने के लिए LDAP interface diagnostics सक्षम करें (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. DC GPO `LDAP server channel binding token requirements` = **When Supported** सेट करें ताकि CBT टेलीमेट्री शुरू हो सके।
3. Directory Service घटनाओं की निगरानी करें:
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds जो CBT को छोड़ देंगे या विफल होंगे (2019/2022 पर KB4520412 की आवश्यकता और ऊपर दिए गए चरण 2)।
4. अलग परिवर्तनों में लागू करें:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## संदर्भ

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
