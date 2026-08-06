# LDAP Signing और Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## यह क्यों महत्वपूर्ण है

LDAP relay/MITM attackers को Domain Controllers तक binds forward करके authenticated contexts प्राप्त करने देता है। दो server-side controls इन paths को प्रभावी रूप से रोकते हैं:

- **LDAP Channel Binding (CBT)** LDAPS bind को specific TLS tunnel से जोड़ता है, जिससे अलग-अलग channels के बीच relays/replays टूट जाते हैं।
- **LDAP Signing** integrity-protected LDAP messages को अनिवार्य करता है, जिससे tampering और अधिकांश unsigned relays रुक जाते हैं।

**त्वरित offensive check**: `netexec ldap <dc> -u user -p pass` जैसे tools server posture दिखाते हैं। यदि आपको `(signing:None)` और `(channel binding:Never)` दिखाई देता है, तो Kerberos/NTLM **relays to LDAP** संभव हैं (उदाहरण के लिए, RBCD के लिए `msDS-AllowedToActOnBehalfOfOtherIdentity` लिखने और administrators का impersonate करने हेतु KrbRelayUp का उपयोग करके)।<sup>[[4]](#references)</sup>

**Server 2025 DCs** एक नई GPO (**LDAP server signing requirements Enforcement**) पेश करते हैं, जो **Not Configured** रहने पर default रूप से **Require Signing** पर सेट होती है। Enforcement से बचने के लिए आपको उस policy को स्पष्ट रूप से **Disabled** पर सेट करना होगा।<sup>[[1]](#references)</sup>

## LDAP Channel Binding (केवल LDAPS)

- **Requirements**:
- CVE-2017-8563 patch (2017) Extended Protection for Authentication support जोड़ता है।<sup>[[3]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, CBT नहीं)
- `When Supported` (audit: failures emit करता है, block नहीं करता)
- `Always` (enforce: valid CBT के बिना LDAPS binds को reject करता है)<sup>[[1]](#references)</sup>
- **Audit**: failures दिखाने के लिए **When Supported** सेट करें:
- **3074** – यदि enforcement लागू होता, तो LDAPS bind CBT validation में fail हो जाता।
- **3075** – LDAPS bind ने CBT data शामिल नहीं किया और यदि enforcement लागू होता, तो reject कर दिया जाता।
- (पुराने builds पर Event **3039** अभी भी CBT failures का संकेत देता है।)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: LDAPS clients द्वारा CBTs भेजे जाने के बाद **Always** सेट करें; यह केवल **LDAPS** पर प्रभावी है (raw 389 पर नहीं)।<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (आधुनिक Windows पर default `Negotiate signing` के विपरीत)।<sup>[[1]](#references)</sup>
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default `None` है)।<sup>[[2]](#references)</sup>
- **Server 2025**: legacy policy को `None` पर रहने दें और `LDAP server signing requirements Enforcement` = `Enabled` सेट करें (Not Configured = default रूप से enforced; इससे बचने के लिए `Disabled` सेट करें)।<sup>[[1]](#references)</sup>
- **Compatibility**: केवल Windows **XP SP3+** LDAP signing को support करता है; enforcement enabled होने पर पुराने systems काम करना बंद कर देंगे।

## Audit-first rollout (अनुशंसित ~30 दिन)

1. unsigned binds को log करने के लिए प्रत्येक DC पर LDAP interface diagnostics enable करें (Event **2889**):<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. DC GPO `LDAP server channel binding token requirements` = **When Supported** सेट करें, ताकि CBT telemetry शुरू हो सके।<sup>[[1]](#references)</sup>
3. Directory Service events की निगरानी करें:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – unsigned/unsigned-allow binds (signing noncompliant)।
- **3074/3075** – ऐसे LDAPS binds जो fail होंगे या CBT को omit करेंगे (2019/2022 पर KB4520412 और ऊपर दिया गया step 2 आवश्यक है)।
4. अलग-अलग changes में enforce करें:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs)।
- `LDAP client signing requirements` = **Require signing** (clients)।
- `LDAP server signing requirements` = **Require signing** (DCs) **या** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**।

## संदर्भ

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
