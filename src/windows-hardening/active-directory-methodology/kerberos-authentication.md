# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**यह शानदार post देखें:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## हमलावरों के लिए TL;DR
- Kerberos default AD auth protocol है; अधिकांश lateral-movement chains इससे होकर गुजरेंगी।
- **तीन operator phases** में सोचें:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → password/hash/certificate का उपयोग करके **TGT** प्राप्त करें। यहीं **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, और **PKINIT** आते हैं।
- **TGS-REQ / TGS-REP** → service tickets प्राप्त करने के लिए TGT का उपयोग करें। यहीं **Kerberoasting**, **S4U abuse**, **delegation abuse**, और अधिकांश **ticket-forging tradecraft** प्रासंगिक होते हैं।
- **AP-REQ / AP-REP** → service को ticket प्रस्तुत करें। यहीं **pass-the-ticket** और service-specific lateral movement होता है।
- Hands-on cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse आदि) के लिए देखें:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- इस page का उपयोग **overview / “हाल में क्या बदला”** index के रूप में करें, फिर [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), या [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md) के dedicated pages पर जाएँ।

## Fresh attack notes (2024-2026)
- **RC4 hardening ने defaults बदले हैं, Kerberos को नहीं** – modern DC hardening उन accounts के लिए **default assumed encryption types** पर केंद्रित है जो `msDS-SupportedEncryptionTypes` को explicitly set नहीं करते। 2026 rollout के बाद, patched DCs पर ऐसे accounts increasingly **AES-only** पर default होते हैं, इसलिए blind `/rc4` Kerberoast assumptions अधिक बार fail होती हैं। हालांकि, **explicitly RC4-enabled service accounts अभी भी excellent offline-crack targets हैं**।<sup>[[1]](#references)</sup>
- **Forged tickets के लिए PAC validation enforcement महत्वपूर्ण है** – 2024 PAC-signature hardening के कारण **golden/diamond/sapphire/extraSID-style abuses** को अधिक realistic PAC data और सही signing context की आवश्यकता होती है। Unpatched domains या compatibility/audit-style deployments में छोड़े गए domains अभी भी softer targets रहते हैं।<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos दो बार बदला है**:<sup>[[2]](#references)</sup>
- **Strong certificate binding** (KB5014754 timeline) पूरी तरह enforced environments में sloppy certificate-to-account mappings को कम reliable बनाता है।
- **CVE-2025-26647** ने **altSecID / SKI certificate mappings** के आसपास एक और hardening layer जोड़ी। यदि DCs unpatched हैं, अभी भी auditing कर रहे हैं, या NTAuth validation को explicitly bypass कर रहे हैं, तो pass-the-certificate / shadow-credential follow-on abuse अधिक practical बना रहता है।
- **Cross-domain / cross-forest delegation abuse अभी भी बहुत सक्रिय है** – Windows modern cross-realm **S4U2Self/S4U2Proxy** flows को support करता है, इसलिए किसी अन्य domain में writable delegation attributes अभी भी valuable हैं। बाधा आमतौर पर tooling fidelity और trust/policy details होती है, protocol support नहीं।
- **Recursive multi-domain RBCD operationally महत्वपूर्ण है** – 3+ domain forests में, **S4U2Self/S4U2Proxy** trust referrals के माध्यम से recurse कर सकता है, और **SPN-less** abuse के लिए final **`S4U2Self+U2U`** hop तथा RC4-dependent ticket handling की आवश्यकता हो सकती है। [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) देखें।<sup>[[4]](#references)</sup>
- **Windows Server 2025 ने dMSA migration logic के माध्यम से नई Kerberos-adjacent attack surface पेश की**। यदि आपको 2025 domain में OUs या service-account objects पर delegated rights दिखाई दें, तो इसे “एक और gMSA” मानने के बजाय dedicated [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) देखें।

## Modern domains में fast operator checks

Kerberos attack path चुनने से पहले जल्दी से चार सवालों के जवाब दें:

1. **कौन से accounts अभी भी RC4-friendly हैं?**
2. **किन users को pre-auth की आवश्यकता नहीं है?**
3. **कौन से objects delegation abuse को expose करते हैं?**
4. **Domain के कौन से हिस्से recent hardening enforce करने के लिए पर्याप्त नए हैं?**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
Practical interpretation:
- यदि **interesting SPN accounts are explicitly RC4-capable**, तो Kerberoasting सस्ता और तेज बना रहता है।
- यदि अधिकांश service accounts में **no explicit etype configuration** है, तो updated 2026 DCs पर **AES-only** behavior की अपेक्षा करें और धीमी offline cracking या किसी अलग path की योजना बनाएं।
- यदि **RBCD / KCD / unconstrained delegation** मौजूद है, तो S4U अक्सर brute-force से बेहतर होता है।
- यदि **certificate auth** उपयोग में है, तो याद रखें कि विफल PKINIT path का अर्थ हमेशा यह नहीं होता कि cert बेकार है; कई environments में वही cert अभी भी **Schannel/LDAPS** abuse के लिए काम करता है (देखें [AD Certificates / PKINIT abuse](ad-certificates.md))।

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → target account / DC आपके द्वारा मांगे गए encryption type का उपयोग नहीं करेगा। केवल RC4 के साथ retry करना बंद करें; **AES keys** दें या इसके बजाय **AES** roast material request करें।
- **`KRB_AP_ERR_MODIFIED`** → संभवतः आपके पास **wrong service key**, **wrong SPN**, या ऐसा forged ticket है जो वास्तव में उसे decrypt करने वाले service account से match नहीं करता।
- **`KRB_AP_ERR_SKEW`** → आपका समय गलत है। किसी अन्य चीज़ को debug करने से पहले DC के साथ sync करें।
- S4U / delegation flows के दौरान **`KDC_ERR_BADOPTION`** → अक्सर इसका अर्थ **sensitive/not-delegable users**, गलत delegation model, या यह होता है कि आप **classic KCD** करने का प्रयास कर रहे हैं, जबकि केवल **RBCD** ही non-forwardable S4U2Self ticket स्वीकार करेगा।

## References
- [1] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): How does Kerberos work? – Theory](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiting RBCD in Cross-Domain & Cross-Forest Environments: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
