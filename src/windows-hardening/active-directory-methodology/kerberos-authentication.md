# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**के बारे में शानदार पोस्ट देखें:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR for attackers
- Kerberos डिफ़ॉल्ट AD auth protocol है; ज़्यादातर lateral-movement chains इसमें शामिल होंगे।
- **तीन operator phases** में सोचें:
- **AS-REQ / AS-REP** → **TGT** प्राप्त करने के लिए password/hash/certificate। यहीं **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, और **PKINIT** होते हैं।
- **TGS-REQ / TGS-REP** → **service tickets** प्राप्त करने के लिए TGT का उपयोग करें। यहीं **Kerberoasting**, **S4U abuse**, **delegation abuse**, और अधिकांश **ticket-forging tradecraft** प्रासंगिक होते हैं।
- **AP-REQ / AP-REP** → ticket को service के सामने प्रस्तुत करें। यहीं **pass-the-ticket** और service-specific lateral movement होता है।
- Hands-on cheatsheets के लिए (AS-REP/Kerberoasting, ticket forgery, delegation abuse, etc.) देखें:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- इस पेज को **overview / “what changed recently”** index की तरह उपयोग करें, फिर dedicated pages पर जाएँ: [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), या [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Fresh attack notes (2024-2026)
- **RC4 hardening ने defaults बदले हैं, Kerberos को नहीं** – modern DC hardening उन accounts के लिए **default assumed encryption types** पर ध्यान देता है जो `msDS-SupportedEncryptionTypes` explicitly set नहीं करते। 2026 rollout के बाद, ऐसे accounts patched DCs पर increasingly **AES-only** default करते हैं, इसलिए blind `/rc4` Kerberoast assumptions अधिकतर fail होती हैं। हालांकि, **explicitly RC4-enabled service accounts अभी भी excellent offline-crack targets हैं**।
- **PAC validation enforcement forged tickets के लिए महत्वपूर्ण है** – 2024 PAC-signature hardening का मतलब है कि **golden/diamond/sapphire/extraSID-style abuses** को अधिक realistic PAC data और सही signing context चाहिए। Unpatched domains या compatibility/audit-style deployments में domains अभी भी softer targets रहते हैं।
- **Certificate-based Kerberos दो बार बदला**:
- **Strong certificate binding** (KB5014754 timeline) fully enforced environments में sloppy certificate-to-account mappings को कम reliable बनाता है।
- **CVE-2025-26647** ने **altSecID / SKI certificate mappings** के आसपास एक और hardening layer जोड़ी। अगर DCs unpatched हैं, अभी भी auditing में हैं, या explicitly NTAuth validation bypass कर रहे हैं, तो pass-the-certificate / shadow-credential follow-on abuse अधिक practical रहता है।
- **Cross-domain / cross-forest delegation abuse अभी भी बहुत alive है** – Windows modern cross-realm **S4U2Self/S4U2Proxy** flows support करता है, इसलिए दूसरी domain में writable delegation attributes अभी भी valuable हैं। Blocker आमतौर पर tooling fidelity और trust/policy details होते हैं, protocol support नहीं।
- **Windows Server 2025 ने नए Kerberos-adjacent attack surface introduce किए** **dMSA** migration logic के माध्यम से। अगर आपको OUs या service-account objects पर delegated rights 2025 domain में दिखते हैं, तो उसे “बस एक और gMSA” की तरह treat करने के बजाय dedicated [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) देखें।

## Fast operator checks in modern domains

Kerberos attack path चुनने से पहले, जल्दी से चार सवालों के जवाब दें:

1. **कौन से accounts अभी भी RC4-friendly हैं?**
2. **कौन से users को pre-auth की आवश्यकता नहीं है?**
3. **कौन से objects delegation abuse expose करते हैं?**
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
व्यावहारिक व्याख्या:
- यदि **interesting SPN accounts explicitly RC4-capable** हैं, तो Kerberoasting सस्ता और तेज़ रहता है।
- यदि अधिकांश service accounts में **no explicit etype configuration** है, तो updated 2026 DCs पर **AES-only** behavior की उम्मीद करें और धीमे offline cracking या किसी अलग path की योजना बनाएं।
- यदि **RBCD / KCD / unconstrained delegation** मौजूद है, तो अक्सर S4U brute-force से बेहतर होता है।
- यदि **certificate auth** use में है, तो याद रखें कि failed PKINIT path का मतलब हमेशा यह नहीं होता कि cert बेकार है; कई environments में वही cert अभी भी **Schannel/LDAPS** abuse के लिए काम करता है (see [AD Certificates / PKINIT abuse](ad-certificates.md))।

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Target account / DC उस encryption type का use नहीं करेगा जो आपने मांगा है। RC4 only के साथ retry करना बंद करें; **AES keys** दें या इसके बजाय **AES** roast material request करें।
- **`KRB_AP_ERR_MODIFIED`** → संभवतः आपके पास **wrong service key**, **wrong SPN**, या ऐसा forged ticket है जो उस service account से match नहीं करता जो वास्तव में उसे decrypt कर रहा है।
- **`KRB_AP_ERR_SKEW`** → आपका time off है। कुछ और debug करने से पहले DC के साथ sync करें।
- **`KDC_ERR_BADOPTION`** during S4U / delegation flows → अक्सर **sensitive/not-delegable users**, गलत delegation model, या यह कि आप **classic KCD** try कर रहे हैं जहाँ केवल **RBCD** non-forwardable S4U2Self ticket accept करेगा।

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
