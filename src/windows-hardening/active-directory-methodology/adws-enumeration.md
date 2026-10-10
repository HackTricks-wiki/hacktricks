# Active Directory Web Services (ADWS) Enumeration और Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS क्या है?

Active Directory Web Services (ADWS) **Windows Server 2008 R2 से हर Domain Controller पर डिफ़ॉल्ट रूप से enabled** है और TCP **9389** पर सुनता है। नाम के बावजूद, **इसमें HTTP शामिल नहीं है**। इसके बजाय, यह proprietary .NET framing protocols के एक stack के ज़रिए LDAP-शैली का data उपलब्ध कराता है:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

क्योंकि traffic इन binary SOAP frames में encapsulated होता है और एक असामान्य port से होकर जाता है, **ADWS के ज़रिए enumeration पर classic LDAP/389 और 636 traffic की तुलना में inspection, filtering या signature लगाए जाने की संभावना बहुत कम होती है**। Operators के लिए इसका मतलब है:<sup>[[1]](#references)[[7]](#references)</sup>

* अधिक stealthy recon – Blue teams अक्सर LDAP queries पर ध्यान केंद्रित करती हैं।
* **Non-Windows hosts (Linux, macOS)** से SOCKS proxy के ज़रिए 9389/TCP tunnel करके data collect करने की सुविधा।
* वही data जो LDAP के ज़रिए मिलता है (users, groups, ACLs, schema, आदि), साथ ही **writes** करने की क्षमता (जैसे, **RBCD** के लिए `msDs-AllowedToActOnBehalfOfOtherIdentity`)।

ADWS interactions, WS-Enumeration के ज़रिए लागू होते हैं: हर query एक `Enumerate` message से शुरू होती है, जो LDAP filter/attributes तय करता है और `EnumerationContext` GUID लौटाता है। इसके बाद एक या अधिक `Pull` messages आते हैं, जो server द्वारा तय result window तक data stream करते हैं।<sup>[[7]](#references)</sup> Contexts लगभग 30 मिनट बाद expire हो जाते हैं, इसलिए state खोने से बचने के लिए tooling को या तो results को pages में बाँटना होता है या filters को विभाजित करना होता है (हर CN के लिए prefix queries)।<sup>[[8]](#references)</sup> Security descriptors माँगते समय, `LDAP_SERVER_SD_FLAGS_OID` control निर्दिष्ट करें ताकि SACLs हट जाएँ; वरना ADWS अपने SOAP response से `nTSecurityDescriptor` attribute को हटा देता है।

> NOTE: कई RSAT GUI/PowerShell tools भी ADWS का इस्तेमाल करते हैं, इसलिए traffic वैध admin activity के साथ घुल-मिल सकता है।

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) **पूरे ADWS protocol stack का pure Python में पूर्ण re-implementation** है। यह NBFX/NBFSE/NNS/NMF frames को byte-for-byte तैयार करता है, जिससे .NET runtime का इस्तेमाल किए बिना Unix-जैसे systems से data collect किया जा सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### मुख्य विशेषताएँ

* **SOCKS के ज़रिए proxying** को support करता है (C2 implants से इस्तेमाल के लिए उपयोगी)।
* LDAP `-q '(objectClass=user)'` के समान fine-grained search filters।
* वैकल्पिक **write** operations ( `--set` / `--delete` )।
* BloodHound में सीधे ingestion के लिए **BOFHound output mode**।<sup>[[3]](#references)</sup>
* जब इंसानों के लिए पढ़ने योग्य output चाहिए, तब timestamps / `userAccountControl` को बेहतर ढंग से दिखाने के लिए `--parse` flag।<sup>[[2]](#references)</sup>

### Targeted collection flags और write operations

SoaPy में ADWS पर सबसे आम LDAP hunting tasks को दोहराने वाले चुने हुए switches शामिल हैं: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, साथ ही custom pulls के लिए raw `--query` / `--filter` विकल्प। इनके साथ `--rbcd <source>` (यह `msDs-AllowedToActOnBehalfOfOtherIdentity` सेट करता है), `--spn <service/cn>` (targeted Kerberoasting के लिए SPN staging) और `--asrep` (`userAccountControl` में `DONT_REQ_PREAUTH` को flip करता है) जैसे write primitives का इस्तेमाल करें।<sup>[[2]](#references)</sup>

यह targeted SPN hunt का उदाहरण है, जो सिर्फ `samAccountName` और `servicePrincipalName` लौटाता है:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

उसी host/credentials का उपयोग करके findings को तुरंत weaponize करें: `--rbcds` से RBCD-capable objects dump करें, फिर Resource-Based Constrained Delegation chain तैयार करने के लिए `--rbcd 'WEBSRV01$' --account 'FILE01$'` लागू करें (पूरे abuse path के लिए [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) देखें).

### इंस्टॉलेशन (operator host)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump` का fork, जो LDAP-signature hits कम करने के लिए LDAP queries की जगह TCP/9389 पर ADWS calls का उपयोग करता है।
* `--force` पास न किए जाने पर 9389 की शुरुआती reachability check करता है (यदि port scans noisy/filtered हों, तो probe छोड़ देता है)।
* README में Microsoft Defender for Endpoint और CrowdStrike Falcon के विरुद्ध सफल bypass के साथ परीक्षण किया गया है।<sup>[[4]](#references)</sup>

### इंस्टॉलेशन

```bash
pipx install .
```

### उपयोग

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

सामान्य output में 9389 reachability check, ADWS bind, और dump के शुरू/समाप्त होने के logs होते हैं:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Golang में ADWS के लिए एक व्यावहारिक client

soapy की तरह, [sopa](https://github.com/Macmod/sopa) Golang में ADWS protocol stack (MS-NNS + MC-NMF + SOAP) लागू करता है और ADWS calls जारी करने के लिए command-line flags उपलब्ध कराता है, जैसे:<sup>[[5]](#references)</sup>

* **Object खोज और retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` और `delete`
* **Attribute संपादन** - `attr [add|replace|delete]`
* **Account प्रबंधन** - `set-password` / `change-password`
* और अन्य, जैसे `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` आदि।

### Protocol mapping की मुख्य बातें

* LDAP-style searches, attribute projection, scope control (Base/OneLevel/Subtree) और pagination के साथ **WS-Enumeration** (`Enumerate` + `Pull`) के ज़रिए जारी की जाती हैं।
* एकल object को fetch करने के लिए **WS-Transfer** `Get` का उपयोग होता है; attribute में बदलाव के लिए `Put` और deletions के लिए `Delete` का उपयोग होता है।
* Built-in object बनाने के लिए **WS-Transfer ResourceFactory** का उपयोग होता है; custom objects के लिए YAML templates द्वारा संचालित **IMDA AddRequest** का उपयोग होता है।
* पासवर्ड operations में **MS-ADCAP** actions (`SetPassword`, `ChangePassword`) का उपयोग होता है।<sup>[[5]](#references)</sup>

### बिना authentication के metadata की खोज (mex)

ADWS बिना credentials के WS-MetadataExchange उपलब्ध कराता है, जो authenticate करने से पहले exposure को जल्दी validate करने का तरीका है:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC discovery और Kerberos targeting notes

यदि `--dc` नहीं दिया गया है और `--domain` दिया गया है, तो Sopa SRV के ज़रिए DCs resolve कर सकता है। यह इस क्रम में query करता है और highest-priority target का उपयोग करता है:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

ऑपरेशनल रूप से, segmented environments में failures से बचने के लिए DC-नियंत्रित resolver को प्राथमिकता दें:

* `--dns <DC-IP>` का उपयोग करें, ताकि **सभी** SRV/PTR/forward lookups DC DNS के ज़रिए हों।
* UDP blocked होने या SRV answers बड़े होने पर `--dns-tcp` का उपयोग करें।
* अगर Kerberos enabled है और `--dc` एक IP है, तो सही SPN/KDC targeting के लिए FQDN पाने हेतु sopa एक **reverse PTR** lookup करता है। अगर Kerberos का उपयोग नहीं किया जाता है, तो कोई PTR lookup नहीं होता।

उदाहरण (IP + Kerberos, DC के ज़रिए DNS को force किया गया):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Auth material विकल्प

Plaintext passwords के अलावा, sopa ADWS auth के लिए **NT hashes**, **Kerberos AES keys**, **ccache** और **PKINIT certificates** (PFX या PEM) को support करता है। `--aes-key`, `-c` (ccache) या certificate-based options का उपयोग करने पर Kerberos implied होता है।<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Templates के जरिए Custom object बनाना

मनमानी object classes के लिए, `create custom` command एक YAML template लेता है, जो IMDA `AddRequest` से मैप होता है:<sup>[[5]](#references)</sup>

* `parentDN` और `rdn` container और relative DN निर्धारित करते हैं।
* `attributes[].name` में `cn` या namespaced `addata:cn` इस्तेमाल किया जा सकता है।
* `attributes[].type` में `string|int|bool|base64|hex` या स्पष्ट `xsd:*` स्वीकार किए जाते हैं।
* `ad:relativeDistinguishedName` या `ad:container-hierarchy-parent` शामिल **न करें**; sopa उन्हें inject करता है।
* `hex` values को `xsd:base64Binary` में बदला जाता है; empty strings सेट करने के लिए `value: ""` इस्तेमाल करें।

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) एक .NET collector है, जो सभी LDAP interactions को ADWS के भीतर रखता है और BloodHound v4-compatible JSON बनाता है। यह एक बार `objectSid`, `objectGUID`, `distinguishedName` और `objectClass` का पूरा cache बनाता है (`--buildcache`), फिर high-volume `--bhdump`, `--certdump` (ADCS) या `--dnsdump` (AD-integrated DNS) passes के लिए इसे दोबारा इस्तेमाल करता है, ताकि DC से केवल ~35 critical attributes ही बाहर जाएँ। बड़े forests में 30-minute EnumerationContext timeout से नीचे रहने के लिए AutoSplit (`--autosplit --threshold <N>`) queries को CN prefix के आधार पर अपने-आप shards में बाँटता है।<sup>[[8]](#references)</sup>

Domain-joined operator VM पर सामान्य workflow:

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

Export किए गए JSON slots सीधे SharpHound/BloodHound workflows में इस्तेमाल किए जा सकते हैं—आगे graphing के तरीकों के लिए [BloodHound methodology](bloodhound.md) देखें। AutoSplit, SOAPHound को multi-million object forests पर resilient बनाता है और query count को ADExplorer-style snapshots से कम रखता है।

## Stealth AD Collection Workflow

यह workflow दिखाता है कि Linux से ADWS के ज़रिए **domain & ADCS objects** को कैसे enumerate करें, उन्हें BloodHound JSON में कैसे बदलें और certificate-based attack paths की खोज कैसे करें:

1. **टारगेट नेटवर्क से अपने बॉक्स तक 9389/TCP tunnel करें** (उदाहरण के लिए Chisel, Meterpreter, SSH dynamic port-forward आदि के ज़रिए)। `export HTTPS_PROXY=socks5://127.0.0.1:1080` सेट करें या SoaPy के `--proxyHost/--proxyPort` का उपयोग करें।

2. **Root domain object collect करें:**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Configuration NC से ADCS-संबंधित objects एकत्र करें:**

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

5. **ZIP अपलोड करें** BloodHound GUI में और certificate escalation paths (ESC1, ESC8, आदि) देखने के लिए `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` जैसी cypher queries चलाएँ।

### `msDs-AllowedToActOnBehalfOfOtherIdentity` लिखना (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

इसे `s4u2proxy`/`Rubeus /getticket` के साथ जोड़कर पूरी **Resource-Based Constrained Delegation** chain बनाएं (देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md))।

## Tooling का सारांश

| उद्देश्य | Tool | नोट्स |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| बड़े पैमाने पर ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch logs को convert करता है |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | इसे उसी SOCKS के जरिए proxy किया जा सकता है |
| ADWS enumeration और object में बदलाव | [sopa](https://github.com/Macmod/sopa) | ज्ञात ADWS endpoints के साथ interface करने वाला generic client — enumeration, object creation, attribute modifications और password changes की अनुमति देता है |

## References

- [1] [SpecterOps – SOAP(y) का इस्तेमाल करना न भूलें – ADWS का उपयोग करके गुप्त तरीके से AD collection करने के लिए Operators की मार्गदर्शिका](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS के जरिए Active Directory environments की गुप्त enumeration](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS के जरिए Active Directory data collect करने वाला SOAPHound tool](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
