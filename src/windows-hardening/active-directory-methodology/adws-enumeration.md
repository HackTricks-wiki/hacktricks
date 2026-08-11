# Active Directory Web Services (ADWS) Enumeration और Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS क्या है?

Active Directory Web Services (ADWS) **Windows Server 2008 R2 से हर Domain Controller पर default रूप से enabled** है और TCP **9389** पर listen करता है। नाम के बावजूद, **इसमें HTTP शामिल नहीं है**। इसके बजाय, यह service proprietary .NET framing protocols के stack के माध्यम से LDAP-style data expose करती है:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

क्योंकि traffic इन binary SOAP frames के अंदर encapsulate होकर एक uncommon port से travel करता है, इसलिए **ADWS के माध्यम से enumeration के classic LDAP/389 और 636 traffic की तुलना में inspect, filter या signature होने की संभावना बहुत कम होती है**। Operators के लिए इसका अर्थ है:<sup>[[1]](#references)[[7]](#references)</sup>

* अधिक stealthy recon – Blue teams अक्सर LDAP queries पर ध्यान केंद्रित करती हैं।
* **non-Windows hosts (Linux, macOS)** से data collect करने की स्वतंत्रता, 9389/TCP को SOCKS proxy के माध्यम से tunnel करके।
* वही data जो LDAP के माध्यम से प्राप्त किया जा सकता है (users, groups, ACLs, schema, आदि) और **writes** करने की क्षमता (जैसे **RBCD** के लिए `msDs-AllowedToActOnBehalfOfOtherIdentity`)।

ADWS interactions को WS-Enumeration के माध्यम से implement किया जाता है: हर query एक `Enumerate` message से शुरू होती है, जो LDAP filter/attributes define करता है और एक `EnumerationContext` GUID return करता है। इसके बाद एक या अधिक `Pull` messages आते हैं, जो server-defined result window तक data stream करते हैं।<sup>[[7]](#references)</sup> Contexts लगभग 30 मिनट बाद expire हो जाते हैं, इसलिए state खोने से बचने के लिए tooling को या तो results को page करना होगा या filters को split करना होगा (CN के अनुसार prefix queries)।<sup>[[8]](#references)</sup> Security descriptors मांगते समय `LDAP_SERVER_SD_FLAGS_OID` control specify करें ताकि SACLs omit हो जाएं; अन्यथा ADWS अपने SOAP response से `nTSecurityDescriptor` attribute को हटा देता है।

> NOTE: ADWS का उपयोग कई RSAT GUI/PowerShell tools द्वारा भी किया जाता है, इसलिए traffic legitimate admin activity के साथ blend हो सकता है।

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) **pure Python में ADWS protocol stack का full re-implementation** है। यह NBFX/NBFSE/NNS/NMF frames को byte-for-byte craft करता है, जिससे .NET runtime को touch किए बिना Unix-like systems से collection संभव होती है।<sup>[[1]](#references)[[2]](#references)</sup>

### Key Features

* **SOCKS के माध्यम से proxying** support करता है (C2 implants से उपयोगी)।
* LDAP `-q '(objectClass=user)'` के समान fine-grained search filters।
* Optional **write** operations ( `--set` / `--delete` )।
* **BOFHound output mode**, जिससे BloodHound में direct ingestion किया जा सकता है।<sup>[[3]](#references)</sup>
* Human readability आवश्यक होने पर timestamps / `userAccountControl` को prettify करने के लिए `--parse` flag।<sup>[[2]](#references)</sup>

### Targeted collection flags और write operations

SoaPy में curated switches उपलब्ध हैं, जो ADWS के माध्यम से सबसे common LDAP hunting tasks को replicate करते हैं: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, साथ ही custom pulls के लिए raw `--query` / `--filter` knobs। इन्हें `--rbcd <source>` जैसे write primitives के साथ pair करें (`msDs-AllowedToActOnBehalfOfOtherIdentity` set करता है), `--spn <service/cn>` (targeted Kerberoasting के लिए SPN staging) और `--asrep` (`userAccountControl` में `DONT_REQ_PREAUTH` flip करता है)।<sup>[[2]](#references)</sup>

Targeted SPN hunt का उदाहरण, जो केवल `samAccountName` और `servicePrincipalName` return करता है:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
उसी host/credentials का उपयोग करके findings को तुरंत weaponise करें: `--rbcds` के साथ RBCD-capable objects dump करें, फिर Resource-Based Constrained Delegation chain को stage करने के लिए `--rbcd 'WEBSRV01$' --account 'FILE01$'` लागू करें (पूरे abuse path के लिए [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) देखें)।

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump` का Fork, जो LDAP queries को TCP/9389 पर ADWS calls से बदलता है ताकि LDAP-signature hits कम किए जा सकें।
* `--force` पास न किए जाने पर 9389 पर initial reachability check करता है (यदि port scans noisy/filtered हों तो probe को skip करता है)।
* README में Microsoft Defender for Endpoint और CrowdStrike Falcon के विरुद्ध successful bypass के साथ Tested किया गया है।<sup>[[4]](#references)</sup>

### Installation
```bash
pipx install .
```
### उपयोग
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
सामान्य आउटपुट 9389 reachability check, ADWS bind और dump start/finish को लॉग करता है:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang में ADWS के लिए एक व्यावहारिक client

soapy की तरह, [sopa](https://github.com/Macmod/sopa) Golang में ADWS protocol stack (MS-NNS + MC-NMF + SOAP) को implement करता है और ADWS calls जारी करने के लिए command-line flags उपलब्ध कराता है, जैसे:<sup>[[5]](#references)</sup>

* **Object search और retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` और `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* और अन्य, जैसे `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, आदि।

### Protocol mapping के मुख्य बिंदु

* LDAP-style searches **WS-Enumeration** (`Enumerate` + `Pull`) के माध्यम से attribute projection, scope control (Base/OneLevel/Subtree) और pagination के साथ जारी की जाती हैं।
* Single-object fetch के लिए **WS-Transfer** `Get` का उपयोग होता है; attribute changes के लिए `Put`; deletions के लिए `Delete`।
* Built-in object creation के लिए **WS-Transfer ResourceFactory** का उपयोग होता है; custom objects के लिए YAML templates द्वारा संचालित **IMDA AddRequest** का उपयोग होता है।
* Password operations **MS-ADCAP** actions (`SetPassword`, `ChangePassword`) हैं।<sup>[[5]](#references)</sup>

### Unauthenticated metadata discovery (mex)

ADWS credentials के बिना WS-MetadataExchange expose करता है, जिससे authenticate करने से पहले exposure को जल्दी validate किया जा सकता है:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery और Kerberos targeting notes

यदि `--dc` omit किया गया हो और `--domain` दिया गया हो, तो Sopa SRV के माध्यम से DCs resolve कर सकता है। यह इसी क्रम में query करता है और highest-priority target का उपयोग करता है:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
व्यावहारिक रूप से, segmented environments में failures से बचने के लिए DC-controlled resolver को प्राथमिकता दें:

* `--dns <DC-IP>` का उपयोग करें ताकि **सभी** SRV/PTR/forward lookups DC DNS के माध्यम से हों।
* UDP blocked होने पर या SRV answers बड़े होने पर `--dns-tcp` का उपयोग करें।
* यदि Kerberos enabled है और `--dc` एक IP है, तो सही SPN/KDC targeting के लिए FQDN प्राप्त करने हेतु sopa एक **reverse PTR** करता है। यदि Kerberos का उपयोग नहीं किया जाता है, तो कोई PTR lookup नहीं होता।

उदाहरण (IP + Kerberos, DC के माध्यम से forced DNS):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Auth material के विकल्प

Plaintext passwords के अलावा, sopa **NT hashes**, **Kerberos AES keys**, **ccache**, और **PKINIT certificates** (PFX या PEM) को ADWS auth के लिए support करता है। `--aes-key`, `-c` (ccache) या certificate-based options का उपयोग करने पर Kerberos implied होता है।<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Templates के माध्यम से Custom Object Creation

मनमानी object classes के लिए, `create custom` command एक YAML template का उपयोग करती है, जो IMDA `AddRequest` पर मैप होता है:<sup>[[5]](#references)</sup>

* `parentDN` और `rdn` container और relative DN को define करते हैं।
* `attributes[].name` `cn` या namespaced `addata:cn` को support करता है।
* `attributes[].type` `string|int|bool|base64|hex` या explicit `xsd:*` स्वीकार करता है।
* `ad:relativeDistinguishedName` या `ad:container-hierarchy-parent` शामिल **न करें**; sopa इन्हें inject करता है।
* `hex` values को `xsd:base64Binary` में convert किया जाता है; empty strings set करने के लिए `value: ""` का उपयोग करें।

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) एक .NET collector है, जो सभी LDAP interactions को ADWS के अंदर रखता है और BloodHound v4-compatible JSON emit करता है। यह एक बार (`--buildcache`) `objectSid`, `objectGUID`, `distinguishedName` और `objectClass` का complete cache बनाता है, फिर उसे high-volume `--bhdump`, `--certdump` (ADCS) या `--dnsdump` (AD-integrated DNS) passes के लिए reuse करता है, ताकि केवल लगभग 35 critical attributes ही DC से बाहर जाएँ। AutoSplit (`--autosplit --threshold <N>`) बड़े forests में 30-minute EnumerationContext timeout से नीचे रहने के लिए CN prefix के आधार पर queries को automatically shards में बाँटता है।<sup>[[8]](#references)</sup>

Domain-joined operator VM पर typical workflow:
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
निर्यात किए गए JSON slots को सीधे SharpHound/BloodHound workflows में डाला गया—downstream graphing ideas के लिए [BloodHound methodology](bloodhound.md) देखें। SOAPHound को multi-million object forests पर resilient बनाए रखते हुए AutoSplit, ADExplorer-style snapshots की तुलना में query count कम रखता है।

## Stealth AD Collection Workflow

निम्न workflow दिखाता है कि Linux से ADWS के माध्यम से **domain & ADCS objects** को कैसे enumerate करें, उन्हें BloodHound JSON में convert करें और certificate-based attack paths की तलाश करें:

1. **Tunnel 9389/TCP** को target network से अपने box तक करें (जैसे Chisel, Meterpreter, SSH dynamic port-forward आदि के माध्यम से)। `export HTTPS_PROXY=socks5://127.0.0.1:1080` export करें या SoaPy के `--proxyHost/--proxyPort` का उपयोग करें।

2. **Root domain object collect करें:**
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
4. **BloodHound में convert करें:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **BloodHound GUI में ZIP अपलोड करें** और `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` जैसी cypher queries चलाकर certificate escalation paths (ESC1, ESC8, आदि) प्रकट करें।

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) लिखना
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
इसे `s4u2proxy`/`Rubeus /getticket` के साथ मिलाकर एक पूर्ण **Resource-Based Constrained Delegation** chain बनाएं (देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md))।

## Tooling का सारांश

| उद्देश्य | Tool | टिप्पणियां |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch logs को convert करता है |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | उसी SOCKS के माध्यम से proxy किया जा सकता है |
| ADWS enumeration और object changes | [sopa](https://github.com/Macmod/sopa) | ज्ञात ADWS endpoints के साथ interface करने वाला generic client - enumeration, object creation, attribute modifications और password changes की अनुमति देता है |

## References

- [1] [SpecterOps – ADWS का उपयोग करके stealthy AD collection के लिए SOAP(y) का उपयोग करना सुनिश्चित करें – Operators Guide](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS के माध्यम से Active Directory environments की stealthy enumeration](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS के माध्यम से Active Directory data collect करने वाला SOAPHound tool](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
