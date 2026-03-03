# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) is **enabled by default on every Domain Controller since Windows Server 2008 R2** and listens on TCP **9389**.  Despite the name, **no HTTP is involved**.  Instead, the service exposes LDAP-style data through a stack of proprietary .NET framing protocols:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Because the traffic is encapsulated inside these binary SOAP frames and travels over an uncommon port, **enumeration through ADWS is far less likely to be inspected, filtered or signatured than classic LDAP/389 & 636 traffic**.  For operators this means:

* Stealthier recon – Blue teams अक्सर LDAP क्वेरीज़ पर केंद्रित होते हैं।
* SOCKS प्रॉक्सी के माध्यम से 9389/TCP को टनल करके **non-Windows hosts (Linux, macOS)** से कलेक्ट करने की स्वतंत्रता।
* वही डेटा जो आप LDAP के माध्यम से प्राप्त कर सकते हैं (users, groups, ACLs, schema, आदि) और **writes** करने की क्षमता (उदा. `msDs-AllowedToActOnBehalfOfOtherIdentity` for **RBCD**).

ADWS interactions are implemented over WS-Enumeration: every query starts with an `Enumerate` message that defines the LDAP filter/attributes and returns an `EnumerationContext` GUID, followed by one or more `Pull` messages that stream up to the server-defined result window. Contexts age out after ~30 minutes, so tooling either needs to page results or split filters (prefix queries per CN) to avoid losing state. When asking for security descriptors, specify the `LDAP_SERVER_SD_FLAGS_OID` control to omit SACLs, otherwise ADWS simply drops the `nTSecurityDescriptor` attribute from its SOAP response.

> NOTE: ADWS is also used by many RSAT GUI/PowerShell tools, so traffic may blend with legitimate admin activity.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) is a **full re-implementation of the ADWS protocol stack in pure Python**.  It crafts the NBFX/NBFSE/NNS/NMF frames byte-for-byte, allowing collection from Unix-like systems without touching the .NET runtime.

### Key Features

* Supports **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Targeted collection flags & write operations

SoaPy ships with curated switches that replicate the most common LDAP hunting tasks over ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` knobs for custom pulls. Pair those with write primitives such as `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging for targeted Kerberoasting) and `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
उसी host/credentials का उपयोग करके तुरंत findings को weaponise करें: `--rbcds` के साथ RBCD-capable objects को dump करें, फिर Resource-Based Constrained Delegation chain को stage करने के लिए `--rbcd 'WEBSRV01$' --account 'FILE01$'` लागू करें (पूर्ण abuse path के लिए देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) ).

### इंस्टॉलेशन (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - ADWS के लिए Golang में एक व्यावहारिक क्लाइंट

soapy की तरह, [sopa](https://github.com/Macmod/sopa) ADWS प्रोटोकॉल स्टैक (MS-NNS + MC-NMF + SOAP) को Golang में लागू करता है, और ADWS कॉल जारी करने के लिए कमांड-लाइन फ्लैग प्रदान करता है, जैसे:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* और अन्य जैसे `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, आदि।

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) एक .NET collector है जो सभी LDAP इंटरैक्शन्स को ADWS के भीतर रखता है और BloodHound v4-compatible JSON उत्पन्न करता है। यह एक बार `objectSid`, `objectGUID`, `distinguishedName` और `objectClass` का पूरा cache बनाता है (`--buildcache`), फिर बड़े पैमाने पर `--bhdump`, `--certdump` (ADCS), या `--dnsdump` (AD-integrated DNS) पास के लिए इसे पुन: उपयोग करता है ताकि केवल लगभग 35 महत्वपूर्ण attributes ही DC से बाहर जाएँ। AutoSplit (`--autosplit --threshold <N>`) स्वचालित रूप से CN प्रीफ़िक्स के हिसाब से क्वेरीज़ को शार्ड करता है ताकि बड़े forests में 30-minute EnumerationContext timeout के अंतर्गत रहा जा सके।

डोमेन-ज़ुड़े हुए ऑपरेटर VM पर सामान्य वर्कफ़्लो:
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
Export किए गए JSON को सीधे SharpHound/BloodHound workflows में इस्तेमाल किया जा सकता है—downstream graphing ideas के लिए [BloodHound methodology](bloodhound.md) देखें। AutoSplit SOAPHound को multi-million ऑब्जेक्ट forests पर अधिक resilient बनाता है, और query count को ADExplorer-style snapshots की तुलना में कम रखता है।

## Stealth AD Collection Workflow

The following workflow shows how to enumerate **domain & ADCS objects** over ADWS, convert them to BloodHound JSON and hunt for certificate-based attack paths – all from Linux:

1. **Target नेटवर्क से अपनी मशीन तक 9389/TCP को tunnel करें** (उदा. Chisel, Meterpreter, SSH dynamic port-forward, आदि के माध्यम से)।  `export HTTPS_PROXY=socks5://127.0.0.1:1080` export करें या SoaPy’s `--proxyHost/--proxyPort` का उपयोग करें।

2. **root domain object को collect करें:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC से ADCS-सम्बंधित ऑब्जेक्ट्स एकत्र करें:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **BloodHound में कन्वर्ट करें:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. BloodHound GUI में **ZIP अपलोड करें** और ऐसे cypher queries चलाएँ जैसे `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ताकि certificate escalation paths (ESC1, ESC8, आदि) प्रकट हों।

### लिखना `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
इसे `s4u2proxy`/`Rubeus /getticket` के साथ मिलाएँ ताकि एक पूर्ण **Resource-Based Constrained Delegation** chain बन सके (देखें [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## उपकरण सारांश

| उद्देश्य | उपकरण | नोट्स |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | इसे उसी SOCKS के माध्यम से प्रॉक्सी किया जा सकता है |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## संदर्भ

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
