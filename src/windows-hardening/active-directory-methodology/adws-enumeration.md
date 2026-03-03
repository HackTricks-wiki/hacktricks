# Active Directory Web Services (ADWS) Uorodheshaji na Ukusanyaji wa Kimficho

{{#include ../../banners/hacktricks-training.md}}

## ADWS ni nini?

Active Directory Web Services (ADWS) imewezeshwa kwa default kwenye kila Domain Controller tangu Windows Server 2008 R2 na inasikiliza kwenye TCP **9389**. Licha ya jina, **hakuna HTTP inayohusika**. Badala yake, huduma huonyesha data ya mtindo wa LDAP kupitia safu ya itifaki za framing za .NET za kipekee:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Kwa sababu trafiki imefungwa ndani ya fremu hizi za binary SOAP na kusafiri juu ya port isiyo ya kawaida, **uorodheshaji kupitia ADWS una uwezekano mdogo wa kukaguliwa, kuchujwa au kusainiwa ikilinganishwa na trafiki ya classic LDAP/389 & 636**. Kwa watendaji hili inamaanisha:

* Uchunguzi wa kimficho zaidi – Blue teams mara nyingi huzingatia LDAP queries.
* Uhuru wa kukusanya kutoka kwa non-Windows hosts (Linux, macOS) kwa kutunelisha 9389/TCP kupitia SOCKS proxy.
* Data ile ile utaipata via LDAP (users, groups, ACLs, schema, n.k.) na uwezo wa kufanya **writes** (mf. `msDs-AllowedToActOnBehalfOfOtherIdentity` kwa **RBCD**).

Mihusiko ya ADWS hutekelezwa juu ya WS-Enumeration: kila swali huanza na ujumbe wa `Enumerate` unaoeleza LDAP filter/attributes na kurudisha `EnumerationContext` GUID, ikifuatiwa na moja au zaidi ya ujumbe wa `Pull` zinazotiririsha hadi dirisha la matokeo lililowekwa na seva. Contexts huisha baada ya takriban dakika ~30, hivyo tooling inahitaji kuruka matokeo au kugawa filters (maswali ya prefix kwa kila CN) ili kuepuka kupoteza hali. Unapouliza kwa security descriptors, bainisha control ya `LDAP_SERVER_SD_FLAGS_OID` ili kutojumuisha SACLs, vinginevyo ADWS hutoa tu attribute ya `nTSecurityDescriptor` kutoka kwenye jibu lake la SOAP.

> NOTE: ADWS pia hutumiwa na zana nyingi za RSAT GUI/PowerShell, hivyo trafiki inaweza kuchanganyika na shughuli halali za admin.

## SoaPy – Mteja wa Asili wa Python

[SoaPy](https://github.com/logangoins/soapy) ni utekelezaji kamili wa upya wa stack ya itifaki ya ADWS kwa Python safi. Inaunda fremu za NBFX/NBFSE/NNS/NMF byte-kwa-byte, ikiruhusu ukusanyaji kutoka kwa mifumo ya Unix bila kugusa runtime ya .NET.

### Vipengele Muhimu

* Inasaidia **proxying kupitia SOCKS** (inayofaa kutoka kwa C2 implants).
* Filters za utafutaji za mchangamfu sawa na LDAP `-q '(objectClass=user)'`.
* Vitendo vya hiari vya **write** ( `--set` / `--delete` ).
* **BOFHound output mode** kwa ingestion moja kwa moja ndani ya BloodHound.
* flag ya `--parse` kuboresha timestamps / `userAccountControl` wakati upendeleo wa usomaji wa binadamu unahitajika.

### Bendera za ukusanyaji uliolengwa & vitendo vya uandishi

SoaPy inakuja na switches zilizochaguliwa ambazo zinarudia kazi za kawaida za LDAP hunting juu ya ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, pamoja na `--query` / `--filter` mbichi kwa pulls za kawaida. Waambatanishe na primitives za uandishi kama `--rbcd <source>` (huweka `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging kwa Kerberoasting iliyolengwa) na `--asrep` (kubadilisha `DONT_REQ_PREAUTH` katika `userAccountControl`).

Mfano wa uwindaji wa SPN uliolengwa ambao unarudisha tu `samAccountName` na `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Tumia host/credentials ile ile ili mara moja kugeuza uvumbuzi kuwa silaha: dump RBCD-capable objects with `--rbcds`, kisha tumia `--rbcd 'WEBSRV01$' --account 'FILE01$'` kuandaa Resource-Based Constrained Delegation chain (angalia [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) kwa njia kamili ya matumizi mabaya).

### Ufungaji (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Mteja wa vitendo wa ADWS katika Golang

Kama ilivyo kwa soapy, [sopa](https://github.com/Macmod/sopa) inatekeleza safu ya itifaki ya ADWS (MS-NNS + MC-NMF + SOAP) katika Golang, ikitoa bendera za command-line za kutoa miito ya ADWS kama:

* **Utafutaji na upokeaji wa object** - `query` / `get`
* **Mzunguko wa maisha ya object** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Uhariri wa sifa** - `attr [add|replace|delete]`
* **Usimamizi wa akaunti** - `set-password` / `change-password`
* na mengine kama `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, n.k.

## SOAPHound – Ukusanyaji wa ADWS wa Kiasi Kikubwa (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ni mkusanyaji wa .NET unaohifadhi mwingiliano wote wa LDAP ndani ya ADWS na kutoa JSON inayolingana na BloodHound v4. Inajenga cache kamili ya `objectSid`, `objectGUID`, `distinguishedName` na `objectClass` mara moja (`--buildcache`), kisha inaitumia tena kwa `--bhdump`, `--certdump` (ADCS), au `--dnsdump` (AD-integrated DNS) za wingi mkubwa, hivyo takriban sifa 35 muhimu tu ndio zinaondoka DC. AutoSplit (`--autosplit --threshold <N>`) inagawanya maswali kwa prefix ya CN kivitendo ili kubaki chini ya muda wa timeout wa EnumerationContext wa dakika 30 katika forests kubwa.

Mtiririko wa kawaida wa kazi kwenye VM ya operator iliyounganishwa na domain:
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
JSON zilizotolewa ziliwekwa moja kwa moja katika workflows za SharpHound/BloodHound—ona [BloodHound methodology](bloodhound.md) kwa mawazo ya kuchora grafu za hatua inayofuata. AutoSplit hufanya SOAPHound kuwa imara kwenye misitu yenye mamilioni ya objects huku ikipunguza idadi ya maswali ikilinganishwa na snapshots za mtindo wa ADExplorer.

## Mtiririko wa Mkusanyiko wa AD wa Stealth

Mtiririko ufuatao unaonyesha jinsi ya kuorodhesha **domain & ADCS objects** kupitia ADWS, kuzibadilisha kuwa BloodHound JSON na kutafuta njia za mashambulizi zinazotegemea vyeti — yote kutoka Linux:

1. **Tunnel 9389/TCP** kutoka kwenye mtandao wa lengo hadi kwenye mashine yako (kwa mfano kupitia Chisel, Meterpreter, SSH dynamic port-forward, n.k.). Weka `export HTTPS_PROXY=socks5://127.0.0.1:1080` au tumia SoaPy’s `--proxyHost/--proxyPort`.

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
5. **Pakia ZIP** kwenye BloodHound GUI na endesha cypher queries kama `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ili kufichua njia za kuinua vyeti (ESC1, ESC8, n.k.).

### Kuandika `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Unganisha hili na `s4u2proxy`/`Rubeus /getticket` kwa mnyororo kamili wa **Resource-Based Constrained Delegation** (angalia [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Muhtasari wa Zana

| Madhumuni | Zana | Maelezo |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## Marejeleo

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
