# Uchanganuzi wa Active Directory Web Services (ADWS) & Ukusanyaji wa Siri

{{#include ../../banners/hacktricks-training.md}}

## ADWS ni nini?

Active Directory Web Services (ADWS) ni **imewezeshwa kwa chaguo-msingi kwenye kila Domain Controller tangu Windows Server 2008 R2** na husikiliza TCP **9389**. Licha ya jina, **hakuna HTTP inahusika**. Badala yake, huduma inaonyesha data ya mtindo wa LDAP kupitia safu ya taratibu za muundo za .NET za umiliki:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Kwa sababu trafiki imefungwa ndani ya fremu hizi za binary SOAP na husafiri juu ya bandari isiyo ya kawaida, **enumeration through ADWS is far less likely to be inspected, filtered or signatured than classic LDAP/389 & 636 traffic**. Kwa waendeshaji hili linamaanisha:

* Stealthier recon – Blue teams often concentrate on LDAP queries.
* Uhuru wa kukusanya kutoka **non-Windows hosts (Linux, macOS)** kwa kufunnuliwa 9389/TCP kupitia proxy ya SOCKS.
* Data sawa utakayopata kupitia LDAP (watumiaji, vikundi, ACLs, schema, n.k.) na uwezo wa kufanya **writes** (mf. `msDs-AllowedToActOnBehalfOfOtherIdentity` kwa **RBCD**).

Mwingiliano ya ADWS hufanyika juu ya WS-Enumeration: kila query inaanza na ujumbe wa `Enumerate` unaoelezea filter/attributes za LDAP na kurudisha `EnumerationContext` GUID, ikifuatiwa na ujumbe mmoja au zaidi za `Pull` zinazotiririsha hadi dirisha la matokeo lililowekwa na server. Contexts huisha baada ya ~30 dakika, kwa hivyo zana zinahitaji kurudisha matokeo kwa kurasa au kugawanya filters (maulizo ya prefix kwa kila CN) ili kuepuka kupoteza state. Unapoomba security descriptors, bainisha control ya `LDAP_SERVER_SD_FLAGS_OID` ili kuondoa SACLs, vinginevyo ADWS itafuta tu attribute `nTSecurityDescriptor` kutoka kwenye jibu lake la SOAP.

> Kumbuka: ADWS pia inatumika na zana nyingi za RSAT GUI/PowerShell, hivyo trafiki inaweza kuchanganyika na shughuli halali za admin.

## SoaPy – Mteja wa asili wa Python

[SoaPy](https://github.com/logangoins/soapy) ni **utekelezaji kamili upya wa safu ya itifaki ya ADWS kwa Python ya safi**. Inaunda fremu za NBFX/NBFSE/NNS/NMF byte kwa byte, ikiwezesha ukusanyaji kutoka mifumo kama Unix bila kugusa runtime ya .NET.

### Sifa Muhimu

* Inasaidia proxying through SOCKS (inayofaa kutoka C2 implants).
* Filters za utafutaji za kina sawa na LDAP `-q '(objectClass=user)'`.
* Operesheni za hiari za **write** (`--set` / `--delete`).
* **BOFHound output mode** kwa uingizaji wa moja kwa moja ndani ya BloodHound.
* Bendera `--parse` kuboresha muonekano wa timestamps / `userAccountControl` wakati inahitajika kwa kusomeka kwa binadamu.

### Bendera za ukusanyaji ulioelekezwa & operesheni za write

SoaPy inakuja na switches zilizochaguliwa ambazo zinarudia kazi za kawaida za kuwinda LDAP kupitia ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, pamoja na `--query` / `--filter` kwa pulls za desturi. Unganisha hizo na primitives za write kama `--rbcd <source>` (inayoweka `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging kwa Kerberoasting ulioelekezwa) na `--asrep` (badilisha `DONT_REQ_PREAUTH` katika `userAccountControl`).

Mfano wa utafutaji wa SPN uliolengwa unaorejesha tu `samAccountName` na `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Tumia host/credentials ile ile ili mara moja ku-weaponise findings: dump RBCD-capable objects kwa `--rbcds`, kisha tumia `--rbcd 'WEBSRV01$' --account 'FILE01$'` ili ku-stage Resource-Based Constrained Delegation chain (tazama [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) kwa ajili ya abuse path kamili).

### Usakinishaji (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Mteja wa vitendo wa ADWS katika Golang

Vivyo hivyo kama soapy, [sopa](https://github.com/Macmod/sopa) inatekeleza ADWS protocol stack (MS-NNS + MC-NMF + SOAP) katika Golang, ikionyesha flag za command-line kutoa miito ya ADWS kama:

* **Utafutaji na upokeaji wa Object** - `query` / `get`
* **Mzunguko wa maisha wa Object** - `create [user|computer|group|ou|container|custom]` na `delete`
* **Uhariri wa attribute** - `attr [add|replace|delete]`
* **Usimamizi wa akaunti** - `set-password` / `change-password`
* na mengine kama `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ni collector wa .NET anayehifadhi mwingiliano yote wa LDAP ndani ya ADWS na kutoa JSON inayolingana na BloodHound v4. Inajenga cache kamili ya `objectSid`, `objectGUID`, `distinguishedName` na `objectClass` mara moja (`--buildcache`), kisha inaitumia tena kwa high-volume `--bhdump`, `--certdump` (ADCS), au `--dnsdump` (AD-integrated DNS) passes hivyo takriban ~35 attributes muhimu pekee ndizo hutoka kwenye DC. AutoSplit (`--autosplit --threshold <N>`) hugawa maswali kwa prefix ya CN kwa njia ya kibinafsi ili kubaki chini ya timeout ya EnumerationContext ya dakika 30 katika forests kubwa.

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
JSON zilizotolewa zinaingizwa moja kwa moja katika workflows za SharpHound/BloodHound—angalia [BloodHound methodology](bloodhound.md) kwa mawazo ya kuchora grafu za baadaye. AutoSplit hufanya SOAPHound kuwa sugu kwenye forests zenye mamilioni ya objects huku ikifanya idadi ya maswali kuwa chini kuliko snapshots za mtindo wa ADExplorer.

## Mtiririko wa Ukusanyaji wa AD kwa Siri

Mtiririko ufuatao unaonyesha jinsi ya kuorodhesha **domain & ADCS objects** kupitia ADWS, kuzibadilisha kuwa BloodHound JSON na kuwinda njia za mashambulizi zinazoegemea vyeti – yote kutoka Linux:

1. **Tunnel 9389/TCP** kutoka kwenye mtandao wa lengo hadi kwa mashine yako (mfano: kupitia Chisel, Meterpreter, SSH dynamic port-forward, n.k.). Weka `export HTTPS_PROXY=socks5://127.0.0.1:1080` au tumia SoaPy’s `--proxyHost/--proxyPort`.

2. **Kusanya object ya root domain:**
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
5. **Upload the ZIP** katika BloodHound GUI na endesha maswali ya cypher kama `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ili kufichua njia za kuinua vyeti (ESC1, ESC8, n.k.).

### Kuandika `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Unganisha hili na `s4u2proxy`/`Rubeus /getticket` kwa mnyororo kamili wa **Resource-Based Constrained Delegation** (tazama [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Muhtasari wa Zana

| Madhumuni | Zana | Maelezo |
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
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
