# Active Directory Web Services (ADWS) Enumerasie & Onopgemerkte Versameling

{{#include ../../banners/hacktricks-training.md}}

## Wat is ADWS?

Active Directory Web Services (ADWS) is **standaard geaktiveer op elke Domain Controller sedert Windows Server 2008 R2** en luister op TCP **9389**. Ten spyte van die naam, is **geen HTTP betrokke nie**. In plaas daarvan openbaar die diens LDAP-styl data deur 'n stapel van eienaardige .NET framing-protokolle:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Omdat die verkeer ingekapsuleer is binne hierdie binêre SOAP-frames en oor 'n minder algemene poort reis, is enumerasie deur ADWS baie minder geneig om geïnspekteer, gefilter of deur signatures opgespoor te word as klassieke LDAP/389 & 636 verkeer. Vir operateurs beteken dit:

* Stilletjieser verkenning – Blue teams konsentreer dikwels op LDAP-navrae.
* Vryheid om van nie-Windows-gashere (Linux, macOS) te versamel deur 9389/TCP deur 'n SOCKS-proxy te tunnel.
* Dieselfde data wat jy via LDAP sou verkry (gebruikers, groepe, ACLs, schema, ens.) en die vermoë om skryfoperasies uit te voer (bv. `msDs-AllowedToActOnBehalfOfOtherIdentity` vir **RBCD**).

ADWS-interaksies word geïmplementeer oor WS-Enumeration: elke navraag begin met 'n `Enumerate` boodskap wat die LDAP-filter/attribute definieer en 'n `EnumerationContext` GUID teruggee, gevolg deur een of meer `Pull` boodskappe wat tot by die deur die bediener-gedefinieerde resultaatvenster stroom. Kontekste verval na ~30 minute, so gereedskap moet óf resultate bladsyer óf filters opsplits (prefix-navrae per CN) om te voorkom dat state verlore gaan. Wanneer jy vir security descriptors vra, spesifiseer die `LDAP_SERVER_SD_FLAGS_OID` control om SACLs uit te sluit, anders gooi ADWS eenvoudig die `nTSecurityDescriptor` attribuut uit sy SOAP-antwoord.

> LET WEL: ADWS word ook deur baie RSAT GUI/PowerShell tools gebruik, so verkeer kan meng met wettige admin-aktiwiteit.

## SoaPy – Inheemse Python-kliënt

[SoaPy](https://github.com/logangoins/soapy) is 'n **volledige herimplementering van die ADWS-protokolstack in suiwer Python**. Dit bou die NBFX/NBFSE/NNS/NMF-frames byte-vir-byte, wat versameling vanaf Unix-agtige stelsels moontlik maak sonder om die .NET-runtime te raak.

### Sleutelkenmerke

* Ondersteun proxying deur SOCKS (nuttig vanaf C2-implante).
* Fynkorrelige soekfilters identies aan LDAP `-q '(objectClass=user)'`.
* Opsionele skryfoperasies ( `--set` / `--delete` ).
* **BOFHound output mode** vir direkte invoer in BloodHound.
* `--parse` vlag om timestamps / `userAccountControl` te verfraai wanneer menslike leesbaarheid benodig word.

### Gerigte versamelingsvlae & skryfoperasies

SoaPy kom met gekurateerde skakelaars wat die mees algemene LDAP-soek-take oor ADWS repliseer: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` knope vir pasgemaakte pulls. Kombineer dit met skryfprimitiewe soos `--rbcd <source>` (stel `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging vir gerigte Kerberoasting) en `--asrep` (draai `DONT_REQ_PREAUTH` in `userAccountControl`).

Voorbeeld van 'n gerigte SPN-soektog wat slegs `samAccountName` en `servicePrincipalName` teruggee:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Gebruik dieselfde host/credentials om bevindinge onmiddellik te wapen: dump RBCD-capable objects met `--rbcds`, en pas dan `--rbcd 'WEBSRV01$' --account 'FILE01$'` toe om 'n Resource-Based Constrained Delegation chain op te stel (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) vir die volledige misbruikpad).

### Installasie (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - 'n praktiese kliënt vir ADWS in Golang

Net soos soapy, [sopa](https://github.com/Macmod/sopa) implementeer die ADWS-protokolstapel (MS-NNS + MC-NMF + SOAP) in Golang, en bied opdragreëlvlae om ADWS-oproepe uit te voer soos:

* **Soek en ophaling van objekte** - `query` / `get`
* **Objeklewensiklus** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribuutredigering** - `attr [add|replace|delete]`
* **Kontobestuur** - `set-password` / `change-password`
* en ander soos `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Hoë-volume ADWS-versameling (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is 'n .NET-versamelaar wat alle LDAP-interaksies binne ADWS hou en BloodHound v4-kompatible JSON uitstuur. Dit bou een keer 'n volledige kas van `objectSid`, `objectGUID`, `distinguishedName` en `objectClass` (`--buildcache`), en hergebruik dit dan vir hoë-volume `--bhdump`, `--certdump` (ADCS), of `--dnsdump` (AD-integrated DNS) draaie, sodat slegs ~35 kritiese attributte ooit die DC verlaat. AutoSplit (`--autosplit --threshold <N>`) verdeel navrae outomaties volgens CN-voorvoegsel om onder die 30-minute EnumerationContext-tydlimiet in groot foreste te bly.

Tipiese werkvloeistroom op 'n domein-gekoppelde operator-VM:
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
Uitgevoerde JSON-insette direk in SharpHound/BloodHound-werkvloeie—sien [BloodHound methodology](bloodhound.md) vir idees oor downstream-grafieke. AutoSplit maak SOAPHound weerbaar op foreste met veelmiljoene objekte terwyl die navraagtelling laer bly as ADExplorer-style snapshots.

## Stealth AD-insamelingswerkvloei

Die volgende werkvloei wys hoe om te enumereer **domain & ADCS objects** oor ADWS, dit na BloodHound JSON te omskakel en te jag na sertifikaat-gebaseerde aanvalspaaie – alles vanaf Linux:

1. **Tunnel 9389/TCP** vanaf die teiken-netwerk na jou masjien (bv. via Chisel, Meterpreter, SSH dynamic port-forward, ens.). Stel `export HTTPS_PROXY=socks5://127.0.0.1:1080` of gebruik SoaPy se `--proxyHost/--proxyPort`.

2. **Versamel die wortel-domein-objek:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Versamel ADCS-verwante objekte van die Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Skakel na BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Laai die ZIP op** in die BloodHound GUI en voer cypher-navrae uit soos `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` om sertifikaateskalasie-paaie te openbaar (ESC1, ESC8, ens.).

### Skryf na `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombineer dit met `s4u2proxy`/`Rubeus /getticket` vir 'n volledige Resource-Based Constrained Delegation-ketting (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Opsomming van gereedskap

| Doel | Gereedskap | Opmerkings |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## Verwysings

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
