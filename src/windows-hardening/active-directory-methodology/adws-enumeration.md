# Active Directory Web Services (ADWS) — Énumération et collecte furtive

{{#include ../../banners/hacktricks-training.md}}

## Qu'est-ce que ADWS ?

Active Directory Web Services (ADWS) est **activé par défaut sur chaque Domain Controller depuis Windows Server 2008 R2** et écoute sur TCP **9389**. Malgré son nom, **aucun HTTP n'est impliqué**. À la place, le service expose des données de type LDAP via une pile de protocoles de framing propriétaires .NET :

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Parce que le trafic est encapsulé dans ces trames SOAP binaires et circule sur un port peu commun, **l'énumération via ADWS est bien moins susceptible d'être inspectée, filtrée ou détectée par des signatures que le trafic LDAP classique/389 & 636**. Pour les opérateurs, cela signifie :

* Recon plus furtif – les Blue teams se concentrent souvent sur les requêtes LDAP.
* Possibilité de collecter depuis des hôtes **non-Windows (Linux, macOS)** en tunnélisant 9389/TCP via un proxy SOCKS.
* Les mêmes données que vous obtiendriez via LDAP (users, groups, ACLs, schema, etc.) et la possibilité d'effectuer des **writes** (par ex. `msDs-AllowedToActOnBehalfOfOtherIdentity` pour **RBCD**).

Les interactions ADWS sont implémentées via WS-Enumeration : chaque requête commence par un message `Enumerate` qui définit le filtre/attributs LDAP et renvoie un `EnumerationContext` GUID, suivi d'un ou plusieurs messages `Pull` qui streament jusqu'à la fenêtre de résultats définie par le serveur. Les contexts expirent après ~30 minutes, donc les outils doivent soit paginer les résultats soit diviser les filtres (requêtes préfixes par CN) pour éviter de perdre l'état. Lorsqu'on demande des security descriptors, spécifiez le contrôle `LDAP_SERVER_SD_FLAGS_OID` pour omettre les SACLs, sinon ADWS supprime simplement l'attribut `nTSecurityDescriptor` de sa réponse SOAP.

> REMARQUE : ADWS est également utilisé par de nombreux outils RSAT GUI/PowerShell, donc le trafic peut se mêler à une activité admin légitime.

## SoaPy – client Python natif

[SoaPy](https://github.com/logangoins/soapy) est une **implémentation complète de la pile de protocoles ADWS en Python pur**. Il construit les trames NBFX/NBFSE/NNS/NMF octet par octet, permettant la collecte depuis des systèmes Unix-like sans toucher au runtime .NET.

### Principales fonctionnalités

* Supporte le **proxying via SOCKS** (utile depuis des implants C2).
* Filtres de recherche fins identiques à LDAP `-q '(objectClass=user)'`.
* Opérations **write** optionnelles ( `--set` / `--delete` ).
* Mode de sortie **BOFHound** pour ingestion directe dans BloodHound.
* L'option `--parse` pour embellir les timestamps / `userAccountControl` lorsque la lisibilité humaine est requise.

### Options de collecte ciblée & opérations d'écriture

SoaPy est fourni avec des switches préconfigurés qui reproduisent les tâches de chasse LDAP les plus courantes via ADWS : `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, ainsi que des commandes brutes `--query` / `--filter` pour des extractions personnalisées. Associez-les à des primitives d'écriture telles que `--rbcd <source>` (définit `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (staging SPN pour Kerberoasting ciblé) et `--asrep` (basculer `DONT_REQ_PREAUTH` dans `userAccountControl`).

Exemple de recherche SPN ciblée qui ne retourne que `samAccountName` et `servicePrincipalName` :
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Utilisez le même host/credentials pour weaponise immédiatement les findings : dump les objets RBCD-capable avec `--rbcds`, puis appliquez `--rbcd 'WEBSRV01$' --account 'FILE01$'` pour mettre en place une Resource-Based Constrained Delegation chain (voir [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) pour le full abuse path).

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump via ADWS (Linux/Windows)

* Fork de `ldapdomaindump` qui remplace les requêtes LDAP par des appels ADWS sur TCP/9389 afin de réduire les hits de signatures LDAP.
* Effectue une vérification initiale d'accessibilité vers le port 9389 sauf si `--force` est passé (ignore la sonde si les scans de ports sont bruyants/filtrés).
* Testé contre Microsoft Defender for Endpoint et CrowdStrike Falcon avec contournement réussi dans le README.

### Installation
```bash
pipx install .
```
### Utilisation
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
La sortie typique enregistre la vérification d'accessibilité 9389, le bind ADWS, et le début/fin du dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - A practical client for ADWS in Golang

De la même manière que soapy, [sopa](https://github.com/Macmod/sopa) implémente la pile de protocoles ADWS (MS-NNS + MC-NMF + SOAP) en Golang, exposant des options en ligne de commande pour émettre des appels ADWS tels que :

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Protocol mapping highlights

* LDAP-style searches are issued via **WS-Enumeration** (`Enumerate` + `Pull`) with attribute projection, scope control (Base/OneLevel/Subtree) and pagination.
* Single-object fetch uses **WS-Transfer** `Get`; attribute changes use `Put`; deletions use `Delete`.
* Built-in object creation uses **WS-Transfer ResourceFactory**; custom objects use an **IMDA AddRequest** driven by YAML templates.
* Password operations are **MS-ADCAP** actions (`SetPassword`, `ChangePassword`).

### Unauthenticated metadata discovery (mex)

ADWS expose WS-MetadataExchange sans authentification, ce qui est un moyen rapide de valider l'exposition avant de s'authentifier :
```bash
sopa mex --dc <DC>
```
### Découverte DNS/DC et notes de ciblage Kerberos

Sopa peut résoudre les DCs via SRV si `--dc` est omis et `--domain` est fourni. Il interroge dans cet ordre et utilise la cible ayant la plus haute priorité :
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Opérationnellement, privilégiez un resolver contrôlé par le DC pour éviter les échecs dans des environnements segmentés :

* Utilisez `--dns <DC-IP>` afin que **toutes** les recherches SRV/PTR/forward passent par le DNS du DC.
* Utilisez `--dns-tcp` lorsque UDP est bloqué ou que les réponses SRV sont volumineuses.
* Si Kerberos est activé et que `--dc` est une IP, sopa effectue un **reverse PTR** pour obtenir un FQDN afin de cibler correctement le SPN/KDC. Si Kerberos n'est pas utilisé, aucune recherche PTR n'est effectuée.

Example (IP + Kerberos, forced DNS via the DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Options d'authentification

En plus des plaintext passwords, sopa prend en charge **NT hashes**, **Kerberos AES keys**, **ccache** et **PKINIT certificates** (PFX ou PEM) pour ADWS auth. Kerberos est implicite lors de l'utilisation de `--aes-key`, `-c` (ccache) ou des options basées sur des certificats.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Custom object creation via templates

Pour des classes d'objet arbitraires, la commande `create custom` consomme un template YAML qui correspond à un IMDA `AddRequest` :

* `parentDN` et `rdn` définissent le conteneur et le DN relatif.
* `attributes[].name` prend en charge `cn` ou le nom avec espace de noms `addata:cn`.
* `attributes[].type` accepte `string|int|bool|base64|hex` ou explicitement `xsd:*`.
* Ne **pas** inclure `ad:relativeDistinguishedName` ou `ad:container-hierarchy-parent` ; sopa les injecte.
* Les valeurs `hex` sont converties en `xsd:base64Binary` ; utilisez `value: ""` pour définir des chaînes vides.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) est un collector .NET qui maintient toutes les interactions LDAP à l'intérieur d'ADWS et émet du JSON compatible BloodHound v4. Il construit un cache complet de `objectSid`, `objectGUID`, `distinguishedName` et `objectClass` une seule fois (`--buildcache`), puis le réutilise pour des passages à haut volume `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (DNS intégré à AD) de sorte que seulement ~35 attributs critiques quittent le DC. AutoSplit (`--autosplit --threshold <N>`) segmente automatiquement les requêtes par préfixe CN pour rester en dessous du timeout EnumerationContext de 30 minutes dans les grandes forêts.

Flux de travail typique sur une VM opérateur jointe au domaine:
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
Les JSON exportés s'intègrent directement dans les workflows SharpHound/BloodHound — see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit rend SOAPHound résilient sur des forêts de plusieurs millions d'objets tout en conservant un nombre de requêtes inférieur à celui des snapshots de type ADExplorer.

## Workflow de collecte AD furtive

Le workflow suivant montre comment énumérer **les objets de domaine et ADCS** via ADWS, les convertir en BloodHound JSON et rechercher des chemins d'attaque basés sur des certificats — le tout depuis Linux :

1. **Tunnel 9389/TCP** depuis le réseau cible vers votre machine (p.ex. via Chisel, Meterpreter, redirection de port dynamique SSH, etc.). Exportez `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou utilisez les options `--proxyHost/--proxyPort` de SoaPy.

2. **Collecter l'objet racine du domaine :**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Collecter les objets liés à ADCS depuis le NC de Configuration :**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Convertir en BloodHound :**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Upload the ZIP** dans la GUI de BloodHound et exécutez des requêtes cypher telles que `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` pour révéler les chemins d'escalade de certificats (ESC1, ESC8, etc.).

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
| Dump ADWS à haut volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modes BH/ADCS/DNS |
| Ingestion pour BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convertit les logs SoaPy/ldapsearch |
| Compromission de certificats | [Certipy](https://github.com/ly4k/Certipy) | Peut être utilisé via le même proxy SOCKS |
| Énumération ADWS et modifications d'objets | [sopa](https://github.com/Macmod/sopa) | client générique pour interagir avec des endpoints ADWS connus - permet l'énumération, la création d'objets, la modification d'attributs et le changement de mots de passe |

## Références

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
