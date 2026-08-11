# Enumeration d’Active Directory Web Services (ADWS) et collecte furtive

{{#include ../../banners/hacktricks-training.md}}

## Qu’est-ce qu’ADWS ?

Active Directory Web Services (ADWS) est **activé par défaut sur chaque Domain Controller depuis Windows Server 2008 R2** et écoute sur le port TCP **9389**. Malgré son nom, **aucun protocole HTTP n’est impliqué**. À la place, le service expose des données de type LDAP via une pile de protocoles propriétaires de framing .NET :<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Comme le trafic est encapsulé dans ces trames SOAP binaires et transite par un port peu courant, **l’enumeration via ADWS a beaucoup moins de chances d’être inspectée, filtrée ou détectée par signature que le trafic LDAP/389 et 636 classique**. Pour les opérateurs, cela signifie :<sup>[[1]](#references)[[7]](#references)</sup>

* Recon plus furtive – Les équipes Blue Team se concentrent souvent sur les requêtes LDAP.
* Possibilité de collecter depuis des hôtes **non-Windows (Linux, macOS)** en tunnellant 9389/TCP via un proxy SOCKS.
* Les mêmes données que celles obtenues via LDAP (utilisateurs, groupes, ACL, schéma, etc.) et la possibilité d’effectuer des **écritures** (par exemple `msDs-AllowedToActOnBehalfOfOtherIdentity` pour **RBCD**).

Les interactions ADWS sont implémentées via WS-Enumeration : chaque requête commence par un message `Enumerate` qui définit le filtre/les attributs LDAP et renvoie un GUID `EnumerationContext`, suivi d’un ou plusieurs messages `Pull` qui transmettent les résultats jusqu’à la fenêtre de résultats définie par le serveur.<sup>[[7]](#references)</sup> Les contextes expirent après environ 30 minutes. Les outils doivent donc paginer les résultats ou diviser les filtres (requêtes par préfixe pour chaque CN) afin d’éviter de perdre l’état.<sup>[[8]](#references)</sup> Lors de la demande de security descriptors, spécifiez le contrôle `LDAP_SERVER_SD_FLAGS_OID` pour exclure les SACL ; sinon, ADWS supprime simplement l’attribut `nTSecurityDescriptor` de sa réponse SOAP.

> NOTE: ADWS est également utilisé par de nombreux outils RSAT GUI/PowerShell ; le trafic peut donc se confondre avec une activité d’administration légitime.

## SoaPy – Client Python natif

[SoaPy](https://github.com/logangoins/soapy) est une **réimplémentation complète de la pile de protocoles ADWS en Python pur**. Il construit les trames NBFX/NBFSE/NNS/NMF octet par octet, ce qui permet la collecte depuis des systèmes de type Unix sans utiliser le runtime .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Fonctionnalités principales

* Prend en charge le **proxying via SOCKS** (utile depuis des implants C2).
* Filtres de recherche précis, identiques à LDAP `-q '(objectClass=user)'`.
* Opérations d’**écriture** facultatives ( `--set` / `--delete` ).
* **Mode de sortie BOFHound** pour une ingestion directe dans BloodHound.<sup>[[3]](#references)</sup>
* L’option `--parse` permet de rendre les timestamps et `userAccountControl` plus lisibles lorsqu’une lecture humaine est nécessaire.<sup>[[2]](#references)</sup>

### Options de collecte ciblée et opérations d’écriture

SoaPy fournit des options spécialisées qui reproduisent les tâches LDAP hunting les plus courantes via ADWS : `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, ainsi que les options `--query` / `--filter` brutes pour les collectes personnalisées. Associez-les à des primitives d’écriture telles que `--rbcd <source>` (définit `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (préparation de SPN pour un Kerberoasting ciblé) et `--asrep` (active `DONT_REQ_PREAUTH` dans `userAccountControl`).<sup>[[2]](#references)</sup>

Exemple de recherche SPN ciblée qui renvoie uniquement `samAccountName` et `servicePrincipalName` :
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Utilisez immédiatement le même host/identifiants pour weaponiser les findings : dump les objets compatibles avec RBCD avec `--rbcds`, puis appliquez `--rbcd 'WEBSRV01$' --account 'FILE01$'` afin de préparer une chaîne de Resource-Based Constrained Delegation (consultez [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) pour le chemin d’abus complet).

### Installation (poste opérateur)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump via ADWS (Linux/Windows)

* Fork de `ldapdomaindump` qui remplace les requêtes LDAP par des appels ADWS sur TCP/9389 afin de réduire les détections de signatures LDAP.
* Effectue un test initial d'accessibilité du port 9389, sauf si `--force` est utilisé (ignore la sonde si les scans de ports sont bruyants ou filtrés).
* Testé avec Microsoft Defender for Endpoint et CrowdStrike Falcon, avec un bypass réussi indiqué dans le README.<sup>[[4]](#references)</sup>

### Installation
```bash
pipx install .
```
### Utilisation
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Une sortie typique consigne la vérification de l'accessibilité du port 9389, la liaison ADWS et le début/la fin du dump :
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Un client pratique pour ADWS en Golang

De même que soapy, [sopa](https://github.com/Macmod/sopa) implémente la pile de protocoles ADWS (MS-NNS + MC-NMF + SOAP) en Golang et expose des options de ligne de commande permettant d'effectuer des appels ADWS tels que :<sup>[[5]](#references)</sup>

* **Recherche et récupération d'objets** - `query` / `get`
* **Cycle de vie des objets** - `create [user|computer|group|ou|container|custom]` et `delete`
* **Modification des attributs** - `attr [add|replace|delete]`
* **Gestion des comptes** - `set-password` / `change-password`
* et d'autres, comme `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Points clés du mapping des protocoles

* Les recherches de type LDAP sont effectuées via **WS-Enumeration** (`Enumerate` + `Pull`), avec projection des attributs, contrôle de la portée (Base/OneLevel/Subtree) et pagination.
* La récupération d'un objet unique utilise **WS-Transfer** `Get` ; les modifications d'attributs utilisent `Put` et les suppressions utilisent `Delete`.
* La création d'objets intégrée utilise **WS-Transfer ResourceFactory** ; les objets personnalisés utilisent une **IMDA AddRequest** pilotée par des modèles YAML.
* Les opérations sur les mots de passe sont des actions **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Découverte de métadonnées sans authentification (mex)

ADWS expose WS-MetadataExchange sans identifiants, ce qui permet de vérifier rapidement l'exposition avant l'authentification :<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Notes sur la découverte DNS/DC et le ciblage Kerberos

Sopa peut résoudre les DC via SRV si `--dc` est omis et que `--domain` est fourni. Il interroge dans cet ordre et utilise la cible ayant la priorité la plus élevée :<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Opérationnellement, privilégiez un resolver contrôlé par un DC afin d’éviter les échecs dans les environnements segmentés :

* Utilisez `--dns <DC-IP>` afin que **toutes** les recherches SRV/PTR/forward passent par le DNS du DC.
* Utilisez `--dns-tcp` lorsque l’UDP est bloqué ou que les réponses SRV sont volumineuses.
* Si Kerberos est activé et que `--dc` est une adresse IP, sopa effectue une **reverse PTR** pour obtenir un FQDN, afin de cibler correctement le SPN/KDC. Si Kerberos n’est pas utilisé, aucune recherche PTR n’est effectuée.

Exemple (IP + Kerberos, DNS forcé via le DC) :
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Options de matériel d'authentification

Outre les mots de passe en clair, sopa prend en charge les **hachages NT**, les **clés AES Kerberos**, les **ccache** et les **certificats PKINIT** (PFX ou PEM) pour l'authentification ADWS. Kerberos est implicite lors de l'utilisation de `--aes-key`, de `-c` (ccache) ou des options basées sur des certificats.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Création d’objets personnalisés via des templates

Pour des classes d’objets arbitraires, la commande `create custom` utilise un template YAML correspondant à un `AddRequest` IMDA :<sup>[[5]](#references)</sup>

* `parentDN` et `rdn` définissent le conteneur et le DN relatif.
* `attributes[].name` prend en charge `cn` ou `addata:cn` namespaced.
* `attributes[].type` accepte `string|int|bool|base64|hex` ou un `xsd:*` explicite.
* N’incluez **pas** `ad:relativeDistinguishedName` ou `ad:container-hierarchy-parent` ; sopa les injecte.
* Les valeurs `hex` sont converties en `xsd:base64Binary` ; utilisez `value: ""` pour définir des chaînes vides.

## SOAPHound – Collecte ADWS à haut volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) est un collector .NET qui conserve toutes les interactions LDAP dans ADWS et génère du JSON compatible avec BloodHound v4. Il crée une cache complète de `objectSid`, `objectGUID`, `distinguishedName` et `objectClass` une seule fois (`--buildcache`), puis la réutilise pour les passes à haut volume `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (DNS intégré à AD), afin que seuls environ 35 attributs critiques quittent le DC. AutoSplit (`--autosplit --threshold <N>`) segmente automatiquement les requêtes par préfixe CN afin de rester sous le délai d’expiration de 30 minutes d’EnumerationContext dans les grandes forêts.<sup>[[8]](#references)</sup>

Workflow typique sur une VM d’opérateur jointe au domaine :
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
Exportez directement les slots JSON dans les workflows SharpHound/BloodHound ; consultez la [méthodologie BloodHound](bloodhound.md) pour des idées de représentation graphique en aval. AutoSplit rend SOAPHound résilient sur les forêts contenant plusieurs millions d’objets tout en maintenant un nombre de requêtes inférieur à celui des snapshots de type ADExplorer.

## Workflow de collecte AD furtive

Le workflow suivant montre comment énumérer les **objets de domaine et ADCS** via ADWS, les convertir en JSON BloodHound et rechercher des chemins d’attaque fondés sur les certificats – le tout depuis Linux :

1. **Tunnélisez 9389/TCP** du réseau cible vers votre machine (par exemple via Chisel, Meterpreter, un port forwarding dynamique SSH, etc.). Exportez `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou utilisez `--proxyHost/--proxyPort` de SoaPy.

2. **Collectez l’objet du domaine racine :**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Collecter les objets liés à ADCS depuis la NC Configuration :**
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
Combinez ceci avec `s4u2proxy`/`Rubeus /getticket` pour obtenir une chaîne complète de **Resource-Based Constrained Delegation** (voir [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Résumé des outils

| Objectif | Outil | Notes |
|---------|------|-------|
| Énumération ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lecture/écriture |
| Dump ADWS à haut volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modes BH/ADCS/DNS |
| Importation dans BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convertit les journaux SoaPy/ldapsearch |
| Compromission de certificats | [Certipy](https://github.com/ly4k/Certipy) | Peut être proxifié via le même SOCKS |
| Énumération ADWS et modification d’objets | [sopa](https://github.com/Macmod/sopa) | Client générique permettant d’interagir avec les endpoints ADWS connus - permet l’énumération, la création d’objets, la modification d’attributs et les changements de mot de passe |

## References

- [1] [SpecterOps – Veillez à utiliser SOAP(y) – Guide de l’opérateur pour une collecte AD furtive avec ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy sur GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound sur GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump sur GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa sur GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Spécifications MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Énumération furtive des environnements Active Directory via ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Outil SOAPHound pour collecter des données Active Directory via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
