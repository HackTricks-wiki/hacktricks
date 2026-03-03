# Active Directory Web Services (ADWS) — Enumération et collecte furtive

{{#include ../../banners/hacktricks-training.md}}

## Qu'est-ce que ADWS ?

Active Directory Web Services (ADWS) est **activé par défaut sur chaque Domain Controller depuis Windows Server 2008 R2** et écoute sur le port TCP **9389**. Malgré son nom, **aucun HTTP n'est impliqué**. Le service expose des données de type LDAP via une pile de protocoles propriétaires .NET d'encapsulation :

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Parce que le trafic est encapsulé dans ces trames SOAP binaires et transite sur un port peu courant, **l'énumération via ADWS est beaucoup moins susceptible d'être inspectée, filtrée ou détectée par signature que le trafic LDAP classique/389 & 636**. Pour les opérateurs, cela signifie :

* Recon plus furtif — les Blue teams se concentrent souvent sur les requêtes LDAP.
* Possibilité de collecter depuis des hôtes **non-Windows (Linux, macOS)** en tunnelant 9389/TCP via un proxy SOCKS.
* Les mêmes données que via LDAP (users, groups, ACLs, schema, etc.) et la capacité d'effectuer des **opérations d'écriture** (par ex. `msDs-AllowedToActOnBehalfOfOtherIdentity` pour **RBCD**).

Les interactions ADWS sont implémentées sur WS-Enumeration : chaque requête commence par un message `Enumerate` qui définit le filtre/les attributs LDAP et renvoie un `EnumerationContext` GUID, suivi d'un ou plusieurs messages `Pull` qui streament jusqu'à la fenêtre de résultats définie par le serveur. Les contexts expirent après ~30 minutes, donc les outils doivent soit paginer les résultats soit diviser les filtres (requêtes par préfixe CN) pour éviter de perdre l'état. Lorsqu'on demande les descripteurs de sécurité, spécifiez le contrôle `LDAP_SERVER_SD_FLAGS_OID` pour omettre les SACLs, sinon ADWS supprime simplement l'attribut `nTSecurityDescriptor` de sa réponse SOAP.

> NOTE: ADWS est aussi utilisé par de nombreux outils RSAT GUI/PowerShell, donc le trafic peut se confondre avec une activité d'administration légitime.

## SoaPy – Client Python natif

[SoaPy](https://github.com/logangoins/soapy) est une **ré-implémentation complète de la pile protocolaire ADWS en pur Python**. Il construit les trames NBFX/NBFSE/NNS/NMF octet par octet, permettant la collecte depuis des systèmes de type Unix sans toucher au runtime .NET.

### Principales fonctionnalités

* Supporte le **proxying via SOCKS** (utile depuis des implants C2).
* Filtres de recherche fins identiques à LDAP `-q '(objectClass=user)'`.
* **Opérations d'écriture optionnelles** ( `--set` / `--delete` ).
* Mode de sortie **BOFHound** pour ingestion directe dans BloodHound.
* Option `--parse` pour améliorer l'affichage des timestamps / `userAccountControl` quand une lisibilité humaine est requise.

### Options de collecte ciblée & opérations d'écriture

SoaPy est livré avec des switches sélectionnés qui répliquent les tâches de recherche LDAP les plus courantes via ADWS : `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus des commandes brutes `--query` / `--filter` pour des extractions personnalisées. Associez-les à des primitives d'écriture comme `--rbcd <source>` (set `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (staging SPN pour Kerberoasting ciblé) et `--asrep` (basculer `DONT_REQ_PREAUTH` dans `userAccountControl`).

Exemple de recherche SPN ciblée qui ne retourne que `samAccountName` et `servicePrincipalName` :
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Utilisez le même host/credentials pour weaponise immédiatement les findings : dump RBCD-capable objects with `--rbcds`, puis apply `--rbcd 'WEBSRV01$' --account 'FILE01$'` pour stage une Resource-Based Constrained Delegation chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) for the full abuse path).

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Un client pratique pour ADWS en Golang

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implémente la pile de protocoles ADWS (MS-NNS + MC-NMF + SOAP) en Golang, et expose des flags en ligne de commande pour effectuer des appels ADWS tels que :

* **Recherche et récupération d'objets** - `query` / `get`
* **Cycle de vie des objets** - `create [user|computer|group|ou|container|custom]` et `delete`
* **Édition d'attributs** - `attr [add|replace|delete]`
* **Gestion des comptes** - `set-password` / `change-password`
* et d'autres tels que `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Collecte ADWS à haut volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) est un collecteur .NET qui maintient toutes les interactions LDAP à l'intérieur d'ADWS et émet du JSON compatible BloodHound v4. Il construit une cache complète de `objectSid`, `objectGUID`, `distinguishedName` et `objectClass` une seule fois (`--buildcache`), puis la réutilise pour des passes à haut volume `--bhdump`, `--certdump` (ADCS) ou `--dnsdump` (DNS intégré à AD), de sorte que seulement ~35 attributs critiques quittent le DC. AutoSplit (`--autosplit --threshold <N>`) segmente automatiquement les requêtes par préfixe CN pour rester en dessous du délai d'attente EnumerationContext de 30 minutes dans les grandes forêts.

Flux de travail typique sur une VM opérateur jointe au domaine :
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
Les JSON exportés s'intègrent directement aux workflows SharpHound/BloodHound — voir [BloodHound methodology](bloodhound.md) pour des idées de visualisation en aval. AutoSplit rend SOAPHound résilient sur des forêts à plusieurs millions d'objets tout en maintenant un nombre de requêtes inférieur aux snapshots de type ADExplorer.

## Flux de collecte AD furtif

Le workflow suivant montre comment énumérer **domain & ADCS objects** via ADWS, les convertir en JSON pour BloodHound et rechercher des chemins d'attaque basés sur des certificats — le tout depuis Linux :

1. **Tunnel 9389/TCP** depuis le réseau cible vers votre machine (par ex. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou utilisez les options `--proxyHost/--proxyPort` de SoaPy.

2. **Collecter l'objet racine du domaine :**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Collecter les objets liés à ADCS à partir de la Configuration NC :**
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
5. **Téléversez le ZIP** dans l'interface BloodHound GUI et exécutez des requêtes cypher telles que `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` pour révéler les chemins d'escalade de certificats (ESC1, ESC8, etc.).

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
| Énumération ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lecture/écriture |
| Dump ADWS à haut volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| Ingestion pour BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convertit les logs SoaPy/ldapsearch |
| Compromission de certificats | [Certipy](https://github.com/ly4k/Certipy) | Peut être utilisé via le même SOCKS |
| Énumération ADWS et modifications d'objets | [sopa](https://github.com/Macmod/sopa) | Client générique pour interagir avec des endpoints ADWS connus — permet l'énumération, la création d'objets, la modification d'attributs et le changement de mots de passe |

## Références

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
