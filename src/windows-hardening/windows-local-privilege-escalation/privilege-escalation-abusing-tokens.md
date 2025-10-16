# Abuser les tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Si vous ne savez pas ce que sont les Windows Access Tokens, lisez cette page avant de continuer :


{{#ref}}
access-tokens.md
{{#endref}}

**Il est possible d'élever les privilèges en abusant des tokens dont vous disposez déjà**

### SeImpersonatePrivilege

C'est un privilège détenu par un processus qui permet l'usurpation (mais pas la création) de n'importe quel token, à condition qu'un handle vers celui-ci puisse être obtenu. Un token privilégié peut être acquis à partir d'un service Windows (DCOM) en l'incitant à effectuer une authentification NTLM contre un exploit, permettant ainsi d'exécuter un processus avec les privilèges SYSTEM. Cette vulnérabilité peut être exploitée avec divers outils, tels que [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (qui requiert que winrm soit désactivé), [SweetPotato](https://github.com/CCob/SweetPotato), et [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

C'est très similaire à **SeImpersonatePrivilege**, il utilisera la **même méthode** pour obtenir un token privilégié.\
Ensuite, ce privilège permet **d'assigner un token primaire** à un processus nouveau/suspendu. Avec le token d'usurpation privilégié, vous pouvez dériver un token primaire (DuplicateTokenEx).\
Avec ce token, vous pouvez créer un **nouveau processus** avec 'CreateProcessAsUser' ou créer un processus en suspension et **définir le token** (généralement, vous ne pouvez pas modifier le token primaire d'un processus en cours d'exécution).

### SeTcbPrivilege

Si vous avez activé ce privilège, vous pouvez utiliser **KERB_S4U_LOGON** pour obtenir un **token d'usurpation** pour n'importe quel autre utilisateur sans connaître ses identifiants, **ajouter un groupe arbitraire** (admins) au token, définir le **niveau d'intégrité** du token sur "**medium**", et affecter ce token au **thread courant** (SetThreadToken).

### SeBackupPrivilege

Ce privilège pousse le système à **accorder tous les droits de lecture** sur n'importe quel fichier (limité aux opérations de lecture). Il est utilisé pour **lire les hashes de mot de passe des comptes Administrateur locaux** depuis le registre, après quoi des outils comme "**psexec**" ou "**wmiexec**" peuvent être utilisés avec le hash (technique Pass-the-Hash). Toutefois, cette technique échoue dans deux cas : lorsque le compte Administrateur local est désactivé, ou lorsqu'une politique empêche les Administrateurs locaux d'avoir des droits administratifs lors d'une connexion distante.\
Vous pouvez **abuser de ce privilège** avec:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- suivant **IppSec** dans [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ou comme expliqué dans la section **escalating privileges with Backup Operators** de:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ce privilège donne la permission d'**écriture** sur n'importe quel fichier système, indépendamment de la liste de contrôle d'accès (ACL) du fichier. Il ouvre de nombreuses possibilités d'escalade, y compris la capacité de **modifier des services**, d'effectuer du DLL Hijacking, et de définir des **débogueurs** via Image File Execution Options, entre autres techniques.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege est un privilège puissant, particulièrement utile lorsqu'un utilisateur a la capacité d'usurper des tokens, mais aussi en l'absence de SeImpersonatePrivilege. Cette capacité repose sur la possibilité d'usurper un token qui représente le même utilisateur et dont le niveau d'intégrité n'excède pas celui du processus courant.

**Points clés :**

- **Usurpation sans SeImpersonatePrivilege :** Il est possible d'exploiter SeCreateTokenPrivilege pour l'EoP en usurpant des tokens sous certaines conditions.
- **Conditions pour l'usurpation de token :** L'usurpation réussie requiert que le token cible appartienne au même utilisateur et ait un niveau d'intégrité inférieur ou égal à celui du processus tentant l'usurpation.
- **Création et modification de tokens d'usurpation :** Les utilisateurs peuvent créer un token d'usurpation et l'améliorer en ajoutant le SID d'un groupe privilégié (Security Identifier).

### SeLoadDriverPrivilege

Ce privilège permet de **charger et décharger des drivers** en créant une entrée de registre avec des valeurs spécifiques pour `ImagePath` et `Type`. Étant donné que l'écriture directe dans `HKLM` (HKEY_LOCAL_MACHINE) est restreinte, il faut utiliser `HKCU` (HKEY_CURRENT_USER) à la place. Cependant, pour rendre `HKCU` reconnaissable par le kernel pour la configuration du driver, un chemin spécifique doit être suivi.

Ce chemin est `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, où `<RID>` est l'identificateur relatif (Relative Identifier) de l'utilisateur courant. Dans `HKCU`, tout ce chemin doit être créé, et deux valeurs doivent être définies :

- `ImagePath`, qui est le chemin vers le binaire à exécuter
- `Type`, avec la valeur `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Étapes à suivre :**

1. Accéder à `HKCU` plutôt qu'à `HKLM` à cause des restrictions d'écriture.
2. Créer le chemin `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dans `HKCU`, où `<RID>` représente le Relative Identifier de l'utilisateur courant.
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
Plus de façons d'abuser de ce privilège dans [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ceci est similaire à **SeRestorePrivilege**. Sa fonction principale permet à un processus **d'assumer la propriété d'un objet**, contournant l'exigence d'un accès discrétionnaire explicite via la fourniture des droits d'accès WRITE_OWNER. Le processus consiste d'abord à s'assurer la propriété de la clé de registre visée à des fins d'écriture, puis à modifier la DACL pour permettre les opérations d'écriture.
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

Ce privilège permet de **déboguer d'autres processus**, y compris de lire et d'écrire dans la mémoire. Diverses stratégies d'injection en mémoire, capables d'échapper à la plupart des antivirus et des solutions de prévention des intrusions sur l'hôte, peuvent être employées avec ce privilège.

#### Dump memory

Vous pouvez utiliser [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) pour **capturer la mémoire d'un processus**. Plus précisément, cela peut s'appliquer au processus **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, qui est responsable du stockage des identifiants utilisateur une fois qu'un utilisateur s'est connecté avec succès à un système.

Vous pouvez ensuite charger ce dump dans mimikatz pour obtenir des mots de passe :
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

Ce droit (Perform volume maintenance tasks) permet d'ouvrir des handles de périphérique de volume bruts (par ex., \\.\C:) pour des E/S disque directes qui contournent les ACL NTFS. Avec ce droit, vous pouvez copier les octets de n'importe quel fichier sur le volume en lisant les blocs sous-jacents, permettant la lecture arbitraire de fichiers contenant des données sensibles (par ex., clés privées machine dans %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Ceci est particulièrement critique sur les serveurs CA, où l'exfiltration de la clé privée de la CA permet de forger un Golden Certificate afin d'usurper n'importe quel principal.

Voir les techniques détaillées et les mesures d'atténuation :

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Vérifier les privilèges
```
whoami /priv
```
Les **tokens qui apparaissent comme Disabled** peuvent être activés ; en fait, vous pouvez abuser des tokens _Enabled_ et _Disabled_.

### Enable All the tokens

Si vous avez des tokens disabled, vous pouvez utiliser le script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) pour activer tous les tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou le **script** intégré dans ce [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tableau

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilège                  | Impact      | Outil                   | Chemin d'exécution                                                                                                                                                                                                                                                                                                                                  | Remarques                                                                                                                                                                                                                                                                                                                       |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | outil tiers             | _"Cela permettrait à un utilisateur d'usurper des tokens et de privesc vers nt system en utilisant des outils tels que potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                          | Merci à [Aurélien Chalot](https://twitter.com/Defte_) pour la mise à jour. J'essaierai de le reformuler pour quelque chose de plus de type "recette" bientôt.                                                                                                                                                                    |
| **`SeBackup`**             | **Menace**  | _**Commandes intégrées**_ | Lire des fichiers sensibles avec `robocopy /b`                                                                                                                                                                                                                                                                                                     | <p>- Peut être plus intéressant si vous pouvez lire %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (et robocopy) n'est pas utile pour les fichiers ouverts.<br><br>- Robocopy nécessite à la fois SeBackup et SeRestore pour fonctionner avec le paramètre /b.</p>                                                     |
| **`SeCreateToken`**        | _**Admin**_ | outil tiers             | Créer un token arbitraire incluant des droits admin locaux avec `NtCreateToken`.                                                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliquer le token de `lsass.exe`.                                                                                                                                                                                                                                                                                                                 | Script disponible sur [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | outil tiers             | <p>1. Charger un pilote noyau défectueux tel que <code>szkg64.sys</code><br>2. Exploiter la vulnérabilité du pilote<br><br>Alternativement, le privilège peut être utilisé pour décharger des pilotes liés à la sécurité avec la commande intégrée <code>ftlMC</code>. i.e.: <code>fltMC sysmondrv</code></p>                                           | <p>1. La vulnérabilité <code>szkg64</code> est répertoriée comme <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Le code d'exploit <code>szkg64</code> a été créé par <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Lancer PowerShell/ISE avec le privilège SeRestore présent.<br>2. Activer le privilège avec <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.)<br>3. Renommer utilman.exe en utilman.old<br>4. Renommer cmd.exe en utilman.exe<br>5. Verrouiller la console et appuyer sur Win+U</p> | <p>L'attaque peut être détectée par certains antivirus.</p><p>La méthode alternative consiste à remplacer des binaires de service stockés dans "Program Files" en utilisant le même privilège</p>                                                                                                                              |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Commandes intégrées**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renommer cmd.exe en utilman.exe<br>4. Verrouiller la console et appuyer sur Win+U</p>                                                                                                                                       | <p>L'attaque peut être détectée par certains antivirus.</p><p>La méthode alternative consiste à remplacer des binaires de service stockés dans "Program Files" en utilisant le même privilège.</p>                                                                                                                                                            |
| **`SeTcb`**                | _**Admin**_ | outil tiers             | <p>Manipuler les tokens pour inclure des droits admin locaux. Peut nécessiter SeImpersonate.</p><p>À vérifier.</p>                                                                                                                                                                                                                                   |                                                                                                                                                                                                                                                                                                                                |

## Références

- Consultez ce tableau définissant les tokens Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Consultez [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) sur le privesc avec les tokens.
- Microsoft – Effectuer des tâches de maintenance de volume (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB : Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
