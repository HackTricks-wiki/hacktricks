# Élévation de privilèges avec Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** peut être utilisé pour exécuter des programmes au **démarrage**. Vérifiez quels binaires sont configurés pour s’exécuter au démarrage avec :

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Tâches planifiées

Les **Tasks** peuvent être planifiées pour s’exécuter à une **fréquence précise**. Utilisez les commandes suivantes pour voir quels binaries sont planifiés pour s’exécuter :

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Une tâche créée avec `/sc ONLOGON /rl HIGHEST` demande le niveau d’exécution le plus élevé **disponible pour son principal enregistré** ; à lui seul, ce commutateur ne modifie pas ce principal et ne contourne pas l’UAC. Un processus à faibles privilèges ne peut pas enregistrer une tâche avec le niveau d’exécution le plus élevé ni choisir SYSTEM comme identité de la tâche. Considérez l’exemple ci-dessus comme une action effectuée par un utilisateur déjà élevé, et non comme un moyen pour un utilisateur standard d’obtenir SYSTEM.<sup>[[8]](#references)</sup>

Une tâche activée qui s’exécute en tant que SYSTEM mérite d’être examinée, même lorsque sa définition et son fichier d’action sont protégés. [Le Planificateur de tâches exige l’autorisation d’exécution sur la tâche pour la lancer à la demande](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Si un utilisateur à faibles privilèges dispose de cette autorisation, examinez l’action exacte, en particulier les scripts PowerShell qui modifient les ACL d’Active Directory ou réinitialisent les paramètres de protection des comptes. Vérifiez le paramètre `AllowDemandStart` de la tâche, ainsi que les entrées et les effets du script ; l’autorisation de lancer une tâche prédéfinie n’implique pas à elle seule l’exécution de code arbitraire.

## Dossiers

Tous les binaires situés dans les **dossiers de démarrage sont exécutés au démarrage**. Les dossiers de démarrage courants sont listés ci-dessous, mais leur emplacement est indiqué dans le registre. [Lisez ceci pour savoir où.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Une entrée Startup d’un utilisateur disposant de privilèges plus élevés peut lancer un script protégé qui ouvre régulièrement des fichiers provenant d’un répertoire où un autre utilisateur peut écrire. Vérifiez l’**identité réelle de l’utilisateur à l’ouverture de session**, le répertoire d’entrée du script et ses ACL, ainsi que l’action exacte, avant de considérer ce répertoire comme une piste d’escalade de privilèges. En particulier, [`hh.exe` ouvre les fichiers HTML Help compilés (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program) ; un script qui lui transmet des fichiers fournis par l’appelant franchit une frontière de confiance du contenu, même s’il vérifie le nom du fichier ou ses premiers octets. [Les stratégies HTML Help peuvent restreindre les raccourcis exécutables](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands) ; vérifiez donc la stratégie installée et le comportement du contenu accessible. Une extension `.chm` ou des octets magiques ne prouvent pas à eux seuls l’exécution de code avec des privilèges plus élevés. Examinez l’autorun, la ligne de commande du processus et les permissions sur les chemins sans ouvrir le fichier non fiable pendant l’énumération.

La même frontière de confiance du contenu existe lorsqu’une personne disposant de privilèges plus élevés **ouvre manuellement** un fichier `.chm` depuis un dossier de documentation qu’un autre utilisateur peut remplacer. Vérifiez les droits d’écriture exacts sur le fichier et son répertoire parent, l’identité réelle du lecteur et l’événement d’ouverture, ainsi que la stratégie HTML Help effective. Un dossier accessible en écriture ou une demande de consulter la documentation ne prouve pas que l’utilisateur disposant de privilèges plus élevés a ouvert du contenu contrôlé par un attaquant.

> **Pour info** : les vulnérabilités de *path traversal* lors de l’extraction d’archives (comme celle exploitée dans WinRAR avant la version 7.13 – CVE-2025-8088) peuvent être utilisées pour **déposer directement des payloads dans ces dossiers Startup pendant la décompression**, entraînant l’exécution de code à la prochaine ouverture de session. Pour une analyse approfondie de cette technique, voir :

{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registre

> [!TIP]
> [Remarque à partir d’ici](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f) : l’entrée de registre **Wow6432Node** indique que vous utilisez une version 64 bits de Windows. Le système d’exploitation utilise cette clé pour présenter une vue distincte de HKEY_LOCAL_MACHINE\SOFTWARE aux applications 32 bits exécutées sur des versions 64 bits de Windows.

### Exécutions

Clés de registre AutoRun **couramment connues** :

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

Les clés de registre **Run** et **RunOnce** sont conçues pour exécuter automatiquement des programmes chaque fois qu’un utilisateur ouvre une session sur le système. La ligne de commande affectée comme valeur de données d’une clé est limitée à 260 caractères.<sup>[[2]](#references)</sup>

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

Sous Windows Vista et les versions ultérieures, les clés de registre **Run** et **RunOnce** ne sont pas générées automatiquement. Les entrées de ces clés peuvent soit démarrer directement des programmes, soit les spécifier comme dépendances. Par exemple, pour charger un fichier DLL à l’ouverture de session, on peut utiliser la clé de registre **RunOnceEx** avec une clé « Depend ». Cela est illustré par l’ajout d’une entrée de registre exécutant « C:\temp\evil.dll » au démarrage du système :<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1** : Si vous pouvez écrire dans l’une des clés de registre mentionnées sous **HKLM**, vous pouvez escalader vos privilèges lorsqu’un autre utilisateur se connecte.

> [!TIP]
> **Exploit 2** : Si vous pouvez remplacer l’un des binaires indiqués dans les clés de registre sous **HKLM**, vous pouvez modifier ce binaire en y ajoutant une backdoor lorsqu’un autre utilisateur se connecte et escalader vos privilèges.

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

Les raccourcis placés dans le dossier **Startup** déclenchent automatiquement le lancement de services ou d’applications lors de la connexion de l’utilisateur ou du redémarrage du système. L’emplacement du dossier **Startup** est défini dans le registre pour les portées **Local Machine** et **Current User**. Ainsi, tout raccourci ajouté à ces emplacements **Startup** spécifiés garantit que le service ou le programme associé démarre après la connexion ou le redémarrage, ce qui constitue une méthode simple pour planifier l’exécution automatique de programmes.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Si vous pouvez écraser un dossier Shell Folder [User] sous **HKLM**, vous pourrez le faire pointer vers un dossier que vous contrôlez et y placer une backdoor qui sera exécutée chaque fois qu’un utilisateur se connecte au système, ce qui permet une élévation de privilèges.

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

Cette valeur de registre par utilisateur peut pointer vers un script ou une commande exécuté lors de la connexion de cet utilisateur. Il s’agit principalement d’un mécanisme de **persistence**, car il ne s’exécute que dans le contexte de l’utilisateur concerné, mais il vaut tout de même la peine de la vérifier lors des analyses post-exploitation et des vérifications d’autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Si vous pouvez modifier cette valeur pour l’utilisateur actuel, vous pouvez relancer l’exécution à sa prochaine ouverture de session interactive sans droits admin. Si vous pouvez la modifier dans la ruche d’un autre utilisateur, vous pouvez obtenir l’exécution de code lorsque cet utilisateur se connecte.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notes :

- Préférez les chemins complets vers les fichiers lanceurs `.bat`, `.cmd`, `.ps1` ou autres déjà accessibles en lecture à l’utilisateur cible.
- Cela persiste jusqu’à la suppression de la valeur, même après une déconnexion ou un redémarrage.
- Contrairement à `HKLM\...\Run`, cela ne confère pas à lui seul une élévation de privilèges ; il s’agit d’une persistance limitée à l’utilisateur.

### Clés Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

En général, la clé **Userinit** est définie sur **userinit.exe**. Toutefois, si cette clé est modifiée, l’exécutable spécifié sera également lancé par **Winlogon** lors de la connexion de l’utilisateur. De même, la clé **Shell** est censée pointer vers **explorer.exe**, le shell par défaut de Windows.<sup>[[1]](#references)</sup>

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

Dans le Registre Windows, sous `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, une valeur **`AlternateShell`** est définie par défaut sur `cmd.exe`. Cela signifie que lorsque vous choisissez « Mode sans échec avec invite de commandes » au démarrage (en appuyant sur F8), `cmd.exe` est utilisé. Cependant, il est possible de configurer votre ordinateur pour qu’il démarre automatiquement dans ce mode sans avoir à appuyer sur F8 et à le sélectionner manuellement.

Étapes pour créer une option de démarrage qui lance automatiquement le « Mode sans échec avec invite de commandes » :<sup>[[5]](#references)</sup>

1. Modifiez les attributs du fichier `boot.ini` pour supprimer les indicateurs lecture seule, système et masqué : `attrib c:\boot.ini -r -s -h`
2. Ouvrez `boot.ini` pour le modifier.
3. Insérez une ligne comme celle-ci : `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Enregistrez les modifications dans `boot.ini`.
5. Rétablissez les attributs d’origine du fichier : `attrib c:\boot.ini +r +s +h`

- **Exploit 1 :** La modification de la clé de Registre **AlternateShell** permet de configurer un shell de commandes personnalisé, ce qui peut permettre un accès non autorisé.
- **Exploit 2 (autorisations d’écriture sur PATH) :** Disposer d’autorisations d’écriture sur une partie quelconque de la variable système **PATH**, en particulier avant `C:\Windows\system32`, permet d’exécuter un `cmd.exe` personnalisé, qui pourrait servir de backdoor si le système démarre en mode sans échec.
- **Exploit 3 (autorisations d’écriture sur PATH et boot.ini) :** Un accès en écriture à `boot.ini` permet de démarrer automatiquement en mode sans échec, facilitant ainsi un accès non autorisé au prochain redémarrage.

Pour vérifier le paramètre **AlternateShell** actuel, utilisez ces commandes :

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Composant installé

Active Setup est une fonctionnalité de Windows qui **se lance avant le chargement complet de l’environnement de bureau**. Elle donne la priorité à l’exécution de certaines commandes, qui doivent se terminer avant que la connexion de l’utilisateur ne se poursuive. Ce processus a lieu avant même le déclenchement d’autres entrées de démarrage, comme celles des sections de registre Run ou RunOnce.

Active Setup est géré par les clés de registre suivantes :

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ces clés contiennent plusieurs sous-clés, chacune correspondant à un composant spécifique. Les valeurs de clé particulièrement intéressantes sont les suivantes :

- **IsInstalled :**
  - `0` indique que la commande du composant ne sera pas exécutée.
  - `1` signifie que la commande sera exécutée une fois pour chaque utilisateur. C’est le comportement par défaut si la valeur `IsInstalled` est absente.
- **StubPath :** définit la commande à exécuter par Active Setup. Il peut s’agir de n’importe quelle ligne de commande valide, par exemple le lancement de `notepad`.

**Informations de sécurité :**

- Modifier ou écrire dans une clé où **`IsInstalled`** est défini sur `"1"` et où **`StubPath`** contient une valeur spécifique peut entraîner l’exécution non autorisée de commandes, potentiellement à des fins d’élévation de privilèges.
- Modifier le fichier binaire référencé par une valeur **`StubPath`** peut également permettre une élévation de privilèges, si les permissions sont suffisantes.

Pour inspecter les configurations **`StubPath`** des composants Active Setup, vous pouvez utiliser les commandes suivantes :

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Présentation des Browser Helper Objects (BHO)

Les Browser Helper Objects (BHO) sont des modules DLL qui ajoutent des fonctionnalités à Microsoft Internet Explorer. Ils se chargent dans Internet Explorer et Windows Explorer à chaque démarrage. Leur exécution peut toutefois être bloquée en définissant la clé **NoExplorer** sur 1, ce qui les empêche de se charger avec les instances de Windows Explorer.<sup>[[1]](#references)</sup>

Les BHO sont compatibles avec Windows 10 via Internet Explorer 11, mais ne sont pas pris en charge dans Microsoft Edge, le navigateur par défaut des versions plus récentes de Windows.

Pour examiner les BHO enregistrés sur un système, vous pouvez consulter les clés de registre suivantes :

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Chaque BHO est représenté dans le registre par son **CLSID**, qui sert d’identifiant unique. Des informations détaillées sur chaque CLSID sont disponibles sous `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Pour rechercher les BHO dans le registre, vous pouvez utiliser les commandes suivantes :

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Extensions Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Notez que le registre contiendra une nouvelle entrée pour chaque DLL, représentée par le **CLSID**. Vous trouverez les informations du CLSID dans `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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

Les gestionnaires du menu contextuel de l’Explorateur sont des extensions du shell enregistrées sous des clés telles que `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` et `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. La valeur par défaut d’un gestionnaire, ou parfois le nom de sa clé, est un CLSID. Suivez ce CLSID jusqu’à `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32` ; sa valeur par défaut indique le nom de la DLL chargée lors de l’appel du gestionnaire.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Vérifiez les vues de registre 32 bits et 64 bits. `HKCR` fusionne les inscriptions de classes propres à l’utilisateur et celles à l’échelle de la machine ; vérifiez donc quelle clé sous-jacente un processus utilisera. Une identité à faibles privilèges capable de modifier une valeur `InprocServer32` à l’échelle de la machine peut rediriger un processus plus privilégié vers une autre DLL, mais l’escalade nécessite que ce processus invoque le gestionnaire. Un chemin de DLL accessible en écriture peut présenter un risque similaire, même si la valeur de registre elle-même est protégée.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Notez que tous les emplacements où vous pouvez trouver des autoruns ont **déjà été analysés par**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Cependant, pour obtenir une **liste plus complète des fichiers exécutés automatiquement**, vous pouvez utiliser [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) de systinternals :

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Plus

**Trouvez d’autres entrées Autoruns, comme les registres, dans** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Mécanismes courants de persistance des malwares](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Catégories de démarrage automatique (Dépannage avec les outils Windows Sysinternals, 2e édition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Comment ajouter une option de démarrage qui lance un shell alternatif ?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Bilan Metasploit 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – Contextes de sécurité des tâches](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
